use csrf_proxy::ParseState::*;
use std::cmp;
use std::collections::VecDeque;
use std::io::{Error, Read};

#[derive(Debug)]
struct Buffer {
    buf: VecDeque<Vec<u8>>,
    pos: VecDeque<usize>,
}

impl Buffer {
    fn new() -> Self {
        Buffer {
            buf: VecDeque::new(),
            pos: VecDeque::new(),
        }
    }

    fn push_back(&mut self, value: Vec<u8>) {
        self.buf.push_back(value);
        self.pos.push_back(0);
    }

    fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut read = 0;
        while buf.len() > read && !self.is_empty() {
            let part_len = self.buf[0].len() - self.pos[0];
            let buf_len = buf.len() - read;
            let to_copy = cmp::min(part_len, buf_len);
            buf[read..read + to_copy]
                .copy_from_slice(&self.buf[0][self.pos[0]..self.pos[0] + to_copy]);
            read += to_copy;
            if part_len == to_copy {
                self.buf.pop_front();
                self.pos.pop_front();
            } else {
                self.pos[0] += to_copy;
            }
        }
        read
    }

    fn len(&self) -> usize {
        self.buf.iter().fold(0, |size, buf| size + buf.len())
            - self.pos.iter().fold(0, |size, pos| size + pos)
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
enum ParseState {
    Init,                    //default state
    PartialFormMatch,        //when parsing "<form"
    SearchFormElem,          //like default state, but inside a form
    PartialFormElemMatch,    //when parsing "<input", "<textarea" or other form elems, and "</form"
    SearchMethod(usize),     //when inside the first <input>, search for begining of a param
    PartialNameMatch(usize), //when parsing "name="_method""
    CloseInputTag,           //only if insert after, search for '>' of a "<input name=\"_method\">"
}

pub struct CsrfProxy<'a> {
    underlying: Box<Read + 'a>, //the underlying Reader from which we get data
    token: Vec<u8>,             //a full input tag loaded with a valid token
    buf: Buffer,
    unparsed: Vec<u8>,
    state: ParseState, //state of the parser
    eof: bool,
}

impl<'a> CsrfProxy<'a> {
    pub fn from(underlying: Box<Read + 'a>, token: &[u8]) -> Self {
        let tag_begin = b"<input type=\"hidden\" name=\"csrf-token\" value=\"";
        let tag_middle = token;
        let tag_end = b"\"/>";
        let mut token = Vec::new();
        token.extend_from_slice(tag_begin);
        token.extend_from_slice(tag_middle);
        token.extend_from_slice(tag_end);
        CsrfProxy {
            underlying,
            token,
            buf: Buffer::new(),
            unparsed: Vec::with_capacity(4096),
            state: ParseState::Init,
            eof: false,
        }
    }
}

impl<'a> Read for CsrfProxy<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        while self.buf.len() < buf.len() && !(self.eof && self.unparsed.is_empty()) {
            let len = if !self.eof {
                let unparsed_len = self.unparsed.len();
                self.unparsed.resize(4096, 0);
                unparsed_len + match self.underlying.read(&mut self.unparsed[unparsed_len..]) {
                    Ok(0) => {
                        self.eof = true;
                        0
                    }
                    Ok(len) => len,
                    Err(e) => return Err(e),
                }
            } else {
                self.unparsed.len()
            };

            self.unparsed.resize(len, 0); //we growed unparsed buffer to 4k before, so shrink it to it's needed size

            let (consumed, insert_token) = {
                let mut buf = &self.unparsed[..len]; //work only on the initialized part
                let mut consumed = 0;
                let mut leave = false;
                let mut insert_token = false;
                while !leave {
                    self.state = match self.state {
                        Init => {
                            if let Some(tag_pos) = buf.iter().position(|&c| c as char == '<') {
                                buf = &buf[tag_pos..];
                                consumed += tag_pos;
                                PartialFormMatch
                            } else {
                                leave = true;
                                consumed += buf.len();
                                Init
                            }
                        }
                        PartialFormMatch => {
                            if let Some(lower_begin) =
                                buf.get(1..5).map(|slice| slice.to_ascii_lowercase())
                            {
                                buf = &buf[5..];
                                consumed += 5;
                                if lower_begin == "form".as_bytes() {
                                    SearchFormElem
                                } else {
                                    Init
                                }
                            } else {
                                leave = true;
                                PartialFormMatch
                            }
                        }
                        SearchFormElem => {
                            if let Some(tag_pos) = buf.iter().position(|&c| c as char == '<') {
                                buf = &buf[tag_pos..];
                                consumed += tag_pos;
                                PartialFormElemMatch
                            } else {
                                leave = true;
                                consumed += buf.len();
                                SearchFormElem
                            }
                        }
                        PartialFormElemMatch => {
                            if let Some(lower_begin) =
                                buf.get(1..9).map(|slice| slice.to_ascii_lowercase())
                            {
                                if lower_begin.starts_with("/form".as_bytes())
                                    || lower_begin.starts_with("textarea".as_bytes())
                                    || lower_begin.starts_with("button".as_bytes())
                                    || lower_begin.starts_with("select".as_bytes())
                                {
                                    insert_token = true;
                                    leave = true;
                                    Init
                                } else if lower_begin.starts_with("input".as_bytes()) {
                                    SearchMethod(6)
                                } else {
                                    buf = &buf[9..];
                                    consumed += 9;
                                    SearchFormElem
                                }
                            } else {
                                leave = true;
                                SearchFormElem
                            }
                        }
                        SearchMethod(pos) => {
                            if let Some(meth_pos) = buf[pos..]
                                .iter()
                                .position(|&c| c as char == ' ' || c as char == '>')
                            {
                                if buf[meth_pos + pos] as char == ' ' {
                                    PartialNameMatch(meth_pos + pos + 1)
                                } else {
                                    //reached '>'
                                    insert_token = true;
                                    leave = true;
                                    Init
                                }
                            } else {
                                leave = true;
                                SearchMethod(buf.len())
                            }
                        }
                        PartialNameMatch(pos) => {
                            if let Some(lower_begin) = buf
                                .get(pos..pos + 14)
                                .map(|slice| slice.to_ascii_lowercase())
                            {
                                if lower_begin.starts_with("name=\"_method\"".as_bytes())
                                    || lower_begin.starts_with("name='_method'".as_bytes())
                                {
                                    buf = &buf[pos + 14..];
                                    consumed += pos + 14;
                                    CloseInputTag
                                } else if lower_begin.starts_with("name=_method".as_bytes()) {
                                    buf = &buf[pos + 12..];
                                    consumed += pos + 12;
                                    CloseInputTag
                                } else {
                                    SearchMethod(pos)
                                }
                            } else {
                                leave = true;
                                PartialNameMatch(pos)
                            }
                        }
                        CloseInputTag => {
                            leave = true;
                            if let Some(tag_pos) = buf.iter().position(|&c| c as char == '>') {
                                buf = &buf[tag_pos + 1..];
                                consumed += tag_pos + 1;
                                insert_token = true;
                                Init
                            } else {
                                consumed += buf.len();
                                CloseInputTag
                            }
                        }
                    }
                }
                (consumed, insert_token)
            };
            self.buf.push_back(self.unparsed[0..consumed].to_vec());
            if insert_token {
                self.buf.push_back(self.token.clone());
            }
            self.unparsed.drain(0..consumed);
        }
        Ok(self.buf.read(buf))
    }
}

#[cfg(test)]
mod tests {
    use csrf_proxy::{Buffer, CsrfProxy};
    use std::io::{Cursor, Read};

    #[test]
    fn test_buffer_size() {
        let mut buffer = Buffer::new();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);

        buffer.push_back(vec![0; 64]);
        assert!(!buffer.is_empty());
        assert_eq!(buffer.len(), 64);
        let mut buf = [0; 32];
        buffer.read(&mut buf);
        assert!(!buffer.is_empty());
        assert_eq!(buffer.len(), 32);
        buffer.read(&mut buf);
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn test_buffer_integrity() {
        let mut buffer = Buffer::new();
        let mut buf = [0; 8];

        buffer.push_back(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        buffer.push_back(vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);

        let size = buffer.read(&mut buf);
        assert_eq!(size, 8);
        assert_eq!(buf, [0, 1, 2, 3, 4, 5, 6, 7]);

        buffer.push_back(vec![20, 21, 22, 23, 24, 25, 26, 27, 28, 29]);

        let size = buffer.read(&mut buf);
        assert_eq!(size, 8);
        assert_eq!(buf, [8, 9, 10, 11, 12, 13, 14, 15]);

        let size = buffer.read(&mut buf);
        assert_eq!(size, 8);
        assert_eq!(buf, [16, 17, 18, 19, 20, 21, 22, 23]);

        let size = buffer.read(&mut buf);
        assert_eq!(size, 6);
        assert_eq!(buf[..6], [24, 25, 26, 27, 28, 29]);

        let size = buffer.read(&mut buf);
        assert_eq!(size, 0);
    }

    #[test]
    fn test_proxy_identity() {
        let data = "<!DOCTYPE html>
<html>
  <head>
    <title>Simple doc</title>
  </head>
  <body>
    Body of this simple doc
  </body>
</html>"
            .as_bytes();
        let mut proxy = CsrfProxy::from(Box::new(Cursor::new(data)), "abcd".as_bytes());
        let mut pr_data = Vec::new();
        let read = proxy.read_to_end(&mut pr_data);
        assert_eq!(read.unwrap(), data.len());
        assert_eq!(&pr_data, &data)
    }

    #[test]
    fn test_token_insertion_empty_form() {
        let data = "<!DOCTYPE html>
<html>
  <head>
    <title>Simple doc</title>
  </head>
  <body>
     <form>
        <p>
          some text
        </p>
     </form>
  </body>
</html>"
            .as_bytes();
        let expected = "<!DOCTYPE html>
<html>
  <head>
    <title>Simple doc</title>
  </head>
  <body>
     <form>
        <p>
          some text
        </p>
     <input type=\"hidden\" name=\"csrf-token\" value=\"abcd\"/></form>
  </body>
</html>"
            .as_bytes();
        let mut proxy = CsrfProxy::from(Box::new(Cursor::new(data)), "abcd".as_bytes());
        let mut pr_data = Vec::new();
        let read = proxy.read_to_end(&mut pr_data);
        assert_eq!(
            read.unwrap(),
            data.len() + "<input type=\"hidden\" name=\"csrf-token\" value=\"abcd\"/>".len()
        );
        assert_eq!(&pr_data, &expected)
    }

    #[test]
    fn test_token_insertion() {
        let data = "<!DOCTYPE html>
<html>
  <head>
    <title>Simple doc</title>
  </head>
  <body>
     <form>
        <input name=\"name\"/>
     </form>
  </body>
</html>"
            .as_bytes();
        let expected = "<!DOCTYPE html>
<html>
  <head>
    <title>Simple doc</title>
  </head>
  <body>
     <form>
        <input type=\"hidden\" name=\"csrf-token\" value=\"abcd\"/><input name=\"name\"/>
     </form>
  </body>
</html>"
            .as_bytes();
        let mut proxy = CsrfProxy::from(Box::new(Cursor::new(data)), "abcd".as_bytes());
        let mut pr_data = Vec::new();
        let read = proxy.read_to_end(&mut pr_data);
        assert_eq!(
            read.unwrap(),
            data.len() + "<input type=\"hidden\" name=\"csrf-token\" value=\"abcd\"/>".len()
        );
        assert_eq!(&pr_data, &expected)
    }

    #[test]
    fn test_token_insertion_with_method() {
        let data = "<!DOCTYPE html>
<html>
  <head>
    <title>Simple doc</title>
  </head>
  <body>
     <form>
        <input name=\"_method\"/>
     </form>
  </body>
</html>"
            .as_bytes();
        let expected = "<!DOCTYPE html>
<html>
  <head>
    <title>Simple doc</title>
  </head>
  <body>
     <form>
        <input name=\"_method\"/><input type=\"hidden\" name=\"csrf-token\" value=\"abcd\"/>
     </form>
  </body>
</html>"
            .as_bytes();
        let mut proxy = CsrfProxy::from(Box::new(Cursor::new(data)), "abcd".as_bytes());
        let mut pr_data = Vec::new();
        let read = proxy.read_to_end(&mut pr_data);
        assert_eq!(
            read.unwrap(),
            data.len() + "<input type=\"hidden\" name=\"csrf-token\" value=\"abcd\"/>".len()
        );
        assert_eq!(&pr_data, &expected)
    }

    struct ErrorReader {}

    impl Read for ErrorReader {
        fn read(&mut self, _buf: &mut [u8]) -> Result<usize, ::std::io::Error> {
            Err(::std::io::Error::new(::std::io::ErrorKind::Other, ""))
        }
    }

    #[test]
    fn test_relay_error() {
        let buf = &mut [0; 1];
        let err = ErrorReader {};
        let mut proxy_err = CsrfProxy::from(Box::new(err), &[0]);
        let read = proxy_err.read(buf).unwrap_err();
        assert_eq!(
            read.kind(),
            ::std::io::Error::new(::std::io::ErrorKind::Other, "").kind()
        );
    }

    struct SlowReader<'a> {
        content: &'a [u8],
    }

    impl<'a> Read for SlowReader<'a> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, ::std::io::Error> {
            if self.content.len() > 0 {
                buf[0] = self.content[0];
                self.content = &self.content[1..];
                Ok(1)
            } else {
                Ok(0)
            }
        }
    }

    #[test]
    fn test_difficult_cut() {
        //this basically re-test the parser, using short reads so it encounter rare code paths
        let data = "<!DOCTYPE html>
<html>
  <head>
    <title>Simple doc</title>
  </head>
  <body>
     <form>
        <p>
          some text
        </p>
     </form>
  </body>
</html>"
            .as_bytes();
        let expected = "<!DOCTYPE html>
<html>
  <head>
    <title>Simple doc</title>
  </head>
  <body>
     <form>
        <p>
          some text
        </p>
     <input type=\"hidden\" name=\"csrf-token\" value=\"abcd\"/></form>
  </body>
</html>"
            .as_bytes();
        let mut proxy = CsrfProxy::from(Box::new(SlowReader { content: data }), "abcd".as_bytes());
        let mut pr_data = Vec::new();
        let read = proxy.read_to_end(&mut pr_data);
        assert_eq!(
            read.unwrap(),
            data.len() + "<input type=\"hidden\" name=\"csrf-token\" value=\"abcd\"/>".len()
        );
        assert_eq!(&pr_data, &expected);

        let data = "<!DOCTYPE html>
<html>
  <head>
    <title>Simple doc</title>
  </head>
  <body>
     <form>
        <input name=\"name\"/>
     </form>
  </body>
</html>"
            .as_bytes();
        let expected = "<!DOCTYPE html>
<html>
  <head>
    <title>Simple doc</title>
  </head>
  <body>
     <form>
        <input type=\"hidden\" name=\"csrf-token\" value=\"abcd\"/><input name=\"name\"/>
     </form>
  </body>
</html>"
            .as_bytes();
        let mut proxy = CsrfProxy::from(Box::new(SlowReader { content: data }), "abcd".as_bytes());
        let mut pr_data = Vec::new();
        let read = proxy.read_to_end(&mut pr_data);
        assert_eq!(
            read.unwrap(),
            data.len() + "<input type=\"hidden\" name=\"csrf-token\" value=\"abcd\"/>".len()
        );
        assert_eq!(&pr_data, &expected);

        let data = "<!DOCTYPE html>
<html>
  <head>
    <title>Simple doc</title>
  </head>
  <body>
     <form>
        <input name=\"_method\"/>
     </form>
  </body>
</html>"
            .as_bytes();
        let expected = "<!DOCTYPE html>
<html>
  <head>
    <title>Simple doc</title>
  </head>
  <body>
     <form>
        <input name=\"_method\"/><input type=\"hidden\" name=\"csrf-token\" value=\"abcd\"/>
     </form>
  </body>
</html>"
            .as_bytes();
        let mut proxy = CsrfProxy::from(Box::new(SlowReader { content: data }), "abcd".as_bytes());
        let mut pr_data = Vec::new();
        let read = proxy.read_to_end(&mut pr_data);
        assert_eq!(
            read.unwrap(),
            data.len() + "<input type=\"hidden\" name=\"csrf-token\" value=\"abcd\"/>".len()
        );
        assert_eq!(&pr_data, &expected)
    }
}
