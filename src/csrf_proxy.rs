use std::io::{Read, Error};
use std::cmp;
use std::collections::VecDeque;
use super::CsrfToken;
use csrf_proxy::ParseState::*;


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
                .copy_from_slice(&self.buf[0][self.pos[0]..self.pos[0]+to_copy]);
            read += to_copy;
            if part_len == to_copy {
                self.buf.pop_front();
                self.pos.pop_front();
            } else {
                self.pos[0]+=to_copy;
            }
        }
        read
    }

    fn len(&self) -> usize {
        self.buf.iter().fold(0, |size, buf| size+buf.len()) - self.pos.iter().fold(0, |size, pos| size + pos)
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
    Init,                           //default state
    PartialFormMatch,               //when parsing "<form"
    SearchFormElem,                 //like default state, but inside a form
    PartialFormElemMatch,           //when parsing "<input"
    SearchMethod(usize),            //when inside the first <input>, search for begining of a param
    PartialNameMatch(usize),        //when parsing "name="_method""
    CloseInputTag,                  //only if insert after, search for '>' of a "<input name=\"_method\">"
}

pub struct CsrfProxy<'a> {
    underlying: Box<Read + 'a>, //the underlying Reader from which we get data
    token: Vec<u8>,             //a full input tag loaded with a valid token
    buf: Buffer,
    unparsed: Vec<u8>,
    state: ParseState,          //state of the parser
    eof: bool,
}

impl<'a> CsrfProxy<'a> {
    pub fn from(underlying: Box<Read + 'a>, token: &CsrfToken) -> Self {
        let tag_begin = b"<input type=\"hidden\" name=\"csrf-token\" value=\"";
        let tag_middle = token.value();
        let tag_end = b"\">";
        let mut token = Vec::new();
        token.extend_from_slice(tag_begin);
        token.extend_from_slice(tag_middle);
        token.extend_from_slice(tag_end);
        CsrfProxy {
            underlying: underlying,
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
        //println!("request {}", buf.len());

        while self.buf.len() < buf.len() && !(self.eof && self.unparsed.is_empty()) {
            let len = if !self.eof {
                let unparsed_len = self.unparsed.len();
                self.unparsed.resize(4096,0);
                unparsed_len +
                    match self.underlying.read(&mut self.unparsed[unparsed_len..]) {
                        Ok(0) => {
                            self.eof = true;
                            0
                        },
                        Ok(len) => len,
                        Err(e) => return Err(e),
                    }
            } else {
                self.unparsed.len()
            };

            let (consumed, insert_token) = {
                let mut buf = &self.unparsed[..len];//work only on the initialized part
                let mut consumed = 0;
                let mut leave = false;
                let mut insert_token = false;
                while !leave {
                    self.state = match self.state {
                        Init => {
                            if let Some(tag_pos) = buf.iter().position(|&c| c as char=='<') {
                                buf = &buf[tag_pos..];
                                consumed+=tag_pos;
                                PartialFormMatch
                            } else {
                                leave = true;
                                consumed += buf.len();
                                Init
                            }
                        },
                        PartialFormMatch => {
                            if let Some(lower_begin) = buf.get(1..5).map(|slice| slice.to_ascii_lowercase()) {
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
                        },
                        SearchFormElem => {
                            if let Some(tag_pos) = buf.iter().position(|&c| c as char=='<') {
                                buf = &buf[tag_pos..];
                                consumed+=tag_pos;
                                PartialFormElemMatch
                            } else {
                                leave = true;
                                consumed += buf.len();
                                SearchFormElem
                            }},
                        PartialFormElemMatch => {
                            if let Some(lower_begin) = buf.get(1..9).map(|slice| slice.to_ascii_lowercase()) {
                                if lower_begin.starts_with("/form".as_bytes())
                                    || lower_begin.starts_with("textarea".as_bytes())
                                    || lower_begin.starts_with("button".as_bytes())
                                    || lower_begin.starts_with("select".as_bytes()) {
                                    insert_token = true;
                                    leave = true;
                                    Init
                                } else if lower_begin.starts_with("input".as_bytes()){
                                    SearchMethod(9)
                                } else {
                                    buf = &buf[9..];
                                    consumed += 9;
                                    SearchFormElem
                                }
                            } else {
                               leave = true;
                               PartialFormMatch
                            }
                        },
                        SearchMethod(pos) => {
                            if let Some(meth_pos) = buf[pos..].iter().position(|&c| c as char == ' ' || c as char == '>') {
                                if buf[meth_pos + pos] as char == ' ' {
                                    PartialNameMatch(meth_pos + pos + 1)
                                } else { //reached '>'
                                    insert_token = true;
                                    leave = true;
                                    Init
                                }
                            } else {
                                leave = true;
                                SearchMethod(buf.len())
                            }
                        },
                        PartialNameMatch(pos) => {
                            if let Some(lower_begin) = buf.get(pos..pos+14).map(|slice| slice.to_ascii_lowercase()) {
                                if lower_begin.starts_with("name=\"_method\"".as_bytes())
                                    || lower_begin.starts_with("name='_method'".as_bytes())
                                    || lower_begin.starts_with("name=_method".as_bytes()) {
                                    buf = &buf[pos+14..];
                                    consumed += pos+14;
                                    CloseInputTag
                                } else {
                                    SearchMethod(pos)
                                }
                            } else {
                               leave = true;
                               PartialNameMatch(pos)
                            }
                        },
                        CloseInputTag => {
                            leave = true;
                            if let Some(tag_pos) = buf.iter().position(|&c| c as char=='>') {
                                buf = &buf[tag_pos..];
                                consumed+=tag_pos;
                                insert_token = true;
                                Init
                            } else {
                                consumed += buf.len();
                                CloseInputTag
                            }
                        },
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
