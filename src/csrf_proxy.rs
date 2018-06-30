use std::io::{Read, Error};
use std::cmp;
use super::CsrfToken;
use csrf_proxy::ParseState::*;

#[derive(Debug)]
enum ParseState {
    Reset,                          //default state
    PartialFormMatch(u8),           //when parsing "<form"
    SearchInput,                    //like default state, but inside a form
    PartialInputMatch(u8, usize),   //when parsing "<input"
    PartialFormEndMatch(u8, usize), //when parsing "</form" ('<' is actally done via PartialInputMarch)
    SearchMethod(usize),            //when inside the first <input>, search for begining of a param
    PartialNameMatch(u8, usize),    //when parsing "name="_method""
    CloseInputTag, //only if insert after, search for '>' of a "<input name=\"_method\">"
}


pub struct CsrfProxy<'a> {
    underlying: Box<Read + 'a>, //the underlying Reader from which we get data
    token: Vec<u8>,             //a full input tag loaded with a valid token
    buf: Vec<(Vec<u8>, usize)>, //a stack of buffers, with a position in case a buffer was not fully transmited
    state: ParseState,          //state of the parser
    insert_tag: Option<usize>, //if we have to insert tag here, and how fare are we in the tag (in case of very short read()s)
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
            underlying,
            token,
            buf: Vec::new(),
            state: ParseState::Reset,
            insert_tag: None,
        }
    }
}

impl<'a> Read for CsrfProxy<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if let Some(pos) = self.insert_tag {
            //if we should insert a tag
            let size = buf.len();
            let copy_size = cmp::min(size, self.token.len() - pos); //get max copy length
            buf[0..copy_size].copy_from_slice(&self.token[pos..copy_size + pos]); //copy that mutch
            if copy_size == self.token.len() - pos {
                //if we copied the full tag, say we don't need to set it again
                self.insert_tag = None;
            } else {
                //if we didn't copy the full tag, save where we were
                self.insert_tag = Some(pos + copy_size);
            }
            return Ok(copy_size); //return the lenght of the copied data
        }

        let len = if let Some((vec, pos)) = self.buf.pop() {
            //if there is a buffer to add here
            let size = buf.len();
            if vec.len() - pos <= size {
                //if the part left of the buffer is smaller than buf
                buf[0..vec.len() - pos].copy_from_slice(&vec[pos..]);
                vec.len() - pos
            } else {
                //else if the part left of the buffer is bigger than buf
                buf.copy_from_slice(&vec[pos..pos + size]);
                self.buf.push((vec, pos + size));
                size
            } //send the size of what was read as if it was a normal read on underlying struct
        } else {
            //if there is no buffer to add, read from underlying struct
            let res = self.underlying.read(buf);
            if res.is_err() {
                return res;
            }
            match res {
                Ok(v) => v,
                Err(_) => return res,
            }
        };

        for i in 0..len {
            //for each byte
            self.state = match self.state {
                Reset => if buf[i] as char == '<' {
                    //if we are in default state and we begin to match any tag
                    PartialFormMatch(0)
                } else {
                    //if we don't match a tag
                    Reset
                },
                PartialFormMatch(count) => match (buf[i] as char, count) {
                    //progressively match "form"
                    ('f', 0) | ('F', 0) => PartialFormMatch(1),
                    ('o', 1) | ('O', 1) => PartialFormMatch(2),
                    ('r', 2) | ('R', 2) => PartialFormMatch(3),
                    ('m', 3) | ('M', 3) => SearchInput, //when we success, go to next state
                    _ => Reset, //if this don't match, go back to defailt state
                },
                SearchInput => if buf[i] as char == '<' {
                    //begin to match any tag
                    PartialInputMatch(0, i)
                } else {
                    SearchInput
                },
                PartialInputMatch(count, pos) => match (buf[i] as char, count) {
                    //progressively match "input"
                    ('i', 0) | ('I', 0) => PartialInputMatch(1, pos),
                    ('n', 1) | ('N', 1) => PartialInputMatch(2, pos),
                    ('p', 2) | ('P', 2) => PartialInputMatch(3, pos),
                    ('u', 3) | ('U', 3) => PartialInputMatch(4, pos),
                    ('t', 4) | ('T', 4) => SearchMethod(pos), //when we success, go to next state
                    ('/', 0) => PartialFormEndMatch(1, pos), //if first char is '/', it may mean we are matching end of form, go to that state
                    _ => SearchInput, //not a input tag, go back to SearchInput
                },
                PartialFormEndMatch(count, pos) => match (buf[i] as char, count) {
                    //progressively match "/form"
                    ('/', 0) => PartialFormEndMatch(1, pos), //unreachable, here only for comprehension
                    ('f', 1) | ('F', 1) => PartialFormEndMatch(2, pos),
                    ('o', 2) | ('O', 2) => PartialFormEndMatch(3, pos),
                    ('r', 3) | ('R', 3) => PartialFormEndMatch(4, pos),
                    ('m', 4) | ('M', 4) => {
                        //if we match end of form, save "</form>" and anything after to a buffer, and insert our token
                        self.insert_tag = Some(0);
                        self.buf.push((buf[pos..len].to_vec(), 0));
                        self.state = Reset;
                        return Ok(pos);
                    }
                    _ => SearchInput,
                },
                SearchMethod(pos) => match buf[i] as char {
                    //try to match params
                    ' ' => PartialNameMatch(0, pos), //space, next char is a new param
                    '>' => {
                        //end of this <input> tag, it's not Rocket special one, so insert before, saving what comes next to buffer
                        self.insert_tag = Some(0);
                        self.buf.push((buf[pos..len].to_vec(), 0));
                        self.state = Reset;
                        return Ok(pos);
                    }
                    _ => SearchMethod(pos),
                },
                PartialNameMatch(count, pos) => match (buf[i] as char, count) {
                    //progressively match "name='_method'", which must be first to work
                    ('n', 0) | ('N', 0) => PartialNameMatch(1, pos),
                    ('a', 1) | ('A', 1) => PartialNameMatch(2, pos),
                    ('m', 2) | ('M', 2) => PartialNameMatch(3, pos),
                    ('e', 3) | ('E', 3) => PartialNameMatch(4, pos),
                    ('=', 4) => PartialNameMatch(5, pos),
                    ('"', 5) | ('\'', 5) => PartialNameMatch(6, pos),
                    ('_', 6) | ('_', 5) => PartialNameMatch(7, pos),
                    ('m', 7) | ('M', 7) => PartialNameMatch(8, pos),
                    ('e', 8) | ('E', 8) => PartialNameMatch(9, pos),
                    ('t', 9) | ('T', 9) => PartialNameMatch(10, pos),
                    ('h', 10) | ('H', 10) => PartialNameMatch(11, pos),
                    ('o', 11) | ('O', 11) => PartialNameMatch(12, pos),
                    ('d', 12) | ('D', 12) => PartialNameMatch(13, pos),
                    ('"', 13) | ('\'', 13) | (' ', 13) => CloseInputTag, //we matched, wait for end of this <input> and insert just after
                    _ => SearchMethod(pos),     //we did not match, search next param
                },
                CloseInputTag => if buf[i] as char == '>' {
                    //search for '>' at the end of an "<input name='_method'>", and insert token after
                    self.insert_tag = Some(0);
                    self.buf.push((buf[i + 1..len].to_vec(), 0));
                    self.state = Reset;
                    return Ok(i + 1);
                } else {
                    CloseInputTag
                },
            }
        }
        Ok(len)
    }
}
