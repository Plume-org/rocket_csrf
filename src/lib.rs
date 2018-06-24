extern crate csrf;
extern crate data_encoding;
extern crate rand;
extern crate rocket;
extern crate serde;


use csrf::{AesGcmCsrfProtection, CsrfProtection};
use data_encoding::{BASE64, BASE64URL_NOPAD};
use rand::prelude::thread_rng;
use rand::Rng;
use rocket::{Data, Request, Response, Rocket, State};
use rocket::http::{Cookie, Status};
use rocket::http::Method::{self,*};
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest};
use rocket::response::Body::Sized;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::uri::Uri;
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::env;
use std::io::Read;
use std::str::from_utf8;

pub struct CsrfFairingBuilder {
    duration: i64,
    default_target: (String, Method),
    exceptions: Vec<(String, String, Method)>,
    secret: Option<[u8; 32]>,
    auto_insert: bool,
    auto_insert_disable_prefix: Vec<String>,
    auto_insert_max_size: u64,
}

impl CsrfFairingBuilder {
    pub fn new() -> Self {
        CsrfFairingBuilder {
            duration: 60*60,
            default_target: (String::from("/"),Get),
            exceptions: Vec::new(),
            secret: None,
            auto_insert: true,
            auto_insert_disable_prefix: Vec::new(),
            auto_insert_max_size: 16*1024,
        }
    }

    pub fn set_timeout(mut self, timeout: i64) -> Self {
        self.duration = timeout;
        self
    }

    pub fn set_default_target(mut self, default_target: String, method: Method) -> Self {
        self.default_target = (default_target, method);
        self
    }

    pub fn set_exceptions(mut self, exceptions: Vec<(String, String, Method)>) -> Self {
        self.exceptions = exceptions;
        self
    }
    pub fn add_exceptions(mut self, exceptions: Vec<(String, String, Method)>) -> Self {
        self.exceptions.extend(exceptions);
        self
    }

    pub fn set_secret(mut self, secret: [u8; 32]) -> Self {
        self.secret = Some(secret);
        self
    }

    pub fn finalize(self) -> Result<CsrfFairing, ()> {

        let secret = self.secret.unwrap_or_else(|| {
            env::vars()
                .filter(|(key, _)| key == "ROCKET_SECRET_KEY")
                .next()
                .and_then(|(_, value)| {
                    let b64 = BASE64.decode(value.as_bytes());
                    if let Ok(b64) = b64 {
                        if b64.len() == 32 {
                            let mut array = [0; 32];
                            array.copy_from_slice(&b64);
                            Some(array)
                        } else {
                            None
                        }
                    } else {
                       None
                    }
                })
                .unwrap_or_else(|| {
                    eprintln!("[rocket_csrf] No secret key was found, you should consider set one to allow application restart");
                    thread_rng().gen()
                })
        });

        let default_target = Path::from(&self.default_target.0);
        let mut hashmap = HashMap::new();
        hashmap.insert("uri", "");
        if default_target.map(hashmap).is_none() {
            return Err(());//invalid default url
        }
        Ok(CsrfFairing {
            duration: self.duration,
            default_target: (default_target,self.default_target.1),
            exceptions: self.exceptions.iter().map(|(a,b,m)| (Path::from(&a), Path::from(&b),*m)).collect(),
            secret: secret,
            auto_insert: self.auto_insert,
            auto_insert_disable_prefix: self.auto_insert_disable_prefix,
            auto_insert_max_size: self.auto_insert_max_size
        })
    }
}

pub struct CsrfFairing {
    duration: i64,
    default_target: (Path,Method),
    exceptions: Vec<(Path, Path, Method)>,
    secret: [u8;32],
    auto_insert: bool,
    auto_insert_disable_prefix: Vec<String>,
    auto_insert_max_size: u64,
}

impl Fairing for CsrfFairing {
    fn info(&self) -> Info {
        if self.auto_insert {
            Info {
                name: "CSRF protection",
                kind: Kind::Attach | Kind::Request | Kind::Response
            }
        } else {
            Info {
                name: "CSRF protection",
                kind: Kind::Attach | Kind::Request
            }
        }
    }

    fn on_attach(&self, rocket: Rocket) -> Result<Rocket, Rocket>{
        Ok(rocket.manage((AesGcmCsrfProtection::from_key(self.secret), self.duration)))
    }

    fn on_request(&self, request: &mut Request, data: &Data) {
        match request.method() {
            Get | Head | Connect | Trace | Options => {
                request.guard::<CsrfToken>();;//force regeneration of csrf cookies
                return
            },
            _ => {},
        };

        let (csrf_engine,_) = request.guard::<State<(AesGcmCsrfProtection, i64)>>().unwrap().inner();


        let cookie = request.cookies().get(csrf::CSRF_COOKIE_NAME)
            .and_then(|cookie| BASE64.decode(cookie.value().as_bytes()).ok())
            .and_then(|cookie| csrf_engine.parse_cookie(&cookie).ok());
       
        request.guard::<CsrfToken>();;//force regeneration of csrf cookies

        let token = parse_args(from_utf8(data.peek()).unwrap_or(""))
            .filter(|(key,_)|key==&csrf::CSRF_FORM_FIELD)
            .filter_map(|(_, token)| BASE64URL_NOPAD.decode(&token.as_bytes()).ok())
            .filter_map(|token| csrf_engine.parse_token(&token).ok())
            .next();

        if let Some(token) = token {
            if let Some(cookie) = cookie {
                if csrf_engine.verify_token_pair(&token, &cookie) {
                    return;
                } 
            }
        }

        for (src, dst, method) in self.exceptions.iter() {
            if let Some(param) = src.extract(&request.uri().to_string()){
                if let Some(destination) = dst.map(param) {
                    request.set_uri(destination);
                    request.set_method(*method);
                    return;
                }
            }
        }
        let uri = request.uri().to_string();
        let uri = Uri::percent_encode(&uri);
        let mut param: HashMap<&str, &str>= HashMap::new();
        param.insert("uri", &uri);
        request.set_uri(self.default_target.0.map(param).unwrap());
        request.set_method(self.default_target.1)
    }

    fn on_response<'a>(&self, request: &Request, response: &mut Response<'a>) {
        if let Some(ct) = response.content_type() {
            if !ct.is_html() {
                return;
            }
        }
        let uri = request.uri().to_string();
        if self.auto_insert_disable_prefix.iter().filter(|prefix| uri.starts_with(*prefix) ).next().is_some() {
            return;
        }

        //content type is html and we are not on static ressources, so we may need to modify this answer

        let token = match request.guard::<CsrfToken>(){
            Outcome::Success(t) => t,
            _ => return,
        };
         

        let body = response.take_body();
        if body.is_none() {
            return;
        }
        let body = body.unwrap();


        if let Sized(body_reader, len) = body {
            if len <= self.auto_insert_max_size {
                let mut res = Vec::with_capacity(len as usize);
                CsrfProxy::from(body_reader, token).read_to_end(&mut res).unwrap();
                response.set_sized_body(std::io::Cursor::new(res));
            } else {
                let body = body_reader;
                response.set_streamed_body(Box::new(CsrfProxy::from(body,token)));
            }
        } else { 
            let body = body.into_inner();
            response.set_streamed_body(Box::new(CsrfProxy::from(body,token)));
        }
    }
}

enum ParseState {
    Reset,//default state
    PartialFormMatch(u8),//when parsing "<form"
    CloseFormTag,//searching for '>'
    SearchInput,//like default state, but inside a form 
    PartialInputMatch(u8, usize),//when parsing "<input"
    PartialFormEndMatch(u8, usize),//when parsing "/form" ('<' done by PartialInputMarch)
    SearchMethod(usize),//like default state, but inside input tag
    PartialNameMatch(u8, usize),//when parsing "name="_method""
    CloseInputTag,//only if insert after
}

struct CsrfProxy<'a>{
   underlying: Box<Read + 'a>,
   token: Vec<u8>,
   buf: Vec<(Vec<u8>, usize)>,
   state: ParseState,
   insert_tag: Option<usize>,
}

impl<'a> CsrfProxy<'a>{
    fn from(underlying: Box<Read + 'a>, token: CsrfToken) -> Self {
        let tag_begin = "<input type=\"hidden\" name=\"csrf-token\" value=\"".as_bytes();
        let tag_middle = token.value.as_bytes();
        let tag_end = "\">".as_bytes();
        let mut token = Vec::new();
        token.extend_from_slice(tag_begin);
        token.extend_from_slice(tag_middle);
        token.extend_from_slice(tag_end);
        CsrfProxy{
            underlying: underlying,
            token: token,
            buf: Vec::new(),
            state: ParseState::Reset,
            insert_tag: None,
        }
    }
}

impl<'a> Read for CsrfProxy<'a>{
   fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        if let Some(pos) = self.insert_tag {
            let size = buf.len(); 
            let copy_size = std::cmp::min(size, self.token.len() - pos);
            buf[0..copy_size].copy_from_slice(&self.token[pos..copy_size+pos]);
            if copy_size == self.token.len() - pos {
                self.insert_tag = None;
            } else {
                self.insert_tag = Some(pos + copy_size);
            }
            return Ok(copy_size);
        }
        
        let len = if let Some((vec,pos)) = self.buf.pop() {
            let size = buf.len();
            if vec.len()-pos <= size{
                buf[0..vec.len()-pos].copy_from_slice(&vec[pos..]);
                vec.len()
            } else {
                buf.copy_from_slice(&vec[pos..pos+size]);
                self.buf.push((vec,pos+size));
                size
            }
        } else {
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
            use ParseState::*;
            self.state = match self.state {
                Reset => if buf[i] as char == '<' {
                        PartialFormMatch(0)
                    } else {
                        Reset
                    },
                PartialFormMatch(count) => match (buf[i] as char, count) {
                        ('f',0) | ('F',0) => PartialFormMatch(1),
                        ('o',1) | ('O',1) => PartialFormMatch(2),
                        ('r',2) | ('R',2) => PartialFormMatch(3),
                        ('m',3) | ('M',3) => CloseFormTag,
                        _ => Reset,
                    },
                CloseFormTag => if buf[i] as char == '>' {
                        SearchInput
                    } else {
                        CloseFormTag   
                    },
                SearchInput => if buf[i] as char == '<' {
                        PartialInputMatch(0, i)
                    } else {
                        SearchInput
                    },
                PartialInputMatch(count, pos) => match (buf[i] as char, count) {
                        ('i', 0) | ('I', 0) => PartialInputMatch(1, pos),
                        ('n', 1) | ('N', 1) => PartialInputMatch(2, pos),
                        ('p', 2) | ('P', 2) => PartialInputMatch(3, pos),
                        ('u', 3) | ('U', 3) => PartialInputMatch(4, pos),
                        ('t', 4) | ('T', 4) => SearchMethod(pos),
                        ('/', 0) => PartialFormEndMatch(1, pos),
                        _ => SearchInput,
                    },
                PartialFormEndMatch(count, pos) => match(buf[i] as char, count) {
                        ('/',0) => PartialFormEndMatch(1, pos),//unreachable, here only for comprehension
                        ('f', 1) | ('F', 1) => PartialFormEndMatch(2, pos),
                        ('o', 2) | ('O', 2) => PartialFormEndMatch(3, pos),
                        ('r', 3) | ('R', 3) => PartialFormEndMatch(4, pos),
                        ('m', 4) | ('M', 4) => {
                            self.insert_tag = Some(0);
                            self.buf.push((buf[pos..].to_vec(),0));
                            self.state = Reset;
                            return Ok(pos)
                        },//TODO
                        _ => SearchInput,
                    },
                SearchMethod(pos) => match buf[i] as char {
                        ' ' => PartialNameMatch(0, pos),
                        '>' => {
                            self.insert_tag = Some(0);
                            self.buf.push((buf[pos..].to_vec(),0));
                            self.state = Reset;
                            return Ok(pos)
                        }, //TODO
                        _ => SearchMethod(pos),
                    }
                PartialNameMatch(count, pos) => match (buf[i] as char, count){
                        ('n', 0) | ('N', 0) => PartialNameMatch(1, pos),
                        ('a', 1) | ('A', 1) => PartialNameMatch(2, pos),
                        ('m', 2) | ('M', 2) => PartialNameMatch(3, pos),
                        ('e', 3) | ('E', 3) => PartialNameMatch(4, pos),
                        ('=', 4) => PartialNameMatch(5, pos),
                        ('"', 5) => PartialNameMatch(6, pos),
                        ('_', 6) => PartialNameMatch(7, pos),
                        ('m', 7) | ('M', 7) => PartialNameMatch(8, pos),
                        ('e', 8) | ('E', 8) => PartialNameMatch(9, pos),
                        ('t', 9) | ('T', 9) => PartialNameMatch(10, pos),
                        ('h', 10) | ('H', 10) => PartialNameMatch(11, pos),
                        ('o', 11) | ('O', 11) => PartialNameMatch(12, pos),
                        ('d', 12) | ('D', 12) => PartialNameMatch(13, pos),
                        ('"', 13) => CloseInputTag,
                        _ => SearchMethod(pos),
                    },
                CloseInputTag => if buf[i] as char == '>' {
                        self.insert_tag = Some(0);
                        self.buf.push((buf[i+1..].to_vec(),0));
                        self.state = Reset;
                        return Ok(i+1)
                        //TODO
                    } else {
                        CloseInputTag
                    },
            }
        }
        Ok(len)
   }
}



#[derive(Debug,Clone)]
pub struct CsrfToken {
    value: String
}

impl Serialize for CsrfToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer, {
        serializer.serialize_str(&self.value)
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for CsrfToken {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, ()> {
        let (csrf_engine, duration) = request.guard::<State<(AesGcmCsrfProtection, i64)>>().unwrap().inner();
        
        let mut cookies = request.cookies();
        let token_value = cookies.get(csrf::CSRF_COOKIE_NAME)
            .and_then(|cookie| BASE64.decode(cookie.value().as_bytes()).ok())
            .and_then(|cookie| csrf_engine.parse_cookie(&cookie).ok())
            .and_then(|cookie|{
                let value = cookie.value();
                if value.len() == 64 {
                    let mut array = [0; 64];
                    array.copy_from_slice(&value);
                    Some(array)
                } else {
                    None
                }
            });
        

        match csrf_engine.generate_token_pair(token_value.as_ref(), *duration) {
            Ok((token, cookie)) => {
                cookies.add(Cookie::new(csrf::CSRF_COOKIE_NAME, cookie.b64_string()));
                Outcome::Success(CsrfToken {
                    value: BASE64URL_NOPAD.encode(token.value())
                })
            },
            Err(_) => Outcome::Failure((Status::InternalServerError,()))
        }
    }
}


#[derive(Debug)]
struct Path {
    path: Vec<PathPart>,
    param: Option<HashMap<String, PathPart>>,
}

impl Path {
    fn from(path: &str) -> Self {
        let (path, query) = if let Some(pos) = path.find('?') {
            let (path,query) = path.split_at(pos);
            let query = &query[1..];
            (path, Some(query))
        } else {
            (path, None)
        };
        Path {
            path: path.split('/').filter(|seg| seg!=&"")
                .map(|seg|
                    if seg.get(..1) == Some("<") && seg.get(seg.len()-1..) == Some(">") {
                        PathPart::Dynamic(seg[1..seg.len()-1].to_owned())
                    } else {
                        PathPart::Static(seg.to_owned())
                    }
                ).collect(),
            param: query.map(|query| {parse_args(query).map(|(k, v)|
                                        (k.to_owned(), if v.get(..1) == Some("<") && v.get(v.len()-1..) == Some(">") {
                                            PathPart::Dynamic(v[1..v.len()-1].to_owned())
                                        } else {
                                            PathPart::Static(v.to_owned())
                                        })
                    )
                .collect()
            }),
        }
    }

    fn extract<'a>(&self, uri: &'a str) -> Option<HashMap<&str, &'a str>> {
        let mut res: HashMap<&str, &'a str> = HashMap::new();
        let (path, query) = if let Some(pos) = uri.find('?') {
            let (path,query) = uri.split_at(pos);
            let query = &query[1..];
            (path, Some(query))
        } else {
            (uri, None)
        };
        let mut path = path.split('/').filter(|seg| seg!=&"");
        let mut reference = self.path.iter();
        loop {
            match path.next() {
                Some(v) => {
                    if let Some(reference) = reference.next() {
                        match reference {
                            PathPart::Static(refe) => if refe!=&v {return None},
                            PathPart::Dynamic(key) => {res.insert(key, v);},
                        };
                    } else {
                        return None
                    }
                },
                None => if reference.next().is_some() {
                    return None
                } else {
                    break
                },
            }
        }
        if let Some(query) = query {
            if let Some(ref param) = self.param {
                let hm = parse_args(query).collect::<HashMap<&str,&str>>();
                for (k, v) in param {
                    match v {
                        PathPart::Static(val) => if val!=hm.get::<str>(k)? {return None},
                        PathPart::Dynamic(key) => {res.insert(key, hm.get::<str>(k)?);},
                    }
                }
            } else {
                return None;
            }
        } else if self.param.is_some() {
            return None;
        }

        Some(res)
    }

    fn map(&self, param: HashMap<&str, &str>) -> Option<String> {
        let mut res = String::new();
        for seg in self.path.iter() {
            res.push('/');
            match seg {
                PathPart::Static(val) => res.push_str(val),
                PathPart::Dynamic(val) => res.push_str(param.get::<str>(val)?)
            }
        }
        if let Some(ref keymap) = self.param {
            res.push('?');
            for (k,v) in keymap {
                res.push_str(k);
                res.push('=');
                match v {
                    PathPart::Static(val) => res.push_str(val),
                    PathPart::Dynamic(val) => res.push_str(param.get::<str>(val)?)
                }
                res.push('&');
            }
        }
        Some(res.trim_right_matches('&').to_owned())
    }
}

#[derive(Debug)]
enum PathPart{
    Static(String),
    Dynamic(String),
}

fn parse_args<'a>(args: &'a str) -> impl Iterator<Item=(&'a str, &'a str)>{
        args.split('&')
            .filter_map(|kv| parse_keyvalue(&kv))
}

fn parse_keyvalue<'a>(kv: &'a str) -> Option<(&'a str, &'a str)>{
    if let Some(pos) = kv.find('=') {
        let (key, value) = kv.split_at(pos+1);
        Some((&key[0..pos], value))
    } else {
        None
    }
}
