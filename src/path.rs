use std::collections::HashMap;
use utils::parse_args;

#[derive(Debug)]
pub struct Path {
    path: Vec<PathPart>,
    param: Option<HashMap<String, PathPart>>,
}

impl Path {
    pub fn from(path: &str) -> Self {
        let (path, query) = if let Some(pos) = path.find('?') {
            //cut the path at pos begining of query parameters
            let (path, query) = path.split_at(pos);
            let query = &query[1..];
            (path, Some(query))
        } else {
            (path, None)
        };
        Path {
            path: path
                .split('/')//split path at each '/'
                .filter(|seg| seg != &"")//remove empty segments
                .map(|seg| {
                    if seg.get(..1) == Some("<") && seg.get(seg.len() - 1..) == Some(">") {//if the segment start with '<' and end with '>', it is dynamic
                        PathPart::Dynamic(seg[1..seg.len() - 1].to_owned())
                    } else {//else it's static
                        PathPart::Static(seg.to_owned())
                    }//TODO add support for <..path> to match more than one segment
                })
                .collect(),
            param: query.map(|query| {
                parse_args(query)
                    .map(|(k, v)| {
                        (
                            k.to_owned(),
                            if v.get(..1) == Some("<") && v.get(v.len() - 1..) == Some(">") {
                                //do the same kind of parsing as above, but on query params
                                PathPart::Dynamic(v[1..v.len() - 1].to_owned())
                            } else {
                                PathPart::Static(v.to_owned())
                            },
                        )
                    })
                    .collect()
            }),
        }
    }

    pub fn extract<'a>(&self, uri: &'a str) -> Option<HashMap<&str, &'a str>> {
        //try to match a str against a path, give back a hashmap of correponding parts if it matched
        let mut res: HashMap<&str, &'a str> = HashMap::new();
        let (path, query) = if let Some(pos) = uri.find('?') {
            let (path, query) = uri.split_at(pos);
            let query = &query[1..];
            (path, Some(query))
        } else {
            (uri, None)
        };
        let mut path = path.split('/').filter(|seg| seg != &"");
        let mut reference = self.path.iter();
        loop {
            match path.next() {
                Some(v) => {
                    if let Some(reference) = reference.next() {
                        match reference {
                            PathPart::Static(refe) => if refe != v {
                                //static, but not the same, fail to parse
                                return None;
                            },
                            PathPart::Dynamic(key) => {
                                //dynamic, store to hashmap
                                res.insert(key, v);
                            }
                        };
                    } else {
                        //not the same lenght, fail to parse
                        return None;
                    }
                }
                None => if reference.next().is_some() {
                    //not the same lenght, fail to parse
                    return None;
                } else {
                    break;
                },
            }
        }
        if let Some(query) = query {
            if let Some(ref param) = self.param {
                let hm = parse_args(query).collect::<HashMap<&str, &str>>();
                for (k, v) in param {
                    match v {
                        PathPart::Static(val) => if val != hm.get::<str>(k)? {
                            //static but not the same, fail to parse
                            return None;
                        },
                        PathPart::Dynamic(key) => {
                            //dynamic, store to hashmap
                            res.insert(key, hm.get::<str>(k)?);
                        }
                    }
                }
            } else {
                //param in query, but not in reference, fail to parse
                return None;
            }
        } else if self.param.is_some() {
            //param in reference, but not in query, fail to parse
            return None;
        }

        Some(res)
    }

    pub fn map(&self, param: &HashMap<&str, &str>) -> Option<String> {
        //Generate a path from a reference and a hashmap
        let mut res = String::new();
        for seg in &self.path {
            //TODO add a / if no elements in self.path
            res.push('/');
            match seg {
                PathPart::Static(val) => res.push_str(val),
                PathPart::Dynamic(val) => res.push_str(param.get::<str>(val)?),
            }
        }
        if let Some(ref keymap) = self.param {
            //if there is some query part
            res.push('?');
            for (k, v) in keymap {
                res.push_str(k);
                res.push('=');
                match v {
                    PathPart::Static(val) => res.push_str(val),
                    PathPart::Dynamic(val) => res.push_str(param.get::<str>(val)?),
                }
                res.push('&');
            }
        }
        Some(res.trim_right_matches('&').to_owned()) //trim the last '&' which was added if there is a query part
    }
}

#[derive(Debug)]
enum PathPart {
    Static(String),
    Dynamic(String),
}
