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
        let path: Vec<_> = path
                .split('/')//split path at each '/'
                .filter(|seg| seg != &"")//remove empty segments
                .map(|seg| {
                    if seg.starts_with('<') && seg.ends_with("..>")  {
                        PathPart::MultiDynamic(seg[1..seg.len() - 3].to_owned())
                    } else if seg.starts_with('<') && seg.ends_with('>') {
                        PathPart::Dynamic(seg[1..seg.len() - 1].to_owned())
                    } else {//else it's static
                        PathPart::Static(seg.to_owned())
                    }
                })
                .collect();
        let is_multidyn = |p: &PathPart| matches!(p, PathPart::MultiDynamic(_));
        if !path.is_empty() && path[0..path.len() - 1].iter().any(is_multidyn) {
            panic!("PathPart::MultiDynamic can only be found at end of path"); //TODO return error instead of panic
        }

        let param = query.map(|query| {
            parse_args(query)
                .map(|(k, v)| {
                    (
                        k.to_owned(),
                        if v.starts_with('<') && v.ends_with("..>") {
                            panic!("PathPart::MultiDynamic is invalid in query part");
                        } else if v.starts_with('<') && v.ends_with('>') {
                            //do the same kind of parsing as above, but on query params
                            PathPart::Dynamic(v[1..v.len() - 1].to_owned())
                        } else {
                            PathPart::Static(v.to_owned())
                        },
                    )
                })
                .collect()
        });
        Path { path, param }
    }

    pub fn extract(&self, uri: &str) -> Option<HashMap<&str, String>> {
        //try to match a str against a path, give back a hashmap of correponding parts if it matched
        let mut res: HashMap<&str, String> = HashMap::new();
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
            match reference.next() {
                Some(reference) => {
                    match reference {
                        PathPart::Static(reference) => {
                            //static, but not the same, fail to parse
                            if let Some(val) = path.next() {
                                if val != reference {
                                    return None;
                                }
                            } else {
                                return None;
                            }
                        }
                        PathPart::Dynamic(key) => {
                            //dynamic, store to hashmap
                            if let Some(val) = path.next() {
                                res.insert(key, val.to_owned());
                            } else {
                                return None;
                            }
                        }
                        PathPart::MultiDynamic(key) => {
                            let val = path.collect::<Vec<_>>().join("/");
                            res.insert(key, val);
                            break;
                        }
                    };
                }
                None => if path.next().is_some() {
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
                            res.insert(key, hm.get::<&str>(&(k as &str))?.to_string());
                        }
                        PathPart::MultiDynamic(_) => {
                            unreachable!("Paramater part can't contain MultiDynamic");
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

    pub fn map(&self, param: &HashMap<&str, String>) -> Option<String> {
        //Generate a path from a reference and a hashmap
        let mut res = String::new();
        for seg in &self.path {
            res.push('/');
            match seg {
                PathPart::Static(val) => res.push_str(val),
                PathPart::Dynamic(val) | PathPart::MultiDynamic(val) => {
                    res.push_str(param.get::<str>(val)?)
                }
            }
        }
        if res.is_empty() {
            res.push('/');
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
                    PathPart::MultiDynamic(_) => {
                        unreachable!("Paramater part can't contain MultiDynamic");
                    }
                }
                res.push('&');
            }
        }
        Some(res.trim_end_matches('&').to_owned()) //trim the last '&' which was added if there is a query part
    }
}

#[derive(Debug)]
enum PathPart {
    Static(String),
    Dynamic(String),
    MultiDynamic(String),
}

#[cfg(test)]
mod tests {
    use path::Path;
    use std::collections::HashMap;
    #[test]
    fn test_static_path_without_query() {
        let no_query = Path::from("/path/no_query");
        assert!(no_query.extract("/path/something").is_none());
        assert!(no_query.extract("/path").is_none());
        assert!(no_query.extract("/path/no_query/longer").is_none());
        assert!(no_query.extract("/path/no_query?with=query").is_none());

        let hashmap = no_query.extract("/path/no_query").unwrap();
        assert_eq!(hashmap.len(), 0);

        assert_eq!(no_query.map(&HashMap::new()).unwrap(), "/path/no_query");

        let mut hashmap = HashMap::new();
        hashmap.insert("key", "value".to_owned());
        assert_eq!(no_query.map(&hashmap).unwrap(), "/path/no_query");
    }

    #[test]
    fn test_static_path_with_query() {
        let query = Path::from("/path/query?param=value&param2=value2");
        assert!(query.extract("/path/query").is_none());
        assert!(
            query
                .extract("/path/other?param=value&param2=value2")
                .is_none()
        );
        assert!(
            query
                .extract("/path/query/longer?param=value&param2=value2")
                .is_none()
        );
        assert!(query.extract("/path?param=value&param2=value2").is_none());

        let hashmap = query
            .extract("/path/query?param=value&param2=value2")
            .unwrap();
        assert_eq!(hashmap.len(), 0);

        let hashmap = query
            .extract("/path/query?param2=value2&param=value")
            .unwrap();
        assert_eq!(hashmap.len(), 0);

        let uri = query.map(&HashMap::new()).unwrap();
        assert!(
            uri == "/path/query?param=value&param2=value2"
                || uri == "/path/query?param2=value2&param=value"
        );

        let mut hashmap = HashMap::new();
        hashmap.insert("key", "value".to_owned());
        let uri = query.map(&hashmap).unwrap();
        assert!(
            uri == "/path/query?param=value&param2=value2"
                || uri == "/path/query?param2=value2&param=value"
        );
    }

    #[test]
    fn test_dynamic_path_without_query() {
        let no_query = Path::from("/path/<with>/<dynamic>/values");
        assert!(
            no_query
                .extract("/path/with/dynamic/values/longer")
                .is_none()
        );
        assert!(no_query.extract("/path/with/dynamic").is_none());
        assert!(no_query.extract("/path/with/dynamic/non_value").is_none());
        assert!(
            no_query
                .extract("/path/with/dynamic/values?and=query")
                .is_none()
        );
        let end_dyn = Path::from("/path/<with>/<dynamic>");
        assert!(end_dyn.extract("/path/shorter").is_none());

        let hashmap = no_query.extract("/path/containing/moving/values").unwrap();
        assert_eq!(hashmap.len(), 2);
        assert_eq!(hashmap.get("with").unwrap(), "containing");
        assert_eq!(hashmap.get("dynamic").unwrap(), "moving");

        assert!(no_query.map(&HashMap::new()).is_none());

        let mut hashmap = HashMap::new();
        hashmap.insert("with", "with".to_owned());
        hashmap.insert("dynamic", "non_static".to_owned());
        assert_eq!(
            no_query.map(&hashmap).unwrap(),
            "/path/with/non_static/values"
        );
        hashmap.insert("random", "value".to_owned());
        assert_eq!(
            no_query.map(&hashmap).unwrap(),
            "/path/with/non_static/values"
        );
    }

    #[test]
    fn test_dynamic_path_with_query() {
        let query = Path::from("/path/<with>/<dynamic>/values?key=<value>&static=static");
        assert!(
            query
                .extract("/path/with/dynamic/values?key=something&static=error")
                .is_none()
        );

        let hashmap = query
            .extract("/path/containing/moving/values?key=val&static=static")
            .unwrap();
        assert_eq!(hashmap.len(), 3);
        assert_eq!(hashmap.get("with").unwrap(), "containing");
        assert_eq!(hashmap.get("dynamic").unwrap(), "moving");
        assert_eq!(hashmap.get("value").unwrap(), "val");

        let hashmap = query
            .extract("/path/containing/moving/values?static=static&key=val")
            .unwrap();
        assert_eq!(hashmap.len(), 3);
        assert_eq!(hashmap.get("with").unwrap(), "containing");
        assert_eq!(hashmap.get("dynamic").unwrap(), "moving");
        assert_eq!(hashmap.get("value").unwrap(), "val");

        assert!(query.map(&HashMap::new()).is_none());

        let mut hashmap = HashMap::new();
        hashmap.insert("with", "with".to_owned());
        hashmap.insert("dynamic", "non_static".to_owned());
        hashmap.insert("value", "something".to_owned());
        assert!(
            query.map(&hashmap).unwrap()
                == "/path/with/non_static/values?key=something&static=static"
                || query.map(&hashmap).unwrap()
                    == "/path/with/non_static/values?static=static&key=something"
        );
        hashmap.insert("random", "value".to_owned());
        assert!(
            query.map(&hashmap).unwrap()
                == "/path/with/non_static/values?key=something&static=static"
                || query.map(&hashmap).unwrap()
                    == "/path/with/non_static/values?static=static&key=something"
        );
    }

    #[test]
    #[should_panic(expected = "PathPart::MultiDynamic is invalid in query part")]
    fn test_mutlidynamic_in_query() {
        Path::from("/path?query=<dynamic..>");
    }

    #[test]
    #[should_panic(expected = "PathPart::MultiDynamic can only be found at end of path")]
    fn test_multidynamic_before_end_of_path() {
        Path::from("/<dynamic..>/something");
    }

    #[test]
    fn test_multidynamic() {
        let query = Path::from("/path/<multidyn..>?static=static");

        let hashmap = query.extract("/path?static=static").unwrap();
        assert_eq!(hashmap.len(), 1);
        assert_eq!(hashmap.get("multidyn").unwrap(), "");

        let hashmap = query
            .extract("/path/longer/than/before?static=static")
            .unwrap();
        assert_eq!(hashmap.len(), 1);
        assert_eq!(hashmap.get("multidyn").unwrap(), "longer/than/before");

        let mut hashmap = HashMap::new();
        hashmap.insert("multidyn", "something".to_owned());
        assert_eq!(
            query.map(&hashmap).unwrap(),
            "/path/something?static=static"
        );
    }

    #[test]
    fn test_empty_url() {
        let query = Path::from("/");
        assert_eq!(query.map(&HashMap::new()).unwrap(), "/");

        let query = Path::from("/?param=<value>");

        let hashmap = query.extract("/?param=something").unwrap();
        assert_eq!(hashmap.len(), 1);
        assert_eq!(hashmap.get("value").unwrap(), "something");

        let mut hashmap = HashMap::new();
        hashmap.insert("value", "something".to_owned());
        assert_eq!(query.map(&hashmap).unwrap(), "/?param=something");
    }
}
