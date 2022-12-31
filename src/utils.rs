pub fn parse_args(args: &str) -> impl Iterator<Item = (&str, &str)> {
    //transform a group of argument into an iterator of key and value
    args.split('&').filter_map(parse_keyvalue)
}

fn parse_keyvalue(kv: &str) -> Option<(&str, &str)> {
    //convert a single key-value pair into a key and a value
    if let Some(pos) = kv.find('=') {
        let (key, value) = kv.split_at(pos + 1);
        Some((&key[0..pos], value))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use utils::{parse_args, parse_keyvalue};
    #[test]
    fn test_parse_keyvalue() {
        assert_eq!(
            parse_keyvalue("a_key=a_value").unwrap(),
            ("a_key", "a_value")
        );

        assert_eq!(parse_keyvalue("=a_value").unwrap(), ("", "a_value"));

        assert_eq!(parse_keyvalue("a_key=").unwrap(), ("a_key", ""));

        assert_eq!(
            parse_keyvalue("a_key=a=value").unwrap(),
            ("a_key", "a=value")
        );

        assert_eq!(parse_keyvalue("=").unwrap(), ("", ""));

        assert!(parse_keyvalue("a_key_a_value").is_none());

        assert!(parse_keyvalue("").is_none());
    }
    #[test]
    fn test_parse_args() {
        let mut it = parse_args("key1=value1&key2&=&&key3=");
        assert_eq!(it.next().unwrap(), ("key1", "value1"));
        assert_eq!(it.next().unwrap(), ("", ""));
        assert_eq!(it.next().unwrap(), ("key3", ""));
        assert!(it.next().is_none());
    }
}
