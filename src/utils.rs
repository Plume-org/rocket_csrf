pub fn parse_args(args: &str) -> impl Iterator<Item = (&str, &str)> {
    //transform a group of argument into an iterator of key and value
    args.split('&').filter_map(|kv| parse_keyvalue(&kv))
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
