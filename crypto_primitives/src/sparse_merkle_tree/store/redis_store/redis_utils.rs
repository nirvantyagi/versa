extern crate redis;
use redis::Commands;

fn get_con() -> Result<redis::Connection, redis::RedisError> {
    let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    return client.get_connection();
}

pub fn get(key: String) -> Result<String, redis::RedisError> {
    let mut con: redis::Connection = get_con().unwrap();
    return con.get(key);
}

pub fn set(key: String, val: String) -> Result<(), redis::RedisError> {
    let mut con: redis::Connection = get_con().unwrap();
    return con.set(key, val);
}

pub fn copy_entries_matching_prefix(old_prefix: String, new_prefix: String) {
    let mut con: redis::Connection = get_con().unwrap();
    let iter: redis::Iter<String> = con.scan_match(old_prefix.clone()).unwrap();
    for key in iter {
        let new_key: String = format!("{}{}", new_prefix, &key[old_prefix.len()-1..]);
        let value: String = get(key).unwrap();
        set(new_key, value).unwrap();
        // println!("{:?}\n{:?}\n", key, new_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn set_and_get_test() {
        let key: String = "abcdefg".to_string();
        let val: String = "my-val".to_string();
        set(key.clone(), val.clone()).unwrap();
        assert_eq!(get(key).unwrap(), val);
    }
}
