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
