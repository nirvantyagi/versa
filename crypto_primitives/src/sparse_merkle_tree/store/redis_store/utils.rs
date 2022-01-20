use crate::sparse_merkle_tree::{
    MerkleDepth,
    MerkleIndex,
};

pub fn to_key(id: String, d: MerkleDepth, i: MerkleIndex) -> String {
    return format!("{}-{}-{}", id, d, i);
}

pub fn from_key(s: String) -> (MerkleDepth, MerkleIndex) {
    let split = s.split("-");
    let coll: Vec<&str> = split.collect();
    let d: u8 = coll[1].parse().unwrap();
    let i: u64 = coll[2].parse().unwrap();
    return (d, i);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn to_key_from_key_test() {
        let id: String = "abcdefg".to_string();
        let d: MerkleDepth = 255;
        let i: MerkleIndex = 9399484;
        assert_eq!(from_key(to_key(id, d, i)), (d, i));
    }
}
