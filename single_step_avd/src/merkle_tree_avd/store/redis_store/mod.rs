use serde_json;
use crate::{
    Error,
};
use crypto_primitives::{
    sparse_merkle_tree::{
        store::{
            SMTStorer,
            redis_store::redis_utils,
        },
        MerkleIndex,
        MerkleTreePath,
        MerkleTreeParameters,
        SparseMerkleTree,
    },
    hash::FixedLengthCRH,
};
use crate::merkle_tree_avd::{
    MerkleTreeAVDParameters,
    store::MTAVDStorer,
};
use rand::{distributions::Alphanumeric, Rng};

pub struct MTAVDRedisStore<M, S>
where
    M: MerkleTreeAVDParameters,
    S: SMTStorer<M::MerkleTreeParameters>,
{
    id: String,
    tree: SparseMerkleTree<M::MerkleTreeParameters, S>,
    // key_d: HashMap<[u8; 32], (u8, u64, [u8; 32])>, // key -> probe, version, value
    // index_d: HashMap<MerkleIndex, [u8; 32]>,
}

impl<M, S> MTAVDStorer<M, S> for MTAVDRedisStore<M, S>
where
    M: MerkleTreeAVDParameters,
    S: SMTStorer<M::MerkleTreeParameters>,
{
    fn new(
        initial_leaf: &[u8],
        pp: &<<<M as MerkleTreeAVDParameters>::MerkleTreeParameters as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters
    ) -> Result<Self, Error> where Self: Sized {
        let smt_store = S::new(&initial_leaf, pp).unwrap();
        let smt: SparseMerkleTree<<M as MerkleTreeAVDParameters>::MerkleTreeParameters, S> = SparseMerkleTree::new(smt_store);
        let id: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
        Ok(MTAVDRedisStore {
            id: id,
            tree: smt,
            // key_d: HashMap::new(),
            // index_d: HashMap::new(),
        })
    }

    // key_d
    fn get_key_d(&self, key: &[u8; 32]) -> Option<(u8, u64, [u8; 32])> {
        let k = format!("{}-key_d-{}", self.id, serde_json::to_string(&key).unwrap());
        match redis_utils::get(k) {
            Ok(val_string) => {
                let val: (u8, u64, [u8; 32]) = serde_json::from_str::<(u8, u64, [u8; 32])>(&val_string).unwrap();
                return Some(val);
            },
            Err(_e) => {
                // e = Response was of incompatible type: "Response type not string compatible." (response was nil)
                return None;
            }
        }
    }
    fn insert_key_d(&mut self, key: [u8; 32], value: (u8, u64, [u8; 32])) -> Option<(u8, u64, [u8; 32])> {
        let k = format!("{}-key_d-{}", self.id, serde_json::to_string(&key).unwrap());
        let val = serde_json::to_string(&value).unwrap();
        redis_utils::set(k, val).unwrap();
        return Some(value);
    }

    // index_d
    fn get_index_d(&self, key: MerkleIndex) -> Option<[u8; 32]> {
        let k = format!("{}-index_d-{}", self.id, serde_json::to_string(&key).unwrap());
        match redis_utils::get(k) {
            Ok(val_string) => {
                let val = serde_json::from_str(&val_string).unwrap();
                return Some(val);
            },
            Err(_e) => {
                // e = Response was of incompatible type: "Response type not string compatible." (response was nil)
                return None;
            }
        }
    }
    fn insert_index_d(&mut self, key: MerkleIndex, value: [u8; 32]) -> Option<[u8; 32]> {
        let k = format!("{}-index_d-{}", self.id, serde_json::to_string(&key).unwrap());
        let val = serde_json::to_string(&value).unwrap();
        redis_utils::set(k, val).unwrap();
        return Some(value);
    }
    fn entry_or_insert_with_index_d(&mut self, i: MerkleIndex, key: [u8; 32]) -> [u8; 32] {
        let k = format!("{}-index_d-{}", self.id, serde_json::to_string(&i).unwrap());
        let val_string_result = redis_utils::get(k.clone());
        match val_string_result {
            Ok(val_string) => {
                let val = serde_json::from_str(&val_string).unwrap();
                return val;
            },
            Err(_e) => {
                // presumably nil error
                let val = serde_json::to_string(&key).unwrap();
                redis_utils::set(k, val).unwrap();
                return key;
            }
        };
    }

    // smt
    fn lookup_smt(&self, index: MerkleIndex) ->  Result<MerkleTreePath<<M as MerkleTreeAVDParameters>::MerkleTreeParameters>, Error> {
        return self.tree.lookup(index);
    }
    fn update_smt(&mut self, index: MerkleIndex, leaf_value: &[u8]) -> Result<(), Error> {
        return self.tree.update(index, leaf_value);
    }
    fn get_smt_root(&self) ->
        <<<M as MerkleTreeAVDParameters>::MerkleTreeParameters as MerkleTreeParameters>::H as FixedLengthCRH>::Output {
        return self.tree.store.get_root();
    }
}
