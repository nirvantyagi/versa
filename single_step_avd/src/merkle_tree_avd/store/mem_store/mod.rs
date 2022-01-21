use std::collections::HashMap;
use crate::{
    Error,
};
use crypto_primitives::{
    sparse_merkle_tree::{
        store::SMTStorer,
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

pub struct MTAVDMemStore<M, S>
where
    M: MerkleTreeAVDParameters,
    S: SMTStorer<M::MerkleTreeParameters>,
{
    tree: SparseMerkleTree<M::MerkleTreeParameters, S>,
    key_d: HashMap<[u8; 32], (u8, u64, [u8; 32])>, // key -> probe, version, value
    index_d: HashMap<MerkleIndex, [u8; 32]>,
}

impl<M, S> MTAVDStorer<M, S> for MTAVDMemStore<M, S>
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
        Ok(MTAVDMemStore {
            tree: smt,
            key_d: HashMap::new(),
            index_d: HashMap::new(),
        })
    }

    // key_d
    fn get_key_d(&self, key: &[u8; 32]) -> Option<(u8, u64, [u8; 32])> {
        match self.key_d.get(key) {
            Some(h) => return Some(h.clone()),
            None => return None,
        }
    }
    fn insert_key_d(&mut self, key: [u8; 32], value: (u8, u64, [u8; 32])) -> Option<(u8, u64, [u8; 32])> {
        return self.key_d.insert(key, value);
    }

    // index_d
    fn get_index_d(&self, key: MerkleIndex) -> Option<[u8; 32]> {
        match self.index_d.get(&key) {
            Some(h) => return Some(h.clone()),
            None => return None,
        }
    }
    fn insert_index_d(&mut self, key: MerkleIndex, value: [u8; 32]) -> Option<[u8; 32]> {
        return self.index_d.insert(key, value);
    }
    fn entry_or_insert_with_index_d(&mut self, i: MerkleIndex, key: [u8; 32]) -> [u8; 32] {
        return *self.index_d.entry(i).or_insert_with(|| key);
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
