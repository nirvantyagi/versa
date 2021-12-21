use std::collections::HashMap;
use crate::{
    Error,
};
use crypto_primitives::{
    sparse_merkle_tree::{
        store::SMTStorer,
        MerkleIndex,
        MerkleTreeParameters,
        SparseMerkleTree,
    },
    hash::FixedLengthCRH,
};
use crate::merkle_tree_avd::{
    concat_leaf_data,
    MerkleTreeAVDParameters,
    store::MTAVDStorer,
};

pub struct MTAVDMemStore<P: MerkleTreeAVDParameters> {
    tree: SparseMerkleTree<P::SMTStorer>,
    key_d: HashMap<[u8; 32], (u8, u64, [u8; 32])>, // key -> probe, version, value
    index_d: HashMap<MerkleIndex, [u8; 32]>,
}

impl<P: MerkleTreeAVDParameters> MTAVDStorer for MTAVDMemStore<P> {
    type S = P;

    fn new(
        initial_leaf_value: &[u8],
        pp: &<<<<Self::S as MerkleTreeAVDParameters>::SMTStorer as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters
    ) -> Result<Self, Error> {
        let initial_leaf = concat_leaf_data(&Default::default(), 0, &Default::default());
        let smt_store = <<Self::S as MerkleTreeAVDParameters>::SMTStorer>::new(&initial_leaf, pp).unwrap();
        let smt: SparseMerkleTree<<Self::S as MerkleTreeAVDParameters>::SMTStorer> = SparseMerkleTree::new(smt_store);
        Ok(MTAVDMemStore {
            tree: smt,
            key_d: HashMap::new(),
            index_d: HashMap::new(),
        })
    }

    // key_d
    fn get_key_d(&self, key: &[u8; 32]) {
        self.key_d.get(key);
    }
    fn insert_key_d(&self, key: [u8; 32], value: (u8, u64, [u8; 32])) {
        self.key_d.insert(key, value);
    }

    // index_d
    fn get_index_d(&self, key: MerkleIndex) {
        self.index_d.get(&key);
    }
    fn insert_index_d(&self, key: MerkleIndex, value: [u8; 32]) {
        self.index_d.insert(key, value);
    }
    fn entry_or_insert_with_index_d(&self, i: MerkleIndex, key: [u8; 32]) {
        self.index_d.entry(i).or_insert_with(|| key);
    }

    // smt
    fn lookup_smt(&self, index: MerkleIndex) {
        self.tree.lookup(index);
    }
    fn update_smt(&mut self, index: MerkleIndex, leaf_value: &[u8]) {
        self.tree.update(index, leaf_value);
    }
    fn get_smt_root(&self) {
        self.tree.store.get_root();
    }
}
