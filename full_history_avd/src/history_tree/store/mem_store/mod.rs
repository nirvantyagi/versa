use std::{
    collections::HashMap,
};
use ark_ff::bytes::ToBytes;
use crypto_primitives::{
    sparse_merkle_tree::{
        store::SMTStorer,
        MerkleIndex,
        SparseMerkleTree,
    }
};

pub struct HTMemStore<T: SMTStorer, D: ToBytes + Eq + Clone> {
    pub tree: SparseMerkleTree<T::P>,
    digest_d: HashMap<MerkleIndex, D>,
    epoch: MerkleIndex,
}
