pub mod mem_store;
pub mod redis_store;

use crate::Error;
use crate::{
    SSAVDStorer,
    merkle_tree_avd::{MerkleTreeAVD, MerkleTreeAVDParameters},
};
use crypto_primitives::{
    hash::FixedLengthCRH,
    sparse_merkle_tree::{
        MerkleIndex,
        MerkleTreePath,
        MerkleTreeParameters,
        store::SMTStorer,
    },
};

pub trait MTAVDStorer<M, S>
where
    M: MerkleTreeAVDParameters,
    S: SMTStorer<M::MerkleTreeParameters>,
{
    fn new(
        initial_leaf: &[u8],
        pp: &<<<M as MerkleTreeAVDParameters>::MerkleTreeParameters as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters
    ) ->
        Result<Self, Error> where Self: Sized;
    fn make_copy(&self) -> Result<Self, Error> where Self: Sized;

    fn get_id(& self) -> String;

    // key_d
    fn get_key_d(&self, key: &[u8; 32]) -> Option<(u8, u64, [u8; 32])>;
    fn insert_key_d(&mut self, key: [u8; 32], value: (u8, u64, [u8; 32])) -> Option<(u8, u64, [u8; 32])>;

    // index_d
    fn get_index_d(&self, key: MerkleIndex) -> Option<[u8; 32]>;
    fn insert_index_d(&mut self, key: MerkleIndex, value: [u8; 32]) -> Option<[u8; 32]>;
    fn entry_or_insert_with_index_d(&mut self, key: MerkleIndex, value: [u8; 32]) -> [u8; 32];

    // smt
    fn lookup_smt(&self, index: MerkleIndex) ->  Result<MerkleTreePath<<M as MerkleTreeAVDParameters>::MerkleTreeParameters>, Error>;
    fn update_smt(&mut self, index: MerkleIndex, leaf_value: &[u8]) -> Result<(), Error>;
    fn get_smt_root(&self) ->
        <<<M as MerkleTreeAVDParameters>::MerkleTreeParameters as MerkleTreeParameters>::H as FixedLengthCRH>::Output;
}

// Anything that implements MTAVDStorer implements SSAVDStorer<MTAVD<S>>
impl<M, T, S> SSAVDStorer<MerkleTreeAVD<M, T, S>> for S
where
    M: MerkleTreeAVDParameters,
    T: SMTStorer<M::MerkleTreeParameters>,
    S: MTAVDStorer<M, T>
{}
