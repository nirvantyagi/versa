pub mod mem_store;
use crate::Error;
use crate::merkle_tree_avd::MerkleTreeAVDParameters;
use crypto_primitives::{
    hash::FixedLengthCRH,
    sparse_merkle_tree::{
        MerkleIndex,
        MerkleTreePath,
        MerkleTreeParameters,
        store::SMTStorer,
    },
};

pub trait MTAVDStorer {
    type S: MerkleTreeAVDParameters;

    fn new(
        initial_leaf_value: &[u8],
        pp: &<<<<Self::S as MerkleTreeAVDParameters>::SMTStorer as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters
    ) ->
        Result<Self, Error> where Self: Sized;

    // key_d
    fn get_key_d(&self, key: &[u8; 32]) -> Option<&(u8, u64, [u8; 32])>;
    fn insert_key_d(&self, key: [u8; 32], value: (u8, u64, [u8; 32])) -> Result<(), Error>;

    // index_d
    fn get_index_d(&self, key: MerkleIndex) -> Option<&[u8; 32]>;
    fn insert_index_d(&self, key: MerkleIndex, value: [u8; 32]) -> Result<(), Error>;
    fn entry_or_insert_with_index_d(&self, key: MerkleIndex, value: [u8; 32]) -> Result<(), Error>;

    // smt
    fn lookup_smt(&self, index: MerkleIndex) ->  Result<MerkleTreePath<<<<Self as MTAVDStorer>::S as MerkleTreeAVDParameters>::SMTStorer as SMTStorer>::P>, Error>;
    fn update_smt(&mut self, index: MerkleIndex, leaf_value: &[u8]) -> Result<(), Error>;
    fn get_smt_root(&self) ->
        <<<<<Self as MTAVDStorer>::S as MerkleTreeAVDParameters>::SMTStorer as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output;
}
