pub mod mem_store;

use ark_ff::bytes::ToBytes;
use crate::Error;
use crypto_primitives::{
    sparse_merkle_tree::{
        store::SMTStorer,
        MerkleIndex,
        MerkleTreePath,
        MerkleTreeParameters
    },
    hash::FixedLengthCRH
};

pub trait HTStorer {
    type S: SMTStorer;
    type D: ToBytes + Eq + Clone;

    fn get_root(&self) ->
        <<<<Self as HTStorer>::S as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output;

    fn get_epoch(&self) -> MerkleIndex;
    fn set_epoch(&mut self, index: MerkleIndex) -> Result<(), Error>;

    fn get_digest_d(&self, key: &MerkleIndex) -> Option<&Self::D>;
    fn insert_digest_d(&mut self, index: MerkleIndex, digest: Self::D) -> Option<Self::D>;

    fn lookup_smt(&mut self, index: MerkleIndex) -> Result<MerkleTreePath<<<Self as HTStorer>::S as SMTStorer>::P>, Error>;
    fn update_smt(&mut self, index: MerkleIndex, leaf_value: &[u8]) -> Result<(), Error>;

    // fn new(
    //     initial_leaf_value: &[u8],
    //     hash_parameters: &<<<Self as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters
    // ) ->
    //     Result<Self, Error> where Self: Sized;
    //
    // fn get(&self, index: &(MerkleDepth, MerkleIndex)) ->
    //     Option<&<<<Self as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output>;
    //
    // fn set(
    //     &mut self,
    //     index: (MerkleDepth, MerkleIndex),
    //     value: <<<Self as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output
    // );
    //
    // fn get_root(&self) ->
    //     <<<Self as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output;
    //
    // fn get_hash_parameters(&self) ->
    //     <<<Self as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters;
    //
    // fn get_sparse_initial_hashes(&self, index: usize) ->
    //     <<<Self as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output;
}
