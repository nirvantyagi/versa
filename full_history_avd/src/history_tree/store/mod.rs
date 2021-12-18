pub mod mem_store;

use ark_ff::bytes::ToBytes;
use crate::Error;
use crypto_primitives::{
    sparse_merkle_tree::{
        store::SMTStorer,
        MerkleDepth, MerkleIndex, MerkleTreeParameters,
    },
    hash::FixedLengthCRH,
};

pub trait HTStorer {
    type S: SMTStorer;
    type D: ToBytes + Eq + Clone;

    fn get_epoch(&self) -> MerkleIndex;
    fn set_epoch(&mut self, index: MerkleIndex) -> Result<(), Error>;
    fn smt_update(&mut self, index: MerkleIndex, leaf_value: &[u8]) -> Result<(), Error>;
    fn digest_d_insert(&mut self, index: MerkleIndex, digest: Self::D) -> Result<(), Error>;

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
