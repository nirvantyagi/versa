pub mod mem_store;

use crate::Error;
use crate::hash::FixedLengthCRH;
use crate::sparse_merkle_tree::{
    MerkleDepth,
    MerkleIndex,
    MerkleTreeParameters,
};

pub trait SMTStorer {
    type P: MerkleTreeParameters;

    fn new(
        initial_leaf_value: &[u8],
        hash_parameters: &<<<Self as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters
    ) ->
        Result<Self, Error> where Self: Sized;

    fn get(&self, index: &(MerkleDepth, MerkleIndex)) ->
        Option<&<<<Self as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output>;

    fn set(
        &mut self,
        index: (MerkleDepth, MerkleIndex),
        value: <<<Self as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output
    );

    fn get_root(&self) ->
        <<<Self as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output;

    fn get_hash_parameters(&self) ->
        <<<Self as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters;

    fn get_sparse_initial_hashes(&self, index: usize) ->
        <<<Self as SMTStorer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output;
}
