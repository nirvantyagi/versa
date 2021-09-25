pub mod mem_store;

use crate::hash::FixedLengthCRH;
use crate::sparse_merkle_tree::{
    MerkleDepth,
    MerkleIndex,
    MerkleTreeParameters,
};

pub trait Storer {
    type P: MerkleTreeParameters;

    fn get(& self, index: &(MerkleDepth, MerkleIndex)) ->
        Option<&<<<Self as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output>;

    fn set(
        &mut self,
        index: (MerkleDepth, MerkleIndex),
        value: <<<Self as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output
    );

    fn set_root(
        &mut self,
        value: <<<Self as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output
    );

    fn get_hash_parameters(&self) ->
        <<<Self as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters;

    fn get_sparse_initial_hashes(&self, index: usize) ->
        <<<Self as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output;
}
