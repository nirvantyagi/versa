pub mod mem_store;

use crate::hash::FixedLengthCRH;
use crate::sparse_merkle_tree::{
    MerkleDepth,
    MerkleIndex,
    MerkleTreeParameters,
};

pub trait Storer {
    type P: MerkleTreeParameters;
    fn set(
        &mut self,
        index: (MerkleDepth, MerkleIndex),
        value: <<<Self as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output
    );
}
