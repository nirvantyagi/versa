pub mod mem_store;

use crate::Error;
use crate::hash::FixedLengthCRH;
use crate::sparse_merkle_tree::{
    MerkleDepth,
    MerkleIndex,
    MerkleTreeParameters,
};

pub trait SMTStorer<P>
where
    P: MerkleTreeParameters,
{
    fn new(
        initial_leaf_value: &[u8],
        hash_parameters: &<<P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters
    ) ->
        Result<Self, Error> where Self: Sized;

    fn get(&self, index: &(MerkleDepth, MerkleIndex)) ->
        Option<&<<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output>;

    fn set(
        &mut self,
        index: (MerkleDepth, MerkleIndex),
        value: <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output
    );

    fn get_root(&self) ->
        <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output;

    fn get_hash_parameters(&self) ->
        <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters;

    fn get_sparse_initial_hashes(&self, index: usize) ->
        <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output;
}
