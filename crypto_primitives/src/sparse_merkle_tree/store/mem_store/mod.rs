use std::{
    collections::HashMap,
    marker::PhantomData,
};

use crate::{
    Error,
    hash::FixedLengthCRH,
};
use crate::sparse_merkle_tree::{
    MerkleDepth,
    MerkleIndex,
    MerkleTreeParameters,
    store::Storer,
};

// #[derive(Debug)] TODO: implement debug
pub struct MemStore<M: MerkleTreeParameters> {
    tree: HashMap<(MerkleDepth, MerkleIndex), <M::H as FixedLengthCRH>::Output>,
    pub root: <M::H as FixedLengthCRH>::Output,
    sparse_initial_hashes: Vec<<M::H as FixedLengthCRH>::Output>,
    pub hash_parameters: <M::H as FixedLengthCRH>::Parameters,
    _parameters: PhantomData<M>,
}

impl<P: MerkleTreeParameters> MemStore<P> {
    pub fn new(
        initial_leaf_value: &[u8],
        hash_parameters: &<P::H as FixedLengthCRH>::Parameters,
    ) -> Result<Self, Error> {
        // Compute initial hashes for each depth of tree
        let mut sparse_initial_hashes =
            vec![hash_leaf::<P::H>(&hash_parameters, initial_leaf_value)?];
        for i in 1..=(P::DEPTH as usize) {
            let child_hash = sparse_initial_hashes[i - 1].clone();
            sparse_initial_hashes.push(hash_inner_node::<P::H>(
                hash_parameters,
                &child_hash,
                &child_hash,
            )?);
        }
        sparse_initial_hashes.reverse();

        Ok(MemStore {
            tree: HashMap::new(),
            root: sparse_initial_hashes[0].clone(),
            sparse_initial_hashes: sparse_initial_hashes,
            hash_parameters: hash_parameters.clone(),
            _parameters: PhantomData,
        })
    }
}

// impl Default for MemStore {
//     fn default() -> Self {
//         MemStore::new()
//     }
// }

impl<M: MerkleTreeParameters> Storer for MemStore<M> {
    type P = M;

    fn get(
        & self,
        index: &(MerkleDepth, MerkleIndex),
    ) -> Option<&<<M as MerkleTreeParameters>::H as FixedLengthCRH>::Output> {
        return self.tree.get(index);
    }

    fn set(
        &mut self,
        index: (MerkleDepth, MerkleIndex),
        value: <<<Self as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output
    ) {
        self.tree.insert(index, value);
    }

    fn set_root(
        &mut self,
        value: <<<Self as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output
    ) {
        self.root = value.clone();
    }

    fn get_hash_parameters(& self) ->
        <<M as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters {
        return self.hash_parameters.clone();
    }

    fn get_sparse_initial_hashes(& self, index: usize) ->
        <<M as MerkleTreeParameters>::H as FixedLengthCRH>::Output {
        return self.sparse_initial_hashes[index].clone();
    }

}

// TODO: dup from sparse_merkle_tree
pub fn hash_leaf<H: FixedLengthCRH>(
    parameters: &H::Parameters,
    leaf: &[u8],
) -> Result<H::Output, Error> {
    H::evaluate_variable_length(parameters, leaf)
}

// TODO: dup from sparse_merkle_tree
pub fn hash_inner_node<H: FixedLengthCRH>(
    parameters: &H::Parameters,
    left: &H::Output,
    right: &H::Output,
) -> Result<H::Output, Error> {
    H::merge(&parameters, left, right)
}
