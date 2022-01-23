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
    store::SMTStorer,
    hash_leaf,
    hash_inner_node,
};

pub struct SMTMemStore<P: MerkleTreeParameters> {
    tree: HashMap<(MerkleDepth, MerkleIndex), <P::H as FixedLengthCRH>::Output>,
    pub root: <P::H as FixedLengthCRH>::Output,
    sparse_initial_hashes: Vec<<P::H as FixedLengthCRH>::Output>,
    pub hash_parameters: <P::H as FixedLengthCRH>::Parameters,
    _parameters: PhantomData<P>,
}

impl<P> SMTStorer<P> for SMTMemStore<P>
where
    P: MerkleTreeParameters,
{
    fn new(
        initial_leaf_value: &[u8],
        hash_parameters: &<P::H as FixedLengthCRH>::Parameters
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

        Ok(SMTMemStore {
            tree: HashMap::new(),
            root: sparse_initial_hashes[0].clone(),
            sparse_initial_hashes: sparse_initial_hashes,
            hash_parameters: hash_parameters.clone(),
            _parameters: PhantomData,
        })
    }

    fn make_copy(&self) -> Result<Self, Error> where Self: Sized {
        // THIS IS DUMMY, IT HAS NO PURPOSE
        return Self::new(&[0u8; 16], &self.hash_parameters);
    }

    fn get_id(& self) -> String {
        // THIS IS DUMMY, IT HAS NO PURPOSE
        return "this is dummy".to_string();
    }

    fn get(&self, index: &(MerkleDepth, MerkleIndex)) -> Option<<<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output> {
        match self.tree.get(index) {
            Some(h) => return Some(h.clone()),
            None => return None,
        }
    }

    fn set(
        &mut self,
        index: (MerkleDepth, MerkleIndex),
        value: <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output
    ) {
        self.tree.insert(index, value.clone());
        if index.0 == 0 && index.1 == 0 {
            self.root = value.clone();
        }
    }

    fn get_root(& self) ->
        <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output {
        return self.root.clone();
    }

    fn get_hash_parameters(& self) ->
        <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters {
        return self.hash_parameters.clone();
    }

    fn get_sparse_initial_hashes(& self, index: usize) ->
        <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output {
        return self.sparse_initial_hashes[index].clone();
    }
}
