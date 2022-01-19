use std::{
    marker::PhantomData,
};
use ark_ff::{
    to_bytes,
};
use uuid::Uuid;
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

pub mod utils;
pub mod redis_utils;

pub struct SMTRedisStore<P: MerkleTreeParameters> {
    pub id: Uuid,
    // tree: HashMap<(MerkleDepth, MerkleIndex), <P::H as FixedLengthCRH>::Output>,
    pub root: <P::H as FixedLengthCRH>::Output,
    sparse_initial_hashes: Vec<<P::H as FixedLengthCRH>::Output>,
    pub hash_parameters: <P::H as FixedLengthCRH>::Parameters,
    _parameters: PhantomData<P>,
}
// NOTE: tree: HashMap<(MerkleDepth, MerkleIndex), <P::H as FixedLengthCRH>::Output>,
//  will get stored in Redis using HSET("id-key", "val")
//
// everything else could get serialized in Redis but doesn't seem important for benchmark

impl<P> SMTStorer<P> for SMTRedisStore<P>
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

        let mut id: Uuid;
        #[cfg(feature = "v4")] {
            id = Uuid::new_v4()?;
        }
        Ok(SMTRedisStore {
            id: id,
            root: sparse_initial_hashes[0].clone(),
            sparse_initial_hashes: sparse_initial_hashes,
            hash_parameters: hash_parameters.clone(),
            _parameters: PhantomData,
        })
    }

    fn get(
        & self,
        index: &(MerkleDepth, MerkleIndex),
    ) -> Option<&<<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output> {
        let key: String = utils::to_key(index.0, index.1);
        let val_string: String = redis_utils::get(key).unwrap();
        let val_bytes = val_string.as_bytes();
        return val_bytes as <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output;
        // return Ok(val_string as <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output);
        // let val: <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output = val_string;
        // return self.tree.get(index);
    }

    fn set(
        &mut self,
        index: (MerkleDepth, MerkleIndex),
        value: <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output
    ) {
        let key: String = utils::to_key(index.0, index.1);
        let val: String = to_bytes![value];
        redis_utils::set(key, val).unwrap();
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
