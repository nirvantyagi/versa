extern crate base64;
use std::{
    marker::PhantomData,
};
use ark_ff::{
    to_bytes,
    FromBytes,
};
use rand::{distributions::Alphanumeric, Rng};
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
    pub id: String,
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

        let id: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
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
    ) -> Option<<<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output> {
        let key: String = utils::to_key(self.id.clone(), index.0, index.1);
        match redis_utils::get(key) {
            Ok(val_string) => {
                let val_bytes: &[u8] = &base64::decode(val_string).unwrap();
                let val: <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output = <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output::read(val_bytes).unwrap();
                return Some(val);
            },
            Err(_e) => {
                // e = Response was of incompatible type: "Response type not string compatible." (response was nil)
                return None;
            }
        }

    }

    fn set(
        &mut self,
        index: (MerkleDepth, MerkleIndex),
        value: <<P as MerkleTreeParameters>::H as FixedLengthCRH>::Output
    ) {
        let key: String = utils::to_key(self.id.clone(), index.0, index.1);
        let val_bytes = to_bytes![value].unwrap();
        let val: String = base64::encode(&val_bytes);
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
