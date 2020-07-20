use zexe_cp::{
    crh::FixedLengthCRH,
};
use algebra::bytes::ToBytes;

use std::{
    error::Error as ErrorTrait,
    fmt,
    io::Cursor,
    collections::HashMap,
    marker::PhantomData,
};

use crate::Error;

pub mod constraints;


// Tips on optimizing implementation: https://ethresear.ch/t/optimizing-sparse-merkle-trees/3751/5

pub type MerkleDepth = u8;
pub type MerkleIndex = u64;
pub const MAX_DEPTH: u8 = 64;

// TODO: Add const hash parameters
pub trait MerkleTreeParameters {
    const DEPTH: MerkleDepth;

    fn is_valid() -> Result<bool, Error> {
        if Self::DEPTH < 1 || Self::DEPTH > MAX_DEPTH {
            return Err(Box::new(MerkleTreeError::TreeDepth(Self::DEPTH)));
        }
        Ok(true)
    }
}

pub struct SparseMerkleTree<H: FixedLengthCRH, P: MerkleTreeParameters> {
    tree: HashMap<(MerkleDepth, MerkleIndex), H::Output>,
    pub root: H::Output,
    sparse_initial_hashes: Vec<H::Output>,
    hash_parameters: H::Parameters,
    _parameters: PhantomData<P>,
}

#[derive(Clone)]
pub struct MerkleTreePath<H: FixedLengthCRH, P: MerkleTreeParameters> {
    path: Vec<H::Output>,
    _parameters: PhantomData<P>,
}

impl<H: FixedLengthCRH, P: MerkleTreeParameters> SparseMerkleTree<H, P> {

    pub fn new(
        initial_leaf_value: &[u8],
        hash_parameters: H::Parameters,
    ) -> Result<Self, Error> {

        // Compute initial hashes for each depth of tree
        let mut sparse_initial_hashes = vec![hash_leaf::<H>(&hash_parameters, initial_leaf_value)?];
        for i in 1..=(P::DEPTH as usize) {
            let child_hash = sparse_initial_hashes[i-1].clone();
            sparse_initial_hashes.push(hash_inner_node::<H>(&hash_parameters, &child_hash, &child_hash)?);
        };
        sparse_initial_hashes.reverse();

        Ok(
            SparseMerkleTree {
                tree: HashMap::new(),
                root: sparse_initial_hashes[0].clone(),
                sparse_initial_hashes: sparse_initial_hashes,
                hash_parameters: hash_parameters,
                _parameters: PhantomData,
            }
        )
    }

    pub fn update(mut self, index: MerkleIndex, leaf_value: &[u8]) -> Result<Self, Error> {
        if index >= 1_u64 << (P::DEPTH as u64) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }

        let mut i = index;
        self.tree.insert((P::DEPTH, i), hash_leaf::<H>(&self.hash_parameters, leaf_value)?);

        for d in (0..P::DEPTH).rev() {
            i >>= 1;
            let lc_i = i << 1;
            let rc_i = lc_i + 1;
            let lc_hash = match self.tree.get(&(d+1, lc_i)) {
                Some(h) => h.clone(),
                None => self.sparse_initial_hashes[(d+1) as usize].clone(),
            };
            let rc_hash = match self.tree.get(&(d+1, rc_i)) {
                Some(h) => h.clone(),
                None => self.sparse_initial_hashes[(d+1) as usize].clone(),
            };
            self.tree.insert((d, i), hash_inner_node::<H>(&self.hash_parameters, &lc_hash, &rc_hash)?);
        }
        self.root = self.tree.get(&(0, 0)).expect("root lookup failed").clone();
        Ok(self)
    }

    pub fn lookup(&self, index: MerkleIndex) -> Result<MerkleTreePath<H, P>, Error> {
        if index >= 1_u64 << (P::DEPTH as u64) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }
        let mut path = Vec::new();

        let mut i = index;
        for d in (1..=P::DEPTH).rev() {
            let sibling_hash = match self.tree.get(&(d, i ^ 1)) {
                Some(h) => h.clone(),
                None => self.sparse_initial_hashes[d as usize].clone(),
            };
            path.push(sibling_hash);
            i >>= 1;
        }
        Ok(MerkleTreePath { path, _parameters: PhantomData })
    }
}


impl<H: FixedLengthCRH, P: MerkleTreeParameters> MerkleTreePath<H, P> {

    pub fn compute_root(
        &self,
        leaf: &[u8],
        index: MerkleIndex,
        hash_parameters: &H::Parameters,
    ) -> Result<H::Output, Error> {
        if index >= 1_u64 << (P::DEPTH as u64) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }
        if self.path.len() != P::DEPTH as usize {
            return Err(Box::new(MerkleTreeError::TreeDepth(self.path.len() as u8)));
        }

        let mut i = index;
        let mut current_hash = hash_leaf::<H>(hash_parameters, leaf)?;
        for sibling_hash in self.path.iter() {
            current_hash = match i % 2 {
                0 => hash_inner_node::<H>(hash_parameters, &current_hash, sibling_hash)?,
                1 => hash_inner_node::<H>(hash_parameters, sibling_hash, &current_hash)?,
                _ => unreachable!(),
            };
            i >>= 1;
        }
        Ok(current_hash)
    }

    pub fn verify(
        &self,
        root: &H::Output,
        leaf: &[u8],
        index: MerkleIndex,
        hash_parameters: &H::Parameters,
    ) -> Result<bool, Error> {
        Ok(self.compute_root(leaf, index, hash_parameters)? == *root)
    }

}

pub fn hash_leaf<H: FixedLengthCRH>(parameters: &H::Parameters, leaf: &[u8]) -> Result<H::Output, Error> {
    let mut buffer = [0u8; 128];
    let mut writer = Cursor::new(&mut buffer[..]);
    leaf.write(&mut writer)?;
    H::evaluate(&parameters, &buffer[..(H::INPUT_SIZE_BITS / 8)])
}

pub fn hash_inner_node<H: FixedLengthCRH>(
    parameters: &H::Parameters,
    left: &H::Output,
    right: &H::Output,
) -> Result<H::Output, Error> {
    let mut buffer = [0u8; 128];
    let mut writer = Cursor::new(&mut buffer[..]);
    left.write(&mut writer)?;
    right.write(&mut writer)?;
    H::evaluate(&parameters, &buffer[..(H::INPUT_SIZE_BITS / 8)])
}

#[derive(Debug)]
pub enum MerkleTreeError {
    TreeDepth(MerkleDepth),
    LeafIndex(MerkleIndex),
}

impl ErrorTrait for MerkleTreeError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> { None }
}

impl fmt::Display for MerkleTreeError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            MerkleTreeError::TreeDepth(h) => format!("tree depth is invalid: {}", h),
            MerkleTreeError::LeafIndex(i) => format!("leaf index is invalid: {}", i),
        };
        write!(f, "{}", msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zexe_cp::{
        crh::{FixedLengthCRH, pedersen::{PedersenCRH, PedersenWindow}},
    };
    use algebra::{ed_on_bls12_381::EdwardsAffine as JubJub};
    use rand::{SeedableRng, rngs::StdRng};

    #[derive(Clone)]
    pub struct Window4x256;

    impl PedersenWindow for  Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = PedersenCRH<JubJub, Window4x256>;

    #[derive(Clone)]
    pub struct JubJubHeight8;

    impl MerkleTreeParameters for JubJubHeight8 {
        const DEPTH: MerkleDepth = 8;
    }

    pub struct JubJubHeight1;

    impl MerkleTreeParameters for JubJubHeight1 {
        const DEPTH: MerkleDepth = 1;
    }

    type JubJubMerkleTree = SparseMerkleTree<H, JubJubHeight8>;



    #[test]
    fn initialize_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let tree = SparseMerkleTree::<H, JubJubHeight1>::new(&[0u8; 16], crh_parameters.clone()).unwrap();
        let leaf_hash = hash_leaf::<H>(&crh_parameters, &[0u8; 16]).unwrap();
        let root_hash = hash_inner_node::<H>(&crh_parameters, &leaf_hash, &leaf_hash).unwrap();
        assert_eq!(tree.root, root_hash);
    }

    #[test]
    fn update_and_verify_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let tree = JubJubMerkleTree::new(&[0u8; 16], crh_parameters.clone()).unwrap();
        let proof_0 = tree.lookup(0).unwrap();
        let proof_177 = tree.lookup(177).unwrap();
        let proof_255 = tree.lookup(255).unwrap();
        let proof_256 = tree.lookup(256);
        assert!(proof_0.verify(&tree.root, &[0u8; 16], 0, &crh_parameters).unwrap());
        assert!(proof_177.verify(&tree.root, &[0u8; 16], 177, &crh_parameters).unwrap());
        assert!(proof_255.verify(&tree.root, &[0u8; 16], 255, &crh_parameters).unwrap());
        assert!(proof_256.is_err());
        let updated_tree = tree.update(177, &[1_u8; 16]).unwrap();
        assert!(proof_177.verify(&updated_tree.root, &[1u8; 16], 177, &crh_parameters).unwrap());
        assert!(!proof_177.verify(&updated_tree.root, &[0u8; 16], 177, &crh_parameters).unwrap());
        assert!(!proof_177.verify(&updated_tree.root, &[1u8; 16], 0, &crh_parameters).unwrap());
        assert!(!proof_0.verify(&updated_tree.root, &[0u8; 16], 0, &crh_parameters).unwrap());
        let updated_proof_0 = updated_tree.lookup(0).unwrap();
        assert!(updated_proof_0.verify(&updated_tree.root, &[0u8; 16], 0, &crh_parameters).unwrap());
    }
}
