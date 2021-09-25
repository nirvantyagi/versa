use std::{
    error::Error as ErrorTrait,
    fmt,
    marker::PhantomData,
};

use crate::{
    hash::FixedLengthCRH,
    Error,
};

pub mod store;
pub mod constraints;

// Tips on optimizing implementation: https://ethresear.ch/t/optimizing-sparse-merkle-trees/3751/5

pub type MerkleDepth = u8;
pub type MerkleIndex = u64;
pub const MAX_DEPTH: u8 = 64;

// TODO: Add const hash parameters
pub trait MerkleTreeParameters {
    const DEPTH: MerkleDepth;
    type H: FixedLengthCRH;

    fn is_valid() -> Result<bool, Error> {
        if Self::DEPTH < 1 || Self::DEPTH > MAX_DEPTH {
            return Err(Box::new(MerkleTreeError::TreeDepth(Self::DEPTH)));
        }
        Ok(true)
    }
}

pub struct SparseMerkleTree<T: store::Storer> {
    pub store: T,
}

pub struct MerkleTreePath<P: MerkleTreeParameters> {
    pub path: Vec<<P::H as FixedLengthCRH>::Output>,
    pub _parameters: PhantomData<P>,
}

impl<P: MerkleTreeParameters> Clone for MerkleTreePath<P> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            _parameters: PhantomData,
        }
    }
}

impl<P: MerkleTreeParameters> Default for MerkleTreePath<P> {
    fn default() -> Self {
        Self {
            path: vec![<P::H as FixedLengthCRH>::Output::default(); P::DEPTH as usize],
            _parameters: PhantomData,
        }
    }
}

impl<T: store::Storer> SparseMerkleTree<T> {
    pub fn new(s: T) -> SparseMerkleTree<T> {
        SparseMerkleTree { store: s }
    }

    pub fn update(&mut self, index: MerkleIndex, leaf_value: &[u8]) -> Result<(), Error> {
        if index >= 1_u64 << (T::P::DEPTH as u64) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }

        let mut i = index;
        self.store.set(
            (T::P::DEPTH, i),
            hash_leaf::<<T::P as MerkleTreeParameters>::H>(&self.store.get_hash_parameters(), leaf_value)?,
        );

        for d in (0..T::P::DEPTH).rev() {
            i >>= 1;
            let lc_i = i << 1;
            let rc_i = lc_i + 1;
            let lc_hash = match self.store.get(&(d + 1, lc_i)) {
                Some(h) => h.clone(),
                None => self.store.get_sparse_initial_hashes((d + 1) as usize).clone(),
            };
            let rc_hash = match self.store.get(&(d + 1, rc_i)) {
                Some(h) => h.clone(),
                None => self.store.get_sparse_initial_hashes((d + 1) as usize).clone(),
            };
            self.store.set(
                (d, i),
                hash_inner_node::<<T::P as MerkleTreeParameters>::H>(&self.store.get_hash_parameters(), &lc_hash, &rc_hash)?,
            );
        }
        // TODO: double borrow makes it possible to create two mutable references for the same data,
        //  which is a violation of Rust aliasing guarantees https://stackoverflow.com/questions/31281155/cannot-borrow-x-as-mutable-more-than-once-at-a-time
        // Is this really needed?
        // self.store.set_root(self.store.get(&(0, 0)).expect("root lookup failed").clone());
        Ok(())
    }

    pub fn lookup(&self, index: MerkleIndex) -> Result<MerkleTreePath<T::P>, Error> {
        if index >= 1_u64 << (T::P::DEPTH as u64) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }
        let mut path = Vec::new();

        let mut i = index;
        for d in (1..=T::P::DEPTH).rev() {
            let sibling_hash = match self.store.get(&(d, i ^ 1)) {
                Some(h) => h.clone(),
                None => self.store.get_sparse_initial_hashes(d as usize).clone(),
            };
            path.push(sibling_hash);
            i >>= 1;
        }
        Ok(MerkleTreePath {
            path,
            _parameters: PhantomData,
        })
    }
}

impl<P: MerkleTreeParameters> MerkleTreePath<P> {
    pub fn compute_root(
        &self,
        leaf: &[u8],
        index: MerkleIndex,
        hash_parameters: &<P::H as FixedLengthCRH>::Parameters,
    ) -> Result<<P::H as FixedLengthCRH>::Output, Error> {
        if index >= 1_u64 << (P::DEPTH as u64) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }
        if self.path.len() != P::DEPTH as usize {
            return Err(Box::new(MerkleTreeError::TreeDepth(self.path.len() as u8)));
        }

        let mut i = index;
        let mut current_hash = hash_leaf::<P::H>(hash_parameters, leaf)?;
        for sibling_hash in self.path.iter() {
            current_hash = match i % 2 {
                0 => hash_inner_node::<P::H>(hash_parameters, &current_hash, sibling_hash)?,
                1 => hash_inner_node::<P::H>(hash_parameters, sibling_hash, &current_hash)?,
                _ => unreachable!(),
            };
            i >>= 1;
        }
        Ok(current_hash)
    }

    pub fn verify(
        &self,
        root: &<P::H as FixedLengthCRH>::Output,
        leaf: &[u8],
        index: MerkleIndex,
        hash_parameters: &<P::H as FixedLengthCRH>::Parameters,
    ) -> Result<bool, Error> {
        Ok(self.compute_root(leaf, index, hash_parameters)? == *root)
    }
}

pub fn hash_leaf<H: FixedLengthCRH>(
    parameters: &H::Parameters,
    leaf: &[u8],
) -> Result<H::Output, Error> {
    H::evaluate_variable_length(parameters, leaf)
}

pub fn hash_inner_node<H: FixedLengthCRH>(
    parameters: &H::Parameters,
    left: &H::Output,
    right: &H::Output,
) -> Result<H::Output, Error> {
    H::merge(&parameters, left, right)
}

#[derive(Debug)]
pub enum MerkleTreeError {
    TreeDepth(MerkleDepth),
    LeafIndex(MerkleIndex),
}

impl ErrorTrait for MerkleTreeError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
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
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use rand::{rngs::StdRng, SeedableRng};
    use ark_crypto_primitives::crh::{
        pedersen::{CRH, Window},
    };

    #[derive(Clone)]
    pub struct Window4x256;

    impl Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = CRH<JubJub, Window4x256>;

    #[derive(Clone)]
    pub struct MerkleTreeTestParameters;

    impl MerkleTreeParameters for MerkleTreeTestParameters {
        const DEPTH: MerkleDepth = 8;
        type H = H;
    }

    pub struct MerkleTreeTinyTestParameters;

    impl MerkleTreeParameters for MerkleTreeTinyTestParameters {
        const DEPTH: MerkleDepth = 1;
        type H = H;
    }

    type TestMerkleTree = SparseMerkleTree<MerkleTreeTestParameters>;
    type TinyTestMerkleTree = SparseMerkleTree<MerkleTreeTinyTestParameters>;

    #[test]
    fn initialize_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let tree = TinyTestMerkleTree::new(&[0u8; 16], &crh_parameters).unwrap();
        let leaf_hash = hash_leaf::<H>(&crh_parameters, &[0u8; 16]).unwrap();
        let root_hash = hash_inner_node::<H>(&crh_parameters, &leaf_hash, &leaf_hash).unwrap();
        assert_eq!(tree.root, root_hash);
    }

    #[test]
    fn update_and_verify_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut tree = TestMerkleTree::new(&[0u8; 16], &crh_parameters).unwrap();
        let proof_0 = tree.lookup(0).unwrap();
        let proof_177 = tree.lookup(177).unwrap();
        let proof_255 = tree.lookup(255).unwrap();
        let proof_256 = tree.lookup(256);
        assert!(proof_0
            .verify(&tree.root, &[0u8; 16], 0, &crh_parameters)
            .unwrap());
        assert!(proof_177
            .verify(&tree.root, &[0u8; 16], 177, &crh_parameters)
            .unwrap());
        assert!(proof_255
            .verify(&tree.root, &[0u8; 16], 255, &crh_parameters)
            .unwrap());
        assert!(proof_256.is_err());
        assert!(tree.update(177, &[1_u8; 16]).is_ok());
        assert!(proof_177
            .verify(&tree.root, &[1u8; 16], 177, &crh_parameters)
            .unwrap());
        assert!(!proof_177
            .verify(&tree.root, &[0u8; 16], 177, &crh_parameters)
            .unwrap());
        assert!(!proof_177
            .verify(&tree.root, &[1u8; 16], 0, &crh_parameters)
            .unwrap());
        assert!(!proof_0
            .verify(&tree.root, &[0u8; 16], 0, &crh_parameters)
            .unwrap());
        let updated_proof_0 = tree.lookup(0).unwrap();
        assert!(updated_proof_0
            .verify(&tree.root, &[0u8; 16], 0, &crh_parameters)
            .unwrap());
    }
}
