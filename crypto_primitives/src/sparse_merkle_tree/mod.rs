use zexe_cp::{
    crh::FixedLengthCRH,
};
use algebra::bytes::ToBytes;

use std::{
    error::Error as ErrorTrait,
    fmt,
    io::Cursor,
    collections::HashMap,
};


// Tips on optimizing implementation: https://ethresear.ch/t/optimizing-sparse-merkle-trees/3751/5

pub type MerkleDepth = u8;
pub type MerkleIndex = u64;
pub const MAX_DEPTH: u8 = 64;

pub struct SparseMerkleHashTree<H: FixedLengthCRH> {
    tree: HashMap<(MerkleDepth, MerkleIndex), H::Output>,
    pub root: H::Output,
    depth: MerkleDepth,
    sparse_initial_hashes: Vec<H::Output>,
    hash_parameters: H::Parameters,
}

pub struct MerkleHashTreePath<H: FixedLengthCRH> {
    path: Vec<H::Output>,
}

impl<H: FixedLengthCRH> SparseMerkleHashTree<H> {

    pub fn new(
        parameters: H::Parameters,
        initial_leaf_value: &[u8],
        depth: MerkleDepth,
    ) -> Result<Self, Error> {
        if depth < 1 || depth > MAX_DEPTH {
            return Err(Box::new(MerkleTreeError::TreeDepth(depth)));
        }

        // Compute initial hashes for each depth of tree
        let mut sparse_initial_hashes = vec![hash_leaf::<H>(&parameters, initial_leaf_value)?];
        for i in 1..=(depth as usize) {
            let child_hash = sparse_initial_hashes[i-1].clone();
            sparse_initial_hashes.push(hash_inner_node::<H>(&parameters, &child_hash, &child_hash)?);
        };
        sparse_initial_hashes.reverse();

        Ok(
            SparseMerkleHashTree {
                tree: HashMap::new(),
                root: sparse_initial_hashes[0].clone(),
                depth: depth,
                sparse_initial_hashes: sparse_initial_hashes,
                hash_parameters: parameters,
            }
        )
    }

    pub fn update(mut self, index: MerkleIndex, leaf_value: &[u8]) -> Result<Self, Error> {
        if index >= 2_u64.pow(self.depth.into()) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }

        let mut i = index;
        self.tree.insert((self.depth, i), hash_leaf::<H>(&self.hash_parameters, leaf_value)?);

        for d in (0..self.depth).rev() {
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

    // TODO: Don't need to return on-path hashes as part of proof since they can be calculated
    pub fn lookup(&self, index: MerkleIndex) -> Result<MerkleHashTreePath<H>, Error> {
        if index >= 2_u64.pow(self.depth.into()) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }
        let mut path = Vec::new();

        let mut i = index;
        for d in (1..=self.depth).rev() {
            let sibling_hash = match self.tree.get(&(d, i ^ 1)) {
                Some(h) => h.clone(),
                None => self.sparse_initial_hashes[d as usize].clone(),
            };
            path.push(sibling_hash);
            i >>= 1;
        }
        Ok(MerkleHashTreePath{ path })
    }
}


impl<H: FixedLengthCRH> MerkleHashTreePath<H> {

    pub fn verify(
        &self,
        parameters: &H::Parameters,
        root: &H::Output,
        leaf: &[u8],
        index: MerkleIndex,
        depth: MerkleDepth,
    ) -> Result<bool, Error> {
        if index >= 2_u64.pow(depth.into()) {
            return Err(Box::new(MerkleTreeError::LeafIndex(index)));
        }
        if self.path.len() != depth as usize {
            return Ok(false)
        }

        let mut i = index;
        let mut current_hash = hash_leaf::<H>(parameters, leaf)?;
        for sibling_hash in self.path.iter() {
            current_hash = match i % 2 {
                0 => hash_inner_node::<H>(parameters, &current_hash, sibling_hash)?,
                1 => hash_inner_node::<H>(parameters, sibling_hash, &current_hash)?,
                _ => unreachable!(),
            };
            i >>= 1;
        }
        Ok(current_hash == *root)
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

pub type Error = Box<dyn ErrorTrait>;

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
        crh::{pedersen::*},
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
    type JubJubMerkleTree = SparseMerkleHashTree<H>;



    #[test]
    fn initialize_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let tree = JubJubMerkleTree::new(crh_parameters.clone(), &[0u8; 16], 1).unwrap();
        let leaf_hash = hash_leaf::<H>(&crh_parameters, &[0u8; 16]).unwrap();
        let root_hash = hash_inner_node::<H>(&crh_parameters, &leaf_hash, &leaf_hash).unwrap();
        assert_eq!(tree.root, root_hash);
    }

    #[test]
    fn update_and_verify_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        const TEST_DEPTH: MerkleDepth = 8;
        let tree = JubJubMerkleTree::new(crh_parameters.clone(), &[0u8; 16], TEST_DEPTH).unwrap();
        let proof_0 = tree.lookup(0).unwrap();
        let proof_177 = tree.lookup(177).unwrap();
        let proof_255 = tree.lookup(255).unwrap();
        let proof_256 = tree.lookup(256);
        assert!(proof_0.verify(&crh_parameters, &tree.root, &[0u8; 16], 0, TEST_DEPTH).unwrap());
        assert!(proof_177.verify(&crh_parameters, &tree.root, &[0u8; 16], 177, TEST_DEPTH).unwrap());
        assert!(proof_255.verify(&crh_parameters, &tree.root, &[0u8; 16], 255, TEST_DEPTH).unwrap());
        assert!(proof_256.is_err());
        let updated_tree = tree.update(177, &[1_u8; 16]).unwrap();
        assert!(proof_177.verify(&crh_parameters, &updated_tree.root, &[1u8; 16], 177, TEST_DEPTH).unwrap());
        assert!(!proof_177.verify(&crh_parameters, &updated_tree.root, &[0u8; 16], 177, TEST_DEPTH).unwrap());
        assert!(!proof_177.verify(&crh_parameters, &updated_tree.root, &[1u8; 16], 0, TEST_DEPTH).unwrap());
        assert!(!proof_0.verify(&crh_parameters, &updated_tree.root, &[0u8; 16], 0, TEST_DEPTH).unwrap());
        let updated_proof_0 = updated_tree.lookup(0).unwrap();
        assert!(updated_proof_0.verify(&crh_parameters, &updated_tree.root, &[0u8; 16], 0, TEST_DEPTH).unwrap());

    }
}
