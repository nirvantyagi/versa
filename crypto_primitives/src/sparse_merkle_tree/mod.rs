use zexe_cp::{
    crh::FixedLengthCRH,
};
use algebra::bytes::ToBytes;

use std::{
    error::Error as ErrorTrait,
    fmt,
    io::Cursor,
};


// Tips on optimizing implementation: https://ethresear.ch/t/optimizing-sparse-merkle-trees/3751/5

pub type MerkleHeight = u8;
pub type MerkleIndex = u64;

pub struct SparseMerkleHashTree<H: FixedLengthCRH> {
    tree: MerkleTree<H>,
    pub root: H::Output,
    height: MerkleHeight,
    sparse_initial_hashes: Vec<H::Output>,
    hash_parameters: H::Parameters,
}

impl<H: FixedLengthCRH> SparseMerkleHashTree<H> {

    pub fn new(
        parameters: H::Parameters,
        initial_leaf_value: &[u8],
        height: MerkleHeight,
    ) -> Result<Self, Error> {
        if height < 1 {
            return Err(Box::new(MerkleTreeError::TreeHeight(height)));
        }

        // Compute initial hashes for each height of tree
        let mut leaf_hash_buffer = [0u8; 128];
        let mut writer = Cursor::new(&mut leaf_hash_buffer[..]);
        initial_leaf_value.write(&mut writer)?;
        let mut sparse_initial_hashes = vec![H::evaluate(&parameters, &leaf_hash_buffer[..(H::INPUT_SIZE_BITS / 8)])?];
        for i in 1..(height as usize) {
            let mut child_hash_buffer = [0u8; 128];
            let mut writer = Cursor::new(&mut child_hash_buffer[..]);
            sparse_initial_hashes[i-1].write(&mut writer)?;
            sparse_initial_hashes[i-1].write(&mut writer)?;
            sparse_initial_hashes.push(H::evaluate(&parameters, &child_hash_buffer[..(H::INPUT_SIZE_BITS / 8)])?);
        };

        Ok(
            SparseMerkleHashTree {
                tree: MerkleTree::Empty,
                root: sparse_initial_hashes[(height as usize) - 1].clone(),
                height: height,
                sparse_initial_hashes: sparse_initial_hashes,
                hash_parameters: parameters,
            }
        )
    }
}

pub enum MerkleTree<H: FixedLengthCRH> {
    Empty,
    Node(H::Output, Box<MerkleTree<H>>, Box<MerkleTree<H>>),
}


pub type Error = Box<dyn ErrorTrait>;

#[derive(Debug)]
pub enum MerkleTreeError {
    TreeHeight(u8),
}

impl ErrorTrait for MerkleTreeError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> { None }
}

impl fmt::Display for MerkleTreeError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            MerkleTreeError::TreeHeight(h) => format!("tree height is invalid: {}", h),
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
    fn initialize_sparse_tree_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let tree = JubJubMerkleTree::new(crh_parameters.clone(), &[0u8; 16], 1).unwrap();
        assert_eq!(tree.root, H::evaluate(&crh_parameters, &[0u8; 128][..(H::INPUT_SIZE_BITS / 8)]).unwrap());
    }
}
