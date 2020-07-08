use zexe_cp::{
    crh::FixedLengthCRH,
    merkle_tree::MerkleTreeConfig,
};

use std::collections::HashMap;


// Tips on optimizing implementation: https://ethresear.ch/t/optimizing-sparse-merkle-trees/3751/5

pub type MerkleHeight = u8;
pub type MerkleIndex = u64;

pub struct SparseMerkleHashTree<P: MerkleTreeConfig> {
    tree: HashMap<(MerkleHeight, MerkleIndex), <P::H as FixedLengthCRH>::Output>,
    init_hashes: Vec<<P::H as FixedLengthCRH>::Output>,
}

impl<P: MerkleTreeConfig> SparseMerkleHashTree<P> {
    pub const HEIGHT: MerkleHeight = P::HEIGHT as MerkleHeight;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
