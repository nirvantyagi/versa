use ark_ff::Field;
use ark_relations::r1cs::{SynthesisError, Namespace};
use ark_r1cs_std::{
    prelude::*,
    uint64::UInt64,
};

use crate::{
    sparse_merkle_tree::{MerkleTreeParameters, MerkleTreePath},
    hash::{FixedLengthCRH, constraints::FixedLengthCRHGadget},
};

use std::{borrow::Borrow, marker::PhantomData};

#[derive(Clone)]
pub struct MerkleTreePathVar<P, HGadget, ConstraintF>
where
    P: MerkleTreeParameters,
    HGadget: FixedLengthCRHGadget<P::H, ConstraintF>,
    ConstraintF: Field,
{
    path: Vec<HGadget::OutputVar>,
    _parameters: PhantomData<P>,
}

impl<P, HGadget, ConstraintF> MerkleTreePathVar<P, HGadget, ConstraintF>
where
    P: MerkleTreeParameters,
    HGadget: FixedLengthCRHGadget<P::H, ConstraintF>,
    ConstraintF: Field,
{
    pub fn compute_root_var(
        &self,
        leaf: &Vec<UInt8<ConstraintF>>,
        index: &UInt64<ConstraintF>,
        hash_parameters: &HGadget::ParametersVar,
    ) -> Result<HGadget::OutputVar, SynthesisError> {
        let mut current_hash = hash_leaf_var::<P::H, HGadget, ConstraintF>(
            hash_parameters,
            leaf,
        )?;
        for (i, b) in index
            .to_bits_le()
            .iter()
            .take(P::DEPTH as usize)
            .enumerate()
        {
            let lc = HGadget::OutputVar::conditionally_select(
                b,
                &self.path[i],
                &current_hash,
            )?;
            let rc = HGadget::OutputVar::conditionally_select(
                b,
                &current_hash,
                &self.path[i],
            )?;
            current_hash = hash_inner_node_var::<P::H, HGadget, ConstraintF>(
                hash_parameters,
                &lc,
                &rc,
            )?;
        }
        Ok(current_hash)
    }

    pub fn check_path(
        &self,
        root: &HGadget::OutputVar,
        leaf: &Vec<UInt8<ConstraintF>>,
        index: &UInt64<ConstraintF>,
        hash_parameters: &HGadget::ParametersVar,
    ) -> Result<(), SynthesisError> {
        self.conditional_check_path(
            root,
            leaf,
            index,
            hash_parameters,
            &Boolean::constant(true),
        )
    }

    pub fn conditional_check_path(
        &self,
        root: &HGadget::OutputVar,
        leaf: &Vec<UInt8<ConstraintF>>,
        index: &UInt64<ConstraintF>,
        hash_parameters: &HGadget::ParametersVar,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let computed_root = self.compute_root_var(
            leaf,
            index,
            hash_parameters,
        )?;
        root.conditional_enforce_equal(&computed_root, condition)
    }

}

pub fn hash_leaf_var<H, HGadget, ConstraintF>(
    parameters: &HGadget::ParametersVar,
    leaf: &Vec<UInt8<ConstraintF>>,
) -> Result<HGadget::OutputVar, SynthesisError>
where
    H: FixedLengthCRH,
    HGadget: FixedLengthCRHGadget<H, ConstraintF>,
    ConstraintF: Field,
{
    HGadget::evaluate_variable_length(parameters, leaf)
}

pub fn hash_inner_node_var<H, HGadget, ConstraintF>(
    parameters: &HGadget::ParametersVar,
    left: &HGadget::OutputVar,
    right: &HGadget::OutputVar,
) -> Result<HGadget::OutputVar, SynthesisError>
where
    H: FixedLengthCRH,
    HGadget: FixedLengthCRHGadget<H, ConstraintF>,
    ConstraintF: Field,
{
    // Little endian byte representation (must match serialization in hash_inner_node)
    HGadget::merge(parameters, left, right)
}

impl<P, HGadget, ConstraintF> AllocVar<MerkleTreePath<P>, ConstraintF>
    for MerkleTreePathVar<P, HGadget, ConstraintF>
where
    P: MerkleTreeParameters,
    HGadget: FixedLengthCRHGadget<P::H, ConstraintF>,
    ConstraintF: Field,
{
    fn new_variable<T: Borrow<MerkleTreePath<P>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode
    ) -> Result<Self, SynthesisError> {
        let f_out = f()?;
        let path = Vec::<HGadget::OutputVar>::new_variable(
            cs,
            || Ok(&f_out.borrow().path[..]),
            mode,
        )?;
        Ok(MerkleTreePathVar{
            path,
            _parameters: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sparse_merkle_tree::*;
    use ark_ed_on_bls12_381::{
        EdwardsProjective as JubJub, Fq,
        constraints::EdwardsVar,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use rand::{rngs::StdRng, SeedableRng};
    use ark_crypto_primitives::crh::{
        pedersen::{constraints::CRHGadget, CRH, Window},
    };

    #[derive(Clone)]
    pub struct Window4x256;

    impl Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = CRH<JubJub, Window4x256>;
    type HG = CRHGadget<JubJub, EdwardsVar, Window4x256>;

    #[derive(Clone)]
    pub struct MerkleTreeTestParameters;

    impl MerkleTreeParameters for MerkleTreeTestParameters {
        const DEPTH: MerkleDepth = 8;
        type H = H;
    }

    type TestMerkleTree = SparseMerkleTree<MerkleTreeTestParameters>;

    #[test]
    fn valid_path_constraints_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut tree = TestMerkleTree::new(&[0u8; 16], &crh_parameters).unwrap();
        tree.update(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup(177).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate hash parameters
        let crh_parameters_var = <HG as FixedLengthCRHGadget<H, Fq>>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "parameters"),
            &crh_parameters,
        )
        .unwrap();

        // Allocate root
        let root_var = <HG as FixedLengthCRHGadget<H, Fq>>::OutputVar::new_input(
            ark_relations::ns!(cs, "root"),
            || Ok(tree.root.clone()),
        ).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fq>>::new_witness(
            ark_relations::ns!(cs, "leaf"),
            || Ok([1_u8; 16]),
        ).unwrap();

        // Allocate leaf
        let index_var = UInt64::<Fq>::new_witness(
            ark_relations::ns!(cs, "index"),
            || Ok(177),
        ).unwrap();

        // Allocate path
        let path_var = MerkleTreePathVar::<MerkleTreeTestParameters, HG, Fq>::new_witness(
            ark_relations::ns!(cs, "path"),
            || Ok(path),
        )
        .unwrap();

        path_var
            .check_path(
                &root_var,
                &leaf_var,
                &index_var,
                &crh_parameters_var,
            )
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn invalid_root_path_constraints_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut tree = TestMerkleTree::new(&[0u8; 16], &crh_parameters).unwrap();
        tree.update(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup(177).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate hash parameters
        let crh_parameters_var = <HG as FixedLengthCRHGadget<H, Fq>>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "parameters"),
            &crh_parameters,
        )
            .unwrap();

        // Allocate root
        let root_var = <HG as FixedLengthCRHGadget<H, Fq>>::OutputVar::new_input(
            ark_relations::ns!(cs, "root"),
            || Ok(<H as FixedLengthCRH>::Output::default()),
        ).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fq>>::new_witness(
            ark_relations::ns!(cs, "leaf"),
            || Ok([1_u8; 16]),
        ).unwrap();

        // Allocate leaf
        let index_var = UInt64::<Fq>::new_witness(
            ark_relations::ns!(cs, "index"),
            || Ok(177),
        ).unwrap();

        // Allocate path
        let path_var = MerkleTreePathVar::<MerkleTreeTestParameters, HG, Fq>::new_witness(
            ark_relations::ns!(cs, "path"),
            || Ok(path),
        )
            .unwrap();

        path_var
            .check_path(
                &root_var,
                &leaf_var,
                &index_var,
                &crh_parameters_var,
            )
            .unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn invalid_leaf_path_constraints_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut tree = TestMerkleTree::new(&[0u8; 16], &crh_parameters).unwrap();
        tree.update(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup(177).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate hash parameters
        let crh_parameters_var = <HG as FixedLengthCRHGadget<H, Fq>>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "parameters"),
            &crh_parameters,
        )
            .unwrap();

        // Allocate root
        let root_var = <HG as FixedLengthCRHGadget<H, Fq>>::OutputVar::new_input(
            ark_relations::ns!(cs, "root"),
            || Ok(tree.root.clone()),
        ).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fq>>::new_witness(
            ark_relations::ns!(cs, "leaf"),
            || Ok([2_u8; 16]),
        ).unwrap();

        // Allocate leaf
        let index_var = UInt64::<Fq>::new_witness(
            ark_relations::ns!(cs, "index"),
            || Ok(177),
        ).unwrap();

        // Allocate path
        let path_var = MerkleTreePathVar::<MerkleTreeTestParameters, HG, Fq>::new_witness(
            ark_relations::ns!(cs, "path"),
            || Ok(path),
        )
            .unwrap();

        path_var
            .check_path(
                &root_var,
                &leaf_var,
                &index_var,
                &crh_parameters_var,
            )
            .unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn invalid_index_path_constraints_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut tree = TestMerkleTree::new(&[0u8; 16], &crh_parameters).unwrap();
        tree.update(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup(177).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate hash parameters
        let crh_parameters_var = <HG as FixedLengthCRHGadget<H, Fq>>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "parameters"),
            &crh_parameters,
        )
            .unwrap();

        // Allocate root
        let root_var = <HG as FixedLengthCRHGadget<H, Fq>>::OutputVar::new_input(
            ark_relations::ns!(cs, "root"),
            || Ok(tree.root.clone()),
        ).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8<Fq>>::new_witness(
            ark_relations::ns!(cs, "leaf"),
            || Ok([1_u8; 16]),
        ).unwrap();

        // Allocate leaf
        let index_var = UInt64::<Fq>::new_witness(
            ark_relations::ns!(cs, "index"),
            || Ok(176),
        ).unwrap();

        // Allocate path
        let path_var = MerkleTreePathVar::<MerkleTreeTestParameters, HG, Fq>::new_witness(
            ark_relations::ns!(cs, "path"),
            || Ok(path),
        )
            .unwrap();

        path_var
            .check_path(
                &root_var,
                &leaf_var,
                &index_var,
                &crh_parameters_var,
            )
            .unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }
}
