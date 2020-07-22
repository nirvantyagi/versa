use algebra::Field;
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::{
    uint64::UInt64,
    uint8::UInt8,
    alloc::AllocGadget,
    bits::ToBytesGadget,
    eq::EqGadget,
    select::CondSelectGadget,
};
use zexe_cp::{
    crh::{FixedLengthCRH, FixedLengthCRHGadget},
};

use crate::sparse_merkle_tree::{MerkleTreeParameters, MerkleTreePath};

use std::{
    borrow::Borrow,
    marker::PhantomData,
};

#[derive(Clone)]
pub struct MerkleTreePathGadget<H, P, HGadget, ConstraintF>
    where
        H: FixedLengthCRH,
        P: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<H, ConstraintF>,
        ConstraintF: Field,
{
    path: Vec<HGadget::OutputGadget>,
    _parameters: PhantomData<P>,
}

impl<H, P, HGadget, ConstraintF> MerkleTreePathGadget<H, P, HGadget, ConstraintF>
    where
        H: FixedLengthCRH,
        P: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<H, ConstraintF>,
        ConstraintF: Field,
{
    pub fn check_path<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
        root: &HGadget::OutputGadget,
        leaf: &Vec<UInt8>,
        index: &UInt64,
        hash_parameters: &HGadget::ParametersGadget,
    ) -> Result<(), SynthesisError> {
        let mut current_hash = hash_leaf_gadget::<H, HGadget, ConstraintF, _>(
            &mut cs.ns(|| "hash_leaf"),
            hash_parameters,
            leaf,
        )?;
        for (i, b) in index.to_bits_le().iter().take(P::DEPTH as usize).enumerate() {
            let lc = HGadget::OutputGadget::conditionally_select(
                &mut cs.ns(|| format!("left_child_index_{}", P::DEPTH as usize - i)),
                b,
                &self.path[i],
                &current_hash,
            )?;
            let rc = HGadget::OutputGadget::conditionally_select(
                &mut cs.ns(|| format!("right_child_index_{}", P::DEPTH as usize - i)),
                b,
                &current_hash,
                &self.path[i],
            )?;
            current_hash = hash_inner_node_gadget::<H, HGadget, ConstraintF, _>(
                &mut cs.ns(|| format!("hash_inner_node_{}", P::DEPTH as usize - i)),
                hash_parameters,
                &lc,
                &rc,
            )?;
        }
        root.enforce_equal(
            &mut cs.ns(|| "root_equal"),
            &current_hash,
        )?;
        Ok(())
    }
}

pub fn hash_leaf_gadget<H, HGadget, ConstraintF, CS>(
    cs: CS,
    parameters: &HGadget::ParametersGadget,
    leaf: &Vec<UInt8>,
) -> Result<HGadget::OutputGadget, SynthesisError>
    where
        H: FixedLengthCRH,
        HGadget: FixedLengthCRHGadget<H, ConstraintF>,
        ConstraintF: Field,
        CS: ConstraintSystem<ConstraintF>,
{
    let mut buffer = leaf.clone();
    buffer.resize(H::INPUT_SIZE_BITS / 8, UInt8::constant(0u8));
    HGadget::check_evaluation_gadget(cs, parameters, &buffer)
}

pub fn hash_inner_node_gadget<H, HGadget, ConstraintF, CS>(
    mut cs: CS,
    parameters: &HGadget::ParametersGadget,
    left: &HGadget::OutputGadget,
    right: &HGadget::OutputGadget,
) -> Result<HGadget::OutputGadget, SynthesisError>
    where
        H: FixedLengthCRH,
        HGadget: FixedLengthCRHGadget<H, ConstraintF>,
        ConstraintF: Field,
        CS: ConstraintSystem<ConstraintF>,
{
    let mut buffer = left.to_bytes(&mut cs.ns(|| "left_to_bytes"))?;
    buffer.extend_from_slice(&right.to_bytes(&mut cs.ns(|| "right_to_bytes"))?);
    buffer.resize(H::INPUT_SIZE_BITS / 8, UInt8::constant(0u8));
    HGadget::check_evaluation_gadget(cs, parameters, &buffer)
}


impl<H, P, HGadget, ConstraintF> AllocGadget<MerkleTreePath<H, P>, ConstraintF>
for MerkleTreePathGadget<H, P, HGadget, ConstraintF>
    where
        H: FixedLengthCRH,
        P: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<H, ConstraintF>,
        ConstraintF: Field,
{
    fn alloc_constant<T, CS>(cs: CS, val: T) -> Result<Self, SynthesisError>
        where
            T: Borrow<MerkleTreePath<H, P>>,
            CS: ConstraintSystem<ConstraintF>,
    {
        let path = Vec::<HGadget::OutputGadget>::alloc_constant(cs, &val.borrow().path[..])?;
        Ok(MerkleTreePathGadget { path, _parameters: PhantomData })
    }

    fn alloc<F, T, CS>(cs: CS, f: F) -> Result<Self, SynthesisError>
        where
            F: FnOnce() -> Result<T, SynthesisError>,
            T: Borrow<MerkleTreePath<H, P>>,
            CS: ConstraintSystem<ConstraintF>,
    {
        let f_out = f()?;
        let path = Vec::<HGadget::OutputGadget>::alloc(
            cs,
            || { Ok(&f_out.borrow().path[..]) },
        )?;
        Ok(MerkleTreePathGadget { path, _parameters: PhantomData })
    }

    fn alloc_input<F, T, CS>(cs: CS, f: F) -> Result<Self, SynthesisError>
        where
            F: FnOnce() -> Result<T, SynthesisError>,
            T: Borrow<MerkleTreePath<H, P>>,
            CS: ConstraintSystem<ConstraintF>,
    {
        let f_out = f()?;
        let path = Vec::<HGadget::OutputGadget>::alloc_input(
            cs,
            || { Ok(&f_out.borrow().path[..]) },
        )?;
        Ok(MerkleTreePathGadget { path, _parameters: PhantomData })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::sparse_merkle_tree::*;
    use zexe_cp::{
        crh::{
            pedersen::{constraints::PedersenCRHGadget, PedersenCRH, PedersenWindow},
            FixedLengthCRH, FixedLengthCRHGadget,
        },
    };
    use algebra::ed_on_bls12_381::{EdwardsAffine as JubJub, Fq};
    use r1cs_core::ConstraintSystem;
    use r1cs_std::{ed_on_bls12_381::EdwardsGadget, test_constraint_system::TestConstraintSystem};
    use rand::{SeedableRng, rngs::StdRng};


    #[derive(Clone)]
    pub struct Window4x256;

    impl PedersenWindow for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = PedersenCRH<JubJub, Window4x256>;
    type HG = PedersenCRHGadget<JubJub, Fq, EdwardsGadget>;

    #[derive(Clone)]
    pub struct JubJubHeight8;

    impl MerkleTreeParameters for JubJubHeight8 {
        const DEPTH: MerkleDepth = 8;
    }

    type JubJubMerkleTree = SparseMerkleTree<H, JubJubHeight8>;


    #[test]
    fn valid_path_constraints_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut tree = JubJubMerkleTree::new(&[0u8; 16], crh_parameters.clone()).unwrap();
        tree.update(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup(177).unwrap();

        let mut cs = TestConstraintSystem::<Fq>::new();

        // Allocate hash parameters
        let crh_parameters_var = <HG as FixedLengthCRHGadget<H, Fq>>::ParametersGadget::alloc(
            &mut cs.ns(|| "hash_parameters"),
            || Ok(crh_parameters.clone()),
        ).unwrap();

        // Allocate root
        let root_var = <HG as FixedLengthCRHGadget<H, _>>::OutputGadget::alloc(
            &mut cs.ns(|| "root"),
            || Ok(tree.root.clone()),
        ).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8>::alloc(
            &mut cs.ns(|| "leaf"),
            || Ok([1_u8; 16]),
        ).unwrap();

        // Allocate leaf
        let index_var = UInt64::alloc(
            &mut cs.ns(|| "index"),
            || Ok(177),
        ).unwrap();

        // Allocate path
        let path_var = MerkleTreePathGadget::<H, JubJubHeight8, HG, Fq>::alloc(
            &mut cs.ns(|| "path"),
            || Ok(path),
        ).unwrap();

        path_var.check_path(
            &mut cs.ns(|| "check_path"),
            &root_var,
            &leaf_var,
            &index_var,
            &crh_parameters_var,
        ).unwrap();

        assert!(cs.is_satisfied());
    }

    #[test]
    fn invalid_root_path_constraints_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut tree = JubJubMerkleTree::new(&[0u8; 16], crh_parameters.clone()).unwrap();
        tree.update(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup(177).unwrap();

        let mut cs = TestConstraintSystem::<Fq>::new();

        // Allocate hash parameters
        let crh_parameters_var = <HG as FixedLengthCRHGadget<H, Fq>>::ParametersGadget::alloc(
            &mut cs.ns(|| "hash_parameters"),
            || Ok(crh_parameters.clone()),
        ).unwrap();

        // Allocate root
        let root_var = <HG as FixedLengthCRHGadget<H, _>>::OutputGadget::alloc(
            &mut cs.ns(|| "root"),
            || Ok(<H as FixedLengthCRH>::Output::default()),
        ).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8>::alloc(
            &mut cs.ns(|| "leaf"),
            || Ok([1_u8; 16]),
        ).unwrap();

        // Allocate leaf
        let index_var = UInt64::alloc(
            &mut cs.ns(|| "index"),
            || Ok(177),
        ).unwrap();

        // Allocate path
        let path_var = MerkleTreePathGadget::<H, JubJubHeight8, HG, Fq>::alloc(
            &mut cs.ns(|| "path"),
            || Ok(path),
        ).unwrap();

        path_var.check_path(
            &mut cs.ns(|| "check_path"),
            &root_var,
            &leaf_var,
            &index_var,
            &crh_parameters_var,
        ).unwrap();

        assert!(!cs.is_satisfied());
    }

    #[test]
    fn invalid_leaf_path_constraints_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut tree = JubJubMerkleTree::new(&[0u8; 16], crh_parameters.clone()).unwrap();
        tree.update(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup(177).unwrap();

        let mut cs = TestConstraintSystem::<Fq>::new();

        // Allocate hash parameters
        let crh_parameters_var = <HG as FixedLengthCRHGadget<H, Fq>>::ParametersGadget::alloc(
            &mut cs.ns(|| "hash_parameters"),
            || Ok(crh_parameters.clone()),
        ).unwrap();

        // Allocate root
        let root_var = <HG as FixedLengthCRHGadget<H, _>>::OutputGadget::alloc(
            &mut cs.ns(|| "root"),
            || Ok(tree.root.clone()),
        ).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8>::alloc(
            &mut cs.ns(|| "leaf"),
            || Ok([2_u8; 16]),
        ).unwrap();

        // Allocate leaf
        let index_var = UInt64::alloc(
            &mut cs.ns(|| "index"),
            || Ok(177),
        ).unwrap();

        // Allocate path
        let path_var = MerkleTreePathGadget::<H, JubJubHeight8, HG, Fq>::alloc(
            &mut cs.ns(|| "path"),
            || Ok(path),
        ).unwrap();

        path_var.check_path(
            &mut cs.ns(|| "check_path"),
            &root_var,
            &leaf_var,
            &index_var,
            &crh_parameters_var,
        ).unwrap();

        assert!(!cs.is_satisfied());
    }

    #[test]
    fn invalid_index_path_constraints_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut tree = JubJubMerkleTree::new(&[0u8; 16], crh_parameters.clone()).unwrap();
        tree.update(177, &[1_u8; 16]).unwrap();
        let path = tree.lookup(177).unwrap();

        let mut cs = TestConstraintSystem::<Fq>::new();

        // Allocate hash parameters
        let crh_parameters_var = <HG as FixedLengthCRHGadget<H, Fq>>::ParametersGadget::alloc(
            &mut cs.ns(|| "hash_parameters"),
            || Ok(crh_parameters.clone()),
        ).unwrap();

        // Allocate root
        let root_var = <HG as FixedLengthCRHGadget<H, _>>::OutputGadget::alloc(
            &mut cs.ns(|| "root"),
            || Ok(tree.root.clone()),
        ).unwrap();

        // Allocate leaf
        let leaf_var = Vec::<UInt8>::alloc(
            &mut cs.ns(|| "leaf"),
            || Ok([1_u8; 16]),
        ).unwrap();

        // Allocate leaf
        let index_var = UInt64::alloc(
            &mut cs.ns(|| "index"),
            || Ok(176),
        ).unwrap();

        // Allocate path
        let path_var = MerkleTreePathGadget::<H, JubJubHeight8, HG, Fq>::alloc(
            &mut cs.ns(|| "path"),
            || Ok(path),
        ).unwrap();

        path_var.check_path(
            &mut cs.ns(|| "check_path"),
            &root_var,
            &leaf_var,
            &index_var,
            &crh_parameters_var,
        ).unwrap();

        assert!(!cs.is_satisfied());
    }
}