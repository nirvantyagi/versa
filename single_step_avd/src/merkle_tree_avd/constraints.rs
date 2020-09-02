use algebra::{Field, PrimeField};
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::{
    alloc::AllocGadget, bits::ToBytesGadget, boolean::Boolean, eq::{ConditionalEqGadget},
    select::CondSelectGadget, uint64::UInt64, uint8::UInt8,
};
use zexe_cp::crh::FixedLengthCRHGadget;

use crate::{
    constraints::SingleStepAVDGadget,
    merkle_tree_avd::{MerkleTreeAVDParameters, UpdateProof},
};
use crypto_primitives::sparse_merkle_tree::{
    constraints::MerkleTreePathGadget, MerkleTreeParameters,
};

use crate::merkle_tree_avd::MerkleTreeAVD;
use std::{borrow::Borrow, marker::PhantomData};

pub struct UpdateProofGadget<P, HGadget, ConstraintF>
where
    P: MerkleTreeAVDParameters,
    HGadget: FixedLengthCRHGadget<
        <<P as MerkleTreeAVDParameters>::MerkleTreeParameters as MerkleTreeParameters>::H,
        ConstraintF,
    >,
    ConstraintF: Field,
{
    paths: Vec<MerkleTreePathGadget<P::MerkleTreeParameters, HGadget, ConstraintF>>,
    indices: Vec<UInt64>,
    keys: Vec<[UInt8; 32]>,
    versions: Vec<UInt64>,
    prev_values: Vec<[UInt8; 32]>,
    new_values: Vec<[UInt8; 32]>,
}

impl<P, HGadget, ConstraintF> AllocGadget<UpdateProof<P>, ConstraintF>
    for UpdateProofGadget<P, HGadget, ConstraintF>
where
    P: MerkleTreeAVDParameters,
    HGadget: FixedLengthCRHGadget<
        <<P as MerkleTreeAVDParameters>::MerkleTreeParameters as MerkleTreeParameters>::H,
        ConstraintF,
    >,
    ConstraintF: Field,
{
    fn alloc_constant<T, CS>(mut cs: CS, val: T) -> Result<Self, SynthesisError>
    where
        T: Borrow<UpdateProof<P>>,
        CS: ConstraintSystem<ConstraintF>,
    {
        let paths = Vec::<MerkleTreePathGadget<P::MerkleTreeParameters, HGadget, ConstraintF>>::alloc_constant(&mut cs.ns(|| "merkle_paths"), &val.borrow().paths[..])?;
        let indices =
            Vec::<UInt64>::alloc_constant(&mut cs.ns(|| "indices"), &val.borrow().indices[..])?;
        let keys =
            Vec::<[UInt8; 32]>::alloc_constant(&mut cs.ns(|| "keys"), &val.borrow().keys[..])?;
        let versions =
            Vec::<UInt64>::alloc_constant(&mut cs.ns(|| "versions"), &val.borrow().versions[..])?;
        let prev_values = Vec::<[UInt8; 32]>::alloc_constant(
            &mut cs.ns(|| "prev_values"),
            &val.borrow().prev_values[..],
        )?;
        let new_values = Vec::<[UInt8; 32]>::alloc_constant(
            &mut cs.ns(|| "new_values"),
            &val.borrow().new_values[..],
        )?;
        Ok(UpdateProofGadget {
            paths,
            indices,
            keys,
            versions,
            prev_values,
            new_values,
        })
    }

    fn alloc<F, T, CS>(mut cs: CS, f: F) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<UpdateProof<P>>,
        CS: ConstraintSystem<ConstraintF>,
    {
        let f_out = f()?;
        let paths =
            Vec::<MerkleTreePathGadget<P::MerkleTreeParameters, HGadget, ConstraintF>>::alloc(
                &mut cs.ns(|| "merkle_paths"),
                || Ok(&f_out.borrow().paths[..]),
            )?;
        let indices =
            Vec::<UInt64>::alloc(&mut cs.ns(|| "indices"), || Ok(&f_out.borrow().indices[..]))?;
        let keys =
            Vec::<[UInt8; 32]>::alloc(&mut cs.ns(|| "keys"), || Ok(&f_out.borrow().keys[..]))?;
        let versions = Vec::<UInt64>::alloc(&mut cs.ns(|| "versions"), || {
            Ok(&f_out.borrow().versions[..])
        })?;
        let prev_values = Vec::<[UInt8; 32]>::alloc(&mut cs.ns(|| "prev_values"), || {
            Ok(&f_out.borrow().prev_values[..])
        })?;
        let new_values = Vec::<[UInt8; 32]>::alloc(&mut cs.ns(|| "new_values"), || {
            Ok(&f_out.borrow().new_values[..])
        })?;
        Ok(UpdateProofGadget {
            paths,
            indices,
            keys,
            versions,
            prev_values,
            new_values,
        })
    }

    fn alloc_input<F, T, CS>(mut cs: CS, f: F) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<UpdateProof<P>>,
        CS: ConstraintSystem<ConstraintF>,
    {
        let f_out = f()?;
        let paths = Vec::<MerkleTreePathGadget<P::MerkleTreeParameters, HGadget, ConstraintF>>::alloc_input(&mut cs.ns(|| "merkle_paths"), || Ok(&f_out.borrow().paths[..]))?;
        let indices = Vec::<UInt64>::alloc_input(&mut cs.ns(|| "indices"), || {
            Ok(&f_out.borrow().indices[..])
        })?;
        let keys = Vec::<[UInt8; 32]>::alloc_input(&mut cs.ns(|| "keys"), || {
            Ok(&f_out.borrow().keys[..])
        })?;
        let versions = Vec::<UInt64>::alloc_input(&mut cs.ns(|| "versions"), || {
            Ok(&f_out.borrow().versions[..])
        })?;
        let prev_values = Vec::<[UInt8; 32]>::alloc_input(&mut cs.ns(|| "prev_values"), || {
            Ok(&f_out.borrow().prev_values[..])
        })?;
        let new_values = Vec::<[UInt8; 32]>::alloc_input(&mut cs.ns(|| "new_values"), || {
            Ok(&f_out.borrow().new_values[..])
        })?;
        Ok(UpdateProofGadget {
            paths,
            indices,
            keys,
            versions,
            prev_values,
            new_values,
        })
    }
}

pub struct MerkleTreeAVDGadget<P, HGadget, ConstraintF>
where
    P: MerkleTreeAVDParameters,
    HGadget: FixedLengthCRHGadget<
        <<P as MerkleTreeAVDParameters>::MerkleTreeParameters as MerkleTreeParameters>::H,
        ConstraintF,
    >,
    ConstraintF: Field,
{
    _parameters: PhantomData<P>,
    _hash_gadget: PhantomData<HGadget>,
    _engine: PhantomData<ConstraintF>,
}

impl<P, HGadget, ConstraintF> SingleStepAVDGadget<MerkleTreeAVD<P>, ConstraintF>
    for MerkleTreeAVDGadget<P, HGadget, ConstraintF>
where
    P: MerkleTreeAVDParameters,
    HGadget: FixedLengthCRHGadget<
        <<P as MerkleTreeAVDParameters>::MerkleTreeParameters as MerkleTreeParameters>::H,
        ConstraintF,
    >,
    ConstraintF: PrimeField,
{
    type PublicParametersGadget = HGadget::ParametersGadget;
    type DigestGadget = HGadget::OutputGadget;
    type UpdateProofGadget = UpdateProofGadget<P, HGadget, ConstraintF>;

    fn check_update_proof<CS: ConstraintSystem<ConstraintF>>(
        cs: CS,
        pp: &Self::PublicParametersGadget,
        prev_digest: &Self::DigestGadget,
        new_digest: &Self::DigestGadget,
        proof: &Self::UpdateProofGadget,
    ) -> Result<(), SynthesisError> {
        Self::conditional_check_update_proof(
            cs,
            pp,
            prev_digest,
            new_digest,
            proof,
            &Boolean::constant(true),
        )
    }

    fn conditional_check_update_proof<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        pp: &Self::PublicParametersGadget,
        prev_digest: &Self::DigestGadget,
        new_digest: &Self::DigestGadget,
        proof: &Self::UpdateProofGadget,
        condition: &Boolean,
    ) -> Result<(), SynthesisError> {
        let mut current_digest = prev_digest.clone();
        for upd_i in 0..proof.paths.len() {
            // Check path with respect to previous leaf
            //TODO: kary_or allocates bits -- need to input as witness
            let is_prev_version_ne_0 = Boolean::kary_or(
                &mut cs.ns(|| format!("version_zero_{}", upd_i)),
                &proof.versions[upd_i].to_bits_le(),
            )?;
            let prev_k = <[UInt8; 32]>::conditionally_select(
                &mut cs.ns(|| format!("select_prev_key_{}", upd_i)),
                &is_prev_version_ne_0,
                &proof.keys[upd_i],
                &Default::default(),
            )?;
            let prev_leaf = concat_leaf_gadget(
                &mut cs.ns(|| format!("concat_prev_leaf_data_{}", upd_i)),
                &prev_k,
                &proof.versions[upd_i],
                &proof.prev_values[upd_i],
            )?;
            proof.paths[upd_i].conditional_check_path(
                &mut cs.ns(|| format!("verify_prev_update_path_{}", upd_i)),
                &current_digest,
                &prev_leaf,
                &proof.indices[upd_i],
                pp,
                condition,
            )?;

            // Calculate new digest with respect to new leaf
            let new_version = UInt64::addmany(
                &mut cs.ns(|| format!("increment_version_{}", upd_i)),
                &[proof.versions[upd_i].clone(), UInt64::constant(1)],
            )?;
            let new_leaf = concat_leaf_gadget(
                &mut cs.ns(|| format!("concat_new_leaf_data_{}", upd_i)),
                &proof.keys[upd_i],
                &new_version,
                &proof.new_values[upd_i],
            )?;
            current_digest = proof.paths[upd_i].check_calc_root(
                &mut cs.ns(|| format!("calc_new_update_path_{}", upd_i)),
                &new_leaf,
                &proof.indices[upd_i],
                pp,
            )?;
        }
        new_digest.conditional_enforce_equal(&mut cs.ns(|| "last_digest_equal"), &current_digest, condition)?;
        Ok(())
    }
}

fn concat_leaf_gadget<ConstraintF: Field, CS: ConstraintSystem<ConstraintF>>(
    cs: CS,
    key: &[UInt8; 32],
    version: &UInt64,
    value: &[UInt8; 32],
) -> Result<Vec<UInt8>, SynthesisError> {
    Ok(key
        .iter()
        // Note: to_bytes must provide little endian repr to match fn concat_leaf_data
        .chain(&version.to_bytes(cs)?)
        .chain(value)
        .cloned()
        .collect())
}

#[cfg(test)]
mod test {
    use super::*;
    use algebra::ed_on_bls12_381::{EdwardsAffine as JubJub, Fq};
    use r1cs_core::ConstraintSystem;
    use r1cs_std::{ed_on_bls12_381::EdwardsGadget, test_constraint_system::TestConstraintSystem};
    use rand::{rngs::StdRng, SeedableRng};
    use zexe_cp::crh::{
        pedersen::{constraints::PedersenCRHGadget, PedersenCRH, PedersenWindow},
        FixedLengthCRH, FixedLengthCRHGadget,
    };

    use crate::SingleStepAVD;
    use crypto_primitives::sparse_merkle_tree::MerkleDepth;

    #[derive(Clone)]
    pub struct Window4x256;

    impl PedersenWindow for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = PedersenCRH<JubJub, Window4x256>;
    type HG = PedersenCRHGadget<JubJub, Fq, EdwardsGadget>;

    #[derive(Clone)]
    pub struct MerkleTreeTestParameters;

    impl MerkleTreeParameters for MerkleTreeTestParameters {
        const DEPTH: MerkleDepth = 4;
        type H = H;
    }

    #[derive(Clone)]
    pub struct MerkleTreeAVDTestParameters;

    impl MerkleTreeAVDParameters for MerkleTreeAVDTestParameters {
        const MAX_UPDATE_BATCH_SIZE: u64 = 8;
        const MAX_OPEN_ADDRESSING_PROBES: u8 = 2;
        type MerkleTreeParameters = MerkleTreeTestParameters;
    }

    type TestMerkleTreeAVD = MerkleTreeAVD<MerkleTreeAVDTestParameters>;
    type TestMerkleTreeAVDGadget = MerkleTreeAVDGadget<MerkleTreeAVDTestParameters, HG, Fq>;

    #[test]
    fn update_and_verify_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let crh_parameters = H::setup(&mut rng).unwrap();
        let mut avd = TestMerkleTreeAVD::new(&mut rng, &crh_parameters).unwrap();
        let digest_0 = avd.digest().unwrap();
        let (digest_1, proof) = avd.update(&[1_u8; 32], &[2_u8; 32]).unwrap();

        let mut cs = TestConstraintSystem::<Fq>::new();

        // Allocate hash parameters
        let crh_parameters_var = <HG as FixedLengthCRHGadget<H, Fq>>::ParametersGadget::alloc(
            &mut cs.ns(|| "hash_parameters"),
            || Ok(crh_parameters.clone()),
        )
        .unwrap();

        // Allocate digest parameters
        let prev_digest_var = <HG as FixedLengthCRHGadget<H, _>>::OutputGadget::alloc(
            &mut cs.ns(|| "prev_digest"),
            || Ok(digest_0.clone()),
        )
        .unwrap();
        let new_digest_var = <HG as FixedLengthCRHGadget<H, _>>::OutputGadget::alloc(
            &mut cs.ns(|| "new_digest"),
            || Ok(digest_1.clone()),
        )
        .unwrap();

        // Allocate proof parameters
        let proof_var =
            UpdateProofGadget::alloc(&mut cs.ns(|| "proof"), || {
                Ok(proof.clone())
            })
            .unwrap();

        TestMerkleTreeAVDGadget::check_update_proof(
            &mut cs.ns(|| "check_update_proof"),
            &crh_parameters_var,
            &prev_digest_var,
            &new_digest_var,
            &proof_var,
        ).unwrap();

        assert!(cs.is_satisfied());
    }
}
