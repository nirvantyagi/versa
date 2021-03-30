use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{SynthesisError, Namespace};
use ark_r1cs_std::{
    prelude::*,
    uint64::UInt64,
};

use crate::{
    constraints::SingleStepAVDGadget,
    merkle_tree_avd::{MerkleTreeAVD, MerkleTreeAVDParameters, UpdateProof},
};
use crypto_primitives::{
    sparse_merkle_tree::{
        constraints::MerkleTreePathVar, MerkleTreeParameters,
    },
    hash::constraints::FixedLengthCRHGadget,
};

use std::{borrow::Borrow, marker::PhantomData, convert::{TryFrom}};

pub struct UpdateProofVar<P, HGadget, ConstraintF>
where
    P: MerkleTreeAVDParameters,
    HGadget: FixedLengthCRHGadget<
        <<P as MerkleTreeAVDParameters>::MerkleTreeParameters as MerkleTreeParameters>::H,
        ConstraintF,
    >,
    ConstraintF: Field,
{
    paths: Vec<MerkleTreePathVar<P::MerkleTreeParameters, HGadget, ConstraintF>>,
    indices: Vec<UInt64<ConstraintF>>,
    keys: Vec<[UInt8<ConstraintF>; 32]>,
    versions: Vec<UInt64<ConstraintF>>,
    prev_values: Vec<[UInt8<ConstraintF>; 32]>,
    new_values: Vec<[UInt8<ConstraintF>; 32]>,
}

impl<P, HGadget, ConstraintF> AllocVar<UpdateProof<P>, ConstraintF>
    for UpdateProofVar<P, HGadget, ConstraintF>
where
    P: MerkleTreeAVDParameters,
    HGadget: FixedLengthCRHGadget<
        <<P as MerkleTreeAVDParameters>::MerkleTreeParameters as MerkleTreeParameters>::H,
        ConstraintF,
    >,
    ConstraintF: Field,
{
    fn new_variable<T: Borrow<UpdateProof<P>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let f_out = f()?;
        let paths = Vec::<MerkleTreePathVar<P::MerkleTreeParameters, HGadget, ConstraintF>>::new_variable(
            ark_relations::ns!(cs, "merkle_paths"),
            || Ok(&f_out.borrow().paths[..]),
            mode,
        )?;
        let indices = Vec::<UInt64<ConstraintF>>::new_variable(
            ark_relations::ns!(cs, "indices"),
            ||  Ok(&f_out.borrow().indices[..]),
            mode,
        )?;
        let keys = f_out.borrow().keys.iter()
            .enumerate()
            .map(|(_i, v)| {
                Vec::<UInt8<ConstraintF>>::new_variable(
                    cs.clone(),
                    || Ok(&v[..]),
                    mode,
                )
            }).collect::<Result<Vec<Vec<UInt8<ConstraintF>>>, SynthesisError>>()?
            .iter()
            .map(|v| <&[UInt8<ConstraintF>; 32] as TryFrom<&[UInt8<ConstraintF>]>>::try_from(v.as_slice()).unwrap().clone())
            .collect::<Vec<[UInt8<ConstraintF>; 32]>>();
        let versions = Vec::<UInt64<ConstraintF>>::new_variable(
            ark_relations::ns!(cs, "versions"),
            || Ok(&f_out.borrow().versions[..]),
            mode,
        )?;
        let prev_values = f_out.borrow().prev_values.iter()
            .enumerate()
            .map(|(_i, v)| {
                Vec::<UInt8<ConstraintF>>::new_variable(
                    cs.clone(),
                    || Ok(&v[..]),
                    mode,
                )
            }).collect::<Result<Vec<Vec<UInt8<ConstraintF>>>, SynthesisError>>()?
            .iter()
            .map(|v| <&[UInt8<ConstraintF>; 32] as TryFrom<&[UInt8<ConstraintF>]>>::try_from(v.as_slice()).unwrap().clone())
            .collect::<Vec<[UInt8<ConstraintF>; 32]>>();
        let new_values = f_out.borrow().new_values.iter()
            .enumerate()
            .map(|(_i, v)| {
                Vec::<UInt8<ConstraintF>>::new_variable(
                    cs.clone(),
                    || Ok(&v[..]),
                    mode,
                )
            }).collect::<Result<Vec<Vec<UInt8<ConstraintF>>>, SynthesisError>>()?
            .iter()
            .map(|v| <&[UInt8<ConstraintF>; 32] as TryFrom<&[UInt8<ConstraintF>]>>::try_from(v.as_slice()).unwrap().clone())
            .collect::<Vec<[UInt8<ConstraintF>; 32]>>();
        Ok(UpdateProofVar {
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
    type PublicParametersVar = HGadget::ParametersVar;
    type DigestVar = HGadget::OutputVar;
    type UpdateProofVar = UpdateProofVar<P, HGadget, ConstraintF>;

    fn check_update_proof(
        pp: &Self::PublicParametersVar,
        prev_digest: &Self::DigestVar,
        new_digest: &Self::DigestVar,
        proof: &Self::UpdateProofVar,
    ) -> Result<(), SynthesisError> {
        Self::conditional_check_update_proof(
            pp,
            prev_digest,
            new_digest,
            proof,
            &Boolean::constant(true),
        )
    }

    #[tracing::instrument(target = "r1cs", skip(pp, prev_digest, new_digest, proof, condition))]
    fn conditional_check_update_proof(
        pp: &Self::PublicParametersVar,
        prev_digest: &Self::DigestVar,
        new_digest: &Self::DigestVar,
        proof: &Self::UpdateProofVar,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let mut current_digest = prev_digest.clone();
        for upd_i in 0..proof.paths.len() {
            // Check path with respect to previous leaf
            let is_prev_version_zero = proof.versions[upd_i].is_eq(&UInt64::constant(0))?;
            let prev_k = <&[UInt8<ConstraintF>; 32] as TryFrom<&[UInt8<ConstraintF>]>>::try_from(
                &proof.keys[upd_i].iter()
                    .map(|v| {
                        <UInt8<ConstraintF>>::conditionally_select(
                            &is_prev_version_zero,
                            &UInt8::constant(Default::default()),
                            v,
                        )
                    }).collect::<Result<Vec<UInt8<ConstraintF>>, SynthesisError>>()?
            ).unwrap().clone();
            let prev_leaf = concat_leaf_var(
                &prev_k,
                &proof.versions[upd_i],
                &proof.prev_values[upd_i],
            )?;
            proof.paths[upd_i].conditional_check_path(
                &current_digest,
                &prev_leaf,
                &proof.indices[upd_i],
                pp,
                condition,
            )?;

            // Calculate new digest with respect to new leaf
            let new_version = UInt64::addmany(
                &[proof.versions[upd_i].clone(), UInt64::constant(1)],
            )?;
            let new_leaf = concat_leaf_var(
                &proof.keys[upd_i],
                &new_version,
                &proof.new_values[upd_i],
            )?;
            current_digest = proof.paths[upd_i].compute_root_var(
                &new_leaf,
                &proof.indices[upd_i],
                pp,
            )?;
        }
        new_digest.conditional_enforce_equal(&current_digest, condition)?;
        Ok(())
    }
}

fn concat_leaf_var<ConstraintF: Field>(
    key: &[UInt8<ConstraintF>; 32],
    version: &UInt64<ConstraintF>,
    value: &[UInt8<ConstraintF>; 32],
) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
    Ok(key
        .iter()
        // Note: to_bytes must provide little endian repr to match fn concat_leaf_data
        .chain(&version.to_bytes()?)
        .chain(value)
        .cloned()
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::{EdwardsProjective as JubJub, Fq, constraints::EdwardsVar};
    use ark_relations::r1cs::ConstraintSystem;
    use rand::{rngs::StdRng, SeedableRng};
    use ark_crypto_primitives::crh::{
        pedersen::{constraints::CRHGadget, CRH, Window},
    };

    use crate::SingleStepAVD;
    use crypto_primitives::{
        sparse_merkle_tree::MerkleDepth, hash::FixedLengthCRH,
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

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate hash parameters
        let crh_parameters_var = <HG as FixedLengthCRHGadget<H, Fq>>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "parameters"),
            &crh_parameters,
        )
            .unwrap();

        // Allocate digest parameters
        let prev_digest_var = <HG as FixedLengthCRHGadget<H, Fq>>::OutputVar::new_input(
            ark_relations::ns!(cs, "prev_digest"),
            || Ok(digest_0.clone()),
        ).unwrap();
        let new_digest_var = <HG as FixedLengthCRHGadget<H, Fq>>::OutputVar::new_input(
            ark_relations::ns!(cs, "new_digest"),
            || Ok(digest_1.clone()),
        ).unwrap();

        // Allocate proof parameters
        let proof_var = UpdateProofVar::new_witness(
            ark_relations::ns!(cs, "proof"),
            || Ok(proof.clone())
            ).unwrap();

        TestMerkleTreeAVDGadget::check_update_proof(
            &crh_parameters_var,
            &prev_digest_var,
            &new_digest_var,
            &proof_var,
        ).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }
}
