use crypto_primitives::sparse_merkle_tree::{
    MerkleTreeParameters,
    constraints::MerkleTreePathVar,
};
use single_step_avd::{SingleStepAVD, constraints::SingleStepAVDGadget};
use crate::history_tree::SingleStepUpdateProof;

use algebra::fields::{Field, PrimeField};
use r1cs_core::{SynthesisError, Namespace};
use r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::ToBytesGadget,
    eq::EqGadget,
    uint8::UInt8,
    uint64::UInt64,
    boolean::Boolean,
};
use zexe_cp::crh::{FixedLengthCRH, FixedLengthCRHGadget};
use std::{
    borrow::Borrow,
};


//TODO: Add lifetimes for public parameter references instead of cloning
//TODO: Optimization: Don't need to take prev/new SSAVD digests
pub struct SingleStepUpdateProofVar<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, ConstraintF>,
        ConstraintF: Field,
{
    pub ssavd_proof: SSAVDGadget::UpdateProofVar,
    pub history_tree_proof: MerkleTreePathVar<HTParams, HGadget, ConstraintF>,
    pub prev_ssavd_digest: SSAVDGadget::DigestVar,
    pub new_ssavd_digest: SSAVDGadget::DigestVar,
    pub prev_digest: HGadget::OutputVar,
    pub new_digest: HGadget::OutputVar,
    pub prev_epoch: UInt64<ConstraintF>,
}

impl<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF> AllocVar<SingleStepUpdateProof<SSAVD, HTParams>, ConstraintF>
for SingleStepUpdateProofVar<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, ConstraintF>,
        ConstraintF: Field,
{
    fn new_variable<T: Borrow<SingleStepUpdateProof<SSAVD, HTParams>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let f_out = f()?;
        let ssavd_proof = SSAVDGadget::UpdateProofVar::new_variable(
            r1cs_core::ns!(cs, "ssavd_proof"),
            || Ok(&f_out.borrow().ssavd_proof),
            mode,
        )?;
        let history_tree_proof = <MerkleTreePathVar<HTParams, HGadget, ConstraintF>>::new_variable(
            r1cs_core::ns!(cs, "history_tree_proof"),
            || Ok(&f_out.borrow().history_tree_proof),
            mode,
        )?;
        let prev_ssavd_digest = SSAVDGadget::DigestVar::new_variable(
            r1cs_core::ns!(cs, "prev_ssavd_digest"),
            || Ok(&f_out.borrow().prev_ssavd_digest),
            mode,
        )?;
        let new_ssavd_digest = SSAVDGadget::DigestVar::new_variable(
            r1cs_core::ns!(cs, "new_ssavd_digest"),
            || Ok(&f_out.borrow().new_ssavd_digest),
            mode,
        )?;
        let prev_digest = HGadget::OutputVar::new_variable(
            r1cs_core::ns!(cs, "prev_digest"),
            || Ok(&f_out.borrow().prev_digest),
            mode,
        )?;
        let new_digest = HGadget::OutputVar::new_variable(
            r1cs_core::ns!(cs, "new_digest"),
            || Ok(&f_out.borrow().new_digest),
            mode,
        )?;
        let prev_epoch = <UInt64<ConstraintF>>::new_variable(
            r1cs_core::ns!(cs, "prev_epoch"),
            || Ok(&f_out.borrow().prev_epoch),
            mode,
        )?;
        Ok(SingleStepUpdateProofVar{
            ssavd_proof,
            history_tree_proof,
            prev_ssavd_digest,
            new_ssavd_digest,
            prev_digest,
            new_digest,
            prev_epoch,
        })
    }
}

impl<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF>
SingleStepUpdateProofVar<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, ConstraintF>,
        ConstraintF: PrimeField,
{
    //TODO: Should be able to reuse this for recursive solution
    //TODO: Don't need conditional is_genesis checks for aggregation solution
    pub fn conditional_check_single_step_with_history_update(
        &self,
        ssavd_pp: &SSAVDGadget::PublicParametersVar,
        history_tree_pp: &HGadget::ParametersVar,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        SSAVDGadget::conditional_check_update_proof(
            &ssavd_pp,
            &self.prev_ssavd_digest,
            &self.new_ssavd_digest,
            &self.ssavd_proof,
            condition,
        )?;
        let history_tree_leaf_default = vec![<UInt8<ConstraintF>>::constant(Default::default()); 32];
        let prev_history_tree_digest = self.history_tree_proof.compute_root_var(
            &history_tree_leaf_default,
            &self.prev_epoch,
            &history_tree_pp,
        )?;
        let calc_prev_digest = hash_to_final_digest_var::<SSAVD, SSAVDGadget, HTParams::H, HGadget, ConstraintF>(
            &history_tree_pp,
            &self.prev_ssavd_digest,
            &prev_history_tree_digest,
            &self.prev_epoch,
        )?;
        self.prev_digest.conditional_enforce_equal(
            &calc_prev_digest,
            condition,
        )?;
        let history_tree_prev_digest_leaf = self.prev_digest.to_bytes()?;
        let new_history_tree_digest = self.history_tree_proof.compute_root_var(
            &history_tree_prev_digest_leaf,
            &self.prev_epoch,
            &history_tree_pp,
        )?;
        let new_epoch = UInt64::addmany(
            &[self.prev_epoch.clone(), UInt64::constant(1)],
        )?;
        let calc_new_digest = hash_to_final_digest_var::<SSAVD, SSAVDGadget, HTParams::H, HGadget, ConstraintF>(
            &history_tree_pp,
            &self.new_ssavd_digest,
            &new_history_tree_digest,
            &new_epoch,
        )?;
        self.new_digest.conditional_enforce_equal(
            &calc_new_digest,
            condition,
        )?;
        Ok(())
    }
}


pub fn hash_to_final_digest_var<SSAVD, SSAVDGadget, H, HGadget, ConstraintF>(
    parameters: &HGadget::ParametersVar,
    ssavd_digest: &SSAVDGadget::DigestVar,
    history_tree_digest: &HGadget::OutputVar,
    epoch: &UInt64<ConstraintF>,
) -> Result<HGadget::OutputVar, SynthesisError>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        H: FixedLengthCRH,
        HGadget: FixedLengthCRHGadget<H, ConstraintF>,
        ConstraintF: Field,
{
    // Hash together digests
    let mut buffer1 = ssavd_digest.to_bytes()?;
    buffer1.extend_from_slice(&history_tree_digest.to_bytes()?);
    buffer1.resize(H::INPUT_SIZE_BITS / 8, UInt8::constant(0u8));
    let digests_hash = HGadget::evaluate(parameters, &buffer1)?;

    // Note: to_bytes must provide little endian repr of u64 to match fn hash_to_final_digest
    let mut buffer2 = epoch.to_bytes()?;
    buffer2.extend_from_slice(&digests_hash.to_bytes()?);
    buffer2.resize(H::INPUT_SIZE_BITS / 8, UInt8::constant(0u8));
    HGadget::evaluate(parameters, &buffer2)
}

#[cfg(test)]
mod test {
    use super::*;
    use algebra::ed_on_bls12_381::{EdwardsProjective as JubJub, Fq};
    use r1cs_core::ConstraintSystem;
    use r1cs_std::{ed_on_bls12_381::EdwardsVar};
    use rand::{rngs::StdRng, SeedableRng};
    use zexe_cp::crh::{
        pedersen::{constraints::CRHGadget, CRH, Window},
    };

    use single_step_avd::{
        merkle_tree_avd::{
            MerkleTreeAVDParameters,
            MerkleTreeAVD,
            constraints::MerkleTreeAVDGadget,
        },
    };
    use crypto_primitives::sparse_merkle_tree::MerkleDepth;
    use crate::{
        history_tree::SingleStepAVDWithHistory,
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
        const MAX_UPDATE_BATCH_SIZE: u64 = 4;
        const MAX_OPEN_ADDRESSING_PROBES: u8 = 2;
        type MerkleTreeParameters = MerkleTreeTestParameters;
    }

    type TestMerkleTreeAVD = MerkleTreeAVD<MerkleTreeAVDTestParameters>;
    type TestMerkleTreeAVDGadget = MerkleTreeAVDGadget<MerkleTreeAVDTestParameters, HG, Fq>;
    type TestAVDWithHistory = SingleStepAVDWithHistory<TestMerkleTreeAVD, MerkleTreeTestParameters>;
    type TestHistoryUpdateVar = SingleStepUpdateProofVar<
        TestMerkleTreeAVD,
        TestMerkleTreeAVDGadget,
        MerkleTreeTestParameters,
        HG,
        Fq,
    >;

    #[test]
    fn update_and_verify_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let (ssavd_pp, crh_pp) = TestAVDWithHistory::setup(&mut rng).unwrap();
        let mut avd = TestAVDWithHistory::new(&mut rng, &ssavd_pp, &crh_pp).unwrap();
        let proof = avd.update(&[1_u8; 32], &[2_u8; 32]).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate proof variables
        let proof_var = TestHistoryUpdateVar::new_input(
            r1cs_core::ns!(cs, "alloc_proof"),
            || Ok(proof),
        ).unwrap();

        let ssavd_pp_gadget = <TestMerkleTreeAVDGadget as SingleStepAVDGadget<TestMerkleTreeAVD, Fq>>::PublicParametersVar::new_constant(
            r1cs_core::ns!(cs, "ssavd_pp"),
            &ssavd_pp,
        ).unwrap();
        let crh_pp_gadget = <HG as FixedLengthCRHGadget<H, Fq>>::ParametersVar::new_constant(
            r1cs_core::ns!(cs, "history_tree_pp"),
            &crh_pp,
        ).unwrap();

        proof_var.conditional_check_single_step_with_history_update(
            &ssavd_pp_gadget,
            &crh_pp_gadget,
            &Boolean::constant(true),
        ).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    #[ignore]
    fn batch_update_and_verify_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let (ssavd_pp, crh_pp) = TestAVDWithHistory::setup(&mut rng).unwrap();
        let mut avd = TestAVDWithHistory::new(&mut rng, &ssavd_pp, &crh_pp).unwrap();
        let updates = vec![
            ([1_u8; 32], [2_u8; 32]),
            ([1_u8; 32], [3_u8; 32]),
            ([10_u8; 32], [11_u8; 32]),
        ];
        let proof = avd.batch_update(&updates).unwrap();

        let cs = ConstraintSystem::<Fq>::new_ref();

        // Allocate proof variables
        let proof_var = TestHistoryUpdateVar::new_input(
            r1cs_core::ns!(cs, "alloc_proof"),
            || Ok(proof),
        ).unwrap();

        let ssavd_pp_gadget = <TestMerkleTreeAVDGadget as SingleStepAVDGadget<TestMerkleTreeAVD, Fq>>::PublicParametersVar::new_constant(
            r1cs_core::ns!(cs, "ssavd_pp"),
            &ssavd_pp,
        ).unwrap();
        let crh_pp_gadget = <HG as FixedLengthCRHGadget<H, Fq>>::ParametersVar::new_constant(
            r1cs_core::ns!(cs, "history_tree_pp"),
            &crh_pp,
        ).unwrap();

        proof_var.conditional_check_single_step_with_history_update(
            &ssavd_pp_gadget,
            &crh_pp_gadget,
            &Boolean::constant(true),
        ).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }
}
