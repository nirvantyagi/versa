use crypto_primitives::sparse_merkle_tree::{
    MerkleTreeParameters,
    constraints::MerkleTreePathGadget,
};
use single_step_avd::{SingleStepAVD, constraints::SingleStepAVDGadget};
use crate::history_tree::SingleStepUpdateProof;

use algebra::fields::{Field, PrimeField};
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::{
    alloc::AllocGadget,
    bits::ToBytesGadget,
    eq::ConditionalEqGadget,
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
pub struct SingleStepUpdateProofGadget<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, ConstraintF>,
        ConstraintF: Field,
{
    ssavd_pp: SSAVDGadget::PublicParametersGadget,
    history_tree_pp: HGadget::ParametersGadget,
    ssavd_proof: SSAVDGadget::UpdateProofGadget,
    history_tree_proof: MerkleTreePathGadget<HTParams, HGadget, ConstraintF>,
    prev_ssavd_digest: SSAVDGadget::DigestGadget,
    new_ssavd_digest: SSAVDGadget::DigestGadget,
    prev_digest: HGadget::OutputGadget,
    new_digest: HGadget::OutputGadget,
    prev_epoch: UInt64,
}

impl<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF> AllocGadget<SingleStepUpdateProof<SSAVD, HTParams>, ConstraintF>
for SingleStepUpdateProofGadget<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, ConstraintF>,
        ConstraintF: Field,
{
    fn alloc_constant<T, CS>(mut cs: CS, val: T) -> Result<Self, SynthesisError>
        where
            T: Borrow<SingleStepUpdateProof<SSAVD, HTParams>>,
            CS: ConstraintSystem<ConstraintF>,
    {
        let ssavd_pp = SSAVDGadget::PublicParametersGadget::alloc_constant(&mut cs.ns(|| "ssavd_pp"), &val.borrow().ssavd_pp)?;
        let history_tree_pp = HGadget::ParametersGadget::alloc_constant(&mut cs.ns(|| "history_tree_pp"), &val.borrow().history_tree_pp)?;
        let ssavd_proof = SSAVDGadget::UpdateProofGadget::alloc_constant(&mut cs.ns(|| "ssavd_proof"), &val.borrow().ssavd_proof)?;
        let history_tree_proof = <MerkleTreePathGadget<HTParams, HGadget, ConstraintF>>::alloc_constant(&mut cs.ns(|| "history_tree_proof"), &val.borrow().history_tree_proof)?;
        let prev_ssavd_digest = SSAVDGadget::DigestGadget::alloc_constant(&mut cs.ns(|| "prev_ssavd_digest"), &val.borrow().prev_ssavd_digest)?;
        let new_ssavd_digest = SSAVDGadget::DigestGadget::alloc_constant(&mut cs.ns(|| "new_ssavd_digest"), &val.borrow().new_ssavd_digest)?;
        let prev_digest = HGadget::OutputGadget::alloc_constant(&mut cs.ns(|| "prev_digest"), &val.borrow().prev_digest)?;
        let new_digest = HGadget::OutputGadget::alloc_constant(&mut cs.ns(|| "new_digest"), &val.borrow().new_digest)?;
        let prev_epoch = UInt64::alloc_constant(&mut cs.ns(|| "prev_epoch"), &val.borrow().prev_epoch)?;
        Ok(SingleStepUpdateProofGadget{
            ssavd_pp,
            history_tree_pp,
            ssavd_proof,
            history_tree_proof,
            prev_ssavd_digest,
            new_ssavd_digest,
            prev_digest,
            new_digest,
            prev_epoch,
        })
    }

    fn alloc<F, T, CS>(mut cs: CS, f: F) -> Result<Self, SynthesisError>
        where
            F: FnOnce() -> Result<T, SynthesisError>,
            T: Borrow<SingleStepUpdateProof<SSAVD, HTParams>>,
            CS: ConstraintSystem<ConstraintF>,
    {
        let f_out = f()?;
        let ssavd_pp = SSAVDGadget::PublicParametersGadget::alloc(&mut cs.ns(|| "ssavd_pp"), || Ok(&f_out.borrow().ssavd_pp))?;
        let history_tree_pp = HGadget::ParametersGadget::alloc(&mut cs.ns(|| "history_tree_pp"), || Ok(&f_out.borrow().history_tree_pp))?;
        let ssavd_proof = SSAVDGadget::UpdateProofGadget::alloc(&mut cs.ns(|| "ssavd_proof"), || Ok(&f_out.borrow().ssavd_proof))?;
        let history_tree_proof = <MerkleTreePathGadget<HTParams, HGadget, ConstraintF>>::alloc(&mut cs.ns(|| "history_tree_proof"), || Ok(&f_out.borrow().history_tree_proof))?;
        let prev_ssavd_digest = SSAVDGadget::DigestGadget::alloc(&mut cs.ns(|| "prev_ssavd_digest"), || Ok(&f_out.borrow().prev_ssavd_digest))?;
        let new_ssavd_digest = SSAVDGadget::DigestGadget::alloc(&mut cs.ns(|| "new_ssavd_digest"), || Ok(&f_out.borrow().new_ssavd_digest))?;
        let prev_digest = HGadget::OutputGadget::alloc(&mut cs.ns(|| "prev_digest"), || Ok(&f_out.borrow().prev_digest))?;
        let new_digest = HGadget::OutputGadget::alloc(&mut cs.ns(|| "new_digest"), || Ok(&f_out.borrow().new_digest))?;
        let prev_epoch = UInt64::alloc(&mut cs.ns(|| "prev_epoch"), || Ok(&f_out.borrow().prev_epoch))?;
        Ok(SingleStepUpdateProofGadget{
            ssavd_pp,
            history_tree_pp,
            ssavd_proof,
            history_tree_proof,
            prev_ssavd_digest,
            new_ssavd_digest,
            prev_digest,
            new_digest,
            prev_epoch,
        })
    }

    fn alloc_input<F, T, CS>(mut cs: CS, f: F) -> Result<Self, SynthesisError>
        where
            F: FnOnce() -> Result<T, SynthesisError>,
            T: Borrow<SingleStepUpdateProof<SSAVD, HTParams>>,
            CS: ConstraintSystem<ConstraintF>,
    {
        let f_out = f()?;
        let ssavd_pp = SSAVDGadget::PublicParametersGadget::alloc_input(&mut cs.ns(|| "ssavd_pp"), || Ok(&f_out.borrow().ssavd_pp))?;
        let history_tree_pp = HGadget::ParametersGadget::alloc_input(&mut cs.ns(|| "history_tree_pp"), || Ok(&f_out.borrow().history_tree_pp))?;
        let ssavd_proof = SSAVDGadget::UpdateProofGadget::alloc_input(&mut cs.ns(|| "ssavd_proof"), || Ok(&f_out.borrow().ssavd_proof))?;
        let history_tree_proof = <MerkleTreePathGadget<HTParams, HGadget, ConstraintF>>::alloc_input(&mut cs.ns(|| "history_tree_proof"), || Ok(&f_out.borrow().history_tree_proof))?;
        let prev_ssavd_digest = SSAVDGadget::DigestGadget::alloc_input(&mut cs.ns(|| "prev_ssavd_digest"), || Ok(&f_out.borrow().prev_ssavd_digest))?;
        let new_ssavd_digest = SSAVDGadget::DigestGadget::alloc_input(&mut cs.ns(|| "new_ssavd_digest"), || Ok(&f_out.borrow().new_ssavd_digest))?;
        let prev_digest = HGadget::OutputGadget::alloc_input(&mut cs.ns(|| "prev_digest"), || Ok(&f_out.borrow().prev_digest))?;
        let new_digest = HGadget::OutputGadget::alloc_input(&mut cs.ns(|| "new_digest"), || Ok(&f_out.borrow().new_digest))?;
        let prev_epoch = UInt64::alloc_input(&mut cs.ns(|| "prev_epoch"), || Ok(&f_out.borrow().prev_epoch))?;
        Ok(SingleStepUpdateProofGadget{
            ssavd_pp,
            history_tree_pp,
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
SingleStepUpdateProofGadget<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, ConstraintF>,
        ConstraintF: PrimeField,
{
    //TODO: Should be able to reuse this for recursive solution
    //TODO: Don't need conditional is_genesis checks for aggregation solution
    pub fn conditional_check_single_step_with_history_update<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
        condition: &Boolean,
    ) -> Result<(), SynthesisError> {
        SSAVDGadget::conditional_check_update_proof(
            &mut cs.ns(|| "check_ssavd_update_proof"),
            &self.ssavd_pp,
            &self.prev_ssavd_digest,
            &self.new_ssavd_digest,
            &self.ssavd_proof,
            condition,
        )?;
        let history_tree_leaf_default = <Vec<UInt8>>::alloc_constant(&mut cs.ns(|| "history_tree_default"), <[u8; 32]>::default())?;
        let prev_history_tree_digest = self.history_tree_proof.check_calc_root(
            &mut cs.ns(|| "calc_prev_history_tree_digest"),
            &history_tree_leaf_default,
            &self.prev_epoch,
            &self.history_tree_pp,
        )?;
        let calc_prev_digest = hash_to_final_digest_gadget::<_, SSAVD, SSAVDGadget, HTParams::H, HGadget, ConstraintF>(
            &mut cs.ns(|| "calc_prev_digest"),
            &self.history_tree_pp,
            &self.prev_ssavd_digest,
            &prev_history_tree_digest,
            &self.prev_epoch,
        )?;
        self.prev_digest.conditional_enforce_equal(
            &mut cs.ns(|| "check_prev_digest"),
            &calc_prev_digest,
            condition,
        )?;
        let history_tree_prev_ssavd_digest_leaf = self.prev_ssavd_digest.to_bytes(&mut cs.ns(|| "prev_ssavd_digest_to_bytes"))?;
        let new_history_tree_digest = self.history_tree_proof.check_calc_root(
            &mut cs.ns(|| "calc_new_history_tree_digest"),
            &history_tree_prev_ssavd_digest_leaf,
            &self.prev_epoch,
            &self.history_tree_pp,
        )?;
        let new_epoch = UInt64::addmany(
            &mut cs.ns(|| "calc_new_epoch"),
            &[self.prev_epoch.clone(), UInt64::constant(1)],
        )?;
        let calc_new_digest = hash_to_final_digest_gadget::<_, SSAVD, SSAVDGadget, HTParams::H, HGadget, ConstraintF>(
            &mut cs.ns(|| "calc_new_digest"),
            &self.history_tree_pp,
            &self.new_ssavd_digest,
            &new_history_tree_digest,
            &new_epoch,
        )?;
        self.new_digest.conditional_enforce_equal(
            &mut cs.ns(|| "check_new_digest"),
            &calc_new_digest,
            condition,
        )?;
        Ok(())
    }
}


pub fn hash_to_final_digest_gadget<CS, SSAVD, SSAVDGadget, H, HGadget, ConstraintF>(
    mut cs: CS,
    parameters: &HGadget::ParametersGadget,
    ssavd_digest: &SSAVDGadget::DigestGadget,
    history_tree_digest: &HGadget::OutputGadget,
    epoch: &UInt64,
) -> Result<HGadget::OutputGadget, SynthesisError>
    where
        CS: ConstraintSystem<ConstraintF>,
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        H: FixedLengthCRH,
        HGadget: FixedLengthCRHGadget<H, ConstraintF>,
        ConstraintF: Field,
{
    // Hash together digests
    let mut buffer1 = ssavd_digest.to_bytes(&mut cs.ns(|| "ssavd_digest_to_bytes"))?;
    buffer1.extend_from_slice(&history_tree_digest.to_bytes(&mut cs.ns(|| "history_tree_digest_to_bytes"))?);
    buffer1.resize(H::INPUT_SIZE_BITS / 8, UInt8::constant(0u8));
    let digests_hash = HGadget::check_evaluation_gadget(
        &mut cs.ns(|| "hash_together_digests"), parameters, &buffer1)?;

    // Note: to_bytes must provide little endian repr of u64 to match fn hash_to_final_digest
    let mut buffer2 = epoch.to_bytes(&mut cs.ns(|| "epoch_to_bytes"))?;
    buffer2.extend_from_slice(&digests_hash.to_bytes(&mut cs.ns(|| "digests_hash_to_bytes"))?);
    buffer2.resize(H::INPUT_SIZE_BITS / 8, UInt8::constant(0u8));
    HGadget::check_evaluation_gadget(
        &mut cs.ns(|| "hash_together_epoch"), parameters, &buffer2)
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
        const MAX_UPDATE_BATCH_SIZE: u64 = 4;
        const MAX_OPEN_ADDRESSING_PROBES: u8 = 2;
        type MerkleTreeParameters = MerkleTreeTestParameters;
    }

    type TestMerkleTreeAVD = MerkleTreeAVD<MerkleTreeAVDTestParameters>;
    type TestMerkleTreeAVDGadget = MerkleTreeAVDGadget<MerkleTreeAVDTestParameters, HG, Fq>;
    type TestAVDWithHistory = SingleStepAVDWithHistory<TestMerkleTreeAVD, MerkleTreeTestParameters>;
    type TestHistoryUpdateGadget = SingleStepUpdateProofGadget<
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

        let mut cs = TestConstraintSystem::<Fq>::new();

        // Allocate proof variables
        let proof_var = TestHistoryUpdateGadget::alloc(
            &mut cs.ns(|| "alloc_proof"),
            || Ok(proof),
        )
            .unwrap();

        proof_var.conditional_check_single_step_with_history_update(
            &mut cs.ns(|| "check_update_proof"),
            &Boolean::constant(true),
        ).unwrap();

        assert!(cs.is_satisfied());
    }
}
