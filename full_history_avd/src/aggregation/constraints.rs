use single_step_avd::{
    SingleStepAVD,
    constraints::SingleStepAVDGadget,
};
use crypto_primitives::sparse_merkle_tree::{
    MerkleTreeParameters,
    constraints::MerkleTreePathGadget,
};

use algebra::{
    ToConstraintField,
    fields::{Field, PrimeField},
};
use r1cs_core::{
    ConstraintSynthesizer, ConstraintSystem, SynthesisError,
};
use r1cs_std::{
    alloc::AllocGadget,
    uint64::UInt64,
    boolean::Boolean,
};
use zexe_cp::crh::{FixedLengthCRH, FixedLengthCRHGadget};

use crate::{
    Error,
    history_tree::{
        SingleStepUpdateProof,
        constraints::SingleStepUpdateProofGadget,
    },
};

use std::marker::PhantomData;


pub struct SingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, ConstraintF>,
        ConstraintF: PrimeField,
{
    proof: SingleStepUpdateProof<SSAVD, HTParams>,
    ssavd_pp: SSAVD::PublicParameters,
    history_tree_pp: <HTParams::H as FixedLengthCRH>::Parameters,
    _ssavd_gadget: PhantomData<SSAVDGadget>,
    _hash_gadget: PhantomData<HGadget>,
    _field: PhantomData<ConstraintF>,
}

pub struct SingleStepProofVerifierInput<HTParams: MerkleTreeParameters> {
    prev_digest: <HTParams::H as FixedLengthCRH>::Output,
    new_digest: <HTParams::H as FixedLengthCRH>::Output,
}

impl<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF> ConstraintSynthesizer<ConstraintF> for SingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF>
where
    SSAVD: SingleStepAVD,
    SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
    HTParams: MerkleTreeParameters,
    HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, ConstraintF>,
    ConstraintF: PrimeField,
{
    fn generate_constraints<CS: ConstraintSystem<ConstraintF>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Allocate constants
        let ssavd_pp = SSAVDGadget::PublicParametersGadget::alloc_constant(&mut cs.ns(|| "ssavd_pp"), &self.ssavd_pp)?;
        let history_tree_pp = HGadget::ParametersGadget::alloc_constant(&mut cs.ns(|| "history_tree_pp"), &self.history_tree_pp)?;

        // Allocate public inputs
        let prev_digest = HGadget::OutputGadget::alloc_input(&mut cs.ns(|| "prev_digest"), || Ok(&self.proof.prev_digest))?;
        let new_digest = HGadget::OutputGadget::alloc_input(&mut cs.ns(|| "new_digest"), || Ok(&self.proof.new_digest))?;

        // Allocate witness inputs
        let ssavd_proof = SSAVDGadget::UpdateProofGadget::alloc(&mut cs.ns(|| "ssavd_proof"), || Ok(&self.proof.ssavd_proof))?;
        let history_tree_proof = <MerkleTreePathGadget<HTParams, HGadget, ConstraintF>>::alloc(&mut cs.ns(|| "history_tree_proof"), || Ok(&self.proof.history_tree_proof))?;
        let prev_ssavd_digest = SSAVDGadget::DigestGadget::alloc(&mut cs.ns(|| "prev_ssavd_digest"), || Ok(&self.proof.prev_ssavd_digest))?;
        let new_ssavd_digest = SSAVDGadget::DigestGadget::alloc(&mut cs.ns(|| "new_ssavd_digest"), || Ok(&self.proof.new_ssavd_digest))?;
        let prev_epoch = UInt64::alloc(&mut cs.ns(|| "prev_epoch"), || Ok(&self.proof.prev_epoch))?;

        // Check update proof
        let proof_gadget = SingleStepUpdateProofGadget::<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF>{
            ssavd_proof,
            history_tree_proof,
            prev_ssavd_digest,
            new_ssavd_digest,
            prev_digest,
            new_digest,
            prev_epoch,
        };
        proof_gadget.conditional_check_single_step_with_history_update(
            &mut cs.ns(|| "check_ssavd_update_proof_with_history"),
            &ssavd_pp,
            &history_tree_pp,
            &Boolean::constant(true),
        )?;
        Ok(())
    }
}

impl<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF> SingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, ConstraintF>,
        ConstraintF: PrimeField,
{
    fn blank(
        ssavd_pp: &SSAVD::PublicParameters,
        history_tree_pp: &<HTParams::H as FixedLengthCRH>::Parameters,
    ) -> Self {
        Self {
            proof: SingleStepUpdateProof::<SSAVD, HTParams>::default(),
            ssavd_pp: ssavd_pp.clone(),
            history_tree_pp: history_tree_pp.clone(),
            _ssavd_gadget: PhantomData ,
            _hash_gadget: PhantomData,
            _field: PhantomData,
        }
    }

    fn new(
        ssavd_pp: &SSAVD::PublicParameters,
        history_tree_pp: &<HTParams::H as FixedLengthCRH>::Parameters,
        proof: SingleStepUpdateProof<SSAVD, HTParams>,
    ) -> Self {
        Self {
            proof: proof,
            ssavd_pp: ssavd_pp.clone(),
            history_tree_pp: history_tree_pp.clone(),
            _ssavd_gadget: PhantomData ,
            _hash_gadget: PhantomData,
            _field: PhantomData,
        }
    }

}

impl <HTParams, ConstraintF> ToConstraintField<ConstraintF> for SingleStepProofVerifierInput<HTParams>
where
HTParams: MerkleTreeParameters,
ConstraintF: Field,
<HTParams::H as FixedLengthCRH>::Output: ToConstraintField<ConstraintF>,
{
    fn to_field_elements(&self) -> Result<Vec<ConstraintF>, Error> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.prev_digest.to_field_elements()?);
        v.extend_from_slice(&self.new_digest.to_field_elements()?);
        Ok(v)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use algebra::{
        ed_on_bls12_381::{EdwardsAffine as JubJub, Fq},
        bls12_381::Bls12_381,
    };
    use r1cs_core::ConstraintSystem;
    use r1cs_std::{ed_on_bls12_381::EdwardsGadget, test_constraint_system::TestConstraintSystem};
    use rand::{rngs::StdRng, SeedableRng};
    use zexe_cp::{
        crh::pedersen::{constraints::PedersenCRHGadget, PedersenCRH, PedersenWindow},
        nizk::{groth16::Groth16, NIZK},
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
        const MAX_UPDATE_BATCH_SIZE: u64 = 1;
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

    type TestCircuit = SingleStepProofCircuit<TestMerkleTreeAVD, TestMerkleTreeAVDGadget, MerkleTreeTestParameters, HG, Fq>;
    type TestVerifierInput = SingleStepProofVerifierInput<MerkleTreeTestParameters>;

    #[test]
    #[ignore] // Expensive test, run with ``cargo test uupdate_and_verify_circuit_test --release -- --ignored``
    fn update_and_verify_circuit_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let (ssavd_pp, crh_pp) = TestAVDWithHistory::setup(&mut rng).unwrap();
        let mut avd = TestAVDWithHistory::new(&mut rng, &ssavd_pp, &crh_pp).unwrap();
        let proof = avd.update(&[1_u8; 32], &[2_u8; 32]).unwrap();
        let verifier_input = TestVerifierInput{
            prev_digest: proof.prev_digest.clone(),
            new_digest: proof.new_digest.clone(),
        };

        // Generate proof circuit
        let blank_circuit = TestCircuit::blank(
            &ssavd_pp,
            &crh_pp,
        );
        let parameters =
            Groth16::<Bls12_381, TestCircuit, TestVerifierInput>::setup(blank_circuit, &mut rng).unwrap();

        // Generate proof
        let circuit_proof = Groth16::<Bls12_381, TestCircuit, TestVerifierInput>::prove(
            &parameters.0,
            TestCircuit::new(&ssavd_pp, &crh_pp, proof),
            &mut rng,
        ).unwrap();

        // Verify proof
        let result = Groth16::<Bls12_381, TestCircuit, TestVerifierInput>::verify(
            &parameters.1,
            &verifier_input,
            &circuit_proof,
        ).unwrap();
        assert!(result);
        let result2 = Groth16::<Bls12_381, TestCircuit, TestVerifierInput>::verify(
            &parameters.1,
            &TestVerifierInput{prev_digest: Default::default(), new_digest: Default::default()},
            &circuit_proof,
        ).unwrap();
        assert!(!result2);
    }
}