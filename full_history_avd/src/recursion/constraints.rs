use single_step_avd::{
    SingleStepAVD,
    constraints::SingleStepAVDGadget,
};
use crypto_primitives::sparse_merkle_tree::{
    MerkleTreeParameters,
    constraints::MerkleTreePathVar,
};
use algebra::{
    ToConstraintField,
    fields::{Field, PrimeField, SquareRootField},
    curves::{CycleEngine, PairingEngine},
};
use groth16::{Proof, VerifyingKey};
use r1cs_core::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
};
use r1cs_std::{
    prelude::*,
    uint64::UInt64,
};
use zexe_cp::{
    crh::{FixedLengthCRH, FixedLengthCRHGadget},
    nizk::{
        NIZK, constraints::NIZKVerifierGadget,
        groth16::{
            constraints::{Groth16VerifierGadget, ProofVar, VerifyingKeyVar},
            Groth16,
        },
    },
};

use crate::{
    Error,
    history_tree::{
        SingleStepAVDWithHistory,
        SingleStepUpdateProof,
        constraints::SingleStepUpdateProofVar,
    },
};

use std::marker::PhantomData;
use rand::rngs::mock::StepRng;
use std::ops::MulAssign;


pub struct InnerSingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E2Gadget>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, <Cycle::E2 as PairingEngine>::Fq>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, <Cycle::E2 as PairingEngine>::Fq>,
        Cycle: CycleEngine,
        E2Gadget: PairingVar<Cycle::E2, <Cycle::E2 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
{
    is_genesis: bool,
    //prev_recursive_proof: Proof<Cycle::E2>,
    //vk: VerifyingKey<Cycle::E2>,
    proof: SingleStepUpdateProof<SSAVD, HTParams>,
    ssavd_pp: SSAVD::PublicParameters,
    history_tree_pp: <HTParams::H as FixedLengthCRH>::Parameters,
    _ssavd_gadget: PhantomData<SSAVDGadget>,
    _hash_gadget: PhantomData<HGadget>,
    _e2_gadget: PhantomData<E2Gadget>,
    _cycle: PhantomData<Cycle>,
}

pub struct InnerSingleStepProofVerifierInput<HTParams: MerkleTreeParameters> {
    pub(crate) new_digest: <HTParams::H as FixedLengthCRH>::Output,
    pub(crate) new_epoch: u64,
}

impl<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E2Gadget> ConstraintSynthesizer<<Cycle::E2 as PairingEngine>::Fq>
for InnerSingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E2Gadget>
where
    SSAVD: SingleStepAVD,
    SSAVDGadget: SingleStepAVDGadget<SSAVD, <Cycle::E2 as PairingEngine>::Fq>,
    HTParams: MerkleTreeParameters,
    HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, <Cycle::E2 as PairingEngine>::Fq>,
    Cycle: CycleEngine,
    E2Gadget: PairingVar<Cycle::E2, <Cycle::E2 as PairingEngine>::Fq>,
    <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
    <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<<Cycle::E2 as PairingEngine>::Fq>,
    ) -> Result<(), SynthesisError> {
        // Allocate constants
        let ssavd_pp = SSAVDGadget::PublicParametersVar::new_constant(
            r1cs_core::ns!(cs, "ssavd_pp"),
            &self.ssavd_pp,
        )?;
        let history_tree_pp = HGadget::ParametersVar::new_constant(
            r1cs_core::ns!(cs, "history_tree_pp"),
            &self.history_tree_pp,
        )?;
        //let vk_gadget = VerifyingKeyVar::<Cycle::E2, E2Gadget>::new_constant(
        //    r1cs_core::ns!(cs, "vk"),
        //    &self.vk,
        //)?;
        let genesis_digest = HGadget::OutputVar::new_constant(
            r1cs_core::ns!(cs, "genesis_digest"),
            &SingleStepAVDWithHistory::<SSAVD, HTParams>::new(
                &mut StepRng::new(1, 1),
                &self.ssavd_pp,
                &self.history_tree_pp,
            ).unwrap().digest().digest,
        )?;

        // Allocate public inputs
        let new_digest = HGadget::OutputVar::new_input(
            r1cs_core::ns!(cs, "new_digest"),
            || Ok(&self.proof.new_digest),
        )?;
        let new_epoch = UInt64::new_input(
            r1cs_core::ns!(cs, "new_epoch"),
            || Ok(if self.is_genesis { 0 } else { self.proof.prev_epoch + 1 }),
        )?;

        // Allocate witness inputs
        let prev_digest = HGadget::OutputVar::new_witness(
            r1cs_core::ns!(cs, "prev_digest"),
            || Ok(&self.proof.prev_digest),
        )?;
        let ssavd_proof = SSAVDGadget::UpdateProofVar::new_witness(
            r1cs_core::ns!(cs, "ssavd_proof"),
            || Ok(&self.proof.ssavd_proof),
        )?;
        let history_tree_proof = <MerkleTreePathVar<HTParams, HGadget, _>>::new_witness(
            r1cs_core::ns!(cs, "history_tree_proof"),
            || Ok(&self.proof.history_tree_proof),
        )?;
        let prev_ssavd_digest = SSAVDGadget::DigestVar::new_witness(
            r1cs_core::ns!(cs, "prev_ssavd_digest"),
            || Ok(&self.proof.prev_ssavd_digest),
        )?;
        let new_ssavd_digest = SSAVDGadget::DigestVar::new_witness(
            r1cs_core::ns!(cs, "new_ssavd_digest"),
            || Ok(&self.proof.new_ssavd_digest),
        )?;
        let prev_epoch = UInt64::new_witness(
            r1cs_core::ns!(cs, "prev_epoch"),
            || Ok(&self.proof.prev_epoch),
        )?;
        //let prev_recursive_proof = ProofVar::<Cycle::E2, E2Gadget>::new_witness(
        //    cs.clone(),
        //    || Ok(&self.prev_recursive_proof),
        //)?;

        // Check if genesis digest
        let is_genesis = new_digest.is_eq(&genesis_digest)?;
        new_epoch.conditional_enforce_equal(&UInt64::constant(0), &is_genesis)?;

        // Else check update proof
        new_epoch.conditional_enforce_equal(
            &UInt64::addmany(&[prev_epoch.clone(), UInt64::constant(1)])?,
            &is_genesis.not(),
        )?;
        let proof_gadget = SingleStepUpdateProofVar::<SSAVD, SSAVDGadget, HTParams, HGadget, _>{
            ssavd_proof,
            history_tree_proof,
            prev_ssavd_digest,
            new_ssavd_digest,
            prev_digest,
            new_digest,
            prev_epoch,
        };
        //TODO: verify previous circuit proof
        proof_gadget.conditional_check_single_step_with_history_update(
            &ssavd_pp,
            &history_tree_pp,
            &is_genesis.not(),
        )?;
        Ok(())
    }
}

impl<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E2Gadget> InnerSingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E2Gadget>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, <Cycle::E2 as PairingEngine>::Fq>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, <Cycle::E2 as PairingEngine>::Fq>,
        Cycle: CycleEngine,
        E2Gadget: PairingVar<Cycle::E2, <Cycle::E2 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
{
    pub fn blank(
        ssavd_pp: &SSAVD::PublicParameters,
        history_tree_pp: &<HTParams::H as FixedLengthCRH>::Parameters,
        //vk: VerifyingKey<Cycle::E2>,
    ) -> Self {
        Self {
            is_genesis: Default::default(),
            proof: SingleStepUpdateProof::<SSAVD, HTParams>::default(),
            ssavd_pp: ssavd_pp.clone(),
            history_tree_pp: history_tree_pp.clone(),
            _ssavd_gadget: PhantomData ,
            _hash_gadget: PhantomData,
            _e2_gadget: PhantomData,
            _cycle: PhantomData,
        }
    }

    pub fn new(
        is_genesis: bool,
        ssavd_pp: &SSAVD::PublicParameters,
        history_tree_pp: &<HTParams::H as FixedLengthCRH>::Parameters,
        proof: SingleStepUpdateProof<SSAVD, HTParams>,
    ) -> Self {
        Self {
            is_genesis,
            proof: proof,
            ssavd_pp: ssavd_pp.clone(),
            history_tree_pp: history_tree_pp.clone(),
            _ssavd_gadget: PhantomData ,
            _hash_gadget: PhantomData,
            _e2_gadget: PhantomData,
            _cycle: PhantomData,
        }
    }

}

impl <HTParams, ConstraintF> ToConstraintField<ConstraintF> for InnerSingleStepProofVerifierInput<HTParams>
where
HTParams: MerkleTreeParameters,
ConstraintF: PrimeField,
<HTParams::H as FixedLengthCRH>::Output: ToConstraintField<ConstraintF>,
{
    fn to_field_elements(&self) -> Result<Vec<ConstraintF>, Error> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.new_digest.to_field_elements()?);
        println!("digest field elements: {}", v.len());
        let mut new_epoch_as_le_bits = Vec::with_capacity(64);
        let mut tmp = self.new_epoch;
        for _ in 0..64 {
            if tmp & 1 == 1 {
                new_epoch_as_le_bits.push(<ConstraintF>::from(true as u8))
            } else {
                new_epoch_as_le_bits.push(<ConstraintF>::from(false as u8))
            }
            tmp >>= 1;
        }
        v.extend_from_slice(&new_epoch_as_le_bits);
        println!("epoch field elements: {}", v.len());
        Ok(v)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use algebra::{
        ed_on_mnt4_298::{EdwardsProjective, Fq},
        mnt4_298::MNT4_298,
        mnt6_298::MNT6_298,
    };
    use r1cs_core::ConstraintSystem;
    use r1cs_std::{
        ed_on_mnt4_298::EdwardsVar,
        mnt4_298::PairingVar as MNT4PairingVar,
        mnt6_298::PairingVar as MNT6PairingVar,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use zexe_cp::{
        crh::pedersen::{constraints::CRHGadget, CRH, Window},
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
    use std::time::Instant;

    #[derive(Clone, Copy, Debug)]
    pub struct MNT298Cycle;

    impl CycleEngine for MNT298Cycle {
        type E1 = MNT4_298;
        type E2 = MNT6_298;
    }

    #[derive(Clone)]
    pub struct Window4x256;

    impl Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = CRH<EdwardsProjective, Window4x256>;
    type HG = CRHGadget<EdwardsProjective, EdwardsVar, Window4x256>;

    #[derive(Clone)]
    pub struct MerkleTreeTestParameters;

    impl MerkleTreeParameters for MerkleTreeTestParameters {
        const DEPTH: MerkleDepth = 4;
        type H = H;
    }

    #[derive(Clone)]
    pub struct MerkleTreeAVDTestParameters;

    impl MerkleTreeAVDParameters for MerkleTreeAVDTestParameters {
        const MAX_UPDATE_BATCH_SIZE: u64 = 3;
        const MAX_OPEN_ADDRESSING_PROBES: u8 = 2;
        type MerkleTreeParameters = MerkleTreeTestParameters;
    }

    type TestMerkleTreeAVD = MerkleTreeAVD<MerkleTreeAVDTestParameters>;
    type TestMerkleTreeAVDGadget = MerkleTreeAVDGadget<MerkleTreeAVDTestParameters, HG, Fq>;
    type TestAVDWithHistory = SingleStepAVDWithHistory<TestMerkleTreeAVD, MerkleTreeTestParameters>;

    type TestInnerCircuit = InnerSingleStepProofCircuit<TestMerkleTreeAVD, TestMerkleTreeAVDGadget, MerkleTreeTestParameters, HG, MNT298Cycle, MNT6PairingVar>;
    type TestInnerVerifierInput = InnerSingleStepProofVerifierInput<MerkleTreeTestParameters>;

    #[test]
    #[ignore] // Expensive test, run with ``cargo test update_and_verify_inner_circuit_test --release -- --ignored --nocapture``
    fn update_and_verify_inner_circuit_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let (ssavd_pp, crh_pp) = TestAVDWithHistory::setup(&mut rng).unwrap();
        let mut avd = TestAVDWithHistory::new(&mut rng, &ssavd_pp, &crh_pp).unwrap();
        let proof = avd.batch_update(
            &vec![
                ([1_u8; 32], [2_u8; 32]),
                ([11_u8; 32], [12_u8; 32]),
                ([21_u8; 32], [22_u8; 32]),
            ]).unwrap();
        let verifier_input = TestInnerVerifierInput{
            new_digest: proof.new_digest.clone(),
            new_epoch: 1,
        };

        // Generate proof circuit
        println!("Setting up proof with tree height: {}, and number of updates: {}...",
                 MerkleTreeTestParameters::DEPTH,
                 MerkleTreeAVDTestParameters::MAX_UPDATE_BATCH_SIZE,
        );
        let start = Instant::now();
        let blank_circuit = TestInnerCircuit::blank(
            &ssavd_pp,
            &crh_pp,
        );
        let parameters =
            Groth16::<MNT4_298, TestInnerCircuit, TestInnerVerifierInput>::setup(blank_circuit, &mut rng).unwrap();
        println!("PreparedVK len: {}", parameters.1.gamma_abc_g1.len());
        let bench = start.elapsed().as_secs();
        println!("\t setup time: {} s", bench);


        // Generate proof
        println!("Generating proof...");
        let start = Instant::now();
        let circuit_proof = Groth16::<MNT4_298, TestInnerCircuit, TestInnerVerifierInput>::prove(
            &parameters.0,
            TestInnerCircuit::new(false, &ssavd_pp, &crh_pp, proof),
            &mut rng,
        ).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t proving time: {} s", bench);

        // Verify proof
        let result = Groth16::<MNT4_298, TestInnerCircuit, TestInnerVerifierInput>::verify(
            &parameters.1,
            &verifier_input,
            &circuit_proof,
        ).unwrap();
        assert!(result);
        let result2 = Groth16::<MNT4_298, TestInnerCircuit, TestInnerVerifierInput>::verify(
            &parameters.1,
            &TestInnerVerifierInput{new_digest: Default::default(), new_epoch: 1 },
            &circuit_proof,
        ).unwrap();
        assert!(!result2);

        // Count constraints
        let blank_circuit_constraint_counter = TestInnerCircuit::blank(
            &ssavd_pp,
            &crh_pp,
        );
        let cs = ConstraintSystem::<Fq>::new_ref();
        blank_circuit_constraint_counter.generate_constraints(cs.clone()).unwrap();
        println!("\t number of constraints: {}", cs.num_constraints());
    }
}
