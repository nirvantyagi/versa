use single_step_avd::{
    SingleStepAVD,
    constraints::SingleStepAVDGadget,
};

use ark_ff::{
    ToConstraintField,
    fields::{PrimeField},
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
};
use ark_r1cs_std::{
    prelude::*,
};

use std::marker::PhantomData;


pub struct SingleStepProofCircuit<SSAVD, SSAVDGadget, ConstraintF>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        ConstraintF: PrimeField,
{
    proof: SSAVD::UpdateProof,
    public_input: SingleStepProofVerifierInput<SSAVD>,
    ssavd_pp: SSAVD::PublicParameters,
    _ssavd_gadget: PhantomData<SSAVDGadget>,
    _field: PhantomData<ConstraintF>,
}

pub struct SingleStepProofVerifierInput<SSAVD: SingleStepAVD> {
    pub(crate) prev_digest: SSAVD::Digest,
    pub(crate) new_digest: SSAVD::Digest,
}

impl<SSAVD, SSAVDGadget, ConstraintF> ConstraintSynthesizer<ConstraintF> for SingleStepProofCircuit<SSAVD, SSAVDGadget, ConstraintF>
where
    SSAVD: SingleStepAVD,
    SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
    ConstraintF: PrimeField,
{
    #[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Allocate constants
        let ssavd_pp = SSAVDGadget::PublicParametersVar::new_constant(
            ark_relations::ns!(cs, "ssavd_pp"),
            &self.ssavd_pp,
        )?;

        // Allocate public inputs
        let prev_digest = SSAVDGadget::DigestVar::new_input(
            ark_relations::ns!(cs, "prev_digest"),
            || Ok(&self.public_input.prev_digest),
        )?;
        let new_digest = SSAVDGadget::DigestVar::new_input(
            ark_relations::ns!(cs, "new_digest"),
            || Ok(&self.public_input.new_digest),
        )?;

        // Allocate witness inputs
        let ssavd_proof = SSAVDGadget::UpdateProofVar::new_witness(
            ark_relations::ns!(cs, "ssavd_proof"),
            || Ok(&self.proof),
        )?;

        // Check update proof
        SSAVDGadget::check_update_proof(
            &ssavd_pp,
            &prev_digest,
            &new_digest,
            &ssavd_proof,
        )?;
        Ok(())
    }
}

impl<SSAVD, SSAVDGadget, ConstraintF> SingleStepProofCircuit<SSAVD, SSAVDGadget, ConstraintF>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        ConstraintF: PrimeField,
{
    pub fn blank(
        ssavd_pp: &SSAVD::PublicParameters,
    ) -> Self {
        Self {
            proof: Default::default(),
            public_input: Default::default(),
            ssavd_pp: ssavd_pp.clone(),
            _ssavd_gadget: PhantomData ,
            _field: PhantomData,
        }
    }

    pub fn new(
        ssavd_pp: &SSAVD::PublicParameters,
        proof: SSAVD::UpdateProof,
        public_input: SingleStepProofVerifierInput<SSAVD>,
    ) -> Self {
        Self {
            proof: proof,
            public_input: public_input,
            ssavd_pp: ssavd_pp.clone(),
            _ssavd_gadget: PhantomData ,
            _field: PhantomData,
        }
    }

}

impl <SSAVD, ConstraintF> ToConstraintField<ConstraintF> for SingleStepProofVerifierInput<SSAVD>
where
SSAVD: SingleStepAVD,
ConstraintF: PrimeField,
SSAVD::Digest: ToConstraintField<ConstraintF>,
{
    fn to_field_elements(&self) -> Option<Vec<ConstraintF>> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.prev_digest.to_field_elements().unwrap_or_default());
        v.extend_from_slice(&self.new_digest.to_field_elements().unwrap_or_default());
        Some(v)
    }
}

impl <SSAVD: SingleStepAVD> Clone for SingleStepProofVerifierInput<SSAVD> {
    fn clone(&self) -> Self {
        Self {
            prev_digest: self.prev_digest.clone(),
            new_digest: self.new_digest.clone(),
        }
    }
}

impl <SSAVD: SingleStepAVD> Default for SingleStepProofVerifierInput<SSAVD> {
    fn default() -> Self {
        Self {
            prev_digest: Default::default(),
            new_digest: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::{EdwardsProjective as JubJub, Fq, constraints::EdwardsVar};
    use ark_bls12_381::Bls12_381;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintLayer};
    use rand::{rngs::StdRng, SeedableRng};
    use ark_crypto_primitives::{
        crh::pedersen::{constraints::CRHGadget, CRH, Window},
        snark::SNARK,
    };
    use ark_groth16::Groth16;
    use tracing_subscriber::layer::SubscriberExt;

    use single_step_avd::{
        merkle_tree_avd::{
            MerkleTreeAVDParameters,
            MerkleTreeAVD,
            constraints::MerkleTreeAVDGadget,
        },
        rsa_avd::{
            RsaAVD, constraints::RsaAVDGadget,
        },
    };
    use crypto_primitives::sparse_merkle_tree::{MerkleDepth, MerkleTreeParameters};
    use rsa::{
        bignat::constraints::BigNatCircuitParams,
        kvac::RsaKVACParams,
        poker::{PoKERParams},
        hog::{RsaGroupParams},
        hash::{
            HasherFromDigest, PoseidonHasher, constraints::PoseidonHasherGadget,
        },
    };

    use std::time::Instant;

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
        const MAX_UPDATE_BATCH_SIZE: u64 = 3;
        const MAX_OPEN_ADDRESSING_PROBES: u8 = 2;
        type MerkleTreeParameters = MerkleTreeTestParameters;
    }

    type TestMerkleTreeAVD = MerkleTreeAVD<MerkleTreeAVDTestParameters>;
    type TestMerkleTreeAVDGadget = MerkleTreeAVDGadget<MerkleTreeAVDTestParameters, HG, Fq>;

    type TestCircuit = SingleStepProofCircuit<TestMerkleTreeAVD, TestMerkleTreeAVDGadget, Fq>;
    type TestVerifierInput = SingleStepProofVerifierInput<TestMerkleTreeAVD>;


    // Parameters for RSA AVD
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestRsa64Params;
    impl RsaGroupParams for TestRsa64Params {
        const RAW_G: usize = 2;
        const RAW_M: &'static str = "17839761582542106619";
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNatTestParams;
    impl BigNatCircuitParams for BigNatTestParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 2;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestPokerParams;
    impl PoKERParams for TestPokerParams {
        const HASH_TO_PRIME_ENTROPY: usize = 32;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestKVACParams;
    impl RsaKVACParams for TestKVACParams {
        const KEY_LEN: usize = 64;
        const VALUE_LEN: usize = 64;
        const PRIME_LEN: usize = 72;
        type RsaGroupParams = TestRsa64Params;
        type PoKERParams = TestPokerParams;
    }

    pub type PoseidonH = PoseidonHasher<Fq>;
    pub type PoseidonHG = PoseidonHasherGadget<Fq>;

    pub type TestRsaAVD = RsaAVD<
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        PoseidonH,
        BigNatTestParams,
    >;

    pub type TestRsaAVDGadget = RsaAVDGadget<
        Fq,
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        PoseidonH,
        PoseidonHG,
        BigNatTestParams,
    >;

    type TestRsaCircuit = SingleStepProofCircuit<TestRsaAVD, TestRsaAVDGadget, Fq>;
    type TestRsaVerifierInput = SingleStepProofVerifierInput<TestRsaAVD>;

    fn u8_to_array(n: u8) -> [u8; 32] {
        let mut arr = [0_u8; 32];
        arr[31] = n;
        arr
    }

    #[test]
    #[ignore] // Expensive test, run with ``cargo test mt_update_and_verify_circuit_test --release -- --ignored --nocapture``
    fn mt_aggr_update_and_verify_circuit_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let ssavd_pp = TestMerkleTreeAVD::setup(&mut rng).unwrap();
        let mut avd = TestMerkleTreeAVD::new(&mut rng, &ssavd_pp).unwrap();
        let d0 = avd.digest().unwrap();
        let (d1, proof) = avd.batch_update(
            &vec![
                //([1_u8; 32], [2_u8; 32]),
                //([11_u8; 32], [12_u8; 32]),
                //([21_u8; 32], [22_u8; 32]),
                (u8_to_array(1), u8_to_array(2)),
                (u8_to_array(11), u8_to_array(12)),
                (u8_to_array(21), u8_to_array(22)),
            ]).unwrap();
        let verifier_input = TestVerifierInput{
            prev_digest: d0.clone(),
            new_digest: d1.clone(),
        };

        // Generate proof circuit
        println!("Setting up proof with tree height: {}, and number of updates: {}...",
                 MerkleTreeTestParameters::DEPTH,
                 MerkleTreeAVDTestParameters::MAX_UPDATE_BATCH_SIZE,
        );
        let start = Instant::now();
        let blank_circuit = TestCircuit::blank(
            &ssavd_pp,
        );
        let parameters =
            Groth16::<Bls12_381>::circuit_specific_setup::<TestCircuit, _>(blank_circuit, &mut rng).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t setup time: {} s", bench);


        // Generate proof
        println!("Generating proof...");
        let start = Instant::now();
        let circuit_proof = Groth16::<Bls12_381>::prove(
            &parameters.0,
            TestCircuit::new(&ssavd_pp, proof, verifier_input.clone()),
            &mut rng,
        ).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t proving time: {} s", bench);

        // Verify proof
        let result = Groth16::<Bls12_381>::verify_with_processed_vk(
            &Groth16::process_vk(&parameters.1).unwrap(),
            &verifier_input.to_field_elements().unwrap(),
            &circuit_proof,
        ).unwrap();
        assert!(result);
        let result2 = Groth16::<Bls12_381>::verify_with_processed_vk(
            &Groth16::process_vk(&parameters.1).unwrap(),
            &TestVerifierInput{prev_digest: Default::default(), new_digest: Default::default()}.to_field_elements().unwrap(),
            &circuit_proof,
        ).unwrap();
        assert!(!result2);

        // Count constraints
        let blank_circuit_constraint_counter = TestCircuit::blank(
            &ssavd_pp,
        );
        let cs = ConstraintSystem::<Fq>::new_ref();
        blank_circuit_constraint_counter.generate_constraints(cs.clone()).unwrap();
        println!("\t number of constraints: {}", cs.num_constraints());
    }

    #[test]
    #[ignore] // Expensive test, run with ``cargo test rsa_aggr_update_and_verify_circuit_test --release -- --ignored --nocapture``
    fn rsa_aggr_update_and_verify_circuit_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let ssavd_pp = TestRsaAVD::setup(&mut rng).unwrap();
        let mut avd = TestRsaAVD::new(&mut rng, &ssavd_pp).unwrap();
        let d0 = avd.digest().unwrap();
        let (d1, proof) = avd.batch_update(
            &vec![
                (u8_to_array(1), u8_to_array(2)),
                (u8_to_array(11), u8_to_array(12)),
                (u8_to_array(21), u8_to_array(22)),
            ]).unwrap();
        let verifier_input = TestRsaVerifierInput{
            prev_digest: d0.clone(),
            new_digest: d1.clone(),
        };

        // Generate proof circuit
        let mut layer = ConstraintLayer::default();
        layer.mode = ark_relations::r1cs::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let cs = ConstraintSystem::<Fq>::new_ref();
            TestRsaCircuit::new(&ssavd_pp, proof.clone(), verifier_input.clone()).generate_constraints(cs.clone()).unwrap();
            println!("Constraints satisfied: {}", cs.is_satisfied().unwrap());
            if !cs.is_satisfied().unwrap() {
                println!("=========================================================");
                println!("Unsatisfied constraints:");
                println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
                println!("=========================================================");
            }
            assert!(cs.is_satisfied().unwrap());
        });

        println!("Generating parameters...");
        let start = Instant::now();
        let blank_circuit = TestRsaCircuit::blank(
            &ssavd_pp,
        );
        let parameters = Groth16::<Bls12_381>::circuit_specific_setup(blank_circuit, &mut rng).unwrap();
        //println!("Verifying key length: {}", parameters.1.gamma_abc_g1.len());
        let bench = start.elapsed().as_secs();
        println!("\t setup time: {} s", bench);


        // Generate proof
        println!("Generating proof...");
        let start = Instant::now();
        let circuit_proof = Groth16::<Bls12_381>::prove(
            &parameters.0,
            TestRsaCircuit::new(&ssavd_pp, proof, verifier_input.clone()),
            &mut rng,
        ).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t proving time: {} s", bench);

        // Verify proof
        let result = Groth16::<Bls12_381>::verify_with_processed_vk(
            &Groth16::process_vk(&parameters.1).unwrap(),
            &verifier_input.to_field_elements().unwrap(),
            &circuit_proof,
        ).unwrap();
        assert!(result);
        let result2 = Groth16::<Bls12_381>::verify_with_processed_vk(
            &Groth16::process_vk(&parameters.1).unwrap(),
            &TestRsaVerifierInput::default().to_field_elements().unwrap(),
            &circuit_proof,
        ).unwrap();
        assert!(!result2);

        // Count constraints
        let blank_circuit_constraint_counter = TestRsaCircuit::blank(
            &ssavd_pp,
        );
        let cs = ConstraintSystem::<Fq>::new_ref();
        blank_circuit_constraint_counter.generate_constraints(cs.clone()).unwrap();
        println!("\t number of constraints: {}", cs.num_constraints());
    }


}
