#[cfg(test)]
mod tests {
    use ark_ff::{UniformRand};
    use ark_ed_on_bls12_381::{Fq};
    use ark_bls12_381::Bls12_381;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintLayer, ConstraintSynthesizer, SynthesisError, ConstraintSystemRef};
    use ark_r1cs_std::{
        prelude::*,
        fields::fp::FpVar,
    };
    use ark_crypto_primitives::{snark::SNARK};
    use ark_groth16::Groth16;
    use tracing_subscriber::layer::SubscriberExt;
    use rand::{rngs::StdRng, SeedableRng};
    use rsa::{
        bignat::{BigNat, constraints::{BigNatCircuitParams, BigNatVar}},
        hog::{
            RsaGroupParams, RsaHiddenOrderGroup,
        },
        hash::{
            HasherFromDigest,
            PoseidonHasher, constraints::PoseidonHasherGadget,
            hash_to_prime::{
                hash_to_pocklington_prime,
                constraints::{
                    PocklingtonCertificateVar,
                    conditional_check_hash_to_pocklington_prime,
                }
            },
        },
        poker::{
            PoKERParams, PoKER, Statement, Witness,
            constraints::{ProofVar, StatementVar, conditional_enforce_poker_valid},
        },
        kvac::{
            RsaKVACParams,
            store::{
                mem_store::RsaKVACMemStore,
            },
        },
    };
    use single_step_avd::{
        SingleStepAVD,
        constraints::SingleStepAVDGadget,
        rsa_avd::{
            RsaAVD,
            store::{
                mem_store::RSAAVDMemStore,
            },
            constraints::{RsaAVDGadget, DigestVar, UpdateProofVar, EmptyVar},
        },
    };

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

    pub type H = PoseidonHasher<Fq>;
    pub type HG = PoseidonHasherGadget<Fq>;
    pub type Hog = RsaHiddenOrderGroup<TestRsa64Params>;
    pub type Poker = PoKER<TestPokerParams, TestRsa64Params, H, BigNatTestParams>;

    pub type TestKvacStore = RsaKVACMemStore<
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        H,
        BigNatTestParams,
    >;
    pub type RSAAVDStore = RSAAVDMemStore<
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        H,
        BigNatTestParams,
        TestKvacStore,
    >;
    pub type TestRsaAVD = RsaAVD<
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        H,
        BigNatTestParams,
        TestKvacStore,
        RSAAVDStore,
    >;
    pub type TestRsaAVDGadget = RsaAVDGadget<
        Fq,
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        H,
        HG,
        BigNatTestParams,
        TestKvacStore,
        RSAAVDStore,
    >;


    fn groth16_test(circuit: impl ConstraintSynthesizer<Fq> + Clone) {
        let mut layer = ConstraintLayer::default();
        layer.mode = ark_relations::r1cs::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let cs = ConstraintSystem::<Fq>::new_ref();
            circuit.clone().generate_constraints(cs.clone()).unwrap();

            if !cs.is_satisfied().unwrap() {
                println!("=========================================================");
                println!("Unsatisfied constraints:");
                println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
                println!("=========================================================");
            }
            assert!(cs.is_satisfied().unwrap());
        });

        println!("Circuit setup");
        let mut rng = StdRng::seed_from_u64(0u64);
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            circuit.clone(),
            &mut rng,
        ).unwrap();

        println!("Proof generation");
        let proof = Groth16::<Bls12_381>::prove(
            &pk, circuit.clone(), &mut rng,
        ).unwrap();

        let b = Groth16::<Bls12_381>::verify(
            &vk, &vec![], &proof,
        ).unwrap();
        assert!(b);
    }


    #[derive(Clone)]
    pub struct RsaAVDCircuit;

    fn u8_to_array(n: u8) -> [u8; 32] {
        let mut arr = [0_u8; 32];
        arr[31] = n;
        arr
    }

    impl ConstraintSynthesizer<Fq> for RsaAVDCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
            let mut rng = StdRng::seed_from_u64(0_u64);
            let crh_pp = TestRsaAVD::setup(&mut rng).unwrap();
            let mut avd = TestRsaAVD::new(&mut rng, &crh_pp).unwrap();
            let digest_0 = avd.digest().unwrap();
            let (digest_1, proof) = avd.batch_update(&vec![
                (u8_to_array(1), u8_to_array(2)),
                (u8_to_array(11), u8_to_array(12)),
                (u8_to_array(21), u8_to_array(22)),
            ]).unwrap();
            let prev_digest_var = <DigestVar<Fq, TestKVACParams, BigNatTestParams>>::new_witness(
                cs.clone(),
                || Ok(&digest_0),
            ).unwrap();
            let new_digest_var = <DigestVar<Fq, TestKVACParams, BigNatTestParams>>::new_witness(
                cs.clone(),
                || Ok(&digest_1),
            ).unwrap();
            let proof_var = <UpdateProofVar<Fq, TestKVACParams, BigNatTestParams, H, HG>>::new_witness(
                cs.clone(),
                || Ok(&proof),
            ).unwrap();
            let pp_var = EmptyVar::new_constant(cs.clone(), &()).unwrap();
            TestRsaAVDGadget::conditional_check_update_proof(
                &pp_var,
                &prev_digest_var,
                &new_digest_var,
                &proof_var,
                &Boolean::TRUE,
            ).unwrap();
            println!("Num_witnesses: {}", cs.num_witness_variables());
            println!("Num_constraints: {}", cs.num_constraints());
            Ok(())
        }
    }

    #[test]
    fn groth16_rsa_avd_test() {
        groth16_test(RsaAVDCircuit);
    }


    #[derive(Clone)]
    pub struct PokerProofCircuit;

    impl ConstraintSynthesizer<Fq> for PokerProofCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
            let u1 = Hog::from_nat(BigNat::from(20));
            let u2 = Hog::from_nat(BigNat::from(30));
            let a = BigNat::from(40);
            let b = BigNat::from(50);
            let w1 = u1.power(&a).op(&u2.power(&b));
            let w2 = u2.power(&a);
            let x = Statement{u1, u2, w1, w2};
            let w = Witness{a, b};
            let proof = Poker::prove(&x, &w).unwrap();

            let x_var= StatementVar::<Fq, TestRsa64Params, BigNatTestParams>::new_witness(
                ark_relations::ns!(cs, "x"),
                || Ok(&x),
            ).unwrap();
            let proof_var = ProofVar::<Fq, TestRsa64Params, BigNatTestParams, H, HG>::new_witness(
                ark_relations::ns!(cs, "proof"),
                || Ok(&proof),
            ).unwrap();
            conditional_enforce_poker_valid::<Fq, TestPokerParams, _, _, H, HG>(
                cs.clone(),
                &x_var,
                &proof_var,
                &Boolean::TRUE,
            ).unwrap();
            println!("Num_witnesses: {}", cs.num_witness_variables());
            println!("Num_constraints: {}", cs.num_constraints());
            Ok(())
        }
    }

    #[test]
    fn groth16_poker_test() {
        groth16_test(PokerProofCircuit);
    }


    #[derive(Clone)]
    pub struct HashToPrimeCircuit;

    impl ConstraintSynthesizer<Fq> for HashToPrimeCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
            let mut rng = StdRng::seed_from_u64(0u64);
            let input = vec![Fq::rand(&mut rng); 12];
            let h = hash_to_pocklington_prime::<H>(&input, 32).unwrap();
            let inputvar = Vec::<FpVar<Fq>>::new_witness(
                ark_relations::ns!(cs, "input"),
                || Ok(&input[..]),
            ).unwrap();
            let hvar = PocklingtonCertificateVar::<Fq, BigNatTestParams, H, HG>::new_witness(
                ark_relations::ns!(cs, "h"),
                || Ok(&h),
            )?;
            conditional_check_hash_to_pocklington_prime::<H, HG, _, _>(
                cs.clone(),
                &inputvar,
                128,
                &hvar,
                &Boolean::TRUE,
            )?;
            println!("Num_witnesses: {}", cs.num_witness_variables());
            Ok(())
        }
    }

    #[test]
    fn groth16_hash_to_prime_test() {
        groth16_test(HashToPrimeCircuit);
    }


    #[derive(Clone)]
    pub struct BigNatMultModCircuit;

    impl ConstraintSynthesizer<Fq> for BigNatMultModCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
            let mut rng = StdRng::seed_from_u64(0u64);
            let n1 = BigNat::from(u32::rand(&mut rng));
            let n2 = BigNat::from(u32::rand(&mut rng));
            let prod = n1.clone() * n2.clone();
            let n1var = BigNatVar::<Fq, BigNatTestParams>::new_witness(
                ark_relations::ns!(cs, "input"),
                || Ok(&n1),
            ).unwrap();
            let n2var = BigNatVar::<Fq, BigNatTestParams>::new_witness(
                ark_relations::ns!(cs, "input"),
                || Ok(&n2),
            ).unwrap();
            let prodvar = BigNatVar::<Fq, BigNatTestParams>::new_witness(
                ark_relations::ns!(cs, "input"),
                || Ok(&prod),
            ).unwrap();
            let m = BigNatVar::<Fq, BigNatTestParams>::constant(&TestRsa64Params::m()).unwrap();
            let cprod = n1var.mult_mod(&n2var, &m).unwrap();
            prodvar.enforce_equal(&cprod).unwrap();
            Ok(())
        }
    }

    #[test]
    fn groth16_mult_mod_test() {
        groth16_test(BigNatMultModCircuit);
    }


    #[derive(Clone)]
    pub struct BigNatPowModCircuit;

    impl ConstraintSynthesizer<Fq> for BigNatPowModCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
            let n1 = BigNat::from(20);
            let n2 = BigNat::from(0b100100011011);
            let pow = n1.clone().pow_mod(&n2.clone(), &TestRsa64Params::m()).unwrap();
            let n1var = BigNatVar::<Fq, BigNatTestParams>::new_witness(
                ark_relations::ns!(cs, "input"),
                || Ok(&n1),
            ).unwrap();
            let n2var = BigNatVar::<Fq, BigNatTestParams>::new_witness(
                ark_relations::ns!(cs, "input"),
                || Ok(&n2),
            ).unwrap();
            let powvar = BigNatVar::<Fq, BigNatTestParams>::new_witness(
                ark_relations::ns!(cs, "input"),
                || Ok(&pow),
            ).unwrap();
            let m = BigNatVar::<Fq, BigNatTestParams>::constant(&TestRsa64Params::m()).unwrap();
            let cpow = n1var.pow_mod(&n2var, &m, 12).unwrap();
            powvar.enforce_equal(&cpow).unwrap();
            Ok(())
        }
    }


    #[test]
    fn groth16_pow_mod_test() {
        groth16_test(BigNatPowModCircuit);
    }
}
