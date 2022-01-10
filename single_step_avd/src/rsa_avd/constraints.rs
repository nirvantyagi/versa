use ark_ff::{PrimeField};
use ark_relations::r1cs::{SynthesisError, Namespace, ConstraintSystemRef};
use ark_r1cs_std::{
    prelude::*,
};

use crate::{
    constraints::SingleStepAVDGadget,
    rsa_avd::{RsaAVD, DigestWrapper, UpdateProofWrapper, store::RSAAVDStorer}};

use rsa::{
    hog::constraints::RsaHogVar,
    kvac::{store::RsaKVACStorer, RsaKVACParams, Commitment},
    hash::{Hasher, constraints::HasherGadget},
    bignat::{constraints::BigNatCircuitParams},
    poker::constraints::{ProofVar, StatementVar, conditional_enforce_poker_valid},
};

use std::{
    borrow::Borrow,
    marker::PhantomData,
};

#[derive(Clone)]
pub struct DigestVar<ConstraintF: PrimeField, P: RsaKVACParams, C: BigNatCircuitParams> {
    c0: RsaHogVar<ConstraintF, P::RsaGroupParams, C>,
    c1: RsaHogVar<ConstraintF, P::RsaGroupParams, C>,
    _params: PhantomData<P>,
}

impl<ConstraintF: PrimeField, P: RsaKVACParams, C: BigNatCircuitParams> AllocVar<DigestWrapper<P, C>, ConstraintF> for DigestVar<ConstraintF, P, C> {
    fn new_variable<T: Borrow<DigestWrapper<P, C>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let f_out = f()?;
        let c0_var = RsaHogVar::<ConstraintF, P::RsaGroupParams, C>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().digest.c1),
            mode,
        )?;
        let c1_var = RsaHogVar::<ConstraintF, P::RsaGroupParams, C>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().digest.c2),
            mode,
        )?;
        Ok(DigestVar {
            c0: c0_var,
            c1: c1_var,
            _params: PhantomData,
        })
    }
}

impl<ConstraintF: PrimeField, P: RsaKVACParams, C: BigNatCircuitParams> R1CSVar<ConstraintF> for DigestVar<ConstraintF, P, C> {
    type Value = DigestWrapper<P, C>;

    fn cs(&self) -> ConstraintSystemRef<ConstraintF> {
        self.c0.cs().or(self.c1.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(DigestWrapper {
            digest: Commitment { c1: self.c0.value()?, c2: self.c1.value()?, _params: PhantomData },
            _params: PhantomData,
            _circuit_params: PhantomData,
        })
    }
}

impl<ConstraintF: PrimeField, P: RsaKVACParams, C: BigNatCircuitParams> CondSelectGadget<ConstraintF> for DigestVar<ConstraintF, P, C> {
    fn conditionally_select(cond: &Boolean<ConstraintF>, true_value: &Self, false_value: &Self) -> Result<Self, SynthesisError> {
        Ok(DigestVar {
            c0: RsaHogVar::conditionally_select(cond, &true_value.c0, &false_value.c0)?,
            c1: RsaHogVar::conditionally_select(cond, &true_value.c1, &false_value.c1)?,
            _params: PhantomData,
        })
    }
}

impl<ConstraintF: PrimeField, P: RsaKVACParams, C: BigNatCircuitParams> EqGadget<ConstraintF> for DigestVar<ConstraintF, P, C> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.c0.is_eq(&other.c0)?
            .and(&self.c1.is_eq(&other.c1)?)
    }

    fn conditional_enforce_equal(&self, other: &Self, should_enforce: &Boolean<ConstraintF>) -> Result<(), SynthesisError> {
        self.c0.conditional_enforce_equal(&other.c0, should_enforce)?;
        self.c1.conditional_enforce_equal(&other.c1, should_enforce)
    }
}

impl<ConstraintF: PrimeField, P: RsaKVACParams, C: BigNatCircuitParams> ToBytesGadget<ConstraintF> for DigestVar<ConstraintF, P, C> {
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        let mut bytes = self.c0.to_bytes()?;
        bytes.extend_from_slice(&self.c1.to_bytes()?);
        Ok(bytes)
    }
}

#[derive(Clone)]
pub struct UpdateProofVar<ConstraintF, P, C, H, HG>
where
    ConstraintF: PrimeField,
    H: Hasher<F = ConstraintF>,
    HG: HasherGadget<H, ConstraintF>,
    P: RsaKVACParams,
    C: BigNatCircuitParams,
{
    proof: ProofVar<ConstraintF, P::RsaGroupParams, C, H, HG>,
    _params: PhantomData<P>,
}

impl<ConstraintF, P, C, H, HG> AllocVar<UpdateProofWrapper<P, H>, ConstraintF> for UpdateProofVar<ConstraintF, P, C, H, HG>
    where
        ConstraintF: PrimeField,
        H: Hasher<F = ConstraintF>,
        HG: HasherGadget<H, ConstraintF>,
        P: RsaKVACParams,
        C: BigNatCircuitParams,
{
    fn new_variable<T: Borrow<UpdateProofWrapper<P, H>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let f_out = f()?;
        let proof_var = ProofVar::<ConstraintF, P::RsaGroupParams, C, H, HG>::new_variable(
            cs,
            || Ok(&f_out.borrow().proof),
            mode,
        )?;
        Ok(UpdateProofVar{
            proof: proof_var,
            _params: PhantomData,
        })
    }
}

pub struct RsaAVDGadget<ConstraintF, P, H, CircuitH, CircuitHG, C, S, T>
    where
        ConstraintF: PrimeField,
        P: RsaKVACParams,
        H: Hasher,
        CircuitH: Hasher<F = ConstraintF>,
        CircuitHG: HasherGadget<CircuitH, ConstraintF>,
        C: BigNatCircuitParams,
        S: RsaKVACStorer<P, H, CircuitH, C>,
        T: RSAAVDStorer<P, H, CircuitH, C, S>
{
    _kvac_params: PhantomData<P>,
    _hash: PhantomData<H>,
    _circuit_hash: PhantomData<CircuitH>,
    _circuit_hash_gadget: PhantomData<CircuitHG>,
    _circuit_params: PhantomData<C>,
    _s: PhantomData<S>,
    _t: PhantomData<T>,
}

impl<ConstraintF, P, H, CircuitH, CircuitHG, C, S, T> SingleStepAVDGadget<RsaAVD<P, H, CircuitH, C, S, T>, ConstraintF>
for RsaAVDGadget<ConstraintF, P, H, CircuitH, CircuitHG, C, S, T>
    where
        ConstraintF: PrimeField,
        P: RsaKVACParams,
        H: Hasher,
        CircuitH: Hasher<F = ConstraintF>,
        CircuitHG: HasherGadget<CircuitH, ConstraintF>,
        C: BigNatCircuitParams,
        S: RsaKVACStorer<P, H, CircuitH, C>,
        T: RSAAVDStorer<P, H, CircuitH, C, S>
{
    type PublicParametersVar = EmptyVar;
    type DigestVar = DigestVar<ConstraintF, P, C>;
    type UpdateProofVar = UpdateProofVar<ConstraintF, P, C, CircuitH, CircuitHG>;

    fn conditional_check_update_proof(_pp: &Self::PublicParametersVar, prev_digest: &Self::DigestVar, new_digest: &Self::DigestVar, proof: &Self::UpdateProofVar, condition: &Boolean<ConstraintF>) -> Result<(), SynthesisError> {
        let statement = StatementVar {
            u1: prev_digest.c0.clone(),
            u2: prev_digest.c1.clone(),
            w1: new_digest.c0.clone(),
            w2: new_digest.c1.clone(),
        };
        conditional_enforce_poker_valid::<_, P::PoKERParams, P::RsaGroupParams, _, _, _>(
            prev_digest.cs().or(new_digest.cs()),
            &statement,
            &proof.proof,
            condition,
        )
    }
}

#[derive(Clone)]
pub struct EmptyVar;

impl<ConstraintF: PrimeField> AllocVar<(), ConstraintF> for EmptyVar {
    fn new_variable<T: Borrow<()>>(_cs: impl Into<Namespace<ConstraintF>>, _f: impl FnOnce() -> Result<T, SynthesisError>, _mode: AllocationMode) -> Result<Self, SynthesisError> {
        Ok(EmptyVar)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::{Fq};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintLayer};
    use tracing_subscriber::layer::SubscriberExt;

    use rsa::{
        poker::{PoKERParams},
        hog::{RsaGroupParams},
        hash::{
            HasherFromDigest, PoseidonHasher, constraints::PoseidonHasherGadget,
        },
    };
    use crate::SingleStepAVD;

    use rand::{SeedableRng, rngs::StdRng};
    use rsa::kvac::{
        RsaKVAC,
        store::mem_store::RsaKVACMemStore,
    };
    use crate::rsa_avd::store::mem_store::RSAAVDMemStore;

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestRsa512Params;

    impl RsaGroupParams for TestRsa512Params {
        const RAW_G: usize = 2;
        const RAW_M: &'static str = "11834783464130424096695514462778\
                                     87028026498993885732873780720562\
                                     30692915355259527228479136942963\
                                     92927890261736769191982212777933\
                                     726583565708193466779811767";
    }


    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNatTestParams;
    impl BigNatCircuitParams for BigNatTestParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 16;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestPokerParams;
    impl PoKERParams for TestPokerParams {
        const HASH_TO_PRIME_ENTROPY: usize = 64;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestKVACParams;
    impl RsaKVACParams for TestKVACParams {
        const KEY_LEN: usize = 256;
        const VALUE_LEN: usize = 256;
        const PRIME_LEN: usize = 264;
        type RsaGroupParams = TestRsa512Params;
        type PoKERParams = TestPokerParams;
    }

    pub type H = PoseidonHasher<Fq>;
    pub type HG = PoseidonHasherGadget<Fq>;

    pub type TestKvacStore = RsaKVACMemStore<
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        PoseidonHasher<Fq>,
        BigNatTestParams,
    >;
    pub type TestRSAKVAC = RsaKVAC<
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        PoseidonHasher<Fq>,
        BigNatTestParams,
        TestKvacStore,
    >;
    pub type RSAAVDStore = RSAAVDMemStore<
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        PoseidonHasher<Fq>,
        BigNatTestParams,
        TestKvacStore
    >;
    pub type TestRsaAVD = RsaAVD<
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        PoseidonHasher<Fq>,
        BigNatTestParams,
        TestKvacStore,
        RSAAVDStore,
    >;

    pub type TestRsaAVDGadget = RsaAVDGadget<
        Fq,
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        PoseidonHasher<Fq>,
        HG,
        BigNatTestParams,
        TestKvacStore,
        RSAAVDStore
    >;


    #[test]
    #[ignore] // Expensive test, run with ``cargo test valid_rsa_avd_update_trivial_test --release -- --ignored --nocapture``
    fn valid_rsa_avd_update_trivial_test() {
        let mut layer = ConstraintLayer::default();
        layer.mode = ark_relations::r1cs::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let mut rng = StdRng::seed_from_u64(0_u64);
            let kvac_mem_store: TestKvacStore = TestKvacStore::new();
            let rsa_kvac: TestRSAKVAC = TestRSAKVAC::new(kvac_mem_store);
            let rsaavd_mem_store: RSAAVDStore = RSAAVDStore::new(rsa_kvac).unwrap();
            let mut avd = TestRsaAVD::new(&mut rng, rsaavd_mem_store).unwrap();
            let digest_0 = avd.digest().unwrap();
            let (digest_1, proof) = avd.batch_update(&vec![
                ([1_u8; 32], [2_u8; 32]),
                ([1_u8; 32], [3_u8; 32]),
                ([10_u8; 32], [11_u8; 32]),
            ]).unwrap();

            let cs = ConstraintSystem::<Fq>::new_ref();

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

            TestRsaAVDGadget::check_update_proof(
                &EmptyVar,
                &prev_digest_var,
                &new_digest_var,
                &proof_var,
            ).unwrap();

            println!("Number of constraints: {}", cs.num_constraints());
            if !cs.is_satisfied().unwrap() {
                println!("=========================================================");
                println!("Unsatisfied constraints:");
                println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
                println!("=========================================================");
            }
            assert!(cs.is_satisfied().unwrap());
        })
    }


    #[test]
    #[ignore] // Expensive test, run with ``cargo test conditional_invalid_rsa_avd_update_test --release -- --ignored --nocapture``
    fn conditional_invalid_rsa_avd_update_test() {
        let mut layer = ConstraintLayer::default();
        layer.mode = ark_relations::r1cs::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let mut rng = StdRng::seed_from_u64(0_u64);
            let kvac_mem_store: TestKvacStore = TestKvacStore::new();
            let rsa_kvac: TestRSAKVAC = TestRSAKVAC::new(kvac_mem_store);
            let rsaavd_mem_store: RSAAVDStore = RSAAVDStore::new(rsa_kvac).unwrap();
            let mut avd = TestRsaAVD::new(&mut rng, rsaavd_mem_store).unwrap();
            let digest_0 = avd.digest().unwrap();
            let (digest_1, _proof) = avd.batch_update(&vec![
                ([1_u8; 32], [2_u8; 32]),
                ([1_u8; 32], [3_u8; 32]),
                ([10_u8; 32], [11_u8; 32]),
            ]).unwrap();
            let invalid_proof = Default::default();

            let cs = ConstraintSystem::<Fq>::new_ref();

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
                || Ok(&invalid_proof),
            ).unwrap();

            TestRsaAVDGadget::conditional_check_update_proof(
                &EmptyVar,
                &prev_digest_var,
                &new_digest_var,
                &proof_var,
                &Boolean::FALSE,
            ).unwrap();

            println!("Number of constraints: {}", cs.num_constraints());
            if !cs.is_satisfied().unwrap() {
                println!("=========================================================");
                println!("Unsatisfied constraints:");
                println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
                println!("=========================================================");
            }
            assert!(cs.is_satisfied().unwrap());
        })
    }

}
