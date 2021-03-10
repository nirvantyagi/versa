use algebra::{PrimeField};
use r1cs_std::{
    prelude::*,
};
use r1cs_core::{ConstraintSystemRef, SynthesisError, Namespace};

use std::{
    borrow::Borrow,
};

use crate::{
    bignat::{constraints::{BigNatCircuitParams, BigNatVar},},
    hog::{RsaGroupParams, constraints::{RsaHogVar}},
    poker::{PoKERParams, Statement, Proof},
    hash::{
        Hasher, constraints::HasherGadget,
        hash_to_prime::{
            PocklingtonPlan,
            constraints::{
                PocklingtonCertificateVar,
                check_hash_to_pocklington_prime,
            }
        },
    },
};

#[derive(Clone)]
pub struct StatementVar<
    ConstraintF: PrimeField,
    RsaP: RsaGroupParams,
    CircuitP: BigNatCircuitParams,
> {
    pub u1: RsaHogVar<ConstraintF, RsaP, CircuitP>,
    pub u2: RsaHogVar<ConstraintF, RsaP, CircuitP>,
    pub w1: RsaHogVar<ConstraintF, RsaP, CircuitP>,
    pub w2: RsaHogVar<ConstraintF, RsaP, CircuitP>,
}

#[derive(Clone)]
pub struct ProofVar<ConstraintF, RsaP, CircuitP, H, HG>
where
    ConstraintF: PrimeField,
    H: Hasher<F = ConstraintF>,
    HG: HasherGadget<H, ConstraintF>,
    RsaP: RsaGroupParams,
    CircuitP: BigNatCircuitParams,
{
    pub v_a: RsaHogVar<ConstraintF, RsaP, CircuitP>,
    pub v_b: RsaHogVar<ConstraintF, RsaP, CircuitP>,
    pub v_1: RsaHogVar<ConstraintF, RsaP, CircuitP>,
    pub v_2: RsaHogVar<ConstraintF, RsaP, CircuitP>,
    r_a: BigNatVar<ConstraintF, CircuitP>,
    r_b: BigNatVar<ConstraintF, CircuitP>,
    cert: PocklingtonCertificateVar<ConstraintF, CircuitP, H, HG>,
}



impl<ConstraintF, RsaP, CircuitP> AllocVar<Statement<RsaP>, ConstraintF> for StatementVar<ConstraintF, RsaP, CircuitP>
    where
        ConstraintF: PrimeField,
        RsaP: RsaGroupParams,
        CircuitP: BigNatCircuitParams,
{
    fn new_variable<T: Borrow<Statement<RsaP>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let f_out = f()?;

        let u1_var = RsaHogVar::<ConstraintF, RsaP, CircuitP>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().u1),
            mode,
        )?;
        let u2_var = RsaHogVar::<ConstraintF, RsaP, CircuitP>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().u2),
            mode,
        )?;
        let w1_var = RsaHogVar::<ConstraintF, RsaP, CircuitP>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().w1),
            mode,
        )?;
        let w2_var = RsaHogVar::<ConstraintF, RsaP, CircuitP>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().w2),
            mode,
        )?;
        Ok(StatementVar{
            u1: u1_var,
            u2: u2_var,
            w1: w1_var,
            w2: w2_var,
        })
    }
}


impl<ConstraintF, RsaP, CircuitP, H, HG> AllocVar<Proof<RsaP, H>, ConstraintF> for ProofVar<ConstraintF, RsaP, CircuitP, H, HG>
    where
        ConstraintF: PrimeField,
        H: Hasher<F = ConstraintF>,
        HG: HasherGadget<H, ConstraintF>,
        RsaP: RsaGroupParams,
        CircuitP: BigNatCircuitParams,
{
    fn new_variable<T: Borrow<Proof<RsaP, H>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let f_out = f()?;

        let va_var = RsaHogVar::<ConstraintF, RsaP, CircuitP>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().v_a),
            mode,
        )?;
        let vb_var = RsaHogVar::<ConstraintF, RsaP, CircuitP>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().v_b),
            mode,
        )?;
        let v1_var = RsaHogVar::<ConstraintF, RsaP, CircuitP>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().v_1),
            mode,
        )?;
        let v2_var = RsaHogVar::<ConstraintF, RsaP, CircuitP>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().v_2),
            mode,
        )?;
        let ra_var = BigNatVar::<ConstraintF, CircuitP>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().r_a),
            mode,
        )?;
        let rb_var = BigNatVar::<ConstraintF, CircuitP>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().r_b),
            mode,
        )?;
        let cert_var = PocklingtonCertificateVar::<ConstraintF, CircuitP, H, HG>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().cert),
            mode,
        )?;
        Ok(ProofVar{
            v_a: va_var,
            v_b: vb_var,
            v_1: v1_var,
            v_2: v2_var,
            r_a: ra_var,
            r_b: rb_var,
            cert: cert_var,
        })
    }
}


pub fn enforce_poker_valid<ConstraintF, P, RsaP, CircuitP, H, HG>(
    cs: ConstraintSystemRef<ConstraintF>,
    x: &StatementVar<ConstraintF, RsaP, CircuitP>,
    proof: &ProofVar<ConstraintF, RsaP, CircuitP, H, HG>,
) -> Result<(), SynthesisError>
where
    ConstraintF: PrimeField,
    H: Hasher<F = ConstraintF>,
    HG: HasherGadget<H, ConstraintF>,
    P: PoKERParams,
    RsaP: RsaGroupParams,
    CircuitP: BigNatCircuitParams,
{
    let g = RsaHogVar::<ConstraintF, RsaP, CircuitP>::generator()?;
    let m = BigNatVar::<ConstraintF, CircuitP>::constant(&RsaP::m())?;
    let l_bits = PocklingtonPlan::new(P::HASH_TO_PRIME_ENTROPY).max_bits();

    let z_a = proof.v_a.power_allow_duplicate(&proof.cert.result, &m, l_bits)?
        .op_allow_duplicate(&g.power_allow_duplicate(&proof.r_a, &m, l_bits)?, &m)?
        .deduplicate(&m)?;
    let z_b = proof.v_b.power_allow_duplicate(&proof.cert.result, &m, l_bits)?
        .op_allow_duplicate(&g.power_allow_duplicate(&proof.r_b, &m, l_bits)?, &m)?
        .deduplicate(&m)?;

    // Check hash challenge
    let mut hash_input = vec![];
    hash_input.extend(x.u1.n.limbs.iter().cloned());
    hash_input.extend(x.u2.n.limbs.iter().cloned());
    hash_input.extend(x.w1.n.limbs.iter().cloned());
    hash_input.extend(x.w2.n.limbs.iter().cloned());
    hash_input.extend(z_a.n.limbs.iter().cloned());
    hash_input.extend(z_b.n.limbs.iter().cloned());
    check_hash_to_pocklington_prime::<H, HG, ConstraintF, CircuitP>(
        cs.clone(),
        &hash_input,
        P::HASH_TO_PRIME_ENTROPY,
        &proof.cert,
    )?;

    // Verify proof
    x.w1.n.limbs.enforce_equal(
        &proof.v_1.power_allow_duplicate(&proof.cert.result, &m, l_bits)?
            .op_allow_duplicate(&x.u1.power_allow_duplicate(&proof.r_a, &m, l_bits)?, &m)?
            .op_allow_duplicate(&x.u2.power_allow_duplicate(&proof.r_b, &m, l_bits)?, &m)?
            .deduplicate(&m)?
            .n.limbs
    )?;
    x.w2.n.limbs.enforce_equal(
        &proof.v_2.power_allow_duplicate(&proof.cert.result, &m, l_bits)?
            .op_allow_duplicate(&x.u2.power_allow_duplicate(&proof.r_a, &m, l_bits)?, &m)?
            .deduplicate(&m)?
            .n.limbs
    )?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{ed_on_bls12_381::{Fq}};
    use r1cs_core::{ConstraintSystem, ConstraintLayer};
    use tracing_subscriber::layer::SubscriberExt;

    use crate::{
        bignat::BigNat,
        poker::{PoKER, Witness},
        hog::RsaHiddenOrderGroup,
        hash::{
            PoseidonHasher, constraints::PoseidonHasherGadget,
        },
    };


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


    #[derive(Clone)]
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

    pub type H = PoseidonHasher<Fq>;
    pub type HG = PoseidonHasherGadget<Fq>;
    pub type Hog = RsaHiddenOrderGroup<TestRsa512Params>;
    pub type Poker = PoKER<TestPokerParams, TestRsa512Params, H, BigNatTestParams>;

    #[test]
    #[ignore] // Expensive test, run with ``cargo test valid_poker_proof_trivial_test --release -- --ignored --nocapture``
    fn valid_poker_proof_trivial_test() {
        let mut layer = ConstraintLayer::default();
        layer.mode = r1cs_core::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let u1 = Hog::from_nat(BigNat::from(20));
            let u2 = Hog::from_nat(BigNat::from(30));
            let a = BigNat::from(40);
            let b = BigNat::from(50);
            let w1 = u1.power(&a).op(&u2.power(&b));
            let w2 = u2.power(&a);
            let x = Statement{u1, u2, w1, w2};
            let w = Witness{a, b};
            let proof = Poker::prove(&x, &w).unwrap();

            let x_var= StatementVar::<Fq, TestRsa512Params, BigNatTestParams>::new_witness(
                r1cs_core::ns!(cs, "x"),
                || Ok(&x),
            ).unwrap();
            let proof_var = ProofVar::<Fq, TestRsa512Params, BigNatTestParams, H, HG>::new_witness(
                r1cs_core::ns!(cs, "proof"),
                || Ok(&proof),
            ).unwrap();
            enforce_poker_valid::<Fq, TestPokerParams, _, _, H, HG>(
                cs.clone(),
                &x_var,
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

}
