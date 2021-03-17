use ark_ff::{PrimeField};
use ark_relations::r1cs::{SynthesisError, Namespace, ConstraintSystemRef};
use ark_r1cs_std::{
    prelude::*,
};

use crate::{
    bignat::{
        constraints::{BigNatCircuitParams, BigNatVar},
    },
    hog::{RsaHiddenOrderGroup, RsaGroupParams},
};

use std::{
    borrow::Borrow,
    marker::PhantomData,
};

#[derive(Clone)]
pub struct RsaHogVar<ConstraintF: PrimeField, RsaP: RsaGroupParams, CircuitP: BigNatCircuitParams> {
    pub n: BigNatVar<ConstraintF, CircuitP>,
    _rsa_params: PhantomData<RsaP>,
}

impl<ConstraintF: PrimeField, RsaP: RsaGroupParams, CircuitP: BigNatCircuitParams> AllocVar<RsaHiddenOrderGroup<RsaP>, ConstraintF>
for RsaHogVar<ConstraintF, RsaP, CircuitP> {
    fn new_variable<T: Borrow<RsaHiddenOrderGroup<RsaP>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let f_out = f()?;
        let nat_var = BigNatVar::new_variable(
            cs,
            || Ok(&f_out.borrow().n),
            mode,
        )?;
        Ok(RsaHogVar{
            n: nat_var,
            _rsa_params: PhantomData,
        })
    }
}

impl<ConstraintF: PrimeField, RsaP: RsaGroupParams, CircuitP: BigNatCircuitParams> R1CSVar<ConstraintF>
for RsaHogVar<ConstraintF, RsaP, CircuitP> {
    type Value = RsaHiddenOrderGroup<RsaP>;

    fn cs(&self) -> ConstraintSystemRef<ConstraintF> {
        self.n.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(RsaHiddenOrderGroup::from_nat(self.n.value()?))
    }
}

impl<ConstraintF: PrimeField, RsaP: RsaGroupParams, CircuitP: BigNatCircuitParams> CondSelectGadget<ConstraintF>
for RsaHogVar<ConstraintF, RsaP, CircuitP> {
    fn conditionally_select(cond: &Boolean<ConstraintF>, true_value: &Self, false_value: &Self) -> Result<Self, SynthesisError> {
        Ok(RsaHogVar {
            n: BigNatVar::conditionally_select(cond, &true_value.n, &false_value.n)?,
            _rsa_params: PhantomData,
        })
    }
}

impl<ConstraintF: PrimeField, RsaP: RsaGroupParams, CircuitP: BigNatCircuitParams> EqGadget<ConstraintF>
for RsaHogVar<ConstraintF, RsaP, CircuitP> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.n.is_eq(&other.n)
    }

    fn conditional_enforce_equal(&self, other: &Self, should_enforce: &Boolean<ConstraintF>) -> Result<(), SynthesisError> {
        self.n.conditional_enforce_equal(&other.n, should_enforce)
    }
}

impl<ConstraintF: PrimeField, RsaP: RsaGroupParams, CircuitP: BigNatCircuitParams> ToBytesGadget<ConstraintF>
for RsaHogVar<ConstraintF, RsaP, CircuitP> {
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        self.n.to_bytes()
    }
}

impl<ConstraintF: PrimeField, RsaP: RsaGroupParams, CircuitP: BigNatCircuitParams> RsaHogVar<ConstraintF, RsaP, CircuitP> {

    pub fn constant(elem: &RsaHiddenOrderGroup<RsaP>) -> Result<Self, SynthesisError> {
        Ok(RsaHogVar{
            n: BigNatVar::constant(&elem.n)?,
            _rsa_params: PhantomData,
        })
    }

    pub fn identity() -> Result<Self, SynthesisError> {
        Self::constant(&RsaHiddenOrderGroup::<RsaP>::identity())
    }

    pub fn generator() -> Result<Self, SynthesisError> {
        Self::constant(&RsaHiddenOrderGroup::<RsaP>::generator())
    }

    // Performs modulo multiplication of op without deduplicating by selecting minimum group element
    // In RSA quotient groups, elements a and M - a are equivalent
    #[tracing::instrument(target = "r1cs", skip(self, other, modulus))]
    pub fn op_allow_duplicate(&self, other: &Self, modulus: &BigNatVar<ConstraintF, CircuitP>) -> Result<Self, SynthesisError> {
        Ok(Self {
            n: self.n.mult_mod(&other.n, modulus)?,
            _rsa_params: PhantomData,
        })
    }

    // Performs modulo exponentiation without deduplicating by selecting minimum group element
    // In RSA quotient groups, elements a and M - a are equivalent
    #[tracing::instrument(target = "r1cs", skip(self, exp, modulus))]
    pub fn power_allow_duplicate(
        &self,
        exp: &BigNatVar<ConstraintF, CircuitP>,
        modulus: &BigNatVar<ConstraintF, CircuitP>,
        num_exp_bits: usize,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            n: self.n.pow_mod(exp, modulus, num_exp_bits)?,
            _rsa_params: PhantomData,
        })
    }

    // Deduplicates self by selecting minimum of self and M - self.
    #[tracing::instrument(target = "r1cs", skip(self, modulus))]
    pub fn deduplicate(&self, modulus: &BigNatVar<ConstraintF, CircuitP>) -> Result<Self, SynthesisError> {
        Ok(Self {
            n: self.n.min(&modulus.sub(&self.n)?)?,
            _rsa_params: PhantomData,
        })
    }

    #[tracing::instrument(target = "r1cs", skip(self, other, modulus))]
    pub fn op(&self, other: &Self, modulus: &BigNatVar<ConstraintF, CircuitP>) -> Result<Self, SynthesisError> {
        Ok(self.op_allow_duplicate(other, modulus)?
                .deduplicate(modulus)?
        )
    }

    #[tracing::instrument(target = "r1cs", skip(self, exp, modulus))]
    pub fn power(
        &self,
        exp: &BigNatVar<ConstraintF, CircuitP>,
        modulus: &BigNatVar<ConstraintF, CircuitP>,
        num_exp_bits: usize,
    ) -> Result<Self, SynthesisError> {
        Ok(self.power_allow_duplicate(exp, modulus, num_exp_bits)?
                .deduplicate(modulus)?
        )
    }

    /// Constrain `self` to be equal to `other`, assumes both have been deduplicated.
    #[tracing::instrument(target = "r1cs", skip(self, other))]
    pub fn enforce_equal(
        &self,
        other: &Self,
    ) -> Result<(), SynthesisError> {
        self.n.enforce_equal_when_carried(&other.n)
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::{Fq};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintLayer};
    use tracing_subscriber::layer::SubscriberExt;
    use crate::{
        hash::{HasherFromDigest, hash_to_integer::hash_to_integer},
        bignat::BigNat,
    };

    pub type H = HasherFromDigest<Fq, blake3::Hasher>;

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestRsaParams;

    impl RsaGroupParams for TestRsaParams {
        const RAW_G: usize = 2;
        const RAW_M: &'static str = "2519590847565789349402718324004839857142928212620403202777713783604366202070\
                          7595556264018525880784406918290641249515082189298559149176184502808489120072\
                          8449926873928072877767359714183472702618963750149718246911650776133798590957\
                          0009733045974880842840179742910064245869181719511874612151517265463228221686\
                          9987549182422433637259085141865462043576798423387184774447920739934236584823\
                          8242811981638150106748104516603773060562016196762561338441436038339044149526\
                          3443219011465754445417842402092461651572335077870774981712577246796292638635\
                          6373289912154831438167899885040445364023527381951378636564391212010397122822\
                          120720357";
    }

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
        const N_LIMBS: usize = 64;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNat512TestParams;

    impl BigNatCircuitParams for BigNat512TestParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 16;
    }

    pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;
    pub type HogVar = RsaHogVar<Fq, TestRsaParams, BigNatTestParams>;
    pub type Hog512 = RsaHiddenOrderGroup<TestRsa512Params>;
    pub type HogVar512 = RsaHogVar<Fq, TestRsa512Params, BigNatTestParams>;
    pub type HogVar512All = RsaHogVar<Fq, TestRsa512Params, BigNat512TestParams>;

    #[test]
    fn valid_inverse_op_test() {
        let mut layer = ConstraintLayer::default();
        layer.mode = ark_relations::r1cs::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = Hog::from_nat(BigNat::from(30));
            let inv_a = a.inverse().unwrap();
            let a_var = HogVar::new_witness(
                ark_relations::ns!(cs, "a"),
                || Ok(&a),
            ).unwrap();
            let inv_a_var = HogVar::new_witness(
                ark_relations::ns!(cs, "inv_a"),
                || Ok(&inv_a),
            ).unwrap();
            let mod_var = BigNatVar::<Fq, BigNatTestParams>::constant(&TestRsaParams::m()).unwrap();
            HogVar::enforce_equal(&HogVar::identity().unwrap(), &a_var.op(&inv_a_var, &mod_var).unwrap()).unwrap();

            // Large value a
            let a = Hog::from_nat(BigNat::from(-30) + TestRsaParams::m());
            let inv_a = a.inverse().unwrap();
            let a_var = HogVar::new_witness(
                ark_relations::ns!(cs, "a"),
                || Ok(&a),
            ).unwrap();
            let inv_a_var = HogVar::new_witness(
                ark_relations::ns!(cs, "inv_a"),
                || Ok(&inv_a),
            ).unwrap();
            let mod_var = BigNatVar::<Fq, BigNatTestParams>::constant(&TestRsaParams::m()).unwrap();
            HogVar::enforce_equal(&HogVar::identity().unwrap(), &a_var.op(&inv_a_var, &mod_var).unwrap()).unwrap();

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
    fn valid_multiple_ops_without_dedup_test() {
        let mut layer = ConstraintLayer::default();
        layer.mode = ark_relations::r1cs::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = Hog::from_nat(BigNat::from(30));
            let b = Hog::from_nat(BigNat::from(40)).inverse().unwrap();
            let c = Hog::from_nat(BigNat::from(50)).inverse().unwrap();
            let d = Hog::from_nat(BigNat::from(60)).inverse().unwrap();
            let result = a.op(&b).op(&c).op(&d);
            let a_var = HogVar::new_witness(
                ark_relations::ns!(cs, "a"),
                || Ok(&a),
            ).unwrap();
            let b_var = HogVar::new_witness(
                ark_relations::ns!(cs, "b"),
                || Ok(&b),
            ).unwrap();
            let c_var = HogVar::new_witness(
                ark_relations::ns!(cs, "c"),
                || Ok(&c),
            ).unwrap();
            let d_var = HogVar::new_witness(
                ark_relations::ns!(cs, "d"),
                || Ok(&d),
            ).unwrap();
            let result_var = HogVar::new_witness(
                ark_relations::ns!(cs, "result"),
                || Ok(&result),
            ).unwrap();
            let mod_var = BigNatVar::<Fq, BigNatTestParams>::constant(&TestRsaParams::m()).unwrap();
            HogVar::enforce_equal(
                &result_var,
                &a_var.op_allow_duplicate(&b_var, &mod_var).unwrap()
                    .op_allow_duplicate(&c_var, &mod_var).unwrap()
                    .op_allow_duplicate(&d_var, &mod_var).unwrap()
                    .deduplicate(&mod_var).unwrap()
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
    fn valid_power_2048_16_test() {
        let mut layer = ConstraintLayer::default();
        layer.mode = ark_relations::r1cs::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = Hog::from_nat(BigNat::from(30)).inverse().unwrap();
            let exp1 = BigNat::from(450);
            let result = a.power(&exp1);
            let a_var = HogVar::new_witness(
                ark_relations::ns!(cs, "a"),
                || Ok(&a),
            ).unwrap();
            let exp1_var = BigNatVar::<Fq, BigNatTestParams>::new_witness(
                ark_relations::ns!(cs, "exp1"),
                || Ok(&exp1),
            ).unwrap();
            let result_var = HogVar::new_witness(
                ark_relations::ns!(cs, "result"),
                || Ok(&result),
            ).unwrap();
            let mod_var = BigNatVar::<Fq, BigNatTestParams>::constant(&TestRsaParams::m()).unwrap();
            HogVar::enforce_equal(
                &result_var,
                &a_var.power(&exp1_var, &mod_var, 16).unwrap()
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
    #[ignore] // Expensive test, run with ``cargo test valid_power_2048_256_test --release -- --ignored --nocapture``
    fn valid_power_2048_256_test() {
        let mut layer = ConstraintLayer::default();
        layer.mode = ark_relations::r1cs::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = Hog::from_nat(BigNat::from(30)).inverse().unwrap();
            let exp1 = hash_to_integer::<H>(&[Fq::from(1u8)], 256);
            let result = a.power(&exp1);
            let a_var = HogVar::new_witness(
                ark_relations::ns!(cs, "a"),
                || Ok(&a),
            ).unwrap();
            let exp1_var = BigNatVar::<Fq, BigNatTestParams>::new_witness(
                ark_relations::ns!(cs, "exp1"),
                || Ok(&exp1),
            ).unwrap();
            let result_var = HogVar::new_witness(
                ark_relations::ns!(cs, "result"),
                || Ok(&result),
            ).unwrap();
            let mod_var = BigNatVar::<Fq, BigNatTestParams>::constant(&TestRsaParams::m()).unwrap();
            HogVar::enforce_equal(
                &result_var,
                &a_var.power(&exp1_var, &mod_var, 256).unwrap()
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
    fn valid_power_512_16_test() {
        let mut layer = ConstraintLayer::default();
        layer.mode = ark_relations::r1cs::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = Hog512::from_nat(BigNat::from(30)).inverse().unwrap();
            let exp1 = hash_to_integer::<H>(&[Fq::from(1u8)], 16);
            let result = a.power(&exp1);
            let a_var = HogVar512::new_witness(
                ark_relations::ns!(cs, "a"),
                || Ok(&a),
            ).unwrap();
            let exp1_var = BigNatVar::<Fq, BigNatTestParams>::new_witness(
                ark_relations::ns!(cs, "exp1"),
                || Ok(&exp1),
            ).unwrap();
            let result_var = HogVar512::new_witness(
                ark_relations::ns!(cs, "result"),
                || Ok(&result),
            ).unwrap();
            let mod_var = BigNatVar::<Fq, BigNatTestParams>::constant(&TestRsa512Params::m()).unwrap();
            HogVar512::enforce_equal(
                &result_var,
                &a_var.power(&exp1_var, &mod_var, 16).unwrap()
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
    fn valid_multiple_power_without_dedup_512_16_test() {
        let mut layer = ConstraintLayer::default();
        layer.mode = ark_relations::r1cs::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = Hog512::from_nat(BigNat::from(30)).inverse().unwrap();
            let exp1 = hash_to_integer::<H>(&[Fq::from(1u8)], 16);
            let exp2 = hash_to_integer::<H>(&[Fq::from(2u8)], 16);
            let exp3 = hash_to_integer::<H>(&[Fq::from(3u8)], 16);
            let result = a.power(&exp1).power(&exp2).power(&exp3);
            let a_var = HogVar512All::new_witness(
                ark_relations::ns!(cs, "a"),
                || Ok(&a),
            ).unwrap();
            let exp1_var = BigNatVar::<Fq, BigNat512TestParams>::new_witness(
                ark_relations::ns!(cs, "exp1"),
                || Ok(&exp1),
            ).unwrap();
            let exp2_var = BigNatVar::<Fq, BigNat512TestParams>::new_witness(
                ark_relations::ns!(cs, "exp2"),
                || Ok(&exp2),
            ).unwrap();
            let exp3_var = BigNatVar::<Fq, BigNat512TestParams>::new_witness(
                ark_relations::ns!(cs, "exp3"),
                || Ok(&exp3),
            ).unwrap();
            let result_var = HogVar512All::new_witness(
                ark_relations::ns!(cs, "result"),
                || Ok(&result),
            ).unwrap();
            let mod_var = BigNatVar::<Fq, BigNat512TestParams>::constant(&TestRsa512Params::m()).unwrap();
            HogVar512All::enforce_equal(
                &result_var,
                &a_var.power_allow_duplicate(&exp1_var, &mod_var, 16).unwrap()
                    .power_allow_duplicate(&exp2_var, &mod_var, 16).unwrap()
                    .power_allow_duplicate(&exp3_var, &mod_var, 16).unwrap()
                    .deduplicate(&mod_var).unwrap()
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
