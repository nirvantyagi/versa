use algebra::{PrimeField, BitIteratorBE, FpParameters};
use r1cs_core::{SynthesisError, Namespace, ConstraintSystemRef};
use r1cs_std::{
    prelude::*,
    fields::fp::FpVar,
};

use crate::bignat::{BigNat, fit_nat_to_limbs, nat_to_limbs, limbs_to_nat, nat_to_f, f_to_nat};

use std::{
    borrow::Borrow,
    marker::PhantomData,
    cmp::{min, max},
};


pub trait BigNatCircuitParams: Clone {
    const LIMB_WIDTH: usize;
    const N_LIMBS: usize;
}

//TODO: Track word_size in number of bits rather than value
#[derive(Clone)]
pub struct BigNatVar<ConstraintF: PrimeField, P: BigNatCircuitParams> {
    limbs: Vec<FpVar<ConstraintF>>,  // Must be of length P::N_LIMBS
    value: BigNat,
    word_size: BigNat,
    _params: PhantomData<P>,
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> AllocVar<BigNat, ConstraintF> for BigNatVar<ConstraintF, P> {
    fn new_variable<T: Borrow<BigNat>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let f_out = f()?;
        let limbs = nat_to_limbs(f_out.borrow(), P::LIMB_WIDTH, P::N_LIMBS).unwrap();
        let limb_vars = Vec::<FpVar<ConstraintF>>::new_variable(
            cs,
            || Ok(&limbs[..]),
            mode,
        )?;
        Ok(BigNatVar{
            limbs: limb_vars,
            value: f_out.borrow().clone(),
            word_size: (BigNat::from(1) << P::LIMB_WIDTH as u32) - 1,
            _params: PhantomData,
        })
    }
}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> R1CSVar<ConstraintF> for BigNatVar<ConstraintF, P> {
    type Value = BigNat;

    fn cs(&self) -> ConstraintSystemRef<ConstraintF> {
        self.limbs.as_slice().cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        debug_assert_eq!(self.limbs.len(), P::N_LIMBS);
        let limbs = self.limbs.iter()
            .map(|f|  f.value() )
            .collect::<Result<Vec<ConstraintF>, SynthesisError>>()?;
        let value = limbs_to_nat::<ConstraintF>(&limbs, P::LIMB_WIDTH);
        debug_assert_eq!(self.value, value);
        Ok(value)
    }
}


impl<ConstraintF: PrimeField, P: BigNatCircuitParams> BigNatVar<ConstraintF, P> {

    /// Reduce `self` to normal form with word size equal to limb width
    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn reduce(&self) -> Result<Self, SynthesisError> {
        let cs = self.cs();
        //TODO: What to do for constants? ConstraintSystemRef::None?
        let reduced = Self::new_witness(cs.clone(),  || Ok(self.value()?))?;
        self.enforce_equal_when_carried(&reduced)?;
        Ok(reduced)
    }

    #[tracing::instrument(target = "r1cs", skip(self, other))]
    pub fn add(&self, other: &Self) -> Result<Self, SynthesisError> {
        //TODO: Ensure that word size does not overflow field capacity?
        let word_size = BigNat::from(&self.word_size + &other.word_size);
        if word_size.significant_bits() > <ConstraintF::Params as FpParameters>::CAPACITY {
            self.reduce()?.add(&other.reduce()?)
        } else {
            let limbs = self.limbs.iter().zip(&other.limbs)
                .map(|(l1, l2)| {
                    l1 + l2
                }).collect::<Vec<FpVar<ConstraintF>>>();
            Ok(Self {
                limbs: limbs,
                value: self.value()? + other.value()?,
                word_size: word_size,
                _params: PhantomData,
            })
        }
    }


    /// Constrain `result` to be equal to `self` - `other`.
    #[tracing::instrument(target = "r1cs", skip(self, other))]
    pub fn sub(
        &self,
        other: &Self,
    ) -> Result<Self, SynthesisError> {
        let cs = self.cs().or(other.cs());
        //TODO: What to do for constants? ConstraintSystemRef::None?
        //TODO: Optimization: compute diff directly: https://github.com/arkworks-rs/nonnative/blob/master/src/allocated_nonnative_field_var.rs#L181
        let diff = Self::new_witness(cs.clone(),  || Ok(self.value()? - other.value()?))?;
        let sum = other.add(&diff)?;
        self.enforce_equal_when_carried(&sum)?;
        Ok(diff)
    }



    /// Constrain `result` to be equal to `(self * other) % modulus`.
    //TODO: Assumes constant modulus that is decided at circuit setup
    //TODO: Allow variable N_LIMBS so as not to need to apply modulus for every mult
    pub fn mult_mod(
        &self,
        other: &Self,
        modulus: &Self,
    ) -> Result<Self, SynthesisError> {
        let cs = self.cs().or(other.cs());

        // Reduce values so that multiplication doesn't overflow
        debug_assert!(2 * (P::LIMB_WIDTH as u32) + log2(P::N_LIMBS) <= <ConstraintF::Params as FpParameters>::CAPACITY);
        if &self.word_size.significant_bits() + &other.word_size.significant_bits() + log2(P::N_LIMBS) > <ConstraintF::Params as FpParameters>::CAPACITY {
            return self.reduce()?.mult_mod(&other.reduce()?, modulus);
        }

        // Compute and allocate quotient and remainder
        let (quotient_value, rem_value) = (self.value()? * other.value()?).div_rem(modulus.value()?);
        let rem = Self::new_witness(cs.clone(),  || Ok(rem_value))?;
        // Since quotient may require more than P::N_LIMBS to allocate, we do not allocate it as a BigNatVar
        let quotient_value_limbs = fit_nat_to_limbs(&quotient_value, P::LIMB_WIDTH).unwrap();
        let mut quotient_limbs = Vec::<FpVar<ConstraintF>>::new_witness(cs.clone(), || Ok(&quotient_value_limbs[..]))?;
        // Compute deterministic upper bound on number of quotient limbs and pad to it
        let num_left_bits = P::LIMB_WIDTH * (P::N_LIMBS - 1) + (self.word_size.significant_bits() as usize) + 1; //TODO: +1 differs from bellman-bignat
        let num_right_bits = P::LIMB_WIDTH * (P::N_LIMBS - 1) + (other.word_size.significant_bits() as usize) + 1;
        let num_mod_bits = modulus.value()?.significant_bits() as usize;
        let num_quotient_bits = (num_left_bits + num_right_bits).saturating_sub(num_mod_bits);
        let num_quotient_limbs = num_quotient_bits / P::LIMB_WIDTH + 1;
        println!("num_quotient_limbs: {}, computed_upper_bound: {}", quotient_limbs.len(), num_quotient_limbs);
        assert!(num_quotient_limbs >= quotient_limbs.len());
        quotient_limbs.resize(num_quotient_limbs, <FpVar<ConstraintF>>::zero());

        // Constrain remainder to appropriate size
        rem.enforce_fits_in_bits(num_mod_bits)?;

        // left (self) * right (other)
        let mut lr_prod_limbs = vec![<FpVar<ConstraintF>>::zero(); P::N_LIMBS + num_quotient_limbs - 1]; // Same length as below
        for i in 0..P::N_LIMBS {
            for j in 0..P::N_LIMBS {
                lr_prod_limbs[i + j] = &lr_prod_limbs[i + j] + (&self.limbs[i] * &other.limbs[j]);
            }
        }
        let lr_word_size = BigNat::from(&self.word_size * &other.word_size) * BigNat::from(P::N_LIMBS);

        // mod * quotient + remainder
        debug_assert!(2 * (P::LIMB_WIDTH as u32) + log2(num_quotient_limbs) + 1 <= <ConstraintF::Params as FpParameters>::CAPACITY);
        let mut mqr_prod_limbs = vec![<FpVar<ConstraintF>>::zero(); P::N_LIMBS + num_quotient_limbs - 1];
        for i in 0..P::N_LIMBS {
            for j in 0..num_quotient_limbs {
                mqr_prod_limbs[i + j] = &mqr_prod_limbs[i + j] + (&modulus.limbs[i] * &quotient_limbs[j]);
            }
            mqr_prod_limbs[i] = &mqr_prod_limbs[i] + &rem.limbs[i];
        }
        let mqr_word_size = BigNat::from(&rem.word_size * &modulus.word_size) * BigNat::from(num_quotient_limbs)
            + &rem.word_size; // rem and quotient word size is default

        Self::enforce_limbs_equal_when_carried(
            cs.clone(),
            &lr_prod_limbs,
            &mqr_prod_limbs,
            &max(lr_word_size, mqr_word_size),
        );
        Ok(rem)
    }


    /// Combines limbs into groups.
    fn group_limbs(limbs: &Vec<FpVar<ConstraintF>>, limbs_per_group: usize) -> Vec<FpVar<ConstraintF>> {
        let mut grouped_limbs = vec![];
        let limb_block = <FpVar<ConstraintF>>::constant(nat_to_f(&(BigNat::from(1) << (P::LIMB_WIDTH as u32))).unwrap());
        for limbs_to_group in limbs.as_slice().chunks(limbs_per_group) {
            let mut shift = <FpVar<ConstraintF>>::one();
            let mut grouped_limb = <FpVar<ConstraintF>>::zero();
            for (i, limb) in limbs_to_group.iter().enumerate() {
                grouped_limb += &(limb * shift.clone());
                shift *= &limb_block;
            }
            grouped_limbs.push(grouped_limb);
        }
        grouped_limbs
    }

    /// Constrain `self` to be equal to `other`, after carrying both.
    #[tracing::instrument(target = "r1cs", skip(self, other))]
    pub fn enforce_equal_when_carried(
        &self,
        other: &Self,
    ) -> Result<(), SynthesisError> {
        let cs = self.cs().or(other.cs());
        let current_word_size = max(&self.word_size, &other.word_size);
        Self::enforce_limbs_equal_when_carried(cs, &self.limbs, &other.limbs, current_word_size)
    }

    /// Constrain `limbs` to be equal to `other_limbs`, after carrying both.
    #[tracing::instrument(target = "r1cs", skip(cs, left_limbs, right_limbs, current_word_size))]
    fn enforce_limbs_equal_when_carried(
        cs: impl Into<Namespace<ConstraintF>>,
        left_limbs: &Vec<FpVar<ConstraintF>>,
        right_limbs: &Vec<FpVar<ConstraintF>>,
        current_word_size: &BigNat,
    ) -> Result<(), SynthesisError> {
        assert_eq!(left_limbs.len(), right_limbs.len());
        let ns = cs.into();
        let cs = ns.cs();

        let carry_bits = (((current_word_size.to_f64() * 2.0).log2() - P::LIMB_WIDTH as f64).ceil() + 0.1) as usize;
        let carry_bits2 = (current_word_size.significant_bits() as usize - P::LIMB_WIDTH + 1) as usize;
        assert_eq!(carry_bits, carry_bits2);
        println!("current_word_size: {}, carry_bits: {}", current_word_size.clone(), carry_bits);

        // Regroup limbs to take advantage of field size and reduce the amount of carrying
        let limbs_per_group = (<ConstraintF::Params as FpParameters>::CAPACITY as usize - carry_bits ) / P::LIMB_WIDTH;
        let grouped_base = BigNat::from(1) << (P::LIMB_WIDTH * limbs_per_group) as u32;
        let grouped_word_size = (0..limbs_per_group).fold(BigNat::from(0), |mut acc, i| {
            acc.set_bit((i * P::LIMB_WIDTH) as u32, true);
            acc
        }) * current_word_size.clone();
        let grouped_carry_bits = (grouped_word_size.significant_bits() as usize - P::LIMB_WIDTH * limbs_per_group + 1) as usize;


        // Propagate carries over grouped limbs.
        let mut carry_in = <FpVar<ConstraintF>>::zero();
        let mut accumulated_extra = BigNat::from(0);
        for (i, (left_limb, right_limb)) in Self::group_limbs(left_limbs, limbs_per_group).iter()
            .zip(Self::group_limbs(right_limbs, limbs_per_group)).enumerate() {
            println!("Round {}:", i);
            let left_limb_value = left_limb.value()?;
            let right_limb_value = right_limb.value()?;
            let carry_in_value = carry_in.value()?;
            println!("left: {}, right: {}, carry_in: {}", f_to_nat(&left_limb_value), f_to_nat(&right_limb_value), f_to_nat(&carry_in_value));

            let carry_value = nat_to_f::<ConstraintF>(
                &(
                    (f_to_nat(&left_limb_value) + f_to_nat(&carry_in_value) - f_to_nat(&right_limb_value) + grouped_word_size.clone())
                        / grouped_base.clone()
                )
            ).unwrap();
            println!("carry: {}", f_to_nat(&carry_value));
            let carry = <FpVar<ConstraintF>>::new_witness(cs.clone(), || Ok(carry_value))?;

            accumulated_extra += grouped_word_size.clone();

            let (tmp_accumulated_extra, remainder) = accumulated_extra.div_rem(grouped_base.clone());
            accumulated_extra = tmp_accumulated_extra;
            println!("accumulated_extra: {}", accumulated_extra.clone());
            let remainder_limb = nat_to_f::<ConstraintF>(&remainder).unwrap();

            let eqn_left: FpVar<ConstraintF> = left_limb
                + &carry_in - right_limb
                + nat_to_f::<ConstraintF>(&grouped_word_size).unwrap();
            let eqn_right = &carry * nat_to_f::<ConstraintF>(&grouped_base).unwrap()
                + remainder_limb;
            println!("eqn_right: {}, eqn_left: {}, i: {}", f_to_nat(&eqn_right.value().unwrap()), f_to_nat(&eqn_left.value().unwrap()), i);
            eqn_left.enforce_equal(&eqn_right)?;

            if i < left_limbs.len() - 1 {
                Self::enforce_limb_fits_in_bits(&carry, grouped_carry_bits)?;
            } else {
                carry.enforce_equal(&FpVar::<ConstraintF>::Constant(nat_to_f::<ConstraintF>(&accumulated_extra).unwrap()))?;
            }

            carry_in = carry.clone();
        }
        Ok(())
    }

    /// Constrains `self` assumed to be in normal form to be of certain bit length
    #[tracing::instrument(target = "r1cs", skip(self, n_bits))]
    fn enforce_fits_in_bits(
        &self,
        n_bits: usize,
    ) -> Result<(), SynthesisError> {
        let num_limbs = n_bits / P::LIMB_WIDTH;
        for (i, limb) in self.limbs.iter().enumerate() {
            if i < num_limbs {
                Self::enforce_limb_fits_in_bits(limb, P::LIMB_WIDTH)?;
            } else if i == num_limbs {
                Self::enforce_limb_fits_in_bits(limb, n_bits % P::LIMB_WIDTH)?;
            } else {
                limb.enforce_equal(&<FpVar<ConstraintF>>::zero())?;
            }
        }
        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(limb, n_bits))]
    fn enforce_limb_fits_in_bits(
        limb: &FpVar<ConstraintF>,
        n_bits: usize,
    ) -> Result<(), SynthesisError> {
        let cs = limb.cs();

        let n_bits = min(ConstraintF::size_in_bits() - 1, n_bits);
        let mut bits = Vec::with_capacity(n_bits);
        let limb_value = limb.value()?;

        for b in BitIteratorBE::new(limb_value.into_repr()).skip(
            <<ConstraintF as PrimeField>::Params as FpParameters>::REPR_SHAVE_BITS as usize
                + (ConstraintF::size_in_bits() - n_bits),
        ) {
            bits.push(b);
        }

        if cs != ConstraintSystemRef::None {
            let mut bit_vars = vec![];
            for b in bits {
                bit_vars.push(Boolean::<ConstraintF>::new_witness(
                    r1cs_core::ns!(cs, "bit"),
                    || Ok(b),
                )?);
            }
            let mut bit_sum = FpVar::<ConstraintF>::zero();
            let mut coeff = ConstraintF::one();
            for bit in bit_vars.iter().rev() {
                bit_sum +=
                    <FpVar<ConstraintF> as From<Boolean<ConstraintF>>>::from((*bit).clone()) * coeff;
                coeff.double_in_place();
            }
            println!("bit_sum: {}, limb: {}", f_to_nat(&bit_sum.value().unwrap()), f_to_nat(&limb.value().unwrap()));
            bit_sum.enforce_equal(limb)?;
        }
        Ok(())
    }

}

impl<ConstraintF: PrimeField, P: BigNatCircuitParams> CondSelectGadget<ConstraintF> for BigNatVar<ConstraintF, P> {
    fn conditionally_select(cond: &Boolean<ConstraintF>, true_value: &Self, false_value: &Self) -> Result<Self, SynthesisError> {
        let selected_limbs = true_value.limbs.iter().zip(&false_value.limbs)
            .map(|(true_limb, false_limb)| {
                cond.select(true_limb, false_limb)
            }).collect::<Result<Vec<FpVar<ConstraintF>>, SynthesisError>>()?;
        let cond_bool = cond.value()?;
        let selected_nat = if cond_bool { true_value } else { false_value };
        Ok(Self {
            limbs: selected_limbs,
            value: selected_nat.value()?,
            word_size: max(true_value.word_size.clone(), false_value.word_size.clone()),
            _params: PhantomData,
        })
    }
}

// Helper methods
pub fn log2(x: usize) -> u32 {
    if x == 0 {
        0
    } else if x.is_power_of_two() {
        1usize.leading_zeros() - x.leading_zeros()
    } else {
        0usize.leading_zeros() - x.leading_zeros()
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use algebra::ed_on_bls12_381::{Fq};
    use r1cs_core::{ConstraintSystem, ConstraintLayer};
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone)]
    pub struct BigNatTestParams;

    impl BigNatCircuitParams for BigNatTestParams {
        const LIMB_WIDTH: usize = 3;
        const N_LIMBS: usize = 4;
    }


    impl<ConstraintF: PrimeField, P: BigNatCircuitParams> BigNatVar<ConstraintF, P> {
        fn alloc_from_u64_limbs(
            cs: impl Into<Namespace<ConstraintF>>,
            u64_limbs: &Vec<u64>,
            word_size: BigNat,
            mode: AllocationMode,
        ) -> Result<BigNatVar<ConstraintF, P>, SynthesisError> {
            let limbs = u64_limbs.iter().rev()
                .map(|int64| ConstraintF::from_repr(ConstraintF::BigInt::from(*int64)).unwrap())
                .collect::<Vec<ConstraintF>>();
            Self::alloc_from_limbs(cs, &limbs, word_size, mode)
        }

        fn alloc_from_limbs(
            cs: impl Into<Namespace<ConstraintF>>,
            limbs: &Vec<ConstraintF>,
            word_size: BigNat,
            mode: AllocationMode,
        ) -> Result<BigNatVar<ConstraintF, P>, SynthesisError> {
            assert_eq!(limbs.len(), P::N_LIMBS);
            let limb_vars = Vec::<FpVar<ConstraintF>>::new_variable(
                cs,
                || Ok(&limbs[..]),
                mode,
            )?;
            Ok(BigNatVar {
                limbs: limb_vars,
                value: limbs_to_nat::<ConstraintF>(limbs, P::LIMB_WIDTH),
                word_size: word_size,
                _params: PhantomData,
            })
        }
    }

    fn carry_over_equal_test(vec1: Vec<u64>, vec2: Vec<u64>, word_size_1: u64, word_size_2: u64, should_satisfy: bool) {
        let mut layer = ConstraintLayer::default();
        layer.mode = r1cs_core::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            println!("vec1: {:?}, vec2: {:?}", vec1.clone(), vec2.clone());
            let cs = ConstraintSystem::<Fq>::new_ref();
            let nat1var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
                r1cs_core::ns!(cs, "nat1"),
                &vec1,
                BigNat::from(word_size_1),
                AllocationMode::Witness,
            ).unwrap();
            let nat2var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
                r1cs_core::ns!(cs, "nat2"),
                &vec2,
                BigNat::from(word_size_2),
                AllocationMode::Witness,
            ).unwrap();
            nat1var.enforce_equal_when_carried(&nat2var).unwrap();

            if should_satisfy && !cs.is_satisfied().unwrap() {
                println!("=========================================================");
                println!("Unsatisfied constraints:");
                println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
                println!("=========================================================");
            }
            assert_eq!(should_satisfy, cs.is_satisfied().unwrap());
        })
    }

    #[test]
    fn carry_over_equal_trivial_test() {
        carry_over_equal_test(
            vec![2,1,4,7],
            vec![2,1,4,7],
            7,
            7,
            true,
        )
    }

    #[test]
    fn carry_over_equal_1carry_test() {
        carry_over_equal_test(
            vec![1,1,0,9],
            vec![1,1,1,1],
            14,
            7,
            true,
        )
    }

    #[test]
    fn carry_over_equal_2carry_test() {
        carry_over_equal_test(
            vec![1,1,9,9],
            vec![1,2,2,1],
            14,
            7,
            true,
        )
    }

    #[test]
    fn carry_over_equal_both_carry_test() {
        carry_over_equal_test(
            vec![1,1,9,9],
            vec![1,0,18,1],
            14,
            21,
            true,
        )
    }

    #[test]
    fn carry_over_equal_large_word_test() {
        carry_over_equal_test(
            vec![1,1,9,66],
            vec![1,3,1,2],
            70,
            7,
            true,
        )
    }

    #[test]
    fn carry_over_equal_3carry_test() {
        carry_over_equal_test(
            vec![1,12,7,12],
            vec![2,5,0,4],
            14,
            7,
            true,
        )
    }

    #[test]
    fn carry_over_equal_3carry_overflow_test() {
        carry_over_equal_test(
            vec![12,12,12,12],
            vec![13,5,5,4],
            14,
            14,
            true,
        )
    }

    fn add_equal_test(
        vec1: Vec<u64>,
        vec2: Vec<u64>,
        vec3: Vec<u64>,
        word_size_1: u64,
        word_size_2: u64,
        word_size_3: u64,
        should_satisfy: bool,
    ) {
        let mut layer = ConstraintLayer::default();
        layer.mode = r1cs_core::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            println!("vec1: {:?}, vec2: {:?}", vec1.clone(), vec2.clone());
            let cs = ConstraintSystem::<Fq>::new_ref();
            let nat1var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
                r1cs_core::ns!(cs, "nat1"),
                &vec1,
                BigNat::from(word_size_1),
                AllocationMode::Witness,
            ).unwrap();
            let nat2var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
                r1cs_core::ns!(cs, "nat2"),
                &vec2,
                BigNat::from(word_size_2),
                AllocationMode::Witness,
            ).unwrap();
            let nat3var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
                r1cs_core::ns!(cs, "nat3"),
                &vec3,
                BigNat::from(word_size_3),
                AllocationMode::Witness,
            ).unwrap();

            let sum = nat1var.add(&nat2var).unwrap();
            nat3var.enforce_equal_when_carried(&sum).unwrap();

            if should_satisfy && !cs.is_satisfied().unwrap() {
                println!("=========================================================");
                println!("Unsatisfied constraints:");
                println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
                println!("=========================================================");
            }
            assert_eq!(should_satisfy, cs.is_satisfied().unwrap());
        })
    }

    #[test]
    fn add_equal_trivial_test() {
        add_equal_test(
            vec![1,1,1,1],
            vec![1,1,1,1],
            vec![2,2,2,2],
            7,
            7,
            7,
            true,
        )
    }

    #[test]
    fn add_equal_carryover_test() {
        add_equal_test(
            vec![1,1,1,6],
            vec![1,1,1,6],
            vec![2,2,3,4],
            7,
            7,
            7,
            true,
        )
    }


    fn sub_equal_test(
        vec1: Vec<u64>,
        vec2: Vec<u64>,
        vec3: Vec<u64>,
        word_size_1: u64,
        word_size_2: u64,
        word_size_3: u64,
        should_satisfy: bool,
    ) {
        let mut layer = ConstraintLayer::default();
        layer.mode = r1cs_core::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            println!("vec1: {:?}, vec2: {:?}", vec1.clone(), vec2.clone());
            let cs = ConstraintSystem::<Fq>::new_ref();
            let nat1var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
                r1cs_core::ns!(cs, "nat1"),
                &vec1,
                BigNat::from(word_size_1),
                AllocationMode::Witness,
            ).unwrap();
            let nat2var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
                r1cs_core::ns!(cs, "nat2"),
                &vec2,
                BigNat::from(word_size_2),
                AllocationMode::Witness,
            ).unwrap();
            let nat3var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
                r1cs_core::ns!(cs, "nat3"),
                &vec3,
                BigNat::from(word_size_3),
                AllocationMode::Witness,
            ).unwrap();

            let diff = nat1var.sub(&nat2var).unwrap();
            nat3var.enforce_equal_when_carried(&diff).unwrap();

            println!("Number of constraints: {}", cs.num_constraints());
            if should_satisfy && !cs.is_satisfied().unwrap() {
                println!("=========================================================");
                println!("Unsatisfied constraints:");
                println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
                println!("=========================================================");
            }
            assert_eq!(should_satisfy, cs.is_satisfied().unwrap());
        })
    }

    #[test]
    fn sub_equal_trivial_test() {
        sub_equal_test(
            vec![2,2,2,2],
            vec![1,1,1,1],
            vec![1,1,1,1],
            7,
            7,
            7,
            true,
        )
    }

    #[test]
    fn sub_equal_carryover_test() {
        sub_equal_test(
            vec![2,0,18,2],
            vec![1,1,1,1],
            vec![1,1,1,1],
            21,
            7,
            7,
            true,
        )
    }


    fn mult_mod_test(
        vec1: Vec<u64>,
        vec2: Vec<u64>,
        vec3: Vec<u64>,
        modvec: Vec<u64>,
        word_size_1: u64,
        word_size_2: u64,
        word_size_3: u64,
        mod_word_size: u64,
        should_satisfy: bool,
    ) {
        let mut layer = ConstraintLayer::default();
        layer.mode = r1cs_core::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            println!("vec1: {:?}, vec2: {:?}", vec1.clone(), vec2.clone());
            let cs = ConstraintSystem::<Fq>::new_ref();
            let nat1var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
                r1cs_core::ns!(cs, "nat1"),
                &vec1,
                BigNat::from(word_size_1),
                AllocationMode::Witness,
            ).unwrap();
            let nat2var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
                r1cs_core::ns!(cs, "nat2"),
                &vec2,
                BigNat::from(word_size_2),
                AllocationMode::Witness,
            ).unwrap();
            let nat3var = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
                r1cs_core::ns!(cs, "nat3"),
                &vec3,
                BigNat::from(word_size_3),
                AllocationMode::Witness,
            ).unwrap();
            let modvar = BigNatVar::<Fq, BigNatTestParams>::alloc_from_u64_limbs(
                r1cs_core::ns!(cs, "mod"),
                &modvec,
                BigNat::from(mod_word_size),
                AllocationMode::Witness,
            ).unwrap();

            let prod = nat1var.mult_mod(&nat2var, &modvar).unwrap();
            nat3var.enforce_equal_when_carried(&prod).unwrap();

            println!("Number of constraints: {}", cs.num_constraints());
            if should_satisfy && !cs.is_satisfied().unwrap() {
                println!("=========================================================");
                println!("Unsatisfied constraints:");
                println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
                println!("=========================================================");
            }
            assert_eq!(should_satisfy, cs.is_satisfied().unwrap());
        })
    }

    #[test]
    fn mult_mod_trivial_test() {
        mult_mod_test(
            vec![0,0,1,1],
            vec![0,0,1,1],
            vec![0,1,2,1],
            vec![1,1,1,1],
            7, 7, 7, 7,
            true,
        )
    }

    #[test]
    fn mult_mod_prod_overflow_test() {
        mult_mod_test(
            vec![1,1,1,1], // 585
            vec![2,2,0,0], // 1152
            vec![3,2,2,0], // 585 * 1152 = 673920 ; 673920 % 2801 = 1680
            vec![5,3,6,1], // prime mod = 2801
            7, 7, 7, 7,
            true,
        )
    }

    #[test]
    fn mult_mod_large_quotient_test() {
        mult_mod_test(
            vec![65,1,1,1], // 33353
            vec![66,2,0,0], // 33920
            vec![2,6,6,1], // (33353 * 33920) % 2801 = 1457
            vec![5,3,6,1], // prime mod = 2801
            70, 70, 7, 7,
            true,
        )
    }




}

