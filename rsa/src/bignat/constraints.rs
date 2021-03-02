use algebra::{PrimeField, BitIteratorBE, FpParameters};
use r1cs_core::{SynthesisError, Namespace, ConstraintSystemRef};
use r1cs_std::{
    prelude::*,
    fields::fp::FpVar,
};

use crate::bignat::{BigNat, fit_nat_to_limbs, limbs_to_nat, nat_to_f, f_to_nat};

use std::{
    borrow::Borrow,
    marker::PhantomData,
    cmp::{min, max},
};


pub trait BigNatCircuitParams: Clone {
    const LIMB_WIDTH: usize;
    const N_LIMBS: usize;
}

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
        let limbs = fit_nat_to_limbs(f_out.borrow(), P::LIMB_WIDTH).unwrap();
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
    /// Constrain `self` to be equal to `other`, after carrying both.
    #[tracing::instrument(target = "r1cs", skip(self, other))]
    fn enforce_equal_when_carried(
        &self,
        other: &Self,
    ) -> Result<(), SynthesisError> {
        let cs = self.cs().or(other.cs());

        // Propagate carries over fixed length of limbs.
        let target_base = BigNat::from(1) << P::LIMB_WIDTH as u32;
        let current_word_size = max(&self.word_size, &other.word_size);

        let carry_bits = (((current_word_size.to_f64() * 2.0).log2() - P::LIMB_WIDTH as f64).ceil() + 0.1) as usize;
        let carry_bits2 = (current_word_size.significant_bits() as usize - P::LIMB_WIDTH + 1) as usize;
        assert_eq!(carry_bits, carry_bits2);
        println!("target_base: {}, current_word_size: {}, carry_bits: {}", target_base.clone(), current_word_size.clone(), carry_bits);

        let mut carry_in = <FpVar<ConstraintF>>::zero();
        let mut accumulated_extra = BigNat::from(0);

        for (i, (left_limb, right_limb)) in self.limbs.iter()
            .zip(&other.limbs).enumerate() {
            println!("Round {}:", i);
            let left_limb_value = left_limb.value()?;
            let right_limb_value = right_limb.value()?;
            let carry_in_value = carry_in.value()?;
            println!("left: {}, right: {}, carry_in: {}", f_to_nat(&left_limb_value), f_to_nat(&right_limb_value), f_to_nat(&carry_in_value));

            let carry_value = nat_to_f::<ConstraintF>(
                &(
                    (f_to_nat(&left_limb_value) + f_to_nat(&carry_in_value) - f_to_nat(&right_limb_value) + current_word_size.clone())
                        / target_base.clone()
                )
            ).unwrap();
            println!("carry: {}", f_to_nat(&carry_value));
            let carry = <FpVar<ConstraintF>>::new_witness(cs.clone(), || Ok(carry_value))?;

            accumulated_extra += current_word_size.clone();
            println!("accumulated_extra: {}", accumulated_extra.clone());

            let (tmp_accumulated_extra, remainder) = accumulated_extra.div_rem(target_base.clone());
            accumulated_extra = tmp_accumulated_extra;
            let remainder_limb = nat_to_f::<ConstraintF>(&remainder).unwrap();

            let eqn_left: FpVar<ConstraintF> = left_limb
                + &carry_in - right_limb
                + nat_to_f::<ConstraintF>(&current_word_size).unwrap();
            let eqn_right = &carry * nat_to_f::<ConstraintF>(&target_base).unwrap()
                + remainder_limb;
            println!("eqn_right: {}, eqn_left: {}, i: {}", f_to_nat(&eqn_right.value().unwrap()), f_to_nat(&eqn_left.value().unwrap()), i);
            eqn_left.enforce_equal(&eqn_right)?;

            if i < P::N_LIMBS - 1 {
                Self::enforce_fits_in_bits(&carry, carry_bits)?;
            } else {
                carry.enforce_equal(&FpVar::<ConstraintF>::Constant(nat_to_f::<ConstraintF>(&accumulated_extra).unwrap()))?;
            }

            carry_in = carry.clone();
        }
        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(limb, n_bits))]
    fn enforce_fits_in_bits(
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

}
