use algebra::PrimeField;
use r1cs_core::{SynthesisError, Namespace, ConstraintSystemRef};
use r1cs_std::{
    prelude::*,
    fields::fp::FpVar,
};

use crate::bignat::{BigNat, fit_nat_to_limbs, limbs_to_nat};

use std::{
    borrow::Borrow,
    marker::PhantomData,
    cmp::{min, max},
};


pub trait BigNatCircuitParams: Clone {
    const LIMB_WIDTH: usize;
}

#[derive(Clone)]
pub struct BigNatVar<ConstraintF: PrimeField, P: BigNatCircuitParams> {
    limbs: Vec<FpVar<ConstraintF>>,
    value: BigNat,
    max_word: BigNat,
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
            max_word: (BigNat::from(1) << P::LIMB_WIDTH as u32) - 1,
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
        let limbs = self.limbs.iter()
            .map(|f|  f.value() )
            .collect::<Result<Vec<ConstraintF>, SynthesisError>>()?;
        let value = limbs_to_nat(limbs.as_slice(), P::LIMB_WIDTH);
        debug_assert_eq!(self.value, value);
        Ok(value)
    }
}


impl<ConstraintF: PrimeField, P: BigNatCircuitParams> BigNatVar<ConstraintF, P> {

    /// Constrain `self` to be equal to `other`, after carrying both.
    fn enforce_equal_when_carried(
        &self,
        other: &Self,
    ) -> Result<(), SynthesisError> {

        // Propagate carries over the first `n` limbs.
        let n = min(self.limbs.len(), other.limbs.len());
        let target_base = BigNat::from(1) << P::LIMB_WIDTH as u32;
        let mut accumulated_extra = BigNat::from(0);
        let max_word = max(&self.max_word, &other.max_word);
        let carry_bits = (((max_word.to_f64() * 2.0).log2() - self.params.limb_width as f64).ceil() + 0.1) as usize;

        let mut carry_in = Num::new(Some(E::Fr::zero()), LinearCombination::zero());

        for i in 0..n {
            let carry = Num::alloc(cs.namespace(|| format!("carry value {}", i)), || {
                Ok(nat_to_f(
                    &((f_to_nat(&self.limb_values.grab()?[i])
                        + f_to_nat(&carry_in.value.unwrap())
                        + max_word
                        - f_to_nat(&other.limb_values.grab()?[i]))
                        / &target_base),
                )
                    .unwrap())
            })?;
            accumulated_extra += max_word;

            cs.enforce(
                || format!("carry {}", i),
                |lc| lc,
                |lc| lc,
                |lc| {
                    lc + &carry_in.num + &self.limbs[i] - &other.limbs[i]
                        + (nat_to_f(&max_word).unwrap(), CS::one())
                        - (nat_to_f(&target_base).unwrap(), &carry.num)
                        - (
                        nat_to_f(&Integer::from(&accumulated_extra % &target_base)).unwrap(),
                        CS::one(),
                    )
                },
            );

            accumulated_extra /= &target_base;

            if i < n - 1 {
                carry.fits_in_bits(cs.namespace(|| format!("carry {} decomp", i)), carry_bits)?;
            } else {
                cs.enforce(
                    || format!("carry {} is out", i),
                    |lc| lc,
                    |lc| lc,
                    |lc| lc + &carry.num - (nat_to_f(&accumulated_extra).unwrap(), CS::one()),
                );
            }
            carry_in = Num::from(carry);
        }

        for (i, zero_limb) in self.limbs.iter().enumerate().skip(n) {
            cs.enforce(
                || format!("zero self {}", i),
                |lc| lc,
                |lc| lc,
                |lc| lc + zero_limb,
            );
        }
        for (i, zero_limb) in other.limbs.iter().enumerate().skip(n) {
            cs.enforce(
                || format!("zero other {}", i),
                |lc| lc,
                |lc| lc,
                |lc| lc + zero_limb,
            );
        }
        Ok(())
    }

}
