use algebra::{PrimeField, BitIteratorBE, FpParameters};
use r1cs_core::{SynthesisError, Namespace, ConstraintSystemRef};
use r1cs_std::{
    prelude::*,
    fields::fp::FpVar,
};

use crate::{
    bignat::{
        BigNat,
        constraints::{BigNatCircuitParams, BigNatVar},
    },
    hog::{RsaHiddenOrderGroup, RsaGroupParams},
};

use std::{
    borrow::Borrow,
    marker::PhantomData,
    cmp::{min, max},
};

#[derive(Clone)]
pub struct RsaHogVar<ConstraintF: PrimeField, RsaP: RsaGroupParams, CircuitP: BigNatCircuitParams> {
    n: BigNatVar<ConstraintF, CircuitP>,
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
