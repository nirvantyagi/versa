use algebra::{Field, PrimeField};
use r1cs_core::{SynthesisError, Namespace, ConstraintSystemRef};
use r1cs_std::{
    prelude::*,
    uint64::UInt64,
};

use crate::{constraints::SingleStepAVDGadget, rsa_avd::{RsaAVD, DigestWrapper, UpdateProofWrapper}};

use rsa::{
    hog::constraints::RsaHogVar,
    kvac::{RsaKVACParams},
    hash::{Hasher, constraints::HasherGadget},
    bignat::{constraints::BigNatCircuitParams},
    poker::constraints::ProofVar,
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

impl<ConstraintF: PrimeField, P: RsaKVACParams, C: BigNatCircuitParams> AllocVar<DigestWrapper<P>, ConstraintF> for DigestVar<ConstraintF, P, C> {
    fn new_variable<T: Borrow<DigestWrapper<P>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let f_out = f()?;
        let c0_var = RsaHogVar::<ConstraintF, P::RsaGroupParams, C>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().digest.0),
            mode,
        )?;
        let c1_var = RsaHogVar::<ConstraintF, P::RsaGroupParams, C>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().digest.1),
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
    type Value = DigestWrapper<P>;

    fn cs(&self) -> ConstraintSystemRef<ConstraintF> {
        self.c0.cs().or(self.c1.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(DigestWrapper {
            digest: (self.c0.value()?, self.c1.value()?),
            _params: PhantomData,
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

pub struct RsaAVDGadget<ConstraintF, P, H, CircuitH, CircuitHG, C>
    where
        ConstraintF: PrimeField,
        P: RsaKVACParams,
        H: Hasher,
        CircuitH: Hasher<F = ConstraintF>,
        CircuitHG: HasherGadget<CircuitH, ConstraintF>,
        C: BigNatCircuitParams,
{
    _kvac_params: PhantomData<P>,
    _hash: PhantomData<H>,
    _circuit_hash: PhantomData<CircuitH>,
    _circuit_hash_gadget: PhantomData<CircuitHG>,
    _circuit_params: PhantomData<C>,
}

impl<ConstraintF, P, H, CircuitH, CircuitHG, C> SingleStepAVDGadget<RsaAVD<P, H, CircuitH, C>, ConstraintF>
for RsaAVDGadget<ConstraintF, P, H, CircuitH, CircuitHG, C>
    where
        ConstraintF: PrimeField,
        P: RsaKVACParams,
        H: Hasher,
        CircuitH: Hasher<F = ConstraintF>,
        CircuitHG: HasherGadget<CircuitH, ConstraintF>,
        C: BigNatCircuitParams,
{
    type PublicParametersVar = EmptyVar;
    type DigestVar = DigestVar<ConstraintF, P, C>;
    type UpdateProofVar = UpdateProofVar<ConstraintF, P, C, CircuitH, CircuitHG>;

    fn check_update_proof(pp: &Self::PublicParametersVar, prev_digest: &Self::DigestVar, new_digest: &Self::DigestVar, proof: &Self::UpdateProofVar) -> Result<(), SynthesisError> {
        unimplemented!()
    }

    fn conditional_check_update_proof(pp: &Self::PublicParametersVar, prev_digest: &Self::DigestVar, new_digest: &Self::DigestVar, proof: &Self::UpdateProofVar, condition: &Boolean<ConstraintF>) -> Result<(), SynthesisError> {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct EmptyVar;

impl<ConstraintF: PrimeField> AllocVar<(), ConstraintF> for EmptyVar {
    fn new_variable<T: Borrow<()>>(_cs: impl Into<Namespace<ConstraintF>>, _f: impl FnOnce() -> Result<T, SynthesisError>, _mode: AllocationMode) -> Result<Self, SynthesisError> {
        Ok(EmptyVar)
    }
}

