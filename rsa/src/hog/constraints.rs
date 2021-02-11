use algebra::PrimeField;
use r1cs_core::{SynthesisError, Namespace};
use r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::ToBytesGadget,
    eq::{EqGadget},
    select::CondSelectGadget,
    uint64::UInt64, uint8::UInt8,
    boolean::Boolean,
    fields::fp::FpVar,
};
use std::marker::PhantomData;

use crate::{
    bignat::{constraints::BigNatVar},
    hog::RsaGroupParams,
};

#[derive(Clone)]
pub struct RsaHogVar<P: RsaGroupParams, ConstraintF: PrimeField> {
    n: BigNatVar<ConstraintF>,
    _params: PhantomData<P>,
}
