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


pub trait BigNatCircuitParams: Clone {
    const LIMB_WIDTH: usize;
}

#[derive(Clone)]
pub struct BigNatVar<ConstraintF: PrimeField> {
    limbs: Vec<FpVar<ConstraintF>>,
}
