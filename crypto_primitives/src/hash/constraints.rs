use ark_ff::Field;
use core::fmt::Debug;

use crate::hash::FixedLengthCRH;
use ark_relations::r1cs::SynthesisError;
use ark_r1cs_std::prelude::*;

pub trait FixedLengthCRHGadget<H: FixedLengthCRH, ConstraintF: Field>: Sized {
    type OutputVar: EqGadget<ConstraintF>
    + ToBytesGadget<ConstraintF>
    + CondSelectGadget<ConstraintF>
    + AllocVar<H::Output, ConstraintF>
    + R1CSVar<ConstraintF>
    + Debug
    + Clone
    + Sized;

    type ParametersVar: AllocVar<H::Parameters, ConstraintF> + Clone;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError>;

    fn evaluate_variable_length(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError>;

    fn merge(
        parameters: &Self::ParametersVar,
        left: &Self::OutputVar,
        right: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError>;
}