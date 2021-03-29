use ark_crypto_primitives::crh::{
    constraints::FixedLengthCRHGadget as ArkFixedLengthCRHGadget,
    pedersen::{CRH, constraints::CRHGadget, Window},
};
use ark_ff::{
    fields::Field,
};
use ark_ec::ProjectiveCurve;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{SynthesisError};

use crate::{
    hash::{
        FixedLengthCRH,
        constraints::FixedLengthCRHGadget,
    },
};

type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

impl<C, GG, W> FixedLengthCRHGadget<CRH<C, W>, ConstraintF<C>> for CRHGadget<C, GG, W>
    where
        C: ProjectiveCurve,
        GG: CurveVar<C, ConstraintF<C>>,
        W: Window,
        for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type OutputVar = <Self as ArkFixedLengthCRHGadget<CRH<C, W>, ConstraintF<C>>>::OutputVar;
    type ParametersVar = <Self as ArkFixedLengthCRHGadget<CRH<C, W>, ConstraintF<C>>>::ParametersVar;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF<C>>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        assert!(input.len() <= CRH::<C, W>::INPUT_SIZE_BITS / 8);
        let mut buffer = input.to_vec();
        buffer.resize(CRH::<C, W>::INPUT_SIZE_BITS / 8, UInt8::constant(0u8));
        <Self as ArkFixedLengthCRHGadget<CRH<C, W>, ConstraintF<C>>>::evaluate(parameters, &buffer)
    }

    fn evaluate_variable_length(parameters: &Self::ParametersVar, input: &[UInt8<ConstraintF<C>>]) -> Result<Self::OutputVar, SynthesisError> {
        if input.len() <= CRH::<C, W>::INPUT_SIZE_BITS / 8 {
            <Self as FixedLengthCRHGadget<CRH<C, W>, ConstraintF<C>>>::evaluate(parameters, input)
        } else {
            let left = Self::evaluate_variable_length(parameters, &input[..input.len() / 2])?;
            let right = Self::evaluate_variable_length(parameters, &input[input.len() / 2..])?;
            Self::merge(parameters, &left, &right)
        }
    }

    fn merge(parameters: &Self::ParametersVar, left: &Self::OutputVar, right: &Self::OutputVar) -> Result<Self::OutputVar, SynthesisError> {
        // Little endian byte representation (must match serialization in FixedLengthCRH::merge)
        let mut buffer = left.to_bytes()?;
        buffer.resize(CRH::<C, W>::INPUT_SIZE_BITS / 16, UInt8::constant(0u8));
        buffer.extend_from_slice(&right.to_bytes()?);
        buffer.resize(CRH::<C, W>::INPUT_SIZE_BITS / 8, UInt8::constant(0u8));
        <Self as FixedLengthCRHGadget<CRH<C, W>, ConstraintF<C>>>::evaluate(parameters, &buffer)
    }
}