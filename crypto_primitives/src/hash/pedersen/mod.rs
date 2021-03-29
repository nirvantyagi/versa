use ark_crypto_primitives::crh::{
    FixedLengthCRH as ArkFixedLengthCRH,
    pedersen::{CRH, Window},
};
use ark_ff::bytes::ToBytes;
use ark_ec::ProjectiveCurve;

use std::{
    io::Cursor,
};
use rand::Rng;

use crate::{
    hash::{HashError, FixedLengthCRH},
    Error,
};

pub mod constraints;

impl<C: ProjectiveCurve, W: Window> FixedLengthCRH for CRH<C, W> {
    const INPUT_SIZE_BITS: usize = W::WINDOW_SIZE * W::NUM_WINDOWS;
    type Output = <CRH<C, W> as ArkFixedLengthCRH>::Output;
    type Parameters = <CRH<C, W> as ArkFixedLengthCRH>::Parameters;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error> {
        <CRH<C, W> as ArkFixedLengthCRH>::setup(r)
    }

    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        if input.len() > <Self as FixedLengthCRH>::INPUT_SIZE_BITS / 8 {
            return Err(Box::new(HashError::InputSizeError(input.len())));
        }
        let mut padded_input = Vec::with_capacity(input.len());
        padded_input.extend_from_slice(input);
        padded_input.resize(<Self as FixedLengthCRH>::INPUT_SIZE_BITS / 8, 0);
        <CRH<C, W> as ArkFixedLengthCRH>::evaluate(parameters, &padded_input)
    }

    fn evaluate_variable_length(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        if input.len() <= <Self as FixedLengthCRH>::INPUT_SIZE_BITS / 8 {
            <Self as FixedLengthCRH>::evaluate(parameters, input)
        } else {
            let left = Self::evaluate_variable_length(parameters, &input[..input.len() / 2])?;
            let right = Self::evaluate_variable_length(parameters, &input[input.len() / 2..])?;
            Self::merge(parameters, &left, &right)
        }
    }

    //Note: Assumes half of input_size length of output is still collision-resistant
    fn merge(parameters: &Self::Parameters, left: &Self::Output, right: &Self::Output) -> Result<Self::Output, Error> {
        let mut left_buffer = vec![];
        let mut left_writer = Cursor::new(&mut left_buffer);
        left.write(&mut left_writer)?;
        let mut right_buffer = vec![];
        let mut right_writer = Cursor::new(&mut right_buffer);
        right.write(&mut right_writer)?;
        left_buffer.resize(<Self as FixedLengthCRH>::INPUT_SIZE_BITS / 16, 0);
        right_buffer.resize(<Self as FixedLengthCRH>::INPUT_SIZE_BITS / 16, 0);
        left_buffer.extend_from_slice(&right_buffer);
        <Self as FixedLengthCRH>::evaluate(parameters, &left_buffer)
    }
}