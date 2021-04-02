use ark_ff::bytes::ToBytes;
use std::{
    hash::Hash, fmt,
    error::Error as ErrorTrait,
};
use rand::Rng;

use crate::Error;

pub mod constraints;
pub mod pedersen;
pub mod poseidon;

// Wrapper around arkworks/crypto_primitives/crh to allow Poseidon without intermediate bytes
// https://github.com/arkworks-rs/crypto-primitives/tree/main/src/crh


//Note: Parameters must be chosen to allow for input length merging two fixed length outputs
pub trait FixedLengthCRH {
    const INPUT_SIZE_BITS: usize;

    type Output: ToBytes + Clone + Eq + core::fmt::Debug + Hash + Default;
    type Parameters: Clone + Default + Send + Sync;

    fn setup<R: Rng>(r: &mut R) -> Result<Self::Parameters, Error>;
    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error>;
    fn evaluate_variable_length(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error>;
    fn merge(parameters: &Self::Parameters, left: &Self::Output, right: &Self::Output) -> Result<Self::Output, Error>;
}

#[derive(Debug)]
pub enum HashError {
    InputSizeError(usize),
}

impl ErrorTrait for HashError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for HashError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            HashError::InputSizeError(inp) => format!("invalid input size: {}", inp),
        };
        write!(f, "{}", msg)
    }
}

