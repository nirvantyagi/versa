use std::convert::TryInto;
use digest::Digest;

use crate::{
    hash::{HashError, FixedLengthCRH},
    Error,
};

use std::marker::PhantomData;
use rand::Rng;

// Implementation of CRH for a hasher derived from the Rust Crypto Digest trait

pub struct CRHFromDigest<D: Digest> {
    _digest: PhantomData<D>,
}

impl<D: Digest> FixedLengthCRH for CRHFromDigest<D> {
    const INPUT_SIZE_BITS: usize = 256; // D::output_size() is not const - requires 256 bit output
    type Output = [u8; 32];
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        if D::output_size() != 32 {
            Err(Box::new(HashError::GeneralError("incorrect output size".to_string())))
        } else {
            Ok(())
        }
    }

    fn evaluate(_parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        match D::digest(input).to_vec().try_into() {
            Ok(arr) => Ok(arr),
            Err(_) => Err(Box::new(HashError::GeneralError("incorrect output size".to_string()))),
        }
    }

    fn evaluate_variable_length(_parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        match D::digest(input).to_vec().try_into() {
            Ok(arr) => Ok(arr),
            Err(_) => Err(Box::new(HashError::GeneralError("incorrect output size".to_string()))),
        }
    }

    fn merge(_parameters: &Self::Parameters, left: &Self::Output, right: &Self::Output) -> Result<Self::Output, Error> {
        let mut hasher = D::new();
        hasher.update(left.as_slice());
        hasher.update(right.as_slice());
        match hasher.finalize().to_vec().try_into() {
            Ok(arr) => Ok(arr),
            Err(_) => Err(Box::new(HashError::GeneralError("incorrect output size".to_string()))),
        }
    }
}