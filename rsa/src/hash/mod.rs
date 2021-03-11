use algebra::{
    biginteger::BigInteger,
    fields::{PrimeField, FpParameters},
};

use crypto_primitives::poseidon::{PoseidonSponge, AlgebraicSponge};

use std::{
    marker::PhantomData,
    cmp::min,
    io::Cursor,
};

use num_traits::identities::{Zero};
use digest::Digest;

pub mod constraints;
pub mod hash_to_integer;
pub mod hash_to_prime;

pub trait Hasher: Clone {
    type F: PrimeField;

    fn hash2(a: Self::F, b: Self::F) -> Self::F;

    fn hash(inputs: &[Self::F]) -> Self::F {
        let mut acc = Self::F::zero();
        for input in inputs {
            acc = Self::hash2(acc, input.clone());
        }
        acc
    }

    fn hash_to_variable_output(inputs: &[Self::F], output_len: usize) -> Vec<Self::F> {
        let mut output = vec![Self::hash(inputs)];
        for _ in 1..output_len {
            output.push(Self::hash(&[output.last().unwrap().clone()]));
        }
        output
    }
}

/// Wrapper around Poseidon hash function
#[derive(Clone)]
pub struct PoseidonHasher<F: PrimeField> {
    _field: PhantomData<F>,
}

impl<F: PrimeField> Hasher for PoseidonHasher<F> {
    type F = F;

    fn hash2(a: Self::F, b: Self::F) -> Self::F {
        let mut sponge = PoseidonSponge::new();
        sponge.absorb(&[a, b]);
        sponge.squeeze(1)[0].clone()
    }

    fn hash(inputs: &[Self::F]) -> Self::F {
        let mut sponge = PoseidonSponge::new();
        sponge.absorb(inputs);
        sponge.squeeze(1)[0].clone()
    }

    fn hash_to_variable_output(inputs: &[Self::F], output_len: usize) -> Vec<Self::F> {
        let mut sponge = PoseidonSponge::new();
        sponge.absorb(inputs);
        sponge.squeeze(output_len)
    }
}

pub struct HasherFromDigest<F: PrimeField, D: Digest> {
    _field: PhantomData<F>,
    _digest: PhantomData<D>,
}

impl<F: PrimeField, D: Digest> Clone for HasherFromDigest<F, D>{
    fn clone(&self) -> Self {
        HasherFromDigest {
            _field: PhantomData,
            _digest: PhantomData,
        }
    }
}

impl<F: PrimeField, D: Digest> Hasher for HasherFromDigest<F, D>{
    type F = F;

    fn hash2(a: Self::F, b: Self::F) -> Self::F {
        let byte_capacity = min(D::output_size(), <F::Params as FpParameters>::CAPACITY as usize / 8);
        let mut writer = Cursor::new(vec![0u8; <F as PrimeField>::BigInt::NUM_LIMBS * 8 * 2]);
        a.write(&mut writer).unwrap();
        b.write(&mut writer).unwrap();
        let h = D::digest(writer.get_ref());
        let mut f_buffer = vec![0u8; <F as PrimeField>::BigInt::NUM_LIMBS * 8];
        f_buffer.iter_mut().zip(&h.as_slice()[..byte_capacity]).for_each(|(a, b)| *a = *b);
        F::read(f_buffer.as_slice()).unwrap()
    }
}
