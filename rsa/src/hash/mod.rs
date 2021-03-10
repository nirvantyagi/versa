use algebra::{
    biginteger::BigInteger,
    fields::{PrimeField, FpParameters},
};

use crate::{
    bignat::{BigNat, f_to_nat},
    Error,
};
use crypto_primitives::poseidon::{PoseidonSponge, AlgebraicSponge};

use std::{
    fmt::{self, Debug},
    error::Error as ErrorTrait,
    marker::PhantomData,
    cmp::min,
    ops::AddAssign,
    io::Cursor,
};

use num_traits::identities::{Zero, One};
use digest::Digest;

pub mod constraints;
pub mod hash_to_integer;
pub mod hash_to_prime;

/// A representation of an integer range to hash to
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HashRangeParams {
    pub n_bits: usize,
    pub n_trailing_ones: usize,
}

impl HashRangeParams {
    pub fn nonce_width(&self) -> usize {
        let n_rounds = -128f64 * 2f64.ln() / (1f64 - 2f64 / self.n_bits as f64).ln();
        let n_bits = (n_rounds.log2().ceil() + 0.1) as usize;
        n_bits
    }
}

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



//TODO: Need to ensure hash range is greater than KVAC value domain

/// Given hash inputs, and a target domain for the prime hash, computes:
///
///    * an appropriate bitwidth for a nonce such that there exists a nonce appendable to the
///    inputs which will result in a prime hash with probability at least 1 - 2 ** -128
///    * the first such nonce in the range defined by the bitwidth
///    * the prime hash
///
/// and returns a tuple `(hash, nonce)`.
///
/// If, by misfortune, there is no such nonce, returns `None`.
pub fn hash_to_prime<H: Hasher>(
    inputs: &[H::F],
    params: &HashRangeParams,
) -> Result<(BigNat, H::F), Error> {
    let n_bits = params.nonce_width();
    let mut inputs: Vec<H::F> = inputs.iter().copied().collect();
    inputs.push(H::F::zero());
    for _ in 0..(1 << n_bits) {
        let hash = hash_to_integer::<H>(&inputs, params);
        if miller_rabin(&hash, 30) {
            // unwrap is safe because of the push above
            return Ok((hash, inputs.pop().unwrap()));
        }
        // unwrap is safe because of the push above
        inputs.last_mut().unwrap().add_assign(&H::F::one());
    }
    Err(Box::new(HashToPrimeError::NoValidNonce))
}



pub fn hash_to_integer<H: Hasher>(inputs: &[H::F], params: &HashRangeParams) -> BigNat {
    let bits_per_hash = <<H::F as PrimeField>::Params as FpParameters>::CAPACITY as usize;

    let bits_from_hash = params.n_bits - 1 - params.n_trailing_ones;
    let n_hashes = (bits_from_hash - 1) / bits_per_hash + 1;

    // First we hash the inputs
    let hash = H::hash(inputs);

    // Then, to get more bits, we extend additively
    let mut sum_of_hashes = low_k_bits(&f_to_nat(&hash), bits_per_hash);
    let mut perm = hash;
    for i in 1..n_hashes {
        perm.add_assign(&H::F::one());
        let low_bits = low_k_bits(&f_to_nat(&perm), bits_per_hash);
        sum_of_hashes += low_bits << (bits_per_hash * i) as u32;
    }

    // Now we assemble the 1024b number. Notice the ORs are all disjoint.
    let mut acc = (BigNat::from(1) << params.n_trailing_ones as u32) - BigNat::from(1usize);
    acc |= low_k_bits(&sum_of_hashes, bits_from_hash) << params.n_trailing_ones as u32;
    acc |= BigNat::from(1) << (params.n_bits - 1) as u32;
    acc
}

/// Returns whether `n` passes Miller-Rabin checks with the first `rounds` primes as bases
pub fn miller_rabin(n: &BigNat, rounds: usize) -> bool {
    fn primes(n: usize) -> Vec<usize> {
        let mut ps = vec![2];
        let mut next = 3;
        while ps.len() < n {
            if !ps.iter().any(|p| next % p == 0) {
                ps.push(next);
            }
            next += 1;
        }
        ps
    }
    let ps = primes(rounds);
    !ps.into_iter()
        .any(|p| !miller_rabin_round(n, &BigNat::from(p)))
}

/// Returns whether `n` passes a Miller-Rabin check with base `b`.
fn miller_rabin_round(n: &BigNat, b: &BigNat) -> bool {
    let n_less_one = BigNat::from(n - 1);
    let mut d = BigNat::from(n - 1);
    let d_bits = d.to_string_radix(2);
    let last_one = d_bits.as_str().rfind('1').expect("Input must be >1");
    if last_one == d_bits.len() - 1 {
        return false;
    }
    let s = d_bits.len() - last_one - 1;
    d >>= s as u32;
    let mut pow = BigNat::from(b.pow_mod_ref(&d, &n).unwrap());
    if pow == BigNat::from(1usize) || pow == n_less_one {
        return true;
    }
    for _ in 0..(s - 1) {
        pow.square_mut();
        pow %= n;
        if pow == n_less_one {
            return true;
        }
    }
    return false;
}

/// Given an integer, returns the integer with its low `k` bits.
pub fn low_k_bits(n: &BigNat, k: usize) -> BigNat {
    n.clone().keep_bits(k as u32)
}


#[derive(Debug)]
pub enum HashToPrimeError {
    NoValidNonce,
}

impl ErrorTrait for HashToPrimeError{
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for HashToPrimeError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            HashToPrimeError::NoValidNonce => format!("No valid nonce found"),
        };
        write!(f, "{}", msg)
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
