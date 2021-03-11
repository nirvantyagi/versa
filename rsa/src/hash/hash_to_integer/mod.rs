use algebra::{PrimeField, FpParameters};
use crate::{
    bignat::{BigNat, f_to_nat},
    hash::{Hasher},
};
use std::ops::AddAssign;
use num_traits::identities::{One};

pub mod constraints;

pub fn hash_to_integer<H: Hasher>(inputs: &[H::F], n_bits: usize) -> BigNat {
    let bits_per_hash = <<H::F as PrimeField>::Params as FpParameters>::CAPACITY as usize;
    // Fix high bit to 1
    let n_hashes = (n_bits - 1 - 1) / bits_per_hash + 1;

    // Hash the inputs
    let hash = H::hash(inputs);

    // Extend additively to get more bits
    let mut sum_of_hashes = low_k_bits(&f_to_nat(&hash), bits_per_hash);
    let mut perm = hash;
    for i in 1..n_hashes {
        perm.add_assign(&H::F::one());
        let low_bits = low_k_bits(&f_to_nat(&perm), bits_per_hash);
        sum_of_hashes += low_bits << (bits_per_hash * i) as u32;
    }

    // Set high bit
    let mut acc = low_k_bits(&sum_of_hashes, n_bits - 1);
    acc |= BigNat::from(1) << (n_bits - 1) as u32;
    acc
}


/// Given an integer, returns the integer with its low `k` bits.
pub fn low_k_bits(n: &BigNat, k: usize) -> BigNat {
    n.clone().keep_bits(k as u32)
}
