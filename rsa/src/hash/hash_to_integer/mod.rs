use algebra::{PrimeField, FpParameters};
use crate::{
    bignat::{BigNat, f_to_nat},
    hash::{Hasher, low_k_bits},
};
use std::ops::AddAssign;
use num_traits::identities::{One};

pub fn hash_to_integer<H: Hasher>(inputs: &[H::F], n_bits: usize) -> BigNat {
    let bits_per_hash = <<H::F as PrimeField>::Params as FpParameters>::CAPACITY as usize;

    let bits_from_hash = n_bits - 1;
    let n_hashes = (bits_from_hash - 1) / bits_per_hash + 1;

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

    // Assemble the number - notice the ORs are disjoint.
    let mut acc = BigNat::from(0);
    acc |= low_k_bits(&sum_of_hashes, bits_from_hash);
    acc |= BigNat::from(1) << (n_bits - 1) as u32;
    acc
}

