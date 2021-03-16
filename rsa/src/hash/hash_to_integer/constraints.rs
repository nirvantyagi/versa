use algebra::{PrimeField, FpParameters};
use r1cs_std::{
    prelude::*,
    fields::fp::FpVar,
};
use r1cs_core::{ConstraintSystemRef, SynthesisError};

use crate::{
    bignat::constraints::{BigNatCircuitParams, BigNatVar},
    hash::{Hasher, constraints::HasherGadget},
};

use std::ops::AddAssign;

#[tracing::instrument(target = "r1cs", skip(cs, inputs, n_bits, result))]
pub fn check_hash_to_integer<H, HG, ConstraintF, P>(
    cs: ConstraintSystemRef<ConstraintF>,
    inputs: &[FpVar<ConstraintF>],
    n_bits: usize,
    result: &BigNatVar<ConstraintF, P>,
) -> Result<(), SynthesisError>
    where
    H: Hasher<F = ConstraintF>,
    HG: HasherGadget<H, ConstraintF>,
    ConstraintF: PrimeField,
    P: BigNatCircuitParams,
{
    let bits_per_hash = <ConstraintF::Params as FpParameters>::CAPACITY as usize;
    let n_hashes = (n_bits - 1 - 1) / bits_per_hash + 1;

    // Hash the inputs
    let hash = HG::hash(cs.clone(), inputs)?;

    // Extend additively to get more bits
    let mut hash_bits = BigNatVar::<ConstraintF, P>::enforce_limb_fits_in_bits(&hash, bits_per_hash)?;
    let mut perm = hash.clone();
    for _ in 1..n_hashes {
        perm.add_assign(&FpVar::<ConstraintF>::one());
        hash_bits.extend(
            BigNatVar::<ConstraintF, P>::enforce_limb_fits_in_bits(&perm, bits_per_hash)?
        );
    }

    // Set high bit
    hash_bits[n_bits - 1] = Boolean::<ConstraintF>::TRUE;
    result.enforce_equals_bits(&hash_bits[..n_bits])
}


#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{ed_on_bls12_381::{Fq}, UniformRand};
    use r1cs_core::{ConstraintSystem};
    use rand::{rngs::StdRng, SeedableRng};

    use crate::hash::{
        PoseidonHasher, constraints::PoseidonHasherGadget,
        hash_to_integer::hash_to_integer,
    };

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNatTestParams;

    impl BigNatCircuitParams for BigNatTestParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 64;
    }

    pub type H = PoseidonHasher<Fq>;
    pub type HG = PoseidonHasherGadget<Fq>;

    #[test]
    fn valid_integer_hash_trivial_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let cs = ConstraintSystem::<Fq>::new_ref();
        let input = vec![Fq::rand(&mut rng); 12];
        let h = hash_to_integer::<H>(&input, 128);
        let inputvar = Vec::<FpVar<Fq>>::new_witness(
            r1cs_core::ns!(cs, "input"),
            || Ok(&input[..]),
        ).unwrap();
        let hvar = BigNatVar::<Fq, BigNatTestParams>::new_witness(
            r1cs_core::ns!(cs, "h"),
            || Ok(&h),
        ).unwrap();
        check_hash_to_integer::<H, HG, _, _>(
            cs.clone(),
            &inputvar,
            128,
            &hvar,
        ).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

}
