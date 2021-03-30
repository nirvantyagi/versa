use ark_ff::{PrimeField};
use ark_r1cs_std::{
    prelude::*,
    fields::fp::FpVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use std::marker::PhantomData;

use crate::hash::{Hasher, PoseidonHasher};
use crypto_primitives::hash::poseidon::constraints::{PoseidonSpongeVar, AlgebraicSpongeVar};

pub trait HasherGadget<H, ConstraintF>: Sized
where
    ConstraintF: PrimeField,
    H: Hasher<F = ConstraintF>,
{
    fn hash2(cs: ConstraintSystemRef<ConstraintF>, a: &FpVar<ConstraintF>, b: &FpVar<ConstraintF>) -> Result<FpVar<ConstraintF>, SynthesisError>;

    fn hash(cs: ConstraintSystemRef<ConstraintF>, inputs: &[FpVar<ConstraintF>]) -> Result<FpVar<ConstraintF>, SynthesisError> {
        let mut acc = <FpVar<ConstraintF>>::zero();
        for input in inputs {
            acc = Self::hash2(cs.clone(), &acc, input)?;
        }
        Ok(acc)
    }

    fn hash_to_variable_output(
        cs: ConstraintSystemRef<ConstraintF>,
        inputs: &[FpVar<ConstraintF>],
        output_len: usize,
    ) -> Result<Vec<FpVar<ConstraintF>>, SynthesisError> {
        let mut output = vec![Self::hash(cs.clone(), inputs)?];
        for _ in 1..output_len {
            output.push(Self::hash(cs.clone(), &[output.last().unwrap().clone()])?);
        }
        Ok(output)
    }
}

/// Wrapper around Poseidon hash function
#[derive(Clone)]
pub struct PoseidonHasherGadget<F: PrimeField> {
    _field: PhantomData<F>,
}

impl<F: PrimeField> HasherGadget<PoseidonHasher<F>, F> for PoseidonHasherGadget<F> {

    fn hash2(cs: ConstraintSystemRef<F>, a: &FpVar<F>, b: &FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
        let mut sponge = PoseidonSpongeVar::new(cs);
        sponge.absorb(&[a.clone(), b.clone()])?;
        Ok(sponge.squeeze(1)?[0].clone())
    }

    #[tracing::instrument(target = "r1cs", skip(cs, inputs))]
    fn hash(cs: ConstraintSystemRef<F>, inputs: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
        let mut sponge = PoseidonSpongeVar::new(cs);
        sponge.absorb(inputs)?;
        Ok(sponge.squeeze(1)?[0].clone())
    }

    #[tracing::instrument(target = "r1cs", skip(cs, inputs, output_len))]
    fn hash_to_variable_output(
        cs: ConstraintSystemRef<F>,
        inputs: &[FpVar<F>],
        output_len: usize,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut sponge = PoseidonSpongeVar::new(cs);
        sponge.absorb(inputs)?;
        sponge.squeeze(output_len)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{UniformRand};
    use ark_ed_on_bls12_381::{Fq};
    use ark_relations::r1cs::{ConstraintSystem};
    use rand::{rngs::StdRng, SeedableRng};


    pub type H = PoseidonHasher<Fq>;
    pub type HG = PoseidonHasherGadget<Fq>;

    #[test]
    fn valid_poseidon_trivial_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let cs = ConstraintSystem::<Fq>::new_ref();
        let input = vec![Fq::rand(&mut rng); 12];
        let h = H::hash(&input);
        let inputvar = Vec::<FpVar<Fq>>::new_witness(
            ark_relations::ns!(cs, "input"),
            || Ok(&input[..]),
        ).unwrap();
        let hvar = <FpVar<Fq>>::new_witness(
            ark_relations::ns!(cs, "h"),
            || Ok(&h),
        ).unwrap();
        let result = HG::hash(
            cs.clone(),
            &inputvar,
        ).unwrap();
        hvar.enforce_equal(&result).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

}
