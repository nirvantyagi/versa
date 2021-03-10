use algebra::{PrimeField, FpParameters, BitIteratorLE};
use r1cs_std::{
    prelude::*,
    fields::fp::FpVar,
};
use r1cs_core::{ConstraintSystemRef, SynthesisError, Namespace};

use std::{
    borrow::Borrow,
    marker::PhantomData,
};

use crate::{
    bignat::{BigNat, constraints::{BigNatCircuitParams, BigNatVar},},
    hash::{
        Hasher, constraints::HasherGadget,
        hash_to_prime::{PlannedExtension, PocklingtonCertificate, ExtensionCertificate},
    },
};

#[derive(Clone)]
pub struct PocklingtonCertificateVar<ConstraintF, P, H, HG>
where
    ConstraintF: PrimeField,
    H: Hasher<F = ConstraintF>,
    HG: HasherGadget<H, ConstraintF>,
    P: BigNatCircuitParams,
{
    pub base_plan: PlannedExtension,
    pub base_prime: BigNatVar<ConstraintF, P>,
    pub base_nonce_as_bits: Vec<Boolean<ConstraintF>>,
    pub extensions: Vec<ExtensionCertificateVar<ConstraintF, P>>,
    pub result: BigNatVar<ConstraintF, P>,
    _hash: PhantomData<H>,
    _hash_gadget: PhantomData<HG>,
}


#[derive(Clone)]
pub struct ExtensionCertificateVar<ConstraintF: PrimeField, P: BigNatCircuitParams> {
    pub plan: PlannedExtension,
    pub nonce_as_bits: Vec<Boolean<ConstraintF>>,
    pub checking_base: BigNatVar<ConstraintF, P>,
}

impl<ConstraintF, P, H, HG> AllocVar<PocklingtonCertificate<H>, ConstraintF> for PocklingtonCertificateVar<ConstraintF, P, H, HG>
where
ConstraintF: PrimeField,
H: Hasher<F = ConstraintF>,
HG: HasherGadget<H, ConstraintF>,
P: BigNatCircuitParams,
{
    fn new_variable<T: Borrow<PocklingtonCertificate<H>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let f_out = f()?;

        let base_plan = f_out.borrow().base_plan.clone();
        let nonce_as_bits_var = BitIteratorLE::new([f_out.borrow().base_nonce as u64])
            .take(base_plan.nonce_bits)
            .map(|b| Boolean::<ConstraintF>::new_variable(cs.clone(), || Ok(&b), mode))
            .collect::<Result<Vec<Boolean<ConstraintF>>, SynthesisError>>()?;
        let base_prime_var = BigNatVar::<ConstraintF, P>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().base_prime),
            mode,
        )?;
        let extensions_var = <Vec<ExtensionCertificateVar<ConstraintF, P>>>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().extensions[..]),
            mode,
        )?;
        let result_var = BigNatVar::<ConstraintF, P>::new_variable(
            cs.clone(),
            || Ok(f_out.borrow().result()),
            mode,
        )?;
        Ok(PocklingtonCertificateVar{
            base_plan,
            base_prime: base_prime_var,
            base_nonce_as_bits: nonce_as_bits_var,
            extensions: extensions_var,
            result: result_var,
            _hash: PhantomData,
            _hash_gadget: PhantomData,
        })
    }
}

impl<ConstraintF, P> AllocVar<ExtensionCertificate, ConstraintF> for ExtensionCertificateVar<ConstraintF, P>
    where
        ConstraintF: PrimeField,
        P: BigNatCircuitParams,
{
    fn new_variable<T: Borrow<ExtensionCertificate>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let f_out = f()?;

        let plan = f_out.borrow().plan.clone();
        let nonce_as_bits_var = BitIteratorLE::new([f_out.borrow().nonce])
            .take(plan.nonce_bits)
            .map(|b| Boolean::<ConstraintF>::new_variable(cs.clone(), || Ok(&b), mode))
            .collect::<Result<Vec<Boolean<ConstraintF>>, SynthesisError>>()?;
        let checking_base_var = BigNatVar::<ConstraintF, P>::new_variable(
            cs.clone(),
            || Ok(&f_out.borrow().checking_base),
            mode,
        )?;
        Ok(ExtensionCertificateVar{
            plan,
            nonce_as_bits: nonce_as_bits_var,
            checking_base: checking_base_var,
        })
    }
}


#[tracing::instrument(target = "r1cs", skip(cs, inputs, entropy, cert))]
pub fn check_hash_to_pocklington_prime<H, HG, ConstraintF, P>(
    cs: ConstraintSystemRef<ConstraintF>,
    inputs: &[FpVar<ConstraintF>],
    entropy: usize,
    cert: &PocklingtonCertificateVar<ConstraintF, P, H, HG>,
) -> Result<(), SynthesisError>
    where
        H: Hasher<F = ConstraintF>,
        HG: HasherGadget<H, ConstraintF>,
        ConstraintF: PrimeField,
        P: BigNatCircuitParams,
{
    // Compute randomness to use when checking certificate
    let bits_per_hash = <<H::F as PrimeField>::Params as FpParameters>::CAPACITY as usize;
    let n_hashes = (entropy - 1) / bits_per_hash + 1;
    let random_hash = HG::hash_to_variable_output(
        cs.clone(),
        inputs,
        n_hashes,
    )?;
    let random_bits_vec = random_hash.iter()
        .map(|f| BigNatVar::<ConstraintF, P>::enforce_limb_fits_in_bits(f, bits_per_hash))
        .flatten()
        .flatten()
        .collect::<Vec<Boolean<ConstraintF>>>();
    let mut random_bits = random_bits_vec.as_slice();

    // Check construction of base prime
    let mut base_prime_bits = vec![];
    base_prime_bits.extend(cert.base_nonce_as_bits.iter().cloned());
    base_prime_bits.extend(random_bits.iter().take(cert.base_plan.random_bits).cloned());
    base_prime_bits.push(Boolean::TRUE);
    cert.base_prime.enforce_equals_bits(&base_prime_bits)?;
    random_bits = &random_bits[cert.base_plan.random_bits..];
    assert_eq!(base_prime_bits.len(), 32);

    // Check primality using Miller-Rabin
    miller_rabin_32b(&cert.base_prime, 32)?.enforce_equal(&Boolean::TRUE)?;
    println!("Base prime checked");

    // Check each extension certificate
    let mut prime = cert.base_prime.clone();
    let mut prime_bits = 32_usize;
    for (i, extension) in cert.extensions.iter().enumerate() {
        // Construct extension term
        let mut extension_term_bits = vec![];
        extension_term_bits.extend(extension.nonce_as_bits.iter().cloned());
        extension_term_bits.extend(random_bits.iter().take(extension.plan.random_bits).cloned());
        extension_term_bits.push(Boolean::TRUE);
        let extension_term = BigNatVar::nat_from_bits(&extension_term_bits[..])?;
        random_bits = &random_bits[extension.plan.random_bits..];
        println!("Round {}: Extension term constructed", i);
        println!("Round {}: extension_term: {}", i, extension_term.value()?);

        // Compute helper values for pocklington's criterion
        let one = BigNatVar::constant(&BigNat::from(1))?;
        let n_less_one = extension_term.mult(&prime)?;
        let n = n_less_one.add(&one)?;
        let part = extension.checking_base.pow_mod(
            &extension_term,
            &n,
            extension.plan.nonce_bits + extension.plan.random_bits + 1,
        )?;
        let part_less_one = part.sub(&one)?;
        println!("Round {}: n: {}", i, n.value()?);
        println!("Round {}: part: {}", i, part.value()?);

        // Check coprimality
        part_less_one.enforce_coprime(&n)?;
        let power = part.pow_mod(
            &prime,
            &n,
            prime_bits,
        )?;
        println!("Round {}: power: {}", i, power.value()?);

        // Check Fermat's little theorem
        power.enforce_equal_when_carried(&one)?;
        println!("Round {}: Extension criterion checked", i);

        prime = n;
        prime_bits = prime_bits + extension.plan.nonce_bits + extension.plan.random_bits + 1;
    }
    prime.enforce_equal_when_carried(&cert.result)
}


#[tracing::instrument(target = "r1cs", skip(n, n_bits, base))]
/// Returns whether `n` passes a Miller-Rabin check with base `b`.
/// Assumes `n` has last two bits fixed to 0x11 and has < `n_bits` significant bits
fn miller_rabin_round<ConstraintF: PrimeField, P: BigNatCircuitParams>(
    n: &BigNatVar<ConstraintF, P>,
    n_bits: usize,
    base: &BigNatVar<ConstraintF, P>,
) -> Result<Boolean<ConstraintF>, SynthesisError> {
    assert!(n_bits > 2);
    let bits = n.enforce_fits_in_bits(n_bits)?;
    bits[0].enforce_equal(&Boolean::TRUE)?;
    bits[1].enforce_equal(&Boolean::TRUE)?;

    // Construct d such that 2d + 1 = n
    let d = BigNatVar::<ConstraintF, P>::nat_from_bits(&bits[1..])?;

    // Check that b^d == 1 (mod self) OR b^d == -1 (mod self)
    let pow = base.pow_mod(&d, n, n_bits-1)?;
    let mut n_less_one = n.clone();
    n_less_one.limbs[0] -= FpVar::one();
    pow.limbs.is_eq(&BigNatVar::<ConstraintF, P>::constant(&BigNat::from(1))?.limbs[..])?
        .or(&pow.limbs.is_eq(&n_less_one.limbs[..])?)
}


#[tracing::instrument(target = "r1cs", skip(n, n_bits))]
pub fn miller_rabin_32b<ConstraintF: PrimeField, P: BigNatCircuitParams>(
    n: &BigNatVar<ConstraintF, P>,
    n_bits: usize,
) -> Result<Boolean<ConstraintF>, SynthesisError> {
    let primes: Vec<usize> = vec![2, 7, 61];
    let mr_results = primes.iter().map(|base| {
        miller_rabin_round(
            n,
            n_bits,
            &BigNatVar::constant(&BigNat::from(*base as u32)).unwrap(),
        )
    }).collect::<Result<Vec<Boolean<ConstraintF>>, SynthesisError>>()?;
    Boolean::kary_and(&mr_results[..])
}


#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{ed_on_bls12_381::{Fq}, UniformRand};
    use r1cs_core::{ConstraintSystem, ConstraintLayer};
    use tracing_subscriber::layer::SubscriberExt;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::hash::{
        PoseidonHasher, constraints::PoseidonHasherGadget,
        hash_to_prime::hash_to_pocklington_prime,
    };

    #[derive(Clone)]
    pub struct BigNatTestParams;

    impl BigNatCircuitParams for BigNatTestParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 64;
    }

    pub type H = PoseidonHasher<Fq>;
    pub type HG = PoseidonHasherGadget<Fq>;

    #[test]
    fn valid_prime_hash_trivial_test() {
        let mut layer = ConstraintLayer::default();
        layer.mode = r1cs_core::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let mut rng = StdRng::seed_from_u64(0u64);
            let cs = ConstraintSystem::<Fq>::new_ref();
            let input = vec![Fq::rand(&mut rng); 12];
            let h = hash_to_pocklington_prime::<H>(&input, 128).unwrap();
            println!("Length of prime: {}", h.result().significant_bits());
            let inputvar = Vec::<FpVar<Fq>>::new_witness(
                r1cs_core::ns!(cs, "input"),
                || Ok(&input[..]),
            ).unwrap();
            let hvar = PocklingtonCertificateVar::<Fq, BigNatTestParams, H, HG>::new_witness(
                r1cs_core::ns!(cs, "h"),
                || Ok(&h),
            ).unwrap();
            check_hash_to_pocklington_prime::<H, HG, _, _>(
                cs.clone(),
                &inputvar,
                128,
                &hvar,
            ).unwrap();
            assert!(cs.is_satisfied().unwrap());
        })
    }

}
