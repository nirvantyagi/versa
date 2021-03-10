/*
A Pocklington extension multiplies a base prime by a term
of the form ( 1 || r || n ), producing
p' = p * (1 || r || n) + 1
such that `p'` is prime.
*/

use algebra::{PrimeField, FpParameters};
use crate::{
    bignat::{BigNat, limbs_to_nat},
    hash::{Hasher},
    Error,
};

use std::{
    cmp::min,
    fmt::{self, Debug},
    error::Error as ErrorTrait,
    marker::PhantomData,
};

pub mod constraints;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocklingtonPlan {
    /// Number of nonce bits in the base prime
    pub base_nonce_bits: usize,
    /// Number of random bits in the base prime
    pub base_random_bits: usize,
    pub extensions: Vec<PlannedExtension>,
}

/// Stores one extension: the size of `r` and `n`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedExtension {
    pub nonce_bits: usize,
    pub random_bits: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionCertificate {
    pub plan: PlannedExtension,
    pub nonce: u64,
    pub checking_base: BigNat,
    pub result: BigNat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocklingtonCertificate<H: Hasher> {
    pub base_plan: PlannedExtension,
    pub base_prime: BigNat,
    pub base_nonce: usize,
    pub extensions: Vec<ExtensionCertificate>,
    _hash: PhantomData<H>,
}

impl PlannedExtension {
    pub fn max_value(&self) -> BigNat {
        (BigNat::from(1) << (self.nonce_bits + self.random_bits + 1) as u32) - 1
    }
    pub fn min_value(&self) -> BigNat {
        BigNat::from(1) << (self.nonce_bits + self.random_bits) as u32
    }
    pub fn evaluate(&self, random_value: &BigNat, nonce_value: u64) -> BigNat {
        assert!(self.nonce_bits <= 64);
        self.min_value() + BigNat::from(random_value << self.nonce_bits as u32) + nonce_value
    }
}

/// Returns the probability that a number with `bits` bits is prime
fn prime_density(bits: usize) -> f64 {
    let log2e = std::f64::consts::E.log2();
    let b = bits as f64;
    log2e / b - log2e * log2e / b / b
}

/// Returns the number of random `bits`-bit numbers that must be checked to find a prime with
/// all but `p_fail` probability
pub fn prime_trials(bits: usize, p_fail: f64) -> usize {
    let p = prime_density(bits);
    (p_fail.log(1.0 - p).ceil() + 0.1) as usize
}

/// The number of nonce bits needed to generate a `bits`-bit prime with all but 2**-64
/// probability.
pub fn nonce_bits_needed(bits: usize) -> usize {
    let trials = prime_trials(bits, 2.0f64.powi(-64));
    ((trials as f64).log2().ceil() + 0.1) as usize
}

impl PocklingtonPlan {
    /// Given a target entropy, constructs a plan for how to make a prime number of that
    /// entropy that can be certified using a recursive Pocklington test
    pub fn new(entropy: usize) -> Self {
        // Both low bits of the base prime are fixed to 1
        // We require an extra nonce bit, since the 2's place bit is artificially fixed
        let nonce_bits_needed_in_base = nonce_bits_needed(32) + 1;
        let mut plan = Self {
            base_nonce_bits: nonce_bits_needed_in_base,
            // High bit is fixed to 1, so 31 bits for the nonce + random bits.
            base_random_bits: min(entropy, 31 - nonce_bits_needed_in_base),
            extensions: Vec::new(),
        };

        // Construct extensions until desired entropy is reached
        while plan.entropy() < entropy {
            // Extension must be less than current base
            let max_extension_bits = plan.min_value().significant_bits() as usize - 1;
            // Determine number of required nonce bits
            let max_nonce_bits_needed = nonce_bits_needed(max_extension_bits + plan.max_bits());
            assert!(max_nonce_bits_needed < max_extension_bits);
            // High bit is fixed to 1
            let max_random_bits = max_extension_bits - max_nonce_bits_needed - 1;
            let random_bits = min(entropy - plan.entropy(), max_random_bits);
            plan.extensions.push(
                PlannedExtension {
                    nonce_bits: max_nonce_bits_needed,
                    random_bits: random_bits,
                }
            )
        }
        plan
    }

    pub fn entropy(&self) -> usize {
        self.extensions.iter().map(|i| i.random_bits).sum::<usize>() + self.base_random_bits
    }

    pub fn max_value(&self) -> BigNat {
        self.extensions.iter().fold(
            (BigNat::from(1) << (self.base_random_bits + self.base_nonce_bits + 1) as u32) - 1,
            |acc, ext| acc * ext.max_value() + 1,
        )
    }

    pub fn min_value(&self) -> BigNat {
        self.extensions.iter().fold(
            BigNat::from(1) << (self.base_random_bits + self.base_nonce_bits) as u32,
            |acc, ext| acc * ext.min_value() + 1,
        )
    }

    pub fn max_bits(&self) -> usize {
        self.max_value().significant_bits() as usize
    }
}

impl<H: Hasher> PocklingtonCertificate<H> {
    pub fn result(&self) -> &BigNat {
        if let Some(l) = self.extensions.last() {
            &l.result
        } else {
            &self.base_prime
        }
    }
}

pub fn attempt_pocklington_base<H: Hasher>(
    plan: &PocklingtonPlan,
    random_bits: &BigNat,
) -> Result<PocklingtonCertificate<H>, Error> {
    assert!(random_bits.significant_bits() <= plan.base_random_bits as u32);
    for nonce in 0..(1u64 << plan.base_nonce_bits) {
        if (nonce & 0b11) == 0b11 {
            let mut base = BigNat::from(1) << (plan.base_nonce_bits + plan.base_random_bits) as u32;
            base |= (random_bits.clone() << plan.base_nonce_bits as u32) + nonce;
            if miller_rabin_32b(&base) {
                return Ok(
                    PocklingtonCertificate {
                        base_plan: PlannedExtension{
                            nonce_bits: plan.base_nonce_bits,
                            random_bits: plan.base_random_bits,
                        },
                        base_prime: base,
                        base_nonce: nonce as usize,
                        extensions: Vec::new(),
                        _hash: PhantomData,
                    }
                );
            }
        }
    }
    Err(Box::new(HashToPrimeError::NoValidNonce))
}

pub fn attempt_pocklington_extension<H: Hasher>(
    mut p: PocklingtonCertificate<H>,
    plan: &PlannedExtension,
    random_bits: &BigNat,
) -> Result<PocklingtonCertificate<H>, Error> {
    assert!(random_bits.significant_bits() <= plan.random_bits as u32);
    for nonce in 0..(1u64 << plan.nonce_bits) {
        let extension = plan.evaluate(random_bits, nonce); // Sets high bit
        let candidate = BigNat::from(p.result() * &extension) + 1;
        let mut base = BigNat::from(2);
        while base < candidate {
            let part = base.clone().pow_mod(&extension, &candidate).unwrap();
            if part.clone().pow_mod(p.result(), &candidate).unwrap() != 1 {
                break;
            }
            if BigNat::from(&part - 1).gcd(&candidate) == 1 {
                p.extensions.push(
                    ExtensionCertificate {
                        plan: plan.clone(),
                        checking_base: base,
                        result: candidate,
                        nonce,
                    }
                );
                return Ok(p);
            }
            base += 1;
        }
    }
    Err(Box::new(HashToPrimeError::NoValidNonce))
}

pub fn hash_to_pocklington_prime<H: Hasher>(
    inputs: &[H::F],
    entropy: usize,
) -> Result<PocklingtonCertificate<H>, Error> {
    let plan = PocklingtonPlan::new(entropy);
    assert_eq!(plan.entropy(), entropy);

    // Compute needed randomness
    let bits_per_hash = <<H::F as PrimeField>::Params as FpParameters>::CAPACITY as usize;
    let n_hashes = (entropy - 1) / bits_per_hash + 1;
    let mut random_bits = limbs_to_nat(
        &H::hash_to_variable_output(inputs, n_hashes),
        bits_per_hash,
    );

    // Construct Pocklington base
    let base_random_bits = random_bits.clone() & ((BigNat::from(1) << plan.base_random_bits as u32) - BigNat::from(1));
    let mut cert = attempt_pocklington_base(&plan, &base_random_bits)?;
    random_bits >>= plan.base_random_bits as u32;

    // Perform each extension
    for extension in &plan.extensions {
        let ext_random_bits = random_bits.clone() & ((BigNat::from(1) << extension.random_bits as u32) - BigNat::from(1));
        cert = attempt_pocklington_extension(cert, extension, &ext_random_bits)?;
        random_bits >>= extension.random_bits as u32;
    }
    Ok(cert)
}

//TODO: Swap asserts for returns (used for testing)
pub fn check_pocklington_certificate<H: Hasher>(
    inputs: &[H::F],
    entropy: usize,
    cert: &PocklingtonCertificate<H>,
) -> Result<bool, Error> {

    // Compute needed randomness
    let bits_per_hash = <<H::F as PrimeField>::Params as FpParameters>::CAPACITY as usize;
    let n_hashes = (entropy - 1) / bits_per_hash + 1;
    let mut random_bits = limbs_to_nat(
        &H::hash_to_variable_output(inputs, n_hashes),
        bits_per_hash,
    );

    // Construct Pocklington base
    let base_random_bits = random_bits.clone() & ((BigNat::from(1) << cert.base_plan.random_bits as u32) - BigNat::from(1));
    random_bits >>= cert.base_plan.random_bits as u32;
    let mut base = BigNat::from(1) << (cert.base_plan.nonce_bits + cert.base_plan.random_bits) as u32;
    base |= (base_random_bits.clone() << cert.base_plan.nonce_bits as u32) + BigNat::from(cert.base_nonce as u32);
    assert_eq!(cert.base_plan.nonce_bits + cert.base_plan.random_bits, 31);
    assert_eq!(cert.base_prime.clone(), base.clone());
    assert!(miller_rabin_32b(&base));
    println!("Base prime: {}", base.clone());

    // Check each extension
    let mut prime = cert.base_prime.clone();
    for (i, extension) in cert.extensions.iter().enumerate() {
        let ext_random_bits = random_bits.clone() & ((BigNat::from(1) << extension.plan.random_bits as u32) - BigNat::from(1));
        random_bits >>= extension.plan.random_bits as u32;
        let extension_term = extension.plan.evaluate(&ext_random_bits, extension.nonce);
        println!("Round {}: extension_term: {}", i, extension_term.clone());

        let n_less_one = extension_term.clone() * prime.clone();
        let n = n_less_one.clone() + BigNat::from(1);
        let part = extension.checking_base.clone().pow_mod(&extension_term, &n).unwrap();
        let part_less_one = part.clone() - BigNat::from(1);
        println!("Round {}: n: {}", i, n.clone());
        println!("Round {}: part: {}", i, part.clone());

        // Enforce coprimality
        let bezout_s = (part_less_one.clone().gcd_cofactors(n.clone(), BigNat::new()).1 + n.clone()) % n.clone();
        println!("Round {}: bezout: {}", i, bezout_s.clone());
        let gcd = (part_less_one.clone() * bezout_s) % n.clone();
        assert_eq!(gcd, BigNat::from(1));

        // Check Fermat's little theorem
        let power = part.clone().pow_mod(&prime, &n).unwrap();
        println!("Round {}: power: {}", i, power.clone());
        assert_eq!(power, BigNat::from(1));

        prime = n;
    }
    Ok(prime == cert.result().clone())
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

pub fn miller_rabin_32b(n: &BigNat) -> bool {
    miller_rabin_round(n, &BigNat::from(2usize))
        && miller_rabin_round(n, &BigNat::from(7usize))
        && miller_rabin_round(n, &BigNat::from(61usize))
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


#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{ed_on_bls12_381::{Fq}, UniformRand};
    use rand::{rngs::StdRng, SeedableRng};

    use crate::hash::{
        PoseidonHasher,
    };

    pub type H = PoseidonHasher<Fq>;

    #[test]
    fn pocklington_prime_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let input = vec![Fq::rand(&mut rng); 12];
        let h = hash_to_pocklington_prime::<H>(&input, 128).unwrap();
        check_pocklington_certificate(&input, 128, &h).unwrap();
    }

}
