use rug::{Integer, integer::Order};
use algebra::{
    fields::{PrimeField, FpParameters},
    biginteger::BigInteger,
};

use std::{
    borrow::Borrow,
    fmt::{self, Debug},
    error::Error as ErrorTrait,
};

use crate::Error;

pub mod constraints;
pub type BigNat = Integer;



pub fn extended_euclidean_gcd(a: &BigNat, b: &BigNat) -> ((BigNat, BigNat), BigNat) {
    let mut prev_r = a.clone();
    let mut r = b.clone();
    let mut prev_s = BigNat::from(1);
    let mut s = BigNat::from(0);
    let mut prev_t = BigNat::from(0);
    let mut t = BigNat::from(1);
    let mut tmp_r: BigNat;
    let mut tmp_s: BigNat;
    let mut tmp_t: BigNat;

    while r != 0 {
        let quotient: BigNat = <BigNat>::from(&prev_r / &r);

        tmp_r = BigNat::from(&prev_r - (&quotient * &r));
        prev_r = r;
        r = tmp_r;

        tmp_s = BigNat::from(&prev_s - (&quotient * &s));
        prev_s = s;
        s = tmp_s;

        tmp_t = BigNat::from(&prev_t - (&quotient * &t));
        prev_t = t;
        t = tmp_t;
    }
    ((prev_s, prev_t), prev_r)
}


/// Convert a field element to a natural number
pub fn f_to_nat<F: PrimeField>(f: &F) -> BigNat {
    let mut s = Vec::new();
    //TODO: Used to be 'write_be', but zexe only has write_le with incorrect documentation
    f.into_repr().write_le(&mut s).unwrap();
    Integer::from_digits(f.into_repr().as_ref(), Order::Lsf)
}

/// Convert a natural number to a field element.
pub fn nat_to_f<F: PrimeField>(n: &BigNat) -> Result<F, Error> {
    let bit_capacity = <F::Params as FpParameters>::CAPACITY as usize;
    match F::from_str(&format!("{}", n)) {
        Ok(f) => Ok(f),
        Err(_) => Err(Box::new(BigNatError::Conversion(1, bit_capacity))),
    }
}


/// Compute the natural number represented by an array of limbs.
/// The limbs are assumed to be based the `limb_width` power of 2.
pub fn limbs_to_nat<F: PrimeField, B: Borrow<F>, I: DoubleEndedIterator<Item = B>>(
    limbs: I,
    limb_width: usize,
) -> BigNat {
    limbs.rev().fold(Integer::from(0), |mut acc, limb| {
        acc <<= limb_width as u32;
        acc += f_to_nat(limb.borrow());
        acc
    })
}

/// Compute the limbs encoding a natural number.
/// The limbs are assumed to be based the `limb_width` power of 2.
pub fn nat_to_limbs<'a, F: PrimeField>(
    nat: &BigNat,
    limb_width: usize,
    n_limbs: usize,
) -> Result<Vec<F>, Error> {
    assert!(limb_width <= <F::Params as FpParameters>::CAPACITY as usize);
    let mask = int_with_n_ones(limb_width);
    let mut nat = nat.clone();
    if nat.significant_bits() as usize <= n_limbs * limb_width {
        Ok((0..n_limbs)
            .map(|_| {
                let r = Integer::from(&nat & &mask);
                nat >>= limb_width as u32;
                nat_to_f(&r).unwrap()
            })
            .collect())
    } else {
        println!(
            "nat {} does not fit in {} limbs of width {}",
            nat, n_limbs, limb_width
        );
        Err(Box::new(BigNatError::Conversion(n_limbs, limb_width)))
    }
}

// Fits a natural number to the minimum number limbs of given width
pub fn fit_nat_to_limbs<F: PrimeField>(
    n: &BigNat,
    limb_width: usize,
) -> Result<Vec<F>, Error> {
    //let bit_capacity = <F::Params as FpParameters>::CAPACITY as usize;
    nat_to_limbs(n, limb_width, n.significant_bits() as usize / limb_width + 1)
}

fn int_with_n_ones(n: usize) -> BigNat {
    let mut m = Integer::from(1);
    m <<= n as u32;
    m -= 1;
    m
}


#[derive(Debug)]
pub enum BigNatError {
    Conversion(usize, usize),
}

impl ErrorTrait for BigNatError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for BigNatError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            BigNatError::Conversion(n_limbs, limb_width) => format!("Integer does not fit in {} limbs of width {}", n_limbs, limb_width),
        };
        write!(f, "{}", msg)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use algebra::UniformRand;
    use algebra::ed_on_bls12_381::{Fq};
    use std::str::FromStr;
    use rand::{rngs::StdRng, SeedableRng};

    const RSA_MODULO: &str = "2519590847565789349402718324004839857142928212620403202777713783604366202070\
                          7595556264018525880784406918290641249515082189298559149176184502808489120072\
                          8449926873928072877767359714183472702618963750149718246911650776133798590957\
                          0009733045974880842840179742910064245869181719511874612151517265463228221686\
                          9987549182422433637259085141865462043576798423387184774447920739934236584823\
                          8242811981638150106748104516603773060562016196762561338441436038339044149526\
                          3443219011465754445417842402092461651572335077870774981712577246796292638635\
                          6373289912154831438167899885040445364023527381951378636564391212010397122822\
                          120720357";


    #[test]
    fn convert_to_field_test() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let f = <Fq>::rand(&mut rng);
        let f2 = nat_to_f::<Fq>(&f_to_nat(&f)).unwrap();
        assert_eq!(f, f2);

        let m = BigNat::from_str(RSA_MODULO).unwrap();
        let bit_capacity = <<Fq as PrimeField>::Params as FpParameters>::CAPACITY as usize;
        let m2 = limbs_to_nat::<Fq, _, _>(nat_to_limbs::<Fq>(&m, bit_capacity, m.significant_bits() as usize / bit_capacity + 1).unwrap().iter(), bit_capacity);
        assert_eq!(m, m2);
    }
}