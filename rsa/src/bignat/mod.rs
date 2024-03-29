use rug::{Integer, integer::Order as BitOrder};
use ark_ff::{
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
pub type Order = BitOrder;



//TODO: Replace with BigNat::gcd_cofactors
pub fn extended_euclidean_gcd(a: &BigNat, b: &BigNat) -> ((BigNat, BigNat), BigNat) {
    let (g, s, t) = a.clone().gcd_cofactors(b.clone(), BigNat::new());
    ((s, t), g)
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
pub fn limbs_to_nat<F: PrimeField>(
    limbs: &Vec<F>,
    limb_width: usize,
) -> BigNat {
    limbs.iter().rev().fold(Integer::from(0), |mut acc, limb| {
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
            "nat-{} {} does not fit in {} limbs of width {}",
            nat.significant_bits(), nat, n_limbs, limb_width
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

// Fits a natural number to the minimum number limbs
pub fn fit_nat_to_limb_capacity<F: PrimeField>(
    n: &BigNat,
) -> Result<Vec<F>, Error> {
    let bit_capacity = <F::Params as FpParameters>::CAPACITY as usize;
    nat_to_limbs(n, bit_capacity, n.significant_bits() as usize / bit_capacity + 1)
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
    use ark_ff::UniformRand;
    use ark_ed_on_bls12_381::{Fq};
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
        let m2 = limbs_to_nat::<Fq>(&nat_to_limbs::<Fq>(&m, bit_capacity, m.significant_bits() as usize / bit_capacity + 1).unwrap(), bit_capacity);
        assert_eq!(m, m2);
    }
}