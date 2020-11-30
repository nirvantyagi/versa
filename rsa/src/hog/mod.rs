use crate::bignat::{
    BigNat,
    extended_euclidean_gcd,
};

use std::{
    error::Error as ErrorTrait,
    marker::PhantomData,
    cmp::{max, min, Ordering},
    str::FromStr,
    fmt::{self, Debug, Display, Formatter},
};

use crate::Error;

//TODO: Rug doesn't support const integers
pub trait RsaGroupParams: Clone + Eq + Debug {
    const raw_G: usize;
    const raw_M: &'static str;

    fn G() -> BigNat {
        BigNat::from(Self::raw_G)
    }

    fn M() -> BigNat {
        BigNat::from_str(Self::raw_M).unwrap()
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RsaHiddenOrderGroup<P: RsaGroupParams> {
    pub n: BigNat,
    _params: PhantomData<P>,
}

impl<P: RsaGroupParams> Default for RsaHiddenOrderGroup<P> {
    fn default() -> Self {
        Self::from_nat(BigNat::from(2))
    }
}

impl<P: RsaGroupParams> RsaHiddenOrderGroup<P> {
    pub fn from_nat(n: BigNat) -> Self {
        let mut a = n;
        if a < 0 {
            a += P::M();
        }
        a %= P::M();
        let mut ma = P::M();
        ma -= &a;
        RsaHiddenOrderGroup{ n: min(a, ma), _params: PhantomData }
    }

    pub fn op(&self, other: &Self) -> Self {
        let mut a = self.n.clone();
        a *= &other.n;
        a %= P::M();
        let mut ma = P::M();
        ma -= &a;
        RsaHiddenOrderGroup{ n: min(a, ma), _params: PhantomData }
    }

    pub fn identity() -> Self {
        RsaHiddenOrderGroup{ n: BigNat::from(1), _params: PhantomData }
    }

    pub fn generator() -> Self {
        RsaHiddenOrderGroup{ n: P::G(), _params: PhantomData }
    }

    pub fn power(&self, e: &BigNat) -> Self {
        let r = BigNat::from(self.n.pow_mod_ref(e, &P::M()).unwrap());
        let mut mr = P::M();
        mr -= &r;
        RsaHiddenOrderGroup{ n: min(r, mr), _params: PhantomData }
    }

    //TODO: Optimization for only calculating needed Bezout coefficient
    pub fn inverse(&self) -> Result<Self, Error> {
        let ((mut inv, _), gcd) = extended_euclidean_gcd(&self.n, &P::M());
        if gcd.abs() > 1 {
            return Err(Box::new(RsaHOGError::NotInvertible))
        }
        if inv < 0 {
            inv += P::M();
        }
        Ok(Self::from_nat(inv))
    }
}


#[derive(Debug)]
pub enum RsaHOGError {
    NotInvertible,
}

impl ErrorTrait for RsaHOGError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for RsaHOGError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            RsaHOGError::NotInvertible => format!("Group element not invertible"),
        };
        write!(f, "{}", msg)
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use algebra::UniformRand;
    use algebra::ed_on_bls12_381::{Fq};
    use rand::{rngs::StdRng, SeedableRng};

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestRsaParams;

    impl RsaGroupParams for TestRsaParams {
        const raw_G: usize = 2;
        const raw_M: &'static str = "2519590847565789349402718324004839857142928212620403202777713783604366202070\
                          7595556264018525880784406918290641249515082189298559149176184502808489120072\
                          8449926873928072877767359714183472702618963750149718246911650776133798590957\
                          0009733045974880842840179742910064245869181719511874612151517265463228221686\
                          9987549182422433637259085141865462043576798423387184774447920739934236584823\
                          8242811981638150106748104516603773060562016196762561338441436038339044149526\
                          3443219011465754445417842402092461651572335077870774981712577246796292638635\
                          6373289912154831438167899885040445364023527381951378636564391212010397122822\
                          120720357";
    }

    pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;

    #[test]
    fn inverse_test() {
        let a = Hog::from_nat(BigNat::from(30));
        let inv_a = a.inverse().unwrap();
        assert_eq!(a.op(&inv_a).n, BigNat::from(1));

        let a = Hog::from_nat(BigNat::from(-30));
        let inv_a = a.inverse().unwrap();
        assert_eq!(a.op(&inv_a).n, BigNat::from(1));
    }

}
