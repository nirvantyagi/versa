use crate::{
    bignat::{BigNat, fit_nat_to_limbs, constraints::BigNatCircuitParams},
    hog::{RsaHiddenOrderGroup, RsaGroupParams},
    hash_to_prime::{HashRangeParams, Hasher, hash_to_prime, hash_to_integer},
    Error,
};

use std::{
    marker::PhantomData,
    fmt::Debug,
};

const SEC_PARAM: usize = 128;
pub type RsaQGroup<P> = RsaHiddenOrderGroup<P>;


// R = { (a, b \in Z); (u1, u2, w1, w2 \in g) : w1 = (u1^a)(u2^b) AND w2 = u2^a }

// Proof of knowledge of exponent representation
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PoKER<P: RsaGroupParams, H: Hasher, C: BigNatCircuitParams> {
    _params: PhantomData<P>,
    _hash: PhantomData<H>,
    _circuit_params: PhantomData<C>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Statement<P: RsaGroupParams> {
    pub u1: RsaQGroup<P>,
    pub u2: RsaQGroup<P>,
    pub w1: RsaQGroup<P>,
    pub w2: RsaQGroup<P>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Witness {
    pub a: BigNat,
    pub b: BigNat,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Proof<P: RsaGroupParams> {
    z_a: RsaQGroup<P>,
    z_b: RsaQGroup<P>,
    q: RsaQGroup<P>,
    r_a: BigNat,
    r_b: BigNat,
}

impl<P: RsaGroupParams, H: Hasher, C: BigNatCircuitParams> PoKER<P, H, C> {
    pub fn prove(x: &Statement<P>, w: &Witness) -> Result<Proof<P>, Error> {
        let g = Self::hash_to_initial_generator(x)?;
        let z_a = g.power_integer(&w.a)?;
        let z_b = g.power_integer(&w.b)?;

        // Hash to challenge (prime and linear combination value)
        let prime_hash_params = HashRangeParams{ n_bits: SEC_PARAM * SEC_PARAM.trailing_zeros() as usize, n_trailing_ones: 2 };
        let lc_hash_params = HashRangeParams{ n_bits: SEC_PARAM, n_trailing_ones: 0 };
        let mut hash_input = vec![];
        hash_input.append(&mut fit_nat_to_limbs::<H::F>(&z_a.n, C::LIMB_WIDTH)?);
        hash_input.append(&mut fit_nat_to_limbs::<H::F>(&z_b.n, C::LIMB_WIDTH)?);
        let (l, _) = hash_to_prime::<H>(&hash_input, &prime_hash_params)?;
        let gamma = hash_to_integer::<H>(&hash_input, &lc_hash_params);
        let gamma2 = <BigNat>::from(&gamma * &gamma);
        let gamma3 = <BigNat>::from(&gamma2 * &gamma);

        // Compute quotient and remainder of witness exponents with challenge prime
        let (q_a, r_a) = <(BigNat, BigNat)>::from(w.a.div_rem_euc_ref(&l));
        let (q_b, r_b) = <(BigNat, BigNat)>::from(w.b.div_rem_euc_ref(&l));

        // Compute proof group elements and combine with linear combination challenge
        let a_1 = x.u1.power_integer(&q_a)?;
        let a_2 = x.u2.power_integer(&q_a)?;
        let a_g = g.power_integer(&q_a)?;
        let b_2 = x.u2.power_integer(&q_b)?;
        let b_g = g.power_integer(&q_b)?;
        let q = a_1.op(&b_2)
            .op(&a_2.power(&gamma))
            .op(&a_g.power(&gamma2))
            .op(&b_g.power(&gamma3));
        Ok(Proof{z_a, z_b, q, r_a, r_b})
    }

    pub fn verify(x: &Statement<P>, proof: &Proof<P>) -> Result<bool, Error> {
        let g = Self::hash_to_initial_generator(x)?;

        // Hash to challenge (prime and linear combination value)
        let prime_hash_params = HashRangeParams{ n_bits: SEC_PARAM * SEC_PARAM.trailing_zeros() as usize, n_trailing_ones: 2 };
        let lc_hash_params = HashRangeParams{ n_bits: SEC_PARAM, n_trailing_ones: 0 };
        let mut hash_input = vec![];
        hash_input.append(&mut fit_nat_to_limbs::<H::F>(&proof.z_a.n, C::LIMB_WIDTH)?);
        hash_input.append(&mut fit_nat_to_limbs::<H::F>(&proof.z_b.n, C::LIMB_WIDTH)?);
        let (l, _) = hash_to_prime::<H>(&hash_input, &prime_hash_params)?;
        let gamma = hash_to_integer::<H>(&hash_input, &lc_hash_params);
        let gamma2 = <BigNat>::from(&gamma * &gamma);
        let gamma3 = <BigNat>::from(&gamma2 * &gamma);

        // Verify proof
        Ok(x.w1
               .op(&x.w2.power(&gamma))
               .op(&proof.z_a.power(&gamma2))
               .op(&proof.z_b.power(&gamma3)) ==
            proof.q.power(&l)
                .op(&x.u1.power(&proof.r_a))
                .op(&x.u2.power(&proof.r_b))
                .op(&x.u2.power(&<BigNat>::from(&gamma * &proof.r_a)))
                .op(&g.power(&<BigNat>::from(&gamma2 * &proof.r_a)))
                .op(&g.power(&<BigNat>::from(&gamma3 * &proof.r_b)))
        )
    }

    pub fn hash_to_initial_generator(x: &Statement<P>) -> Result<RsaQGroup<P>, Error> {
        let initial_generator_hash_params = HashRangeParams{
            n_bits: SEC_PARAM,
            n_trailing_ones: 0
        };
        let mut hash_input = vec![];
        hash_input.append(&mut fit_nat_to_limbs::<H::F>(&x.u1.n, C::LIMB_WIDTH)?);
        hash_input.append(&mut fit_nat_to_limbs::<H::F>(&x.u2.n, C::LIMB_WIDTH)?);
        hash_input.append(&mut fit_nat_to_limbs::<H::F>(&x.w1.n, C::LIMB_WIDTH)?);
        hash_input.append(&mut fit_nat_to_limbs::<H::F>(&x.w2.n, C::LIMB_WIDTH)?);
        Ok(RsaQGroup::<P>::from_nat(hash_to_integer::<H>(&hash_input, &initial_generator_hash_params)))
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use algebra::ed_on_bls12_381::{Fq};
    use crate::hash_to_prime::HasherFromDigest;

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestRsaParams;

    impl RsaGroupParams for TestRsaParams {
        const RAW_G: usize = 2;
        const RAW_M: &'static str = "2519590847565789349402718324004839857142928212620403202777713783604366202070\
                          7595556264018525880784406918290641249515082189298559149176184502808489120072\
                          8449926873928072877767359714183472702618963750149718246911650776133798590957\
                          0009733045974880842840179742910064245869181719511874612151517265463228221686\
                          9987549182422433637259085141865462043576798423387184774447920739934236584823\
                          8242811981638150106748104516603773060562016196762561338441436038339044149526\
                          3443219011465754445417842402092461651572335077870774981712577246796292638635\
                          6373289912154831438167899885040445364023527381951378636564391212010397122822\
                          120720357";
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct CircuitParams;
    impl BigNatCircuitParams for CircuitParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 64; // 32 * 64 = 2048 (RSA key size)
    }

    pub type H = HasherFromDigest<Fq, blake3::Hasher>;
    pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;
    pub type TestWesolowski = PoKER<TestRsaParams, H, CircuitParams>;

    #[test]
    fn valid_proof_of_exponentiation_test() {
        let u1 = Hog::from_nat(BigNat::from(20));
        let u2 = Hog::from_nat(BigNat::from(30));
        let a = BigNat::from(40);
        let b = BigNat::from(50);
        let w1 = u1.power(&a).op(&u2.power(&b));
        let w2 = u2.power(&a);
        let x = Statement{u1, u2, w1, w2};
        let w = Witness{a, b};

        let proof = TestWesolowski::prove(&x, &w).unwrap();
        let is_valid = TestWesolowski::verify(&x, &proof).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn valid_large_proof_of_exponentiation_test() {
        let exp_hash_params = HashRangeParams{ n_bits: 4096, n_trailing_ones: 0 };
        let u1 = Hog::from_nat(BigNat::from(20)).inverse().unwrap();
        let u2 = Hog::from_nat(BigNat::from(30)).inverse().unwrap();
        let a = hash_to_integer::<H>(&fit_nat_to_limbs(&BigNat::from(40), CircuitParams::LIMB_WIDTH).unwrap(), &exp_hash_params);
        let b = hash_to_integer::<H>(&fit_nat_to_limbs(&BigNat::from(50), CircuitParams::LIMB_WIDTH).unwrap(), &exp_hash_params);
        let w1 = u1.power(&a).op(&u2.power(&b));
        let w2 = u2.power(&a);
        let x = Statement{u1, u2, w1, w2};
        let w = Witness{a, b};

        let proof = TestWesolowski::prove(&x, &w).unwrap();
        let is_valid = TestWesolowski::verify(&x, &proof).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn valid_large_proof_of_negative_exponentiation_test() {
        let exp_hash_params = HashRangeParams{ n_bits: 4096, n_trailing_ones: 0 };
        let u1 = Hog::from_nat(BigNat::from(20)).inverse().unwrap();
        let u2 = Hog::from_nat(BigNat::from(30)).inverse().unwrap();
        let a = hash_to_integer::<H>(&fit_nat_to_limbs(&BigNat::from(40), CircuitParams::LIMB_WIDTH).unwrap(), &exp_hash_params);
        let b = -hash_to_integer::<H>(&fit_nat_to_limbs(&BigNat::from(50), CircuitParams::LIMB_WIDTH).unwrap(), &exp_hash_params);
        let w1 = u1.power(&a).op(&u2.power(&b));
        let w2 = u2.power(&a);
        let x = Statement{u1, u2, w1, w2};
        let w = Witness{a, b};

        let proof = TestWesolowski::prove(&x, &w).unwrap();
        let is_valid = TestWesolowski::verify(&x, &proof).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn invalid_large_proof_of_exponentiation_test() {
        let exp_hash_params = HashRangeParams{ n_bits: 4096, n_trailing_ones: 0 };
        let u1 = Hog::from_nat(BigNat::from(20)).inverse().unwrap();
        let u2 = Hog::from_nat(BigNat::from(30)).inverse().unwrap();
        let a = hash_to_integer::<H>(&fit_nat_to_limbs(&BigNat::from(40), CircuitParams::LIMB_WIDTH).unwrap(), &exp_hash_params);
        let b = hash_to_integer::<H>(&fit_nat_to_limbs(&BigNat::from(50), CircuitParams::LIMB_WIDTH).unwrap(), &exp_hash_params);
        let w1 = u1.power(&a).op(&u2.power(&b));
        let w2 = u2.power(&a);
        let x = Statement{u1, u2, w1, w2};
        let w = Witness{a, b: BigNat::from(50)};

        let proof = TestWesolowski::prove(&x, &w).unwrap();
        let is_valid = TestWesolowski::verify(&x, &proof).unwrap();
        assert!(!is_valid);
    }

}
