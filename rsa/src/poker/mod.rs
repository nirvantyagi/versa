use crate::{
    bignat::{BigNat, nat_to_limbs, constraints::BigNatCircuitParams},
    hog::{RsaHiddenOrderGroup, RsaGroupParams},
    hash::{
        Hasher,
        hash_to_prime::{PocklingtonCertificate, hash_to_pocklington_prime},
    },
    Error,
};

use std::{
    marker::PhantomData,
    fmt::Debug,
};

pub mod constraints;

pub type Hog<P> = RsaHiddenOrderGroup<P>;

// R = { (a, b \in Z); (u1, u2, w1, w2 \in g) : w1 = (u1^a)(u2^b) AND w2 = u2^a }

pub trait PoKERParams: Clone {
    const HASH_TO_PRIME_ENTROPY: usize;
}


// Proof of knowledge of exponent representation
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PoKER<P: PoKERParams, RsaP: RsaGroupParams, H: Hasher, C: BigNatCircuitParams> {
    _params: PhantomData<P>,
    _rsa_params: PhantomData<RsaP>,
    _hash: PhantomData<H>,
    _circuit_params: PhantomData<C>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Statement<P: RsaGroupParams> {
    pub u1: Hog<P>,
    pub u2: Hog<P>,
    pub w1: Hog<P>,
    pub w2: Hog<P>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Witness {
    pub a: BigNat,
    pub b: BigNat,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Proof<P: RsaGroupParams, H: Hasher> {
    pub v_a: Hog<P>,
    pub v_b: Hog<P>,
    pub v_1: Hog<P>,
    pub v_2: Hog<P>,
    pub r_a: BigNat,
    pub r_b: BigNat,
    pub l: BigNat,
    pub cert: PocklingtonCertificate<H>,
}

impl<P: PoKERParams, RsaP: RsaGroupParams, H: Hasher, C: BigNatCircuitParams> PoKER<P, RsaP, H, C> {
    pub fn prove(x: &Statement<RsaP>, w: &Witness) -> Result<Proof<RsaP, H>, Error> {
        let g = Hog::<RsaP>::generator();
        let z_a = g.power(&w.a);
        let z_b = g.power(&w.b);

        // Hash to challenge
        let mut hash_input = vec![];
        hash_input.append(&mut nat_to_limbs::<H::F>(&x.u1.n, C::LIMB_WIDTH, C::N_LIMBS)?);
        hash_input.append(&mut nat_to_limbs::<H::F>(&x.u2.n, C::LIMB_WIDTH, C::N_LIMBS)?);
        hash_input.append(&mut nat_to_limbs::<H::F>(&x.w1.n, C::LIMB_WIDTH, C::N_LIMBS)?);
        hash_input.append(&mut nat_to_limbs::<H::F>(&x.w2.n, C::LIMB_WIDTH, C::N_LIMBS)?);
        hash_input.append(&mut nat_to_limbs::<H::F>(&z_a.n, C::LIMB_WIDTH, C::N_LIMBS)?);
        hash_input.append(&mut nat_to_limbs::<H::F>(&z_b.n, C::LIMB_WIDTH, C::N_LIMBS)?);
        let cert = hash_to_pocklington_prime::<H>(
            &hash_input,
            P::HASH_TO_PRIME_ENTROPY,
        )?;
        let l = cert.result().clone();

        // Compute quotient and remainder of witness exponents with challenge prime
        let (q_a, r_a) = <(BigNat, BigNat)>::from(w.a.div_rem_euc_ref(&l));
        let (q_b, r_b) = <(BigNat, BigNat)>::from(w.b.div_rem_euc_ref(&l));

        // Compute proof group elements
        Ok(Proof{
            v_a: g.power(&q_a),
            v_b: g.power(&q_b),
            v_1: x.u1.power(&q_a).op(&x.u2.power(&q_b)),
            v_2: x.u2.power(&q_a),
            r_a,
            r_b,
            l,
            cert,
        })
    }

    pub fn verify(x: &Statement<RsaP>, proof: &Proof<RsaP, H>) -> Result<bool, Error> {
        let g = Hog::<RsaP>::generator();

        let z_a = proof.v_a.power(&proof.l).op(&g.power(&proof.r_a));
        let z_b = proof.v_b.power(&proof.l).op(&g.power(&proof.r_b));

        // Hash to challenge
        let mut hash_input = vec![];
        hash_input.append(&mut nat_to_limbs::<H::F>(&x.u1.n, C::LIMB_WIDTH, C::N_LIMBS)?);
        hash_input.append(&mut nat_to_limbs::<H::F>(&x.u2.n, C::LIMB_WIDTH, C::N_LIMBS)?);
        hash_input.append(&mut nat_to_limbs::<H::F>(&x.w1.n, C::LIMB_WIDTH, C::N_LIMBS)?);
        hash_input.append(&mut nat_to_limbs::<H::F>(&x.w2.n, C::LIMB_WIDTH, C::N_LIMBS)?);
        hash_input.append(&mut nat_to_limbs::<H::F>(&z_a.n, C::LIMB_WIDTH, C::N_LIMBS)?);
        hash_input.append(&mut nat_to_limbs::<H::F>(&z_b.n, C::LIMB_WIDTH, C::N_LIMBS)?);
        // Outside of circuit faster to recompute rather than check certificate
        let cert = hash_to_pocklington_prime::<H>(
            &hash_input,
            P::HASH_TO_PRIME_ENTROPY,
        )?;
        let l = cert.result().clone();
        //check_pocklington_certificate::<H>(&hash_input, P::HASH_TO_PRIME_ENTROPY, &cert)?;

        // Verify proof
        Ok(l == proof.l &&
            x.w1 == proof.v_1.power(&proof.l)
                .op(&x.u1.power(&proof.r_a))
                .op(&x.u2.power(&proof.r_b)) &&
            x.w2 == proof.v_2.power(&proof.l)
                .op(&x.u2.power(&proof.r_a))
        )
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::{Fq};
    use crate::{
        hash::{HasherFromDigest, PoseidonHasher, hash_to_integer::hash_to_integer},
        bignat::fit_nat_to_limbs,
    };

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
    pub struct TestPokerParams;
    impl PoKERParams for TestPokerParams {
        const HASH_TO_PRIME_ENTROPY: usize = 128;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct CircuitParams;
    impl BigNatCircuitParams for CircuitParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 64; // 32 * 64 = 2048 (RSA key size)
    }

    pub type H = HasherFromDigest<Fq, blake3::Hasher>;
    pub type H2 = PoseidonHasher<Fq>;
    pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;
    pub type TestWesolowski = PoKER<TestPokerParams, TestRsaParams, H, CircuitParams>;
    pub type TestWesolowski2 = PoKER<TestPokerParams, TestRsaParams, H2, CircuitParams>;

    // Parameters to match up with constraints test (CM = ConstraintMatch)
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestRsa512Params;

    impl RsaGroupParams for TestRsa512Params {
        const RAW_G: usize = 2;
        const RAW_M: &'static str = "11834783464130424096695514462778\
                                     87028026498993885732873780720562\
                                     30692915355259527228479136942963\
                                     92927890261736769191982212777933\
                                     726583565708193466779811767";
    }


    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNatCM;

    impl BigNatCircuitParams for BigNatCM {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 16;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct PokerParamsCM;
    impl PoKERParams for PokerParamsCM {
        const HASH_TO_PRIME_ENTROPY: usize = 64;
    }

    pub type HogCM = RsaHiddenOrderGroup<TestRsa512Params>;
    pub type PokerCM = PoKER<PokerParamsCM, TestRsa512Params, H2, BigNatCM>;

    #[test]
    fn valid_proof_of_exponentiation_match_constraint_test() {
        let u1 = HogCM::from_nat(BigNat::from(20));
        let u2 = HogCM::from_nat(BigNat::from(30));
        let a = BigNat::from(40);
        let b = BigNat::from(50);
        let w1 = u1.power(&a).op(&u2.power(&b));
        let w2 = u2.power(&a);
        let x = Statement{u1, u2, w1, w2};
        let w = Witness{a, b};

        let proof = PokerCM::prove(&x, &w).unwrap();
        let is_valid = PokerCM::verify(&x, &proof).unwrap();
        assert!(is_valid);
    }


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
        let n_bits = 4096;
        let u1 = Hog::from_nat(BigNat::from(20)).inverse().unwrap();
        let u2 = Hog::from_nat(BigNat::from(30)).inverse().unwrap();
        let a = hash_to_integer::<H>(&fit_nat_to_limbs(&BigNat::from(40), CircuitParams::LIMB_WIDTH).unwrap(), n_bits);
        let b = hash_to_integer::<H>(&fit_nat_to_limbs(&BigNat::from(50), CircuitParams::LIMB_WIDTH).unwrap(), n_bits);
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
        let n_bits = 4096;
        let u1 = Hog::from_nat(BigNat::from(20)).inverse().unwrap();
        let u2 = Hog::from_nat(BigNat::from(30)).inverse().unwrap();
        let a = hash_to_integer::<H>(&fit_nat_to_limbs(&BigNat::from(40), CircuitParams::LIMB_WIDTH).unwrap(), n_bits);
        let b = -hash_to_integer::<H>(&fit_nat_to_limbs(&BigNat::from(50), CircuitParams::LIMB_WIDTH).unwrap(), n_bits);
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
        let n_bits = 4096;
        let u1 = Hog::from_nat(BigNat::from(20)).inverse().unwrap();
        let u2 = Hog::from_nat(BigNat::from(30)).inverse().unwrap();
        let a = hash_to_integer::<H>(&fit_nat_to_limbs(&BigNat::from(40), CircuitParams::LIMB_WIDTH).unwrap(), n_bits);
        let b = hash_to_integer::<H>(&fit_nat_to_limbs(&BigNat::from(50), CircuitParams::LIMB_WIDTH).unwrap(), n_bits);
        let w1 = u1.power(&a).op(&u2.power(&b));
        let w2 = u2.power(&a);
        let x = Statement{u1, u2, w1, w2};
        let w = Witness{a, b: BigNat::from(50)};

        let proof = TestWesolowski::prove(&x, &w).unwrap();
        let is_valid = TestWesolowski::verify(&x, &proof).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn valid_proof_of_exponentiation_with_poseidon_test() {
        let u1 = Hog::from_nat(BigNat::from(20));
        let u2 = Hog::from_nat(BigNat::from(30));
        let a = BigNat::from(40);
        let b = BigNat::from(50);
        let w1 = u1.power(&a).op(&u2.power(&b));
        let w2 = u2.power(&a);
        let x = Statement{u1, u2, w1, w2};
        let w = Witness{a, b};

        let proof = TestWesolowski2::prove(&x, &w).unwrap();
        let is_valid = TestWesolowski2::verify(&x, &proof).unwrap();
        assert!(is_valid);
    }


}
