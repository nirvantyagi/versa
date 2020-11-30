use crate::{
    bignat::{BigNat, extended_euclidean_gcd},
    hog::{RsaHiddenOrderGroup, RsaGroupParams},
    hash_to_prime::{HashRangeParams, Hasher, hash_to_prime},
    Error,
};

use std::{
    error::Error as ErrorTrait,
    marker::PhantomData,
    cmp::{max, min, Ordering},
    collections::HashMap,
    fmt::{self, Debug, Display, Formatter},
};

use rug::ops::Pow;
use digest::Digest;

pub trait RsaKVACParams: Clone + Eq + Debug {
    const KEY_LEN: usize;
    const VALUE_LEN: usize;
    type RsaGroupParams: RsaGroupParams;
}

pub type RsaParams<P> = <P as RsaKVACParams>::RsaGroupParams;
pub type RsaQGroup<P> = RsaHiddenOrderGroup<RsaParams<P>>;
pub type Commitment<P> = (RsaQGroup<P>, RsaQGroup<P>);

//TODO: Optimization: pi_2 and pi_3 are redundant -- can remove pi_2
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MembershipWitness<P: RsaKVACParams> {
    pi_1: RsaQGroup<P>,
    pi_2: RsaQGroup<P>,
    pi_3: RsaQGroup<P>,
    a: BigNat,
    b: RsaQGroup<P>,
    u: usize,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UpdateProof<P: RsaKVACParams> {
    _params: PhantomData<P>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RsaKVAC<P: RsaKVACParams, H: Hasher> {
    pub map: HashMap<BigNat, (BigNat, MembershipWitness<P>, usize)>,
    pub commitment: Commitment<P>,
    pub counter_dict_exp: BigNat,
    pub epoch: usize,
    pub epoch_updates: Vec<(BigNat, BigNat)>,
    pub hash_params: HashRangeParams,
    _hash: PhantomData<H>,
}

impl<P: RsaKVACParams, H: Hasher> RsaKVAC<P, H> {
    pub fn new() -> Self {
        RsaKVAC {
            map: HashMap::new(),
            commitment: (
                RsaQGroup::<P>::identity(),
                RsaQGroup::<P>::generator(),
            ),
            counter_dict_exp: BigNat::from(1),
            epoch: 0,
            epoch_updates: vec![],
            hash_params: HashRangeParams{
                n_bits: P::KEY_LEN * P::KEY_LEN.next_power_of_two().trailing_zeros() as usize,
                n_trailing_ones: 2
            },
            _hash: PhantomData,
        }
    }

    pub fn lookup(&mut self, k: &BigNat) -> Result<(Option<BigNat>, MembershipWitness<P>), Error> {
        match self.map.get(k) {
            Some((value, witness, last_update_epoch)) => {
                let value = value.clone(); // Needed for borrow checker
                let updated_witness = self._full_update_witness(k, *last_update_epoch, witness)?;
                self.map.insert(k.clone(), (value.clone(), updated_witness.clone(), self.epoch));
                Ok((Some(value.clone()), updated_witness))
            },
            None => {
                let (z, _) = hash_to_prime::<H>(&k, &self.hash_params)?;
                let ((a, b), gcd) = extended_euclidean_gcd(&self.counter_dict_exp, &z);
                assert_eq!(gcd, 1);
                Ok((
                       None,
                       MembershipWitness{
                           pi_1: Default::default(),
                           pi_2: Default::default(),
                           pi_3: Default::default(),
                           a,
                           b: RsaQGroup::<P>::generator().power(&b),
                           u: 0,
                       }),
                )
            },
        }
    }

    pub fn verify_witness(
        k: &BigNat,
        v: Option<&BigNat>,
        c: Commitment<P>,
        witness: MembershipWitness<P>,
        hash_params: &HashRangeParams,
    ) -> Result<bool, Error> {
        let (c1, c2) = c;
        let (z, _) = hash_to_prime::<H>(&k, hash_params)?;
        if  v.is_none() {
            // Non-membership proof
            Ok(c2.power(&witness.a).op(&witness.b.power(&z)) == RsaQGroup::<P>::generator())
        } else {
            // Membership proof
            let z_u = z.clone().pow(witness.u as u32);
            let b_1 = witness.pi_2.power(&z) == c2;
            let b_2 = witness.pi_1.power(&z_u).op(&witness.pi_2.power(v.unwrap())) == c1;
            let b_3 = witness.pi_3.power(&z_u) == c2;
            let b_4 = witness.pi_3.power(&witness.a).op(&witness.b.power(&z)) == RsaQGroup::<P>::generator();
            Ok(b_1 && b_2 && b_3 && b_4)
        }
    }


    pub fn update(&mut self, k: BigNat, v: BigNat) -> Result<(Commitment<P>, UpdateProof<P>), Error> {
        if v.significant_bits() > P::VALUE_LEN as u32 || v < 0 {
            return Err(Box::new(RsaKVACError::InvalidValue(v)))
        }
        if k.significant_bits() > P::KEY_LEN as u32 || k < 0 {
            return Err(Box::new(RsaKVACError::InvalidKey(k)))
        }
        // Update value and witness
        let (z, _) = hash_to_prime::<H>(&k, &self.hash_params)?;
        let (c1, c2) = &self.commitment;
        let v_delta = if let Some((prev_v, prev_witness, last_update_epoch)) = self.map.get(&k) {
            let prev_v = prev_v.clone(); // Needed for borrow checker
            let mut current_witness = self._full_update_witness(&k, *last_update_epoch, prev_witness)?;
            current_witness.pi_2 = current_witness.pi_2.power(&z);
            current_witness.u = current_witness.u + 1;
            self.map.insert(k.clone(), (v.clone(), current_witness, self.epoch + 1));
            v - prev_v
        } else {
            let ((a, b), gcd) = extended_euclidean_gcd(&self.counter_dict_exp, &z);
            assert_eq!(gcd, 1);
            let initial_witness = MembershipWitness{
                pi_1: <RsaQGroup<P>>::clone(c1),
                pi_2: <RsaQGroup<P>>::clone(c2),
                pi_3: <RsaQGroup<P>>::clone(c2),
                a,
                b: RsaQGroup::<P>::generator().power(&b),
                u: 1,
            };
            self.map.insert(k.clone(), (v.clone(), initial_witness, self.epoch + 1));
            v
        };

        // Update commitment
        let c1_new = if v_delta > 0 {
            c1.power(&z).op(&c2.power(&v_delta))
        } else {
            c1.power(&z).op(&c2.inverse()?.power(&BigNat::from(v_delta.abs_ref())))
        };
        let c2_new = c2.power(&z);
        self.commitment = (c1_new, c2_new);
        self.counter_dict_exp *= z;
        self.epoch += 1;

        // Prove update append-only
        // TODO: Modified Wesolowski Sigma protocol
        let update_proof = UpdateProof{_params: PhantomData};
        self.epoch_updates.push((k.clone(), v_delta.clone()));

        Ok((self.commitment.clone(), update_proof))
    }

    // Updates membership witness for all updates from 'last_update_epoch' to self.epoch.
    // Assumes all updates are for k'\neq k since membership witness is updated if value is updated
    fn _full_update_witness(&self, k: &BigNat, last_update_epoch: usize, witness: &MembershipWitness<P>) -> Result<MembershipWitness<P>, Error> {
        let mut witness = witness.clone();
        for epoch in (last_update_epoch..self.epoch) {
            witness = self._update_witness(k, epoch, &witness)?;
        }
        Ok(witness)
    }

    // Updates membership witness with update from epoch 'update_epoch'
    // Assumes update is for k'\neq k since membership witness is updated if value is updated
    fn _update_witness(&self, k: &BigNat, update_epoch: usize, witness: &MembershipWitness<P>) -> Result<MembershipWitness<P>, Error> {
        let (uk, delta) = &self.epoch_updates[update_epoch];
        let (z, _) = hash_to_prime::<H>(&k, &self.hash_params)?;
        let (uz, _) = hash_to_prime::<H>(uk, &self.hash_params)?;

        let ((_alpha, beta), gcd) = extended_euclidean_gcd(&z, &uz);
        assert_eq!(gcd, 1);
        let gamma = BigNat::from(&BigNat::from(&witness.a * &beta) % &z);
        let eta = BigNat::from(&BigNat::from(&witness.a - (&gamma * &uz)) / &z);

        Ok(MembershipWitness{
            pi_1: witness.pi_1.power(&uz).op(&witness.pi_2.power(&delta)),
            pi_2: witness.pi_2.power(&uz),
            pi_3: witness.pi_3.power(&uz),
            a: gamma,
            b: witness.b.op(&witness.pi_3.power(&eta)),
            u: witness.u,
        })
    }

}


#[derive(Debug)]
pub enum RsaKVACError {
    InvalidValue(BigNat),
    InvalidKey(BigNat),
}

impl ErrorTrait for RsaKVACError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl fmt::Display for RsaKVACError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            RsaKVACError::InvalidValue(n) => format!("Value invalid: {}", n),
            RsaKVACError::InvalidKey(n) => format!("Key invalid: {}", n),
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

    use crate::hash_to_prime::HasherFromDigest;

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

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestKVACParams;

    impl RsaKVACParams for TestKVACParams {
        const KEY_LEN: usize = 256;
        const VALUE_LEN: usize = 256;
        type RsaGroupParams = TestRsaParams;
    }

    pub type Hog = RsaHiddenOrderGroup<TestRsaParams>;
    //pub type Kvac = RsaKVAC<TestKVACParams, Blake3<Fq>>;
    pub type Kvac = RsaKVAC<TestKVACParams, HasherFromDigest<Fq, blake3::Hasher>>;

    #[test]
    fn lookup_test() {
        let mut kvac = Kvac::new();

        let k1 = BigNat::from(100);
        let v1 = BigNat::from(101);
        let (c1, _) = kvac.update(k1.clone(), v1.clone()).unwrap();

        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), v1);
        let b = Kvac::verify_witness(&k1, v.as_ref(), c1.clone(), witness, &kvac.hash_params).unwrap();
        assert!(b);

        let k2 = BigNat::from(200);
        let v2 = BigNat::from(201);
        let (c2, _) = kvac.update(k2.clone(), v2.clone()).unwrap();

        let k3 = BigNat::from(300);
        let v3 = BigNat::from(301);
        let (c3, _) = kvac.update(k3.clone(), v3.clone()).unwrap();

        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), v1);
        let b = Kvac::verify_witness(&k1, v.as_ref(), c3.clone(), witness, &kvac.hash_params).unwrap();
        assert!(b);

        let (v, witness) = kvac.lookup(&k2).unwrap();
        assert_eq!(v.clone().unwrap(), v2);
        let b = Kvac::verify_witness(&k2, v.as_ref(), c3.clone(), witness, &kvac.hash_params).unwrap();
        assert!(b);

        let k4 = BigNat::from(400);
        let (v, witness) = kvac.lookup(&k4).unwrap();
        assert!(v.is_none());
        let b = Kvac::verify_witness(&k4, v.as_ref(), c3.clone(), witness, &kvac.hash_params).unwrap();
        assert!(b);
    }

    #[test]
    fn update_value_test() {
        let mut kvac = Kvac::new();

        let k1 = BigNat::from(100);
        let v1 = BigNat::from(101);
        let (c1, _) = kvac.update(k1.clone(), v1.clone()).unwrap();

        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), v1);
        let b = Kvac::verify_witness(&k1, v.as_ref(), c1.clone(), witness, &kvac.hash_params).unwrap();
        assert!(b);

        let k2 = BigNat::from(200);
        let v2 = BigNat::from(201);
        let (c2, _) = kvac.update(k2.clone(), v2.clone()).unwrap();

        let v1_new = BigNat::from(102);
        let (c3, _) = kvac.update(k1.clone(), v1_new.clone()).unwrap();

        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), v1_new);
        let b = Kvac::verify_witness(&k1, v.as_ref(), c3.clone(), witness, &kvac.hash_params).unwrap();
        assert!(b);

        // Update with negative delta
        let v1_neg = BigNat::from(50);
        let (c4, _) = kvac.update(k1.clone(), v1_neg.clone()).unwrap();

        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), v1_neg);
        let b = Kvac::verify_witness(&k1, v.as_ref(), c4.clone(), witness, &kvac.hash_params).unwrap();
        assert!(b);
    }

}
