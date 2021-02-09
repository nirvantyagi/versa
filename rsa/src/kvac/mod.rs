use crate::{
    bignat::{BigNat, extended_euclidean_gcd, fit_nat_to_limbs},
    hog::{RsaHiddenOrderGroup, RsaGroupParams},
    hash_to_prime::{HashRangeParams, Hasher, hash_to_prime},
    wesolowski::{PoKER, Statement as PoKERStatement, Witness as PoKERWitness, Proof as PoKERProof},
    Error,
};

use std::{
    error::Error as ErrorTrait,
    marker::PhantomData,
    collections::HashMap,
    fmt::{self, Debug},
};

use rug::ops::Pow;

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

// Helper wrapper to allow for deferring expensive witness operations
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum WitnessWrapper<P: RsaKVACParams> {
    Complete(MembershipWitness<P>),
    IncompleteCoprimeProof(MembershipWitness<P>),
}

pub type UpdateProof<P> =  PoKERProof<<P as RsaKVACParams>::RsaGroupParams>;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RsaKVAC<P: RsaKVACParams, H: Hasher> {
    pub map: HashMap<BigNat, (BigNat, WitnessWrapper<P>, usize)>, // key -> (value, witness, last_epoch_witness_updated)
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
            Some((value, witness_status, last_update_epoch)) => {
                let value = value.clone(); // Needed for borrow checker
                let updated_witness = match witness_status {
                    WitnessWrapper::Complete(witness) => {
                        let updated_witness = self._full_update_witness(k, *last_update_epoch, witness)?;
                        updated_witness
                    },
                    WitnessWrapper::IncompleteCoprimeProof(witness) => {
                        // Finish witness proof
                        // TODO: Optimization: updating this witness also updates the filler coprime proof values
                        let mut updated_incomplete_witness = self._full_update_witness(k, *last_update_epoch, witness)?;
                        let (z, _) = hash_to_prime::<H>(&fit_nat_to_limbs(&k)?, &self.hash_params)?;
                        let z_u = z.clone().pow(updated_incomplete_witness.u as u32);
                        let ((a, b), gcd) = extended_euclidean_gcd(
                            &BigNat::from(self.counter_dict_exp.div_exact_ref(&z_u)),
                            &z,
                        );
                        assert_eq!(gcd, 1);
                        updated_incomplete_witness.a = a;
                        updated_incomplete_witness.b = RsaQGroup::<P>::generator().power_integer(&b)?;
                        updated_incomplete_witness
                    }
                };
                self.map.insert(k.clone(), (value.clone(), WitnessWrapper::Complete(updated_witness.clone()), self.epoch));
                Ok((Some(value.clone()), updated_witness))
            },
            None => {
                let (z, _) = hash_to_prime::<H>(&fit_nat_to_limbs(&k)?, &self.hash_params)?;
                let ((a, b), gcd) = extended_euclidean_gcd(&self.counter_dict_exp, &z);
                assert_eq!(gcd, 1);
                Ok((
                       None,
                       MembershipWitness{
                           pi_1: Default::default(),
                           pi_2: Default::default(),
                           pi_3: Default::default(),
                           a,
                           b: RsaQGroup::<P>::generator().power_integer(&b)?,
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
        let (z, _) = hash_to_prime::<H>(&fit_nat_to_limbs(&k)?, hash_params)?;
        if  v.is_none() {
            // Non-membership proof
            Ok(c2.power_integer(&witness.a)?.op(&witness.b.power(&z)) == RsaQGroup::<P>::generator())
        } else {
            // Membership proof
            let z_u = z.clone().pow(witness.u as u32);
            let b_1 = witness.pi_2.power(&z) == c2;
            let b_2 = witness.pi_1.power(&z_u).op(&witness.pi_2.power(v.unwrap())) == c1;
            let b_3 = witness.pi_3.power(&z_u) == c2;
            let b_4 = witness.pi_3.power_integer(&witness.a)?.op(&witness.b.power(&z)) == RsaQGroup::<P>::generator();
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
        // Update value (but not witness - create incomplete witness for new keys)
        let (z, _) = hash_to_prime::<H>(&fit_nat_to_limbs(&k)?, &self.hash_params)?;
        let (c1, c2) = self.commitment.clone();
        let v_delta = if let Some(map_value) = self.map.get(&k) {
            let (prev_v, prev_witness, last_update_epoch) = map_value.clone(); // Needed for borrow checker
            self.map.insert(k.clone(), (v.clone(), prev_witness, last_update_epoch));
            v - prev_v
        } else {
            // Defer computation of (a,b) coprime proof by creating incomplete witness
            let incomplete_witness = MembershipWitness{
                pi_1: <RsaQGroup<P>>::clone(&c1),
                pi_2: <RsaQGroup<P>>::clone(&c2),
                pi_3: <RsaQGroup<P>>::clone(&c2),
                a: BigNat::from(1), // dummy
                b: RsaQGroup::<P>::generator(), // dummy
                u: 1,
            };
            self.map.insert(k.clone(), (v.clone(), WitnessWrapper::IncompleteCoprimeProof(incomplete_witness), self.epoch + 1));
            v
        };

        // Update commitment
        let c1_new = c1.power(&z).op(&c2.power_integer(&v_delta)?);
        let c2_new = c2.power(&z);
        self.commitment = (c1_new, c2_new);
        self.counter_dict_exp *= z.clone();
        self.epoch += 1;

        // Prove update append-only
        let statement = PoKERStatement {
            u1: RsaQGroup::<P>::clone(&c1),
            u2: RsaQGroup::<P>::clone(&c2),
            w1: self.commitment.0.clone(),
            w2: self.commitment.1.clone(),
        };
        let witness = PoKERWitness {
            a: z.clone(),
            b: v_delta.clone(),
        };
        let update_proof = PoKER::<RsaParams<P>, H>::prove(&statement, &witness)?;
        self.epoch_updates.push((k.clone(), v_delta.clone()));

        Ok((self.commitment.clone(), update_proof))
    }

    pub fn verify_update_append_only(
        c: &Commitment<P>,
        c_new: &Commitment<P>,
        proof: &UpdateProof<P>,
    ) -> Result<bool, Error> {
        let statement = PoKERStatement {
            u1: RsaQGroup::<P>::clone(&c.0),
            u2: RsaQGroup::<P>::clone(&c.1),
            w1: RsaQGroup::<P>::clone(&c_new.0),
            w2: RsaQGroup::<P>::clone(&c_new.1),
        };
        PoKER::<RsaParams<P>, H>::verify(&statement, &proof)
    }

    // Updates membership witness for all updates from 'last_update_epoch' to self.epoch.
    fn _full_update_witness(&self, k: &BigNat, last_update_epoch: usize, witness: &MembershipWitness<P>) -> Result<MembershipWitness<P>, Error> {
        let mut witness = witness.clone();
        for epoch in last_update_epoch..self.epoch {
            witness = self._update_witness(k, epoch, &witness)?;
        }
        Ok(witness)
    }

    // Updates membership witness with update from epoch 'update_epoch'
    fn _update_witness(&self, k: &BigNat, update_epoch: usize, witness: &MembershipWitness<P>) -> Result<MembershipWitness<P>, Error> {
        let (uk, delta) = &self.epoch_updates[update_epoch];
        let (z, _) = hash_to_prime::<H>(&fit_nat_to_limbs(&k)?, &self.hash_params)?;
        if k == uk {
            // If k = uk, then only need to perform a simple update
            Ok(MembershipWitness {
                pi_1: witness.pi_1.clone(),
                pi_2: witness.pi_2.power(&z),
                pi_3: witness.pi_3.clone(),
                a: witness.a.clone(),
                b: witness.b.clone(),
                u: witness.u + 1,
            })
        } else {
            // Otherwise need to recompute co-primality proof
            let (uz, _) = hash_to_prime::<H>(&fit_nat_to_limbs(uk)?, &self.hash_params)?;

            let ((_alpha, beta), gcd) = extended_euclidean_gcd(&z, &uz);
            assert_eq!(gcd, 1);
            let gamma = BigNat::from(&BigNat::from(&witness.a * &beta) % &z);
            let eta = BigNat::from(&BigNat::from(&witness.a - (&gamma * &uz)) / &z);

            Ok(MembershipWitness {
                pi_1: witness.pi_1.power(&uz).op(&witness.pi_2.power(&delta)),
                pi_2: witness.pi_2.power(&uz),
                pi_3: witness.pi_3.power(&uz),
                a: gamma,
                b: witness.b.op(&witness.pi_3.power(&eta)),
                u: witness.u,
            })
        }
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
    pub struct TestKVACParams;

    impl RsaKVACParams for TestKVACParams {
        const KEY_LEN: usize = 256;
        const VALUE_LEN: usize = 256;
        type RsaGroupParams = TestRsaParams;
    }

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
        let (_c2, _) = kvac.update(k2.clone(), v2.clone()).unwrap();

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
        let c0 = kvac.commitment.clone();

        // Insert and lookup (k1, v1) and verify update
        let k1 = BigNat::from(100);
        let v1 = BigNat::from(101);
        let (c1, update1) = kvac.update(k1.clone(), v1.clone()).unwrap();

        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), v1);
        let b = Kvac::verify_witness(&k1, v.as_ref(), c1.clone(), witness, &kvac.hash_params).unwrap();
        assert!(b);
        let b = Kvac::verify_update_append_only(&c0, &c1, &update1).unwrap();
        assert!(b);

        // Insert (k2, v2) and verify update
        let k2 = BigNat::from(200);
        let v2 = BigNat::from(201);
        let (c2, update2) = kvac.update(k2.clone(), v2.clone()).unwrap();
        let b = Kvac::verify_update_append_only(&c1, &c2, &update2).unwrap();
        assert!(b);
        let b = Kvac::verify_update_append_only(&c0, &c2, &update2).unwrap();
        assert!(!b);

        // Insert (k1, v1_new) and verify update and lookup of updated witness
        let v1_new = BigNat::from(102);
        let (c3, update3) = kvac.update(k1.clone(), v1_new.clone()).unwrap();

        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), v1_new);
        let b = Kvac::verify_witness(&k1, v.as_ref(), c3.clone(), witness, &kvac.hash_params).unwrap();
        assert!(b);
        let b = Kvac::verify_update_append_only(&c2, &c3, &update3).unwrap();
        assert!(b);

        // Update with negative delta
        let v1_neg = BigNat::from(50);
        let (c4, update4) = kvac.update(k1.clone(), v1_neg.clone()).unwrap();

        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), v1_neg);
        let b = Kvac::verify_witness(&k1, v.as_ref(), c4.clone(), witness, &kvac.hash_params).unwrap();
        assert!(b);
        let b = Kvac::verify_update_append_only(&c3, &c4, &update4).unwrap();
        assert!(b);
    }


    #[test]
    fn defer_witness_multiple_update_test() {
        let mut kvac = Kvac::new();

        // Insert and (k1, v1)
        let k1 = BigNat::from(100);
        let v1 = BigNat::from(101);
        let (c1, _) = kvac.update(k1.clone(), v1.clone()).unwrap();

        // Insert (k2, v2) and verify update
        let k2 = BigNat::from(200);
        let v2 = BigNat::from(201);
        let (c2, update2) = kvac.update(k2.clone(), v2.clone()).unwrap();
        let b = Kvac::verify_update_append_only(&c1, &c2, &update2).unwrap();
        assert!(b);

        // Update (k1, v1_2) and verify update
        let v1_2 = BigNat::from(102);
        let (c3, update3) = kvac.update(k1.clone(), v1_2.clone()).unwrap();
        let b = Kvac::verify_update_append_only(&c2, &c3, &update3).unwrap();
        assert!(b);

        // Update (k1, v1_3) and verify update
        let v1_3 = BigNat::from(103);
        let (c4, update4) = kvac.update(k1.clone(), v1_3.clone()).unwrap();
        let b = Kvac::verify_update_append_only(&c3, &c4, &update4).unwrap();
        assert!(b);

        // Update (k1, v1_4) and verify update and perform lookup verifying deferred update of witness
        let v1_4 = BigNat::from(104);
        let (c5, update5) = kvac.update(k1.clone(), v1_4.clone()).unwrap();
        let b = Kvac::verify_update_append_only(&c4, &c5, &update5).unwrap();
        assert!(b);
        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), v1_4);
        let b = Kvac::verify_witness(&k1, v.as_ref(), c5.clone(), witness, &kvac.hash_params).unwrap();
        assert!(b);
    }

}
