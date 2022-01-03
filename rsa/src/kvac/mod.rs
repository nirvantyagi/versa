use crate::{
    bignat::{BigNat, Order, extended_euclidean_gcd, fit_nat_to_limb_capacity, constraints::BigNatCircuitParams},
    hog::{RsaHiddenOrderGroup, RsaGroupParams},
    hash::hash_to_prime::{hash_to_prime},
    poker::{
        PoKER,
        Statement as PoKERStatement,
        Witness as PoKERWitness,
        Proof as PoKERProof,
        PoKERParams,
    },
    Error,
};

use ark_ff::ToBytes;

use std::{
    error::Error as ErrorTrait,
    marker::PhantomData,
    fmt::{self, Debug},
    io::{Result as IoResult, Write},
    collections::HashSet,
};

use rug::ops::Pow;
use rayon::prelude::*;

pub mod store;

pub trait RsaKVACParams: Clone + Eq + Debug {
    const KEY_LEN: usize;
    const VALUE_LEN: usize;
    //TODO: Ensure that primes are greater than value
    const PRIME_LEN: usize; // KEY_LEN + log_2(KEY_LEN)
    type RsaGroupParams: RsaGroupParams;
    type PoKERParams: PoKERParams;
}

pub type RsaParams<P> = <P as RsaKVACParams>::RsaGroupParams;
pub type PoKParams<P> = <P as RsaKVACParams>::PoKERParams;
pub type Hog<P> = RsaHiddenOrderGroup<RsaParams<P>>;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Commitment<P: RsaKVACParams> {
    pub c1: Hog<P>,
    pub c2: Hog<P>,
    pub _params: PhantomData<P>,
}

impl<P: RsaKVACParams> ToBytes for Commitment<P> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        let c1_bytes = self.c1.n.to_digits::<u8>(Order::LsfBe);
        c1_bytes.write(&mut writer)?;
        let c2_bytes = self.c2.n.to_digits::<u8>(Order::LsfBe);
        c2_bytes.write(&mut writer)
    }
}

impl<P: RsaKVACParams> Default for Commitment<P> {
    fn default() -> Self {
        Commitment {
            c1: Hog::<P>::identity(),
            c2: Hog::<P>::generator(),
            _params: PhantomData,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MembershipWitness<P: RsaKVACParams> {
    pub pi_1: Hog<P>,
    pub pi_3: Hog<P>,
    pub a: BigNat,
    pub b: Hog<P>,
    pub u: usize,
}

// Helper wrapper to allow for deferring expensive witness operations
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum WitnessWrapper<P: RsaKVACParams> {
    Complete(MembershipWitness<P>),
    IncompleteCoprimeProof(MembershipWitness<P>),
}

pub type UpdateProof<P, H> =  PoKERProof<<P as RsaKVACParams>::RsaGroupParams, H>;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RsaKVAC<T: store::RsaKVACStorer> {
    pub store: T,
}

impl<T: store::RsaKVACStorer> RsaKVAC<T> {
    pub fn new(s: T) -> Self {
        RsaKVAC { store: s }
    }

    pub fn get_counter_dict_exp(&mut self) -> BigNat {
        let mut deferred_updates = vec![];
        deferred_updates.append(&mut self.store.get_deferred_counter_dict_exp_updates());
        self.store.clear_deferred_counter_dict_exp_updates();
        assert_eq!(self.store.get_deferred_counter_dict_exp_updates(), Vec::<BigNat>::new());
        self.store.set_counter_dict_exp(deferred_updates.into_iter().fold(self.store.get_counter_dict_exp(), |exp, z| exp * z));
        self.store.get_counter_dict_exp()
    }

    pub fn lookup(&mut self, k: &BigNat) -> Result<(Option<BigNat>, MembershipWitness<T::P>), Error> {
        match self.store.get_map(k) {
            Some((value, version, witness_status, last_update_epoch)) => {
                let (value, version) = (value.clone(), version.clone()); // Needed for borrow checker
                let updated_witness = match witness_status {
                    WitnessWrapper::Complete(witness) => {
                        let updated_witness = self._full_update_witness(k, *last_update_epoch, witness)?;
                        updated_witness
                    },
                    WitnessWrapper::IncompleteCoprimeProof(witness) => {
                        // Finish witness proof
                        // TODO: Optimization: updating this witness also updates the filler coprime proof values
                        let mut updated_incomplete_witness = self._full_update_witness(k, *last_update_epoch, witness)?;
                        let (z, _) = hash_to_prime::<T::H>(&fit_nat_to_limb_capacity(&k)?, T::P::PRIME_LEN)?;
                        let z_u = z.clone().pow(updated_incomplete_witness.u as u32);
                        let ((a, b), gcd) = extended_euclidean_gcd(
                            &BigNat::from(self.get_counter_dict_exp().div_exact_ref(&z_u)),
                            &z,
                        );
                        assert_eq!(gcd, 1);
                        updated_incomplete_witness.a = a;
                        updated_incomplete_witness.b = Hog::<T::P>::generator().power(&b);
                        updated_incomplete_witness
                    }
                };
                self.store.insert_map(k.clone(), (value.clone(), version, WitnessWrapper::Complete(updated_witness.clone()), self.store.get_epoch()));
                Ok((Some(value.clone()), updated_witness))
            },
            None => {
                let (z, _) = hash_to_prime::<T::H>(&fit_nat_to_limb_capacity(&k)?, T::P::PRIME_LEN)?;
                let ((a, b), gcd) = extended_euclidean_gcd(&self.get_counter_dict_exp(), &z);
                assert_eq!(gcd, 1);
                Ok((
                       None,
                       MembershipWitness{
                           pi_1: Default::default(),
                           pi_3: Default::default(),
                           a,
                           b: Hog::<T::P>::generator().power(&b),
                           u: 0,
                       }),
                )
            },
        }
    }

    pub fn verify_witness(
        k: &BigNat,
        v: &Option<BigNat>,
        c: &Commitment<T::P>,
        witness: &MembershipWitness<T::P>,
    ) -> Result<bool, Error> {
        let (c1, c2) = (c.c1.clone(), c.c2.clone());
        let (z, _) = hash_to_prime::<T::H>(&fit_nat_to_limb_capacity(&k)?, T::P::PRIME_LEN)?;
        if  v.is_none() {
            // Non-membership proof
            Ok(c2.power(&witness.a).op(&witness.b.power(&z)) == Hog::<T::P>::generator())
        } else {
            // Membership proof
            //TODO: Optimization tradeoff: Can track optional "pi_2" from KVAC paper so don't need to do z^{u-1}
            let z_u1 = z.clone().pow(witness.u as u32 - 1);
            let z_u = BigNat::from(&z_u1 * &z);
            let b_1 = witness.pi_1.power(&z_u).op(&witness.pi_3.power(&BigNat::from(v.as_ref().unwrap() * &z_u1))) == c1.clone();
            let b_2 = witness.pi_3.power(&z_u) == c2.clone();
            let b_3 = witness.pi_3.power(&witness.a).op(&witness.b.power(&z)) == Hog::<T::P>::generator();
            Ok(b_1 && b_2 && b_3)
        }
    }

    pub fn update(&mut self, k: BigNat, v: BigNat) -> Result<(Commitment<T::P>, UpdateProof<T::P, T::CircuitH>), Error> {
        let (c, proof, _) = self._update(k, v)?;
        Ok((c, proof))
    }

    pub fn batch_update(&mut self, kvs: &Vec<(BigNat, BigNat)>) -> Result<(Commitment<T::P>, UpdateProof<T::P, T::CircuitH>), Error> {
        let (c, proof, _) = self._batch_update(kvs)?;
        Ok((c, proof))
    }

    fn _update(
        &mut self, k: BigNat,
        v: BigNat,
    ) -> Result<(Commitment<T::P>, UpdateProof<T::P, T::CircuitH>, (BigNat, BigNat)), Error> {
        // Update value
        let v_delta = self._update_value(k.clone(), v.clone())?;

        // Update commitment
        let (z, _) = hash_to_prime::<T::H>(&fit_nat_to_limb_capacity(&k)?, T::P::PRIME_LEN)?;
        let update_proof = self._update_commitment(&z, &v_delta)?;
        self.store.push_epoch_updates(vec![(k.clone(), v_delta.clone())]);
        Ok((self.store.get_commitment(), update_proof, (z, v_delta)))
    }


    pub fn _batch_update(
        &mut self,
        kvs: &Vec<(BigNat, BigNat)>,
    ) -> Result<(Commitment<T::P>, UpdateProof<T::P, T::CircuitH>, (BigNat, BigNat)), Error> {
        // Update individual values and compute batched update values
        let mut z_vals = vec![];
        let mut delta_vals= vec![];
        for (k, v) in kvs.iter() {
            let (z, _) = hash_to_prime::<T::H>(&fit_nat_to_limb_capacity(k)?, T::P::PRIME_LEN)?;
            z_vals.push(z);
            delta_vals.push(self._update_value(k.clone(), v.clone())?);
        }

        let (z_product, delta_sum) = Self::_compute_batch_z_delta(
            &z_vals.iter().zip(&delta_vals)
                .map(|(z, delta)| (z.clone(), BigNat::from(1), delta.clone()))
                .collect::<Vec<_>>()
        );

        // Update commitment
        let update_proof = self._update_commitment(&z_product, &delta_sum)?;
        self.store.push_epoch_updates(kvs.iter().zip(&delta_vals).map(|((k, _v), d)| (k.clone(), d.clone())).collect());

        Ok((self.store.get_commitment(), update_proof, (z_product, delta_sum)))
    }

    pub fn verify_update_append_only(
        c: &Commitment<T::P>,
        c_new: &Commitment<T::P>,
        proof: &UpdateProof<T::P, T::CircuitH>,
    ) -> Result<bool, Error> {
        let statement = PoKERStatement {
            u1: Hog::<T::P>::clone(&c.c1),
            u2: Hog::<T::P>::clone(&c.c2),
            w1: Hog::<T::P>::clone(&c_new.c1),
            w2: Hog::<T::P>::clone(&c_new.c2),
        };
        PoKER::<PoKParams<T::P>, RsaParams<T::P>, T::CircuitH, T::C>::verify(&statement, &proof)
    }



    fn _update_value(&mut self, k: BigNat, v: BigNat) -> Result<BigNat, Error> {
        if v.significant_bits() > T::P::VALUE_LEN as u32 || v < 0 {
            return Err(Box::new(RsaKVACError::InvalidValue(v)))
        }
        if k.significant_bits() > T::P::KEY_LEN as u32 || k < 0 {
            return Err(Box::new(RsaKVACError::InvalidKey(k)))
        }
        // Update value (but not witness - create incomplete witness for new keys) and returns "value delta" to be incorporated in commitment update
        let (c1, c2) = (self.store.get_commitment().c1.clone(), self.store.get_commitment().c2.clone());
        if let Some(map_value) = self.store.get_map(&k) {
            let (prev_v, version, prev_witness, last_update_epoch) = map_value.clone(); // Needed for borrow checker
            self.store.insert_map(k.clone(), (v.clone(), version + 1, prev_witness, last_update_epoch));
            Ok(v - prev_v)
        } else {
            // Defer computation of (a,b) coprime proof by creating incomplete witness
            let incomplete_witness = MembershipWitness {
                pi_1: <Hog<T::P>>::clone(&c1),
                pi_3: <Hog<T::P>>::clone(&c2),
                a: BigNat::from(1), // dummy
                b: Hog::<T::P>::generator(), // dummy
                u: 0,
            };
            self.store.insert_map(k.clone(), (v.clone(), 1, WitnessWrapper::IncompleteCoprimeProof(incomplete_witness), self.store.get_epoch()));
            // Set u=0 and last_epoch_updated=self.epoch so that future witness update catches other updates in this epoch batch
            Ok(v)
        }
    }

    fn _update_commitment(&mut self, z: &BigNat, delta: &BigNat) -> Result<UpdateProof<T::P, T::CircuitH>, Error> {
        let (c1, c2) = (self.store.get_commitment().c1.clone(), self.store.get_commitment().c2.clone());
        let c1_new = c1.power(z).op(&c2.power(delta));
        let c2_new = c2.power(z);
        self.store.set_commitment(Commitment { c1: c1_new, c2: c2_new, _params: PhantomData });
        self.store.push_deferred_counter_dict_exp_updates(z.clone());
        self.store.increment_epoch();

        // Prove update append-only
        let statement = PoKERStatement {
            u1: Hog::<T::P>::clone(&c1),
            u2: Hog::<T::P>::clone(&c2),
            w1: self.store.get_commitment().c1.clone(),
            w2: self.store.get_commitment().c2.clone(),
        };
        let witness = PoKERWitness {
            a: z.clone(),
            b: delta.clone(),
        };
        PoKER::<PoKParams<T::P>, RsaParams<T::P>, T::CircuitH, T::C>::prove(&statement, &witness)
    }


        // Updates membership witness for all updates from 'last_update_epoch' to self.epoch.
    fn _full_update_witness(&self, k: &BigNat, last_update_epoch: usize, witness: &MembershipWitness<T::P>) -> Result<MembershipWitness<T::P>, Error> {
        let mut witness = witness.clone();
        for epoch in last_update_epoch..self.store.get_epoch() {
            for (uk, delta) in self.store.get_epoch_updates()[epoch].iter() {
                let (uz, _) = hash_to_prime::<T::H>(&fit_nat_to_limb_capacity(uk)?, T::P::PRIME_LEN)?;
                witness = Self::_update_witness(k, (uk, &uz, delta), &witness)?;
            }
        }
        Ok(witness)
    }

    // Updates membership witness with update from epoch 'update_epoch'
    pub fn _update_witness(
        k: &BigNat,
        update: (&BigNat, &BigNat, &BigNat),
        witness: &MembershipWitness<T::P>,
    ) -> Result<MembershipWitness<T::P>, Error> {
        let (uk, uz, delta) = update;
        let (z, _) = hash_to_prime::<T::H>(&fit_nat_to_limb_capacity(&k)?, T::P::PRIME_LEN)?;
        if k == uk {
            // If k = uk, then only need to perform a simple update
            Ok(MembershipWitness {
                pi_1: witness.pi_1.clone(),
                pi_3: witness.pi_3.clone(),
                a: witness.a.clone(),
                b: witness.b.clone(),
                u: witness.u + 1,
            })
        } else {
            // Otherwise need to recompute co-primality proof
            let ((_alpha, beta), gcd) = extended_euclidean_gcd(&z, uz);
            assert_eq!(gcd, 1);
            let gamma = BigNat::from(&BigNat::from(&witness.a * &beta) % &z);
            let eta = BigNat::from(&BigNat::from(&witness.a - (&gamma * uz)) / &z);

            Ok(MembershipWitness {
                pi_1: witness.pi_1.power(uz).op(&witness.pi_3.power(delta)),
                pi_3: witness.pi_3.power(uz),
                a: gamma,
                b: witness.b.op(&witness.pi_3.power(&eta)),
                u: witness.u,
            })
        }
    }

    pub fn batch_update_membership_witnesses(&mut self, keys: Option<&HashSet<BigNat>>) -> Result<(), Error> {
        let witnesses = Self::_batch_update_membership_witnesses(
            self.store.get_iterable_map()
                .map(|(k, (v, u, _, _))| (k.clone(), v.clone(), *u)),
            keys,
        )?;

        // Update witnesses in state
        for ((k, (h, g, a, b)), z_u1) in witnesses.into_iter() {
            let (v, u, _, _) = self.store.get_map(&k).unwrap();
            let (v, u) = (v.clone(), u.clone()); // For borrow checker
            let updated_witness = MembershipWitness {
                pi_1: h,
                pi_3: g,
                a: a,
                b: b.power(&z_u1),
                u: u,
            };
            self.store.insert_map(k, (v, u, WitnessWrapper::Complete(updated_witness), self.store.get_epoch()));
        }
        Ok(())
    }

    // Note: split off for easier entry point for benchmarking
    pub fn _batch_update_membership_witnesses(
        kvs: impl Iterator<Item = (BigNat, BigNat, usize)>,
        keys: Option<&HashSet<BigNat>>,
    ) -> Result<Vec<((BigNat, (Hog<T::P>, Hog<T::P>, BigNat, Hog<T::P>)), BigNat)>, Error> { // ((k, (witness)), z_u1)
        let update_all_keys = keys.is_none();
        let mut keys_to_update = vec![];
        let mut keys_to_update_u1 = vec![];
        let mut keys_to_update_values = vec![];
        let mut keys_no_update_values = vec![];

        if update_all_keys {
            for (k, v, u) in kvs.into_iter() {
                let (z, _) = hash_to_prime::<T::H>(&fit_nat_to_limb_capacity(&k)?, T::P::PRIME_LEN)?;
                let z_u1 = z.clone().pow(u as u32 - 1);
                let z_u = BigNat::from(&z_u1 * &z);
                keys_to_update.push(k.clone());
                keys_to_update_u1.push(z_u1.clone());
                keys_to_update_values.push((z_u, z_u1, v.clone()));
            }
        } else {
            let keys = keys.unwrap();
            for (k, v, u) in kvs.into_iter() {
                let (z, _) = hash_to_prime::<T::H>(&fit_nat_to_limb_capacity(&k)?, T::P::PRIME_LEN)?;
                let z_u1 = z.clone().pow(u as u32 - 1);
                let z_u = BigNat::from(&z_u1 * &z);
                if keys.contains(&k) {
                    keys_to_update.push(k.clone());
                    keys_to_update_u1.push(z_u1.clone());
                    keys_to_update_values.push((z_u, z_u1, v.clone()));
                } else {
                    keys_no_update_values.push((z_u, z_u1, v.clone()));
                }
            }
        }

        // Compute initial values from keys not being updated
        let (initial_z, initial_delta) =  if keys_no_update_values.len() == 0 {
            (BigNat::from(1), BigNat::from(0))
        } else {
            Self::_compute_batch_z_delta(&keys_no_update_values)
        };
        std::mem::drop(keys_no_update_values);
        let initial_g = Hog::<T::P>::generator().power(&initial_z);
        let initial_h = Hog::<T::P>::generator().power(&initial_delta);

        // Compute witnesses
        let witnesses = Self::mem_witness_recurse_helper_unrolled(
            initial_h,
            initial_g,
            initial_z,
            keys_to_update_values,
        );
        assert_eq!(witnesses.len(), keys_to_update.len());
        Ok(keys_to_update.into_iter()
               .zip(witnesses.into_iter())
               .zip(keys_to_update_u1.into_iter())
               .collect::<Vec<_>>())
    }

    //fn mem_witness_recurse_helper(
    //    h: Hog<P>,
    //    g: Hog<P>,
    //    a: BigNat,
    //    b: Hog<P>,
    //    values: Vec<(BigNat, BigNat, BigNat)>, // (z^{u}, z^{u-1}, value)
    //) -> Vec<(Hog<P>, Hog<P>, BigNat, Hog<P>)> { // (h, g, a, b)
    //    assert!(values.len() > 0);
    //    if values.len() == 1 {
    //        vec![(h, g, a, b)]
    //    } else {
    //        let mut l_values = values;
    //        let r_values = l_values.split_off(l_values.len() / 2);
    //        let (z_l, delta_l) = Self::_compute_batch_z_delta(&l_values);
    //        let (z_r, delta_r) = Self::_compute_batch_z_delta(&r_values);
    //        debug_assert!(g.power(&a).op(&b.power(&(z_l.clone()*z_r.clone()))) == Hog::<P>::generator());
    //        let (h_l, g_l) = (h.power(&z_l).op(&g.power(&delta_l)), g.power(&z_l));
    //        let (h_r, g_r) = (h.power(&z_r).op(&g.power(&delta_r)), g.power(&z_r));
    //        let ((s, t), gcd) = extended_euclidean_gcd(&z_l, &z_r);
    //        assert_eq!(gcd, 1);
    //        let (a_t, a_s) = (a.clone() * t.clone(), a.clone() * s.clone());
    //        let (q_l, r_l) = a_t.clone().div_rem(z_l.clone());
    //        let (q_r, r_r) = a_s.clone().div_rem(z_r.clone());
    //        let b_l = g_r.power(&q_l).op(&g.power(&a_s)).op(&b.power(&z_r));
    //        let b_r = g_l.power(&q_r).op(&g.power(&a_t)).op(&b.power(&z_l));
    //        debug_assert!(g_r.power(&r_l).op(&b_l.power(&z_l)) == Hog::<P>::generator());
    //        debug_assert!(g_l.power(&r_r).op(&b_r.power(&z_r)) == Hog::<P>::generator());
    //        let mut witnesses = Self::mem_witness_recurse_helper(h_r, g_r, r_l, b_l, l_values);
    //        witnesses.append(&mut Self::mem_witness_recurse_helper(h_l, g_l, r_r, b_r, r_values));
    //        witnesses
    //    }
    //}

    // Unrolling recursion is more amenable to parallelization
    fn mem_witness_recurse_helper_unrolled(
        initial_h: Hog<T::P>,
        initial_g: Hog<T::P>,
        initial_z: BigNat,
        values: Vec<(BigNat, BigNat, BigNat)>, // (z^{u}, z^{u-1}, value)
    ) -> Vec<(Hog<T::P>, Hog<T::P>, BigNat, Hog<T::P>)> { // (h, g, a, b)
        // Compute z and delta values
        let mut z_deltas = vec![values.iter().map(|v| (v.0.clone(), v.1.clone() * v.2.clone())).collect::<Vec<_>>()];
        for i in 0..(values.len() - 1).next_power_of_two().count_zeros() as usize {
            let next_z_delta = z_deltas[i].par_chunks(2)
                .map(|chunk| {
                    if chunk.len() == 2 {
                        let (l_prod, l_delta) = &chunk[0];
                        let (r_prod, r_delta) = &chunk[1];
                        let lr_prod = l_prod.clone() * r_prod.clone();
                        let lr_delta = l_prod.clone() * r_delta.clone() + r_prod.clone() * l_delta.clone();
                        (lr_prod, lr_delta)
                    } else {
                        chunk[0].clone()
                    }
                }).collect::<Vec<(BigNat, BigNat)>>();
            z_deltas.push(next_z_delta);
        }
        assert_eq!(z_deltas.last().unwrap().len(), 1);
        let (update_z, _) = &z_deltas.last().unwrap()[0];
        let ((initial_a, initial_b), gcd) = extended_euclidean_gcd(&initial_z, &update_z);
        assert_eq!(gcd, 1);
        let initial_b = Hog::<T::P>::generator().power(&initial_b);

        // Compute witnesses
        let mut witnesses = vec![(initial_h, initial_g, initial_a, initial_b)];
        for z_delta_vec in z_deltas.iter().rev().skip(1) {
            let next_witnesses = z_delta_vec.par_chunks(2).enumerate()
                .map(|(j, chunk)| {
                    if chunk.len() == 2 {
                        let (z_l, delta_l) = &chunk[0];
                        let (z_r, delta_r) = &chunk[1];
                        let (h, g, a, b) = &witnesses[j];
                        let (h_l, g_l) = (h.power(&z_l).op(&g.power(&delta_l)), g.power(&z_l));
                        let (h_r, g_r) = (h.power(&z_r).op(&g.power(&delta_r)), g.power(&z_r));
                        let ((s, t), gcd) = extended_euclidean_gcd(&z_l, &z_r);
                        assert_eq!(gcd, 1);
                        let (a_t, a_s) = (a.clone() * t.clone(), a.clone() * s.clone());
                        let (q_l, r_l) = a_t.clone().div_rem(z_l.clone());
                        let (q_r, r_r) = a_s.clone().div_rem(z_r.clone());
                        let b_l = g_r.power(&q_l).op(&g.power(&a_s)).op(&b.power(&z_r));
                        let b_r = g_l.power(&q_r).op(&g.power(&a_t)).op(&b.power(&z_l));
                        debug_assert!(g_r.power(&r_l).op(&b_l.power(&z_l)) == Hog::<T::P>::generator());
                        debug_assert!(g_l.power(&r_r).op(&b_r.power(&z_r)) == Hog::<T::P>::generator());
                        vec![(h_r, g_r, r_l, b_l), (h_l, g_l, r_r, b_r)]
                    } else {
                        vec![witnesses[j].clone()]
                    }

                }).flatten().collect::<Vec<(Hog<T::P>, Hog<T::P>, BigNat, Hog<T::P>)>>();
            witnesses = next_witnesses;
        }
        witnesses
    }



    fn _compute_batch_z_delta(
        values: &Vec<(BigNat, BigNat, BigNat)>, // (z^{u}, z^{u-1}, value)
    ) -> (BigNat, BigNat) { // (z_prod, delta_sum)
        assert!(values.len() > 0);
        let mut values = values.iter()
            .map(|(zu, zu_minus1, v)| (zu.clone(), v.clone() * zu_minus1.clone()))
            .collect::<Vec<(BigNat, BigNat)>>();
        let result = 'recurse: loop {
            if values.len() == 1 {
                // base case
                break 'recurse values[0].clone();
            } else {
                values = values.par_chunks(2)
                    .map(|chunk| {
                        if chunk.len() == 2 {
                            let (l_prod, l_delta) = &chunk[0];
                            let (r_prod, r_delta) = &chunk[1];
                            let lr_prod = l_prod.clone() * r_prod.clone();
                            let lr_delta = l_prod.clone() * r_delta.clone() + r_prod.clone() * l_delta.clone();
                            (lr_prod, lr_delta)
                        } else {
                            chunk[0].clone()
                        }
                    }).collect::<Vec<(BigNat, BigNat)>>();
            }
        };
        result
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
    use ark_ed_on_bls12_381::{Fq};

    use crate::hash::{HasherFromDigest, PoseidonHasher};
    use crate::kvac::{
        store::mem_store::RsaKVACMemStore,
        store::RsaKVACStorer,
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
    pub struct CircuitParams;
    impl BigNatCircuitParams for CircuitParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 64; // 32 * 64 = 2048 (RSA key size)
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestPokerParams;
    impl PoKERParams for TestPokerParams {
        const HASH_TO_PRIME_ENTROPY: usize = 128;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestKVACParams;

    impl RsaKVACParams for TestKVACParams {
        const KEY_LEN: usize = 256;
        const VALUE_LEN: usize = 256;
        const PRIME_LEN: usize = 264;
        type RsaGroupParams = TestRsaParams;
        type PoKERParams = TestPokerParams;
    }

    pub type KvacStore = RsaKVACMemStore<TestKVACParams, HasherFromDigest<Fq, blake3::Hasher>, PoseidonHasher<Fq>, CircuitParams>;
    pub type Kvac = RsaKVAC<KvacStore>;

    #[test]
    fn lookup_test() {
        let mut kvac = Kvac::new(KvacStore::new());
        let k1 = BigNat::from(100);
        let v1 = BigNat::from(101);
        let (c1, _) = kvac.update(k1.clone(), v1.clone()).unwrap();

        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), v1);
        let b = Kvac::verify_witness(&k1, &v, &c1, &witness).unwrap();
        assert!(b);

        let k2 = BigNat::from(200);
        let v2 = BigNat::from(201);
        let (_c2, _) = kvac.update(k2.clone(), v2.clone()).unwrap();

        let k3 = BigNat::from(300);
        let v3 = BigNat::from(301);
        let (c3, _) = kvac.update(k3.clone(), v3.clone()).unwrap();

        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), v1);
        let b = Kvac::verify_witness(&k1, &v, &c3, &witness).unwrap();
        assert!(b);

        let (v, witness) = kvac.lookup(&k2).unwrap();
        assert_eq!(v.clone().unwrap(), v2);
        let b = Kvac::verify_witness(&k2, &v, &c3, &witness).unwrap();
        assert!(b);

        let k4 = BigNat::from(400);
        let (v, witness) = kvac.lookup(&k4).unwrap();
        assert!(v.is_none());
        let b = Kvac::verify_witness(&k4, &v, &c3, &witness).unwrap();
        assert!(b);
    }

    #[test]
    fn update_value_test() {
        let mut kvac = Kvac::new(KvacStore::new());
        let c0 = kvac.store.commitment.clone();

        // Insert and lookup (k1, v1) and verify update
        let k1 = BigNat::from(100);
        let v1 = BigNat::from(101);
        let (c1, update1) = kvac.update(k1.clone(), v1.clone()).unwrap();

        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), v1);
        let b = Kvac::verify_witness(&k1, &v, &c1, &witness).unwrap();
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
        let b = Kvac::verify_witness(&k1, &v, &c3, &witness).unwrap();
        assert!(b);
        let b = Kvac::verify_update_append_only(&c2, &c3, &update3).unwrap();
        assert!(b);

        // Update with negative delta
        let v1_neg = BigNat::from(50);
        let (c4, update4) = kvac.update(k1.clone(), v1_neg.clone()).unwrap();

        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), v1_neg);
        let b = Kvac::verify_witness(&k1, &v, &c4, &witness).unwrap();
        assert!(b);
        let b = Kvac::verify_update_append_only(&c3, &c4, &update4).unwrap();
        assert!(b);
    }


    #[test]
    fn defer_witness_multiple_update_test() {
        let mut kvac = Kvac::new(KvacStore::new());

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

        // Update (k2, v2_2) and verify update
        let v2_2 = BigNat::from(202);
        let (c4, update4) = kvac.update(k2.clone(), v2_2.clone()).unwrap();
        let b = Kvac::verify_update_append_only(&c3, &c4, &update4).unwrap();
        assert!(b);

        // Update (k1, v1_4) and verify update and perform lookup verifying deferred update of witness
        let v1_4 = BigNat::from(104);
        let (c5, update5) = kvac.update(k1.clone(), v1_4.clone()).unwrap();
        let b = Kvac::verify_update_append_only(&c4, &c5, &update5).unwrap();
        assert!(b);
        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), v1_4);
        let b = Kvac::verify_witness(&k1, &v, &c5, &witness).unwrap();
        assert!(b);
    }

    #[test]
    fn kvac_batch_update_test() {
        let mut kvac = Kvac::new(KvacStore::new());
        let c0 = kvac.store.commitment.clone();

        let k1 = BigNat::from(100);
        let k2 = BigNat::from(200);
        let k3 = BigNat::from(300);

        // Insert (k1, k2, k3)
        let kvs1 = vec![
            (k1.clone(), BigNat::from(101)),
            (k2.clone(), BigNat::from(201)),
            (k3.clone(), BigNat::from(301)),
        ];
        let (c1, update1) = kvac.batch_update(&kvs1).unwrap();
        let b = Kvac::verify_update_append_only(&c0, &c1, &update1).unwrap();
        assert!(b);
        // Lookup k3
        let (v, witness) = kvac.lookup(&k3).unwrap();
        assert_eq!(v.clone().unwrap(), kvs1[2].1);
        let b = Kvac::verify_witness(&k3, &v, &c1, &witness).unwrap();
        assert!(b);

        // Update (k1, k2, k3)
        let kvs2 = vec![
            (k1.clone(), BigNat::from(102)),
            (k2.clone(), BigNat::from(202)),
            (k3.clone(), BigNat::from(302)),
        ];
        let (c2, update2) = kvac.batch_update(&kvs2).unwrap();
        let b = Kvac::verify_update_append_only(&c1, &c2, &update2).unwrap();
        assert!(b);
        // Lookup k3
        let (v, witness) = kvac.lookup(&k3).unwrap();
        assert_eq!(v.clone().unwrap(), kvs2[2].1);
        let b = Kvac::verify_witness(&k3, &v, &c2, &witness).unwrap();
        assert!(b);
        // Lookup k1
        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), kvs2[0].1);
        let b = Kvac::verify_witness(&k1, &v, &c2, &witness).unwrap();
        assert!(b);

        // Update (k1, k2) (repeat k1)
        let kvs3 = vec![
            (k1.clone(), BigNat::from(103)),
            (k2.clone(), BigNat::from(203)),
            (k1.clone(), BigNat::from(104)),
        ];
        let (c3, update3) = kvac.batch_update(&kvs3).unwrap();
        let b = Kvac::verify_update_append_only(&c2, &c3, &update3).unwrap();
        assert!(b);
        // Lookup k2
        let (v, witness) = kvac.lookup(&k2).unwrap();
        assert_eq!(v.clone().unwrap(), kvs3[1].1);
        let b = Kvac::verify_witness(&k2, &v, &c3, &witness).unwrap();
        assert!(b);
        // Lookup k1
        let (v, witness) = kvac.lookup(&k1).unwrap();
        assert_eq!(v.clone().unwrap(), kvs3[2].1);
        let b = Kvac::verify_witness(&k1, &v, &c3, &witness).unwrap();
        assert!(b);
    }


    #[test]
    fn kvac_witness_batch_update_test() {
        let mut kvac = Kvac::new(KvacStore::new());

        let k1 = BigNat::from(100);
        let k2 = BigNat::from(200);
        let k3 = BigNat::from(300);

        // Insert (k1, k2, k3)
        let kvs1 = vec![
            (k1.clone(), BigNat::from(101)),
            (k2.clone(), BigNat::from(201)),
            (k3.clone(), BigNat::from(301)),
        ];
        kvac.batch_update(&kvs1).unwrap();

        // Update (k1, k2, k3)
        let kvs2 = vec![
            (k1.clone(), BigNat::from(102)),
            (k2.clone(), BigNat::from(202)),
            (k3.clone(), BigNat::from(302)),
        ];
        kvac.batch_update(&kvs2).unwrap();

        // Update (k1, k2) (repeat k1)
        let kvs3 = vec![
            (k1.clone(), BigNat::from(103)),
            (k2.clone(), BigNat::from(203)),
            (k1.clone(), BigNat::from(104)),
            (k3.clone(), BigNat::from(303)),
        ];
        let (c3, _) = kvac.batch_update(&kvs3).unwrap();

        let (_, _, _, u) = kvac.store.map.get(&k1).unwrap();
        assert_eq!(*u, 0);

        // Batch update all witnesses
        kvac.batch_update_membership_witnesses(
            Some(&vec![k1.clone(), k2.clone(), k3.clone()].iter().cloned().collect()),
        ).unwrap();

        // Lookup k1
        let (v, _, w, u) = kvac.store.map.get(&k1).unwrap();
        let witness = match w {
            WitnessWrapper::Complete(witness) => witness.clone(),
            WitnessWrapper::IncompleteCoprimeProof(_) => unreachable!(),
        };
        assert_eq!(*u, 3);
        let b = Kvac::verify_witness(&k1, &Some(v.clone()), &c3, &witness).unwrap();
        assert!(b);
    }

}
