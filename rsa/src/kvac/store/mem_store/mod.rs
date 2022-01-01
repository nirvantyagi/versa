use std::{
    marker::PhantomData,
    collections::HashMap,
};

use crate::{
    bignat::{BigNat, constraints::BigNatCircuitParams},
    kvac::{
        RsaKVACParams,
        Commitment,
        WitnessWrapper,
        Hog,
        store::RsaKVACStorer,
    },
    hash::Hasher,
};


#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RsaKVACMemStore<P: RsaKVACParams, H: Hasher, CircuitH: Hasher, C: BigNatCircuitParams> {
    pub map: HashMap<BigNat, (BigNat, usize, WitnessWrapper<P>, usize)>, // key -> (value, version, witness, last_epoch_witness_updated)
    pub commitment: Commitment<P>,
    pub counter_dict_exp: BigNat,
    pub deferred_counter_dict_exp_updates: Vec<BigNat>,
    pub epoch: usize,
    pub epoch_updates: Vec<Vec<(BigNat, BigNat)>>,
    _hash: PhantomData<H>,
    _circuit_hash: PhantomData<CircuitH>,
    _circuit_params: PhantomData<C>,
}

impl<P: RsaKVACParams, H: Hasher, CircuitH: Hasher, C: BigNatCircuitParams> RsaKVACStorer for RsaKVACMemStore<P, H, CircuitH, C> {
    type P = P;
    type H = H;
    type CircuitH = CircuitH;
    type C = C;

    fn new() -> Self {
        RsaKVACMemStore {
            map: HashMap::new(),
            commitment: Commitment {
                c1: Hog::<P>::identity(),
                c2: Hog::<P>::generator(),
                _params: PhantomData,
            },
            counter_dict_exp: BigNat::from(1),
            deferred_counter_dict_exp_updates: vec![],
            epoch: 0,
            epoch_updates: vec![],
            _hash: PhantomData,
            _circuit_hash: PhantomData,
            _circuit_params: PhantomData,
        }
    }

    // epoch
    fn get_epoch(&self) -> usize {
        return self.epoch;
    }
    fn increment_epoch(&mut self) {
        self.epoch += 1;
    }

    // epoch updates
    fn push_epoch_updates(&mut self, value: Vec<(rug::Integer, rug::Integer)>) {
        self.epoch_updates.push(value);
    }
    fn get_epoch_updates(&self) -> Vec<Vec<(rug::Integer, rug::Integer)>> {
        return self.epoch_updates.clone();
    }

    // map
    fn get_map(&self, key: &BigNat) -> Option<&(rug::Integer, usize, WitnessWrapper<P>, usize)> {
        return self.map.get(key);
    }
    fn insert_map(&mut self, key: BigNat, value: (rug::Integer, usize, WitnessWrapper<P>, usize)) -> Option<(rug::Integer, usize, WitnessWrapper<P>, usize)> {
        return self.map.insert(key, value);
    }
    fn get_iterable_map(&mut self) -> std::collections::hash_map::Iter<'_, rug::Integer, (rug::Integer, usize, WitnessWrapper<P>, usize)> {
        return self.map.iter();
    }

    // deferred counter dict
    fn get_deferred_counter_dict_exp_updates(&self) -> Vec<BigNat> {
        return self.deferred_counter_dict_exp_updates.clone();
    }
    fn push_deferred_counter_dict_exp_updates(&mut self, value: BigNat) {
        self.deferred_counter_dict_exp_updates.push(value);
    }

    // counter dict
    fn get_counter_dict_exp(&self) -> BigNat {
        return self.counter_dict_exp.clone();
    }
    fn set_counter_dict_exp(&mut self, value: BigNat) {
        self.counter_dict_exp = value;
    }

    // commitment
    fn get_commitment(&self) -> Commitment<Self::P> {
        return self.commitment.clone();
    }
    fn set_commitment(&mut self, value: Commitment<Self::P>) {
        self.commitment = value;
    }
}
