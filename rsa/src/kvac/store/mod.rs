pub mod mem_store;
use crate::{
    bignat::{BigNat},
    kvac::{
        RsaKVACParams,
        BigNatCircuitParams,
        WitnessWrapper,
        Commitment,
    },
    hash::Hasher,
};

pub trait RsaKVACStorer {
    type P: RsaKVACParams;
    type H: Hasher;
    type CircuitH: Hasher;
    type C: BigNatCircuitParams;

    // new
    fn new() -> Self where Self: Sized;

    // epoch
    fn get_epoch(&self) -> usize;
    fn increment_epoch(&mut self);

    // epoch updates
    fn get_epoch_updates(&self) -> Vec<Vec<(rug::Integer, rug::Integer)>>;
    fn push_epoch_updates(&mut self, value: Vec<(rug::Integer, rug::Integer)>);

    // map
    fn get_map(&self, key: &BigNat) -> Option<&(rug::Integer, usize, WitnessWrapper<Self::P>, usize)>;
    fn insert_map(&mut self, key: BigNat, value: (rug::Integer, usize, WitnessWrapper<Self::P>, usize)) -> Option<(rug::Integer, usize, WitnessWrapper<Self::P>, usize)>;
    fn get_iterable_map(&mut self) -> std::collections::hash_map::Iter<'_, rug::Integer, (rug::Integer, usize, WitnessWrapper<Self::P>, usize)>;

    // deferred counter dict
    fn get_deferred_counter_dict_exp_updates(&self) -> Vec<BigNat>;
    fn push_deferred_counter_dict_exp_updates(&mut self, value: BigNat);

    // counter dict
    fn get_counter_dict_exp(&self) -> BigNat;
    fn set_counter_dict_exp(&mut self, value: BigNat);

    // commitment
    fn get_commitment(&self) -> Commitment<Self::P>;
    fn set_commitment(&mut self, value: Commitment<Self::P>);
}
