pub mod mem_store;

use crate::{
    Error,
    FHAVDStorer,
    rsa_algebraic::RsaFullHistoryAVD,
};
use rsa::{
    kvac::{
        store::RsaKVACStorer,
        RsaKVACParams,
        Commitment,
        MembershipWitness,
        UpdateProof,
    },
    hash::Hasher,
    bignat::{
        constraints::BigNatCircuitParams,
        BigNat,
    }
};

pub trait RsaFullHistoryAVDStorer<P, H1, H2, C, S>
where
    P: RsaKVACParams,
    H1: Hasher,
    H2: Hasher,
    C: BigNatCircuitParams,
    S: RsaKVACStorer<P, H1, H2, C>,
{
    fn new(k: S) -> Result<Self, Error> where Self: Sized;

    fn digest_get(&self, index: usize) -> Commitment<P>;
    fn digest_get_last(&self) -> Commitment<P>;
    fn digest_get_len(&self) -> usize;
    fn digest_push(&mut self, d: Commitment<P>);

    fn range_proofs_get_specific(&self, level: usize, index: usize) -> (UpdateProof<P, H2>, BigNat, BigNat);
    fn range_proofs_get_len(&self) -> usize;
    fn range_proofs_get_level_len(&self, level: usize) -> usize;
    fn range_proofs_push(&mut self, rp: Vec<(UpdateProof<P, H2>, BigNat, BigNat)>);
    fn range_proofs_push_index(&mut self, index: usize, val: (UpdateProof<P, H2>, BigNat, BigNat));

    fn kvac_lookup(&mut self, key: &BigNat) -> Result<(Option<BigNat>, MembershipWitness<P>), Error>;
    fn kvac_batch_update(&mut self, kvs: &Vec<(BigNat, BigNat)>) -> Result<(Commitment<P>, UpdateProof<P, H2>, (BigNat, BigNat)), Error>;
}

impl<P, H1, H2, C, S, T> FHAVDStorer<RsaFullHistoryAVD<P, H1, H2, C, S, T>> for T
where
    P: RsaKVACParams,
    H1: Hasher,
    H2: Hasher,
    C: BigNatCircuitParams,
    S: RsaKVACStorer<P, H1, H2, C>,
    T: RsaFullHistoryAVDStorer<P, H1, H2, C, S>
{}
