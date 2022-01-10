pub mod mem_store;

use crate::{
    Error,
    SSAVDStorer,
    rsa_avd::RsaAVD,
};
use rsa::{
    kvac::{
        store::RsaKVACStorer,
        Commitment,
        MembershipWitness,
        UpdateProof,
        RsaKVACParams,
        RsaKVAC,
    },
    hash::Hasher,
    bignat::{
        BigNat,
        constraints::BigNatCircuitParams,
    }
};


pub trait RSAAVDStorer<P, H, CircuitH, C, S>
where
    P: RsaKVACParams,
    H: Hasher,
    CircuitH: Hasher,
    C: BigNatCircuitParams,
    S: RsaKVACStorer<P, H, CircuitH, C>,
{
    fn new(k: RsaKVAC<P, H, CircuitH, C, S>) -> Result<Self, Error> where Self: Sized;
    fn kvac_lookup(&mut self, key: &BigNat) -> Result<(Option<BigNat>, MembershipWitness<P>), Error>;
    fn kvac_get_commitment(&self) -> Commitment<P>;
    fn kvac_update(&mut self, k: BigNat, v: BigNat) -> Result<(Commitment<P>, UpdateProof<P, CircuitH>), Error>;
    fn kvac_batch_update(&mut self, kvs: &Vec<(BigNat, BigNat)>) -> Result<(Commitment<P>, UpdateProof<P, CircuitH>), Error>;
}

// Anything that implements RSAAVDStorer implements SSAVDStorer<RsaAVD<S>>
impl<P, H, CircuitH, C, S, T> SSAVDStorer<RsaAVD<P, H, CircuitH, C, S, T>> for T
where
    P: RsaKVACParams,
    H: Hasher,
    CircuitH: Hasher,
    C: BigNatCircuitParams,
    S: RsaKVACStorer<P, H, CircuitH, C>,
    T: RSAAVDStorer<P, H, CircuitH, C, S>,
{}
