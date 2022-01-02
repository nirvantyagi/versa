use crate::{
    SSAVDStorer,
    rsa_avd::RsaAVD,
};
use std::error::Error;
use rsa::{
    kvac::{
        RsaKVACParams,
        Commitment,
        MembershipWitness,
        UpdateProof,
    },
    hash::Hasher,
    bignat::{
        BigNat,
        constraints::BigNatCircuitParams,
    }
};

pub trait RSAAVDStorer {
    type P: RsaKVACParams;
    type H: Hasher;
    type CircuitH: Hasher;
    type C: BigNatCircuitParams;

    fn kvac_lookup(&self, key: &BigNat) -> Result<(Option<BigNat>, MembershipWitness<Self::P>), Error>;
    fn kvac_get_commitment(&self) -> Commitment<Self::P>;
    fn kvac_update(&mut self, k: BigNat, v: BigNat) -> Result<(Commitment<Self::P>, UpdateProof<Self::P, Self::CircuitH>), Error>;
    fn kvac_batch_update(&mut self, kvs: &Vec<(BigNat, BigNat)>) -> Result<(Commitment<Self::P>, UpdateProof<Self::P, Self::CircuitH>), Error>;
}

// Anything that implements RSAAVDStorer implements SSAVDStorer<RsaAVD<S>>
impl<S: RSAAVDStorer> SSAVDStorer<RsaAVD<S>> for S {}
