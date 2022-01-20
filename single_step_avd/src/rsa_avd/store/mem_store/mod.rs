use crate::{
    Error,
    rsa_avd::store::RSAAVDStorer
};
use rsa::{
    kvac::{
        RsaKVAC,
        Commitment,
        MembershipWitness,
        UpdateProof,
        RsaKVACParams,
        store::{
            RsaKVACStorer,
        }
    },
    hash::Hasher,
    bignat::{
        BigNat,
        constraints::BigNatCircuitParams,
    },
};

pub struct RSAAVDMemStore<P, H, CircuitH, C, S>
where
    P: RsaKVACParams,
    H: Hasher,
    CircuitH: Hasher,
    C: BigNatCircuitParams,
    S: RsaKVACStorer<P, H, CircuitH, C>,
{
    kvac: RsaKVAC<P, H, CircuitH, C, S>
}

impl<P, H, CircuitH, C, S> RSAAVDStorer<P, H, CircuitH, C, S> for RSAAVDMemStore<P, H, CircuitH, C, S>
where
    P: RsaKVACParams,
    H: Hasher,
    CircuitH: Hasher,
    C: BigNatCircuitParams,
    S: RsaKVACStorer<P, H, CircuitH, C>,
{
    fn new() -> Result<Self, Error> where Self: Sized {
        let k = RsaKVAC::<P, H, CircuitH, C, S>::new();
        Ok(RSAAVDMemStore {
            kvac: k,
        })
    }
    fn kvac_lookup(&mut self, key: &BigNat) -> Result<(Option<BigNat>, MembershipWitness<P>), Error> {
        return self.kvac.lookup(key);
    }
    fn kvac_get_commitment(&self) -> Commitment<P> {
        return self.kvac.store.get_commitment();
    }
    fn kvac_update(&mut self, k: BigNat, v: BigNat) -> Result<(Commitment<P>, UpdateProof<P, CircuitH>), Error> {
        return self.kvac.update(k, v);
    }
    fn kvac_batch_update(&mut self, kvs: &Vec<(BigNat, BigNat)>) -> Result<(Commitment<P>, UpdateProof<P, CircuitH>), Error> {
        return self.kvac.batch_update(kvs);
    }
}
