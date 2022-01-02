use crate::{
    SSAVDStorer,
    rsa_avd::RsaAVD,
};
use rsa::{
    kvac::{
        RsaKVAC,
        RsaKVACParams,
        store::RsaKVACStorer
    },
    hash::Hasher,
    bignat::constraints::BigNatCircuitParams,
};

pub struct RSAAVDMemStore<P: RsaKVACParams, H: Hasher, CircuitH: Hasher, C: BigNatCircuitParams> {
    kvac: RsaKVAC<RsaKVACStorer<P, H, CircuitH, C>>
}

impl<P: RsaKVACParams, H: Hasher, CircuitH: Hasher, C: BigNatCircuitParams> RSAAVDStorer for RSAAVDMemStore<P, H, CircuitH, C> {
    type P = P;
    type H = H;
    type CircuitH = CircuitH;
    type C = C;

    fn kvac_lookup(&self, key: &BigNat) -> Result<(Option<BigNat>, MembershipWitness<Self::P>), Error> {
        return self.kvac.lookup(key);
    }
    fn kvac_get_commitment(&self) -> Commitment<Self::P> {
        return self.kvac.get_commitment();
    }
    fn kvac_update(&mut self, k: BigNat, v: BigNat) -> Result<(Commitment<Self::P>, UpdateProof<Self::P, Self::CircuitH>), Error> {
        return self.kvac.update(k, v);
    }
    fn kvac_batch_update(&mut self, kvs: &Vec<(BigNat, BigNat)>) -> Result<(Commitment<Self::P>, UpdateProof<Self::P, Self::CircuitH>), Error> {
        return self.kvac.batch_update(kvs);
    }
}
