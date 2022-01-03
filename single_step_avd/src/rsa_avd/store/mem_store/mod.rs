use crate::rsa_avd::store::RSAAVDStorer;
use std::error::Error;
use rsa::{
    kvac::{
        RsaKVAC,
        Commitment,
        MembershipWitness,
        UpdateProof,
        store::{
            RsaKVACStorer,
            mem_store::RsaKVACMemStore,
        }
    },
    bignat::{
        BigNat,
    },
};

pub struct RSAAVDMemStore<S: RsaKVACStorer> {
    kvac: RsaKVAC<RsaKVACMemStore<S::P, S::H, S::CircuitH, S::C>>
}

impl<S: RsaKVACStorer> RSAAVDStorer for RSAAVDMemStore<S> {

    fn kvac_lookup(&self, key: &BigNat) -> Result<(Option<BigNat>, MembershipWitness<<<Self as RSAAVDStorer>::S as RsaKVACStorer>::P>), dyn Error> {
        return self.kvac.lookup(key);
    }
    fn kvac_get_commitment(&self) -> Commitment<<<Self as RSAAVDStorer>::S as RsaKVACStorer>::P> {
        return self.kvac.store.get_commitment();
    }
    fn kvac_update(&mut self, k: BigNat, v: BigNat) -> Result<(Commitment<<<Self as RSAAVDStorer>::S as RsaKVACStorer>::P>, UpdateProof<<<Self as RSAAVDStorer>::S as RsaKVACStorer>::P, <<Self as RSAAVDStorer>::S as RsaKVACStorer>::CircuitH>), dyn Error> {
        return self.kvac.update(k, v);
    }
    fn kvac_batch_update(&mut self, kvs: &Vec<(BigNat, BigNat)>) -> Result<(Commitment<<<Self as RSAAVDStorer>::S as RsaKVACStorer>::P>, UpdateProof<<<Self as RSAAVDStorer>::S as RsaKVACStorer>::P, <<Self as RSAAVDStorer>::S as RsaKVACStorer>::CircuitH>), dyn Error> {
        return self.kvac.batch_update(kvs);
    }
}
