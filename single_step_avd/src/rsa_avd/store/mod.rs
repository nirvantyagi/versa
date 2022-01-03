pub mod mem_store;

use crate::{
    SSAVDStorer,
    rsa_avd::RsaAVD,
};
use std::error::Error;
use rsa::{
    kvac::{
        store::RsaKVACStorer,
        Commitment,
        MembershipWitness,
        UpdateProof,
    },
    bignat::{
        BigNat,
    }
};

pub trait RSAAVDStorer {
    type S: RsaKVACStorer;

    fn kvac_lookup(&self, key: &BigNat) -> Result<(Option<BigNat>, MembershipWitness<<<Self as RSAAVDStorer>::S as RsaKVACStorer>::P>), dyn Error>;
    fn kvac_get_commitment(&self) -> Commitment<<<Self as RSAAVDStorer>::S as RsaKVACStorer>::P>;
    fn kvac_update(&mut self, k: BigNat, v: BigNat) -> Result<(Commitment<<<Self as RSAAVDStorer>::S as RsaKVACStorer>::P>, UpdateProof<<<Self as RSAAVDStorer>::S as RsaKVACStorer>::P, <<Self as RSAAVDStorer>::S as RsaKVACStorer>::CircuitH>), dyn Error>;
    fn kvac_batch_update(&mut self, kvs: &Vec<(BigNat, BigNat)>) -> Result<(Commitment<<<Self as RSAAVDStorer>::S as RsaKVACStorer>::P>, UpdateProof<<<Self as RSAAVDStorer>::S as RsaKVACStorer>::P, <<Self as RSAAVDStorer>::S as RsaKVACStorer>::CircuitH>), dyn Error>;
}

// Anything that implements RSAAVDStorer implements SSAVDStorer<RsaAVD<S>>
impl<S: RSAAVDStorer> SSAVDStorer<RsaAVD<S>> for S {}
