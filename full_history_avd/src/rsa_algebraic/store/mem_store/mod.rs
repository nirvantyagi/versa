use crate::{
    Error,
    rsa_algebraic::store::RsaFullHistoryAVDStorer,
};
use rsa::{
    kvac::{
        store::RsaKVACStorer,
        Commitment,
        UpdateProof,
        RsaKVACParams,
        RsaKVAC,
        MembershipWitness,
    },
    hash::Hasher,
    bignat::{
        BigNat,
        constraints::BigNatCircuitParams,
    }
};

pub struct RsaFullHistoryAVDMemStore<P, H1, H2, C, S>
where
    P: RsaKVACParams,
    H1: Hasher,
    H2: Hasher,
    C: BigNatCircuitParams,
    S: RsaKVACStorer<P, H1, H2, C>,
{
    kvac: RsaKVAC<P, H1, H2, C, S>,
    digests: Vec<Commitment<P>>,
    range_proofs: Vec<Vec<(UpdateProof<P, H2>, BigNat, BigNat)>>, // (proof, z_product, delta_sum)
}

impl<P, H1, H2, C, S> RsaFullHistoryAVDStorer<P, H1, H2, C, S> for RsaFullHistoryAVDMemStore<P, H1, H2, C, S>
where
    P: RsaKVACParams,
    H1: Hasher,
    H2: Hasher,
    C: BigNatCircuitParams,
    S: RsaKVACStorer<P, H1, H2, C>,
{
    fn new(k: S) -> Result<Self, Error> where Self: Sized {
        let kvac = RsaKVAC::<P, H1, H2, C, S>::new(k);
        let digests = vec![kvac.store.get_commitment()];
        Ok(RsaFullHistoryAVDMemStore {
            kvac: kvac,
            digests: digests,
            range_proofs: vec![],
        })
    }

    fn digest_get(&self, index: usize) -> Commitment<P> {
        return self.digests[index].clone();
    }
    fn digest_get_last(&self) -> Commitment<P> {
        return self.digests.last().unwrap().clone();
    }
    fn digest_get_len(&self) -> usize {
        return self.digests.len();
    }
    fn digest_push(&mut self, d: Commitment<P>) {
        self.digests.push(d);
    }

    fn range_proofs_get_specific(&self, level: usize, index: usize) -> (UpdateProof<P, H2>, BigNat, BigNat) {
        return self.range_proofs[level][index].clone();
    }
    fn range_proofs_get_len(&self) -> usize {
        return self.range_proofs.len();
    }
    fn range_proofs_get_level_len(&self, level: usize) -> usize {
        return self.range_proofs[level].len();
    }
    fn range_proofs_push(&mut self, rp: Vec<(UpdateProof<P, H2>, BigNat, BigNat)>) {
        self.range_proofs.push(rp);
    }
    fn range_proofs_push_index(&mut self, index: usize, val: (UpdateProof<P, H2>, BigNat, BigNat)) {
        self.range_proofs[index].push(val);
    }

    fn kvac_lookup(&mut self, key: &BigNat) -> Result<(Option<BigNat>, MembershipWitness<P>), Error> {
        return self.kvac.lookup(key);
    }
    fn kvac_batch_update(&mut self, kvs: &Vec<(BigNat, BigNat)>) -> Result<(Commitment<P>, UpdateProof<P, H2>, (BigNat, BigNat)), Error> {
        return self.kvac._batch_update(kvs);
    }

}
