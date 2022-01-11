use std::{
    collections::HashMap,
    marker::PhantomData,
};
use crate::Error;
use ark_ff::bytes::ToBytes;
use crypto_primitives::{
    sparse_merkle_tree::{
        store::SMTStorer,
        MerkleIndex,
        MerkleTreeParameters,
        MerkleTreePath,
        SparseMerkleTree,
    },
    hash::FixedLengthCRH,
};
use crate::history_tree::{
    store::{
        HTStorer,
        SingleStepAVDWithHistoryStorer,
    },
    HistoryTree,
};
use single_step_avd::SingleStepAVD;

pub struct HTMemStore<P, D, S>
where
    P: MerkleTreeParameters,
    D: ToBytes + Eq + Clone,
    S: SMTStorer<P>,
{
    pub tree: SparseMerkleTree<P, S>,
    digest_d: HashMap<MerkleIndex, D>,
    epoch: MerkleIndex,
}

impl<P, D, S> HTStorer<P, D, S> for HTMemStore<P, D, S>
where
    P: MerkleTreeParameters,
    D: ToBytes + Eq + Clone,
    S: SMTStorer<P>,
{

    fn smt_lookup(&mut self, index: MerkleIndex) -> Result<MerkleTreePath<P>, Error> {
        return self.tree.lookup(index);
    }
    fn smt_update(&mut self, index: MerkleIndex, leaf_value: &[u8]) -> Result<(), Error> {
        return self.tree.update(index, leaf_value);
    }
    fn smt_get_hash_parameters(&self) -> <P::H as FixedLengthCRH>::Parameters {
        return self.tree.store.get_hash_parameters();
    }
    fn smt_get_root(&self) -> <P::H as FixedLengthCRH>::Output {
        return self.tree.store.get_root();
    }

    fn get_epoch(&self) -> MerkleIndex {
        return self.epoch.clone();
    }
    fn set_epoch(&mut self, index: MerkleIndex) -> Result<(), Error> {
        self.epoch = index;
        return Ok(());
    }

    fn digest_d_get(&self, key: &MerkleIndex) -> Option<&D> {
        return self.digest_d.get(key);
    }
    fn digest_d_insert(&mut self, index: MerkleIndex, digest: D) -> Option<D> {
        return self.digest_d.insert(index, digest);
    }
}

pub struct SingleStepAVDWithHistoryMemStore<SSAVD, HTParams, SMTStore, HTStore>
where
    SSAVD: SingleStepAVD,
    HTParams: MerkleTreeParameters,
    SMTStore: SMTStorer<HTParams>,
    HTStore: HTStorer<HTParams, <HTParams::H as FixedLengthCRH>::Output, SMTStore>,
{
    pub ssavd: SSAVD,
    pub history_tree: HistoryTree<HTParams, <HTParams::H as FixedLengthCRH>::Output, SMTStore, HTStore>,
    digest: <HTParams::H as FixedLengthCRH>::Output,
    _smtstore: PhantomData<SMTStore>,
}

impl<SSAVD, HTParams, SMTStore, HTStore> SingleStepAVDWithHistoryStorer<SSAVD, HTParams, SMTStore, HTStore> for SingleStepAVDWithHistoryMemStore<SSAVD, HTParams, SMTStore, HTStore>
where
    SSAVD: SingleStepAVD,
    HTParams: MerkleTreeParameters,
    SMTStore: SMTStorer<HTParams>,
    HTStore: HTStorer<HTParams, <HTParams::H as FixedLengthCRH>::Output, SMTStore>,
{
    fn ssavd_digest(&self) -> Result<SSAVD::Digest, Error> {
        return self.ssavd.digest();
    }
    fn ssavd_lookup(&mut self, key: &[u8; 32],) -> Result<(Option<(u64, [u8; 32])>, SSAVD::Digest, SSAVD::LookupProof), Error> {
        return self.ssavd.lookup(key);
    }
    fn ssavd_update(&mut self, key: &[u8; 32], value: &[u8; 32]) -> Result<(SSAVD::Digest, SSAVD::UpdateProof), Error> {
        return self.ssavd.update(key, value);
    }
    fn ssavd_batch_update(&mut self, kvs: &Vec<([u8; 32], [u8; 32])>) -> Result<(SSAVD::Digest, SSAVD::UpdateProof), Error> {
        return self.ssavd.batch_update(kvs);
    }

    fn history_tree_get_epoch(&self) -> MerkleIndex {
        return self.history_tree.store.get_epoch();
    }
    fn history_tree_get_root(&self) -> <HTParams::H as FixedLengthCRH>::Output {
        return self.history_tree.store.smt_get_root();
    }
    fn history_tree_append_digest(&mut self, digest: &<HTParams::H as FixedLengthCRH>::Output) -> Result<(), Error> {
        return self.history_tree.append_digest(digest);
    }
    fn history_tree_lookup_path(&self, epoch: MerkleIndex) -> Result<MerkleTreePath<HTParams>, Error> {
        return self.history_tree.lookup_path(epoch);
    }
    fn history_tree_lookup_digest(&self, epoch: MerkleIndex) -> Option<<HTParams::H as FixedLengthCRH>::Output> {
        return self.history_tree.lookup_digest(epoch);
    }
    fn history_tree_get_hash_parameters(&self) -> <HTParams::H as FixedLengthCRH>::Parameters {
        return self.history_tree.store.smt_get_hash_parameters();
    }

    fn get_digest(&self) -> <HTParams::H as FixedLengthCRH>::Output {
        return self.digest.clone();
    }
    fn set_digest(&self, val: <HTParams::H as FixedLengthCRH>::Output) {
        self.digest = val;
    }
}
