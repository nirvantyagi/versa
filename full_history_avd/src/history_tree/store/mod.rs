pub mod mem_store;
pub mod redis_store;
use rand::Rng;
use crate::Error;
use ark_ff::bytes::ToBytes;
use crypto_primitives::{
    sparse_merkle_tree::{
        store::SMTStorer,
        MerkleIndex,
        MerkleTreePath,
        MerkleTreeParameters
    },
    hash::FixedLengthCRH,
};
use single_step_avd::SingleStepAVD;

pub trait HTStorer<P, D, S>
where
    P: MerkleTreeParameters,
    D: ToBytes + Eq + Clone,
    S: SMTStorer<P>,
{
    fn new(initial_leaf: &[u8], hash_parameters: &<P::H as FixedLengthCRH>::Parameters) -> Result<Self, Error> where Self: Sized;
    fn make_copy(&self) -> Result<Self, Error> where Self: Sized;
    fn get_id(& self) -> String;
    fn smt_lookup(&mut self, index: MerkleIndex) -> Result<MerkleTreePath<P>, Error>;
    fn smt_update(&mut self, index: MerkleIndex, leaf_value: &[u8]) -> Result<(), Error>;
    fn smt_get_hash_parameters(&self) -> <P::H as FixedLengthCRH>::Parameters;
    fn smt_get_root(&self) -> <P::H as FixedLengthCRH>::Output;

    fn get_epoch(&self) -> MerkleIndex;
    fn set_epoch(&mut self, index: MerkleIndex) -> Result<(), Error>;

    fn digest_d_get(&self, key: &MerkleIndex) -> Option<D>;
    fn digest_d_insert(&mut self, index: MerkleIndex, digest: D) -> Option<D>;
}

pub trait SingleStepAVDWithHistoryStorer<SSAVD, HTParams, SMTStore, HTStore>
where
    SSAVD: SingleStepAVD,
    HTParams: MerkleTreeParameters,
    SMTStore: SMTStorer<HTParams>,
    HTStore: HTStorer<HTParams, <HTParams::H as FixedLengthCRH>::Output, SMTStore>,
{
    fn new<R: Rng>(rng: &mut R, ssavd_pp: &SSAVD::PublicParameters, crh_pp: &<HTParams::H as FixedLengthCRH>::Parameters) -> Result<Self, Error> where Self: Sized;
    fn make_copy(&self) -> Result<Self, Error> where Self: Sized;
    fn ssavd_digest(&self) -> Result<SSAVD::Digest, Error>;
    fn ssavd_lookup(&mut self, key: &[u8; 32],) -> Result<(Option<(u64, [u8; 32])>, SSAVD::Digest, SSAVD::LookupProof), Error>;
    fn ssavd_update(&mut self, key: &[u8; 32], value: &[u8; 32]) -> Result<(SSAVD::Digest, SSAVD::UpdateProof), Error>;
    fn ssavd_batch_update(&mut self, kvs: &Vec<([u8; 32], [u8; 32])>) -> Result<(SSAVD::Digest, SSAVD::UpdateProof), Error>;

    fn history_tree_get_epoch(&self) -> MerkleIndex;
    fn history_tree_get_root(&self) -> <HTParams::H as FixedLengthCRH>::Output;
    fn history_tree_append_digest(&mut self, digest: &<HTParams::H as FixedLengthCRH>::Output) -> Result<(), Error>;
    fn history_tree_lookup_path(&mut self, epoch: MerkleIndex) -> Result<MerkleTreePath<HTParams>, Error>;
    fn history_tree_lookup_digest(&self, epoch: MerkleIndex) -> Option<<HTParams::H as FixedLengthCRH>::Output>;
    fn history_tree_get_hash_parameters(&self) -> <HTParams::H as FixedLengthCRH>::Parameters;

    fn get_digest(&self) -> <HTParams::H as FixedLengthCRH>::Output;
    fn set_digest(&mut self, val: <HTParams::H as FixedLengthCRH>::Output);
}
