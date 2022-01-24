extern crate base64;
use serde_json;
use std::{
    marker::PhantomData,
};
use rand::Rng;
use crate::Error;
use ark_ff::{
    bytes::ToBytes,
    to_bytes,
    FromBytes,
};
use rand::{distributions::Alphanumeric};
use crypto_primitives::{
    sparse_merkle_tree::{
        store::SMTStorer,
        store::redis_store::redis_utils,
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
    hash_to_final_digest,
};
use single_step_avd::SingleStepAVD;

pub struct HTRedisStore<P, D, S>
where
    P: MerkleTreeParameters,
    D: ToBytes + Eq + Clone,
    S: SMTStorer<P>,
{
    id: String,
    pub tree: SparseMerkleTree<P, S>,
    // digest_d: HashMap<MerkleIndex, D>,
    epoch: MerkleIndex,
    _d: PhantomData<D>,
}

impl<P, D, S> HTStorer<P, D, S> for HTRedisStore<P, D, S>
where
    P: MerkleTreeParameters,
    D: ToBytes + FromBytes + Eq + Clone,
    S: SMTStorer<P>,
{

    fn new(initial_leaf: &[u8], hash_parameters: &<P::H as FixedLengthCRH>::Parameters) -> Result<Self, Error> where Self: Sized {
        let smt_store: S = S::new(initial_leaf, hash_parameters).unwrap();
        let smt: SparseMerkleTree<P, S> = SparseMerkleTree::<P, S>::new(smt_store);
        let id: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
        Ok(Self {
            id: id,
            tree: smt,
            // digest_d: HashMap::new(),
            epoch: 0,
            _d: PhantomData,
        })
    }

    fn make_copy(&self) -> Result<Self, Error> where Self: Sized {
        let old_store_id = self.get_id();
        let new_store_id: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
        // copy digest_d-
        let old_prefix = format!("{}-digest_d-*", old_store_id);
        let new_prefix = format!("{}-digest_d-", new_store_id);
        redis_utils::copy_entries_matching_prefix(old_prefix, new_prefix);
        Ok(HTRedisStore {
            id: new_store_id,
            tree: self.tree.make_copy(),
            epoch: self.epoch.clone(),
            _d: PhantomData,
        })
    }

    fn get_id(& self) -> String {
        return self.id.clone();
    }

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

    fn digest_d_get(&self, key: &MerkleIndex) -> Option<D> {
        let k = format!("{}-digest_d-{}", self.id, serde_json::to_string(&key).unwrap());
        match redis_utils::get(k) {
            Ok(val_string) => {
                let val_bytes: &[u8] = &base64::decode(val_string).unwrap();
                let val: D = D::read(val_bytes).unwrap();
                return Some(val);
            },
            Err(_e) => {
                // e = Response was of incompatible type: "Response type not string compatible." (response was nil)
                return None;
            }
        }
    }
    fn digest_d_insert(&mut self, index: MerkleIndex, digest: D) -> Option<D> {
        let k = format!("{}-digest_d-{}", self.id, serde_json::to_string(&index).unwrap());
        let val_bytes = to_bytes![digest].unwrap();
        let val: String = base64::encode(&val_bytes);
        redis_utils::set(k, val).unwrap();
        return Some(digest);
    }
}

pub struct SingleStepAVDWithHistoryRedisStore<SSAVD, HTParams, SMTStore, HTStore>
where
    SSAVD: SingleStepAVD,
    HTParams: MerkleTreeParameters,
    SMTStore: SMTStorer<HTParams>,
    HTStore: HTStorer<HTParams, <HTParams::H as FixedLengthCRH>::Output, SMTStore>,
{
    pub ssavd: SSAVD,
    pub history_tree: HistoryTree<HTParams, <HTParams::H as FixedLengthCRH>::Output, SMTStore, HTStore>,
    digest: <HTParams::H as FixedLengthCRH>::Output,
}

impl<SSAVD, HTParams, SMTStore, HTStore> SingleStepAVDWithHistoryStorer<SSAVD, HTParams, SMTStore, HTStore> for SingleStepAVDWithHistoryRedisStore<SSAVD, HTParams, SMTStore, HTStore>
where
    SSAVD: SingleStepAVD,
    HTParams: MerkleTreeParameters,
    SMTStore: SMTStorer<HTParams>,
    HTStore: HTStorer<HTParams, <HTParams::H as FixedLengthCRH>::Output, SMTStore>,
{
    fn new<R: Rng>(rng: &mut R, ssavd_pp: &SSAVD::PublicParameters, crh_pp: &<HTParams::H as FixedLengthCRH>::Parameters) -> Result<Self, Error> where Self: Sized {
        let ssavd = SSAVD::new(rng, ssavd_pp).unwrap();
        let history_tree = HistoryTree::<HTParams, <<HTParams as MerkleTreeParameters>::H as FixedLengthCRH>::Output, SMTStore, HTStore>::new(crh_pp).unwrap();
        let digest = hash_to_final_digest::<SSAVD, HTParams::H>(
            &history_tree.store.smt_get_hash_parameters(),
            &ssavd.digest()?,
            &history_tree.store.smt_get_root(),
            &history_tree.store.get_epoch(),
        )?;

        Ok(Self {
            ssavd: ssavd,
            history_tree: history_tree,
            digest: digest,
        })
    }
    fn make_copy(&self) -> Result<Self, Error> where Self: Sized {
        let ssavd_copy = self.ssavd.make_copy().unwrap();
        let ht_copy = self.history_tree.make_copy().unwrap();
        Ok(Self {
            ssavd: ssavd_copy,
            history_tree: ht_copy,
            digest: self.digest.clone(),
        })
    }
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
    fn history_tree_lookup_path(&mut self, epoch: MerkleIndex) -> Result<MerkleTreePath<HTParams>, Error> {
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
    fn set_digest(&mut self, val: <HTParams::H as FixedLengthCRH>::Output) {
        self.digest = val;
    }
}
