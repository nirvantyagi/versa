use ark_ff::bytes::ToBytes;

use crypto_primitives::{
    sparse_merkle_tree::{
        store::SMTStorer,
        MerkleIndex,
        MerkleTreeParameters,
        MerkleTreePath,
        MerkleTreeError,
    },
    hash::FixedLengthCRH,
};
use single_step_avd::SingleStepAVD;

use crate::Error;

use std::{
    io::{
        Write,
        Cursor,
        Result as IoResult
    },
    marker::PhantomData,
};
use rand::Rng;

pub mod store;
pub mod constraints;

pub struct HistoryTree<P, D, S, T>
where
    P: MerkleTreeParameters,
    D: ToBytes + Eq + Clone,
    S: SMTStorer<P>,
    T: store::HTStorer<P, D, S>,
{
    store: T,
    _p: PhantomData<P>,
    _d: PhantomData<D>,
    _s: PhantomData<S>,
}

impl<P, D, S, T> HistoryTree<P, D, S, T>
where
    P: MerkleTreeParameters,
    D: ToBytes + Eq + Clone,
    S: SMTStorer<P>,
    T: store::HTStorer<P, D, S>,
{
    pub fn new(crh_pp: &<P::H as FixedLengthCRH>::Parameters) -> Result<Self, Error> {
        let s = T::new(&[0; 32], crh_pp).unwrap();
        Ok(Self {
            store: s,
            _p: PhantomData,
            _d: PhantomData,
            _s: PhantomData,
        })
    }

    // TODO: Manage digest lifetimes so as not to store clones
    pub fn append_digest(&mut self, digest: &D) -> Result<(), Error> {
        self.store.smt_update(self.store.get_epoch(), &digest_to_bytes(digest)?)?;
        self.store.digest_d_insert(self.store.get_epoch(), digest.clone());
        self.store.set_epoch(self.store.get_epoch() + 1).unwrap();
        Ok(())
    }

    pub fn lookup_path(&mut self, epoch: MerkleIndex) -> Result<MerkleTreePath<P>, Error> {
        self.store.smt_lookup(epoch)
    }

    pub fn lookup_digest(&self, epoch: MerkleIndex) -> Option<D> {
        self.store.digest_d_get(&epoch)
    }
}

pub struct SingleStepUpdateProof<SSAVD: SingleStepAVD, HTParams: MerkleTreeParameters>
{
    pub ssavd_proof: SSAVD::UpdateProof,
    pub history_tree_proof: MerkleTreePath<HTParams>,
    pub prev_ssavd_digest: SSAVD::Digest,
    pub new_ssavd_digest: SSAVD::Digest,
    pub prev_digest: <<HTParams as MerkleTreeParameters>::H as FixedLengthCRH>::Output,
    pub new_digest: <<HTParams as MerkleTreeParameters>::H as FixedLengthCRH>::Output,
    pub prev_epoch: u64,
}

impl<SSAVD: SingleStepAVD, HTParams: MerkleTreeParameters> Default for SingleStepUpdateProof<SSAVD, HTParams>{
    fn default() -> Self {
        Self {
            ssavd_proof: SSAVD::UpdateProof::default(),
            history_tree_proof: <MerkleTreePath<HTParams>>::default(),
            prev_ssavd_digest: SSAVD::Digest::default(),
            new_ssavd_digest: SSAVD::Digest::default(),
            prev_digest: Default::default(),
            new_digest: Default::default(),
            prev_epoch: Default::default(),
        }
    }
}

impl<SSAVD: SingleStepAVD, HTParams: MerkleTreeParameters> Clone for SingleStepUpdateProof<SSAVD, HTParams>{
    fn clone(&self) -> Self {
        Self {
            ssavd_proof: self.ssavd_proof.clone(),
            history_tree_proof: self.history_tree_proof.clone(),
            prev_ssavd_digest: self.prev_ssavd_digest.clone(),
            new_ssavd_digest: self.new_ssavd_digest.clone(),
            prev_digest: self.prev_digest.clone(),
            new_digest: self.new_digest.clone(),
            prev_epoch: self.prev_epoch,
        }
    }
}

pub struct SingleStepAVDWithHistory<SSAVD, HTParams, SMTStore, HTStore, SSAVDWHStore>
where
    SSAVD: SingleStepAVD,
    HTParams: MerkleTreeParameters,
    SMTStore: SMTStorer<HTParams>,
    HTStore: store::HTStorer<HTParams, <HTParams::H as FixedLengthCRH>::Output, SMTStore>,
    SSAVDWHStore: store::SingleStepAVDWithHistoryStorer<SSAVD, HTParams, SMTStore, HTStore>,
{
    pub store: SSAVDWHStore,
    _ssavd: PhantomData<SSAVD>,
    _htparamas: PhantomData<HTParams>,
    _smtstore: PhantomData<SMTStore>,
    _htstore: PhantomData<HTStore>,
}

pub struct Digest<HTParams: MerkleTreeParameters> {
    pub epoch: u64,
    pub digest: <HTParams::H as FixedLengthCRH>::Output,
}

impl<HTParams: MerkleTreeParameters> ToBytes for Digest<HTParams> {
    fn write<W: Write>(self: &Self, mut writer: W) -> IoResult<()> {
        self.epoch.write(&mut writer)?;
        self.digest.write(&mut writer)
    }
}

impl<HTParams: MerkleTreeParameters> Clone for Digest<HTParams> {
    fn clone(&self) -> Self {
        Self {
            epoch: self.epoch,
            digest: self.digest.clone(),
        }
    }
}

impl<HTParams: MerkleTreeParameters> PartialEq for Digest<HTParams> {
    fn eq(&self, other: &Self) -> bool {
        self.epoch.eq(&other.epoch) && self.digest.eq(&other.digest)
    }
}

impl<HTParams: MerkleTreeParameters> Eq for Digest<HTParams> {}

pub struct LookupProof<SSAVD: SingleStepAVD, HTParams: MerkleTreeParameters> {
    ssavd_proof: SSAVD::LookupProof,
    ssavd_digest: SSAVD::Digest,
    history_tree_digest: <HTParams::H as FixedLengthCRH>::Output,
}

pub enum HistoryProof<SSAVD: SingleStepAVD, HTParams: MerkleTreeParameters> {
    PrevEpoch(PrevEpochHistoryProof<SSAVD, HTParams>),
    CurrEpoch(),
}

pub struct PrevEpochHistoryProof<SSAVD: SingleStepAVD, HTParams: MerkleTreeParameters> {
    path: MerkleTreePath<HTParams>,
    ssavd_digest: SSAVD::Digest,
    history_tree_digest: <HTParams::H as FixedLengthCRH>::Output,
}

impl<SSAVD: SingleStepAVD, HTParams: MerkleTreeParameters> Clone for PrevEpochHistoryProof<SSAVD, HTParams> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            ssavd_digest: self.ssavd_digest.clone(),
            history_tree_digest: self.history_tree_digest.clone(),
        }
    }
}

impl<SSAVD: SingleStepAVD, HTParams: MerkleTreeParameters> Clone for HistoryProof<SSAVD, HTParams> {
    fn clone(&self) -> Self {
        match self {
            HistoryProof::PrevEpoch(proof) => HistoryProof::PrevEpoch(proof.clone()),
            HistoryProof::CurrEpoch() => HistoryProof::CurrEpoch(),
        }
    }
}

impl<SSAVD, HTParams, SMTStore, HTStore, SSAVDWHStore> SingleStepAVDWithHistory<SSAVD, HTParams, SMTStore, HTStore, SSAVDWHStore>
where
    SSAVD: SingleStepAVD,
    HTParams: MerkleTreeParameters,
    SMTStore: SMTStorer<HTParams>,
    HTStore: store::HTStorer<HTParams, <HTParams::H as FixedLengthCRH>::Output, SMTStore>,
    SSAVDWHStore: store::SingleStepAVDWithHistoryStorer<SSAVD, HTParams, SMTStore, HTStore>,
{

    pub fn setup<R: Rng>(rng: &mut R)
        -> Result<(SSAVD::PublicParameters, <HTParams::H as FixedLengthCRH>::Parameters), Error> {
        let ssavd_pp = SSAVD::setup(rng)?;
        let crh_pp = <HTParams::H as FixedLengthCRH>::setup(rng)?;
        Ok((
            ssavd_pp,
            crh_pp,
        ))
    }

    //TODO: Double storing hash parameters if shared across SSAVD and history tree
    pub fn new<R: Rng>(rng: &mut R, ssavd_pp: &SSAVD::PublicParameters, crh_pp: &<HTParams::H as FixedLengthCRH>::Parameters) -> Result<Self, Error>{
        let s = SSAVDWHStore::new(rng, ssavd_pp, crh_pp).unwrap();
        Ok(SingleStepAVDWithHistory{
            store: s,
            _ssavd: PhantomData,
            _htparamas: PhantomData,
            _smtstore: PhantomData,
            _htstore: PhantomData,
        })
    }

    pub fn digest(&self) -> Digest<HTParams> {
        Digest {
            epoch: self.store.history_tree_get_epoch(),
            digest: self.store.get_digest(),
        }
    }

    pub fn update(
        &mut self,
        key: &[u8; 32],
        value: &[u8; 32],
    ) -> Result<SingleStepUpdateProof<SSAVD, HTParams>, Error>{
        let prev_ssavd_digest = self.store.ssavd_digest()?;
        let (new_ssavd_digest, ssavd_proof) = self.store.ssavd_update(key, value)?;
        let prev_epoch = self.store.history_tree_get_epoch();
        let prev_digest = self.store.get_digest();
        self.store.history_tree_append_digest(&prev_digest)?;
        let history_tree_proof = self.store.history_tree_lookup_path(prev_epoch)?;

        // Update digest
        self.store.set_digest(
            hash_to_final_digest::<SSAVD, HTParams::H>(
                &self.store.history_tree_get_hash_parameters(),
                &new_ssavd_digest,
                &self.store.history_tree_get_root(),
                &self.store.history_tree_get_epoch(),
            )?
        );

        Ok(SingleStepUpdateProof{
            ssavd_proof: ssavd_proof,
            history_tree_proof: history_tree_proof,
            prev_ssavd_digest: prev_ssavd_digest,
            new_ssavd_digest: new_ssavd_digest,
            prev_digest: prev_digest,
            new_digest: self.store.get_digest(),
            prev_epoch: prev_epoch,
        })
    }

    pub fn batch_update(
        &mut self,
        kvs: &Vec<([u8; 32], [u8; 32])>,
    ) -> Result<SingleStepUpdateProof<SSAVD, HTParams>, Error>{
        let prev_ssavd_digest = self.store.ssavd_digest()?;
        let (new_ssavd_digest, ssavd_proof) = self.store.ssavd_batch_update(kvs)?;
        let prev_epoch = self.store.history_tree_get_epoch();
        let prev_digest = self.store.get_digest();
        self.store.history_tree_append_digest(&prev_digest)?;
        let history_tree_proof = self.store.history_tree_lookup_path(prev_epoch)?;

        // Update digest
        self.store.set_digest(
            hash_to_final_digest::<SSAVD, HTParams::H>(
                &self.store.history_tree_get_hash_parameters(),
                &new_ssavd_digest,
                &self.store.history_tree_get_root(),
                &self.store.history_tree_get_epoch(),
            )?
        );

        Ok(SingleStepUpdateProof{
            ssavd_proof: ssavd_proof,
            history_tree_proof: history_tree_proof,
            prev_ssavd_digest: prev_ssavd_digest,
            new_ssavd_digest: new_ssavd_digest,
            prev_digest: prev_digest,
            new_digest: self.store.get_digest(),
            prev_epoch: prev_epoch,
        })
    }

    pub fn lookup(
        &mut self,
        key: &[u8; 32],
    ) -> Result<(Option<(u64, [u8; 32])>, LookupProof<SSAVD, HTParams>), Error>{
        let (result, ssavd_digest, ssavd_proof) = self.store.ssavd_lookup(key)?;
        Ok((
            result,
            LookupProof {
                ssavd_proof: ssavd_proof,
                ssavd_digest: ssavd_digest,
                history_tree_digest: self.store.history_tree_get_root(),
            }
        ))
    }

    pub fn verify_lookup(
        ssavd_pp: &SSAVD::PublicParameters,
        history_tree_pp: &<HTParams::H as FixedLengthCRH>::Parameters,
        key: &[u8; 32],
        value: &Option<(u64, [u8; 32])>,
        digest: &Digest<HTParams>,
        proof: &LookupProof<SSAVD, HTParams>,
    ) -> Result<bool, Error>{
        Ok(
            SSAVD::verify_lookup(ssavd_pp, key, value, &proof.ssavd_digest, &proof.ssavd_proof)? &&
                digest.digest ==
                    hash_to_final_digest::<SSAVD, HTParams::H>(
                        history_tree_pp,
                        &proof.ssavd_digest,
                        &proof.history_tree_digest,
                        &digest.epoch,
                    )?
        )
    }

    pub fn lookup_history(
        &mut self,
        prev_epoch: usize,
    ) -> Result<(Digest<HTParams>, HistoryProof<SSAVD, HTParams>), Error> {
        if prev_epoch as u64 > self.store.history_tree_get_epoch() {
            Err(Box::new(MerkleTreeError::LeafIndex(prev_epoch as u64)))
        } else if prev_epoch as u64 == self.store.history_tree_get_epoch() {
            Ok((self.digest(), HistoryProof::CurrEpoch()))
        } else {
            Ok((
                   Digest { digest: self.store.history_tree_lookup_digest(prev_epoch as u64).unwrap().clone(), epoch: prev_epoch as u64 },
                   HistoryProof::PrevEpoch(
                        PrevEpochHistoryProof {
                            path: self.store.history_tree_lookup_path(prev_epoch as u64).unwrap().clone(),
                            ssavd_digest: self.store.ssavd_digest()?,
                            history_tree_digest: self.store.history_tree_get_root(),
                        }
                   )
            ))
        }
    }

    pub fn verify_history(
        history_tree_pp: &<HTParams::H as FixedLengthCRH>::Parameters,
        prev_epoch: usize,
        prev_digest: &Digest<HTParams>,
        digest: &Digest<HTParams>,
        proof: &HistoryProof<SSAVD, HTParams>,
    ) -> Result<bool, Error> {
        match proof {
            HistoryProof::CurrEpoch() => Ok(digest.epoch == prev_epoch as u64),
            HistoryProof::PrevEpoch(proof) => {
                Ok(
                    proof.path.verify(
                        &proof.history_tree_digest,
                        &digest_to_bytes(&prev_digest.digest)?,
                        prev_epoch as u64,
                        history_tree_pp,
                    )? &&
                        digest.digest ==
                            hash_to_final_digest::<SSAVD, HTParams::H>(
                            history_tree_pp,
                            &proof.ssavd_digest,
                            &proof.history_tree_digest,
                            &digest.epoch,
                        )?
                )
            }
        }
    }
}


//TODO: Optimization: Pick a hash function compatible with digest sizes and epoch size -- current fix for PedersenHash is hash twice
pub fn hash_to_final_digest<SSAVD: SingleStepAVD, H: FixedLengthCRH>(
    parameters: &H::Parameters,
    ssavd_digest: &SSAVD::Digest,
    history_tree_digest: &H::Output,
    epoch: &u64,
) -> Result<H::Output, Error> {
    // Assumes digests require only 256 bits for collision resistance
    let mut buffer1 = vec![];
    let mut writer1 = Cursor::new(&mut buffer1);
    ssavd_digest.write(&mut writer1)?;
    let mut buffer2 = vec![];
    let mut writer2 = Cursor::new(&mut buffer2);
    history_tree_digest.write(&mut writer2)?;
    buffer1.resize(32, 0);
    buffer2.resize(32, 0);
    buffer1.extend_from_slice(&buffer2);
    buffer1.extend_from_slice(&epoch.to_le_bytes());
    H::evaluate_variable_length(&parameters, &buffer1)
}

pub fn digest_to_bytes<D: ToBytes>(digest: &D) -> Result<Vec<u8>, Error> {
    let mut buffer = vec![];
    let mut writer = Cursor::new(&mut buffer);
    digest.write(&mut writer)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::{EdwardsProjective as JubJub};
    use rand::{rngs::StdRng, SeedableRng};
    use ark_crypto_primitives::crh::{
        pedersen::{CRH, Window},
    };
    use crate::history_tree::{
        store::{
            mem_store::{
                HTMemStore,
                SingleStepAVDWithHistoryMemStore,
            },
            redis_store::{
                HTRedisStore,
                SingleStepAVDWithHistoryRedisStore,
            }
        },
    };
    use single_step_avd::{
        merkle_tree_avd::{
            MerkleTreeAVDParameters,
            MerkleTreeAVD,
            store::{
                mem_store::MTAVDMemStore,
                redis_store::MTAVDRedisStore,
            },
        },
    };
    use crypto_primitives::sparse_merkle_tree::{
        MerkleDepth,
        store::mem_store::SMTMemStore,
        store::redis_store::SMTRedisStore,
    };

    #[derive(Clone)]
    pub struct Window4x256;

    impl Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = CRH<JubJub, Window4x256>;

    #[derive(Clone)]
    pub struct MerkleTreeTestParameters;

    impl MerkleTreeParameters for MerkleTreeTestParameters {
        const DEPTH: MerkleDepth = 4;
        type H = H;
    }

    #[derive(Clone)]
    pub struct MerkleTreeAVDTestParameters;

    impl MerkleTreeAVDParameters for MerkleTreeAVDTestParameters {
        const MAX_UPDATE_BATCH_SIZE: u64 = 4;
        const MAX_OPEN_ADDRESSING_PROBES: u8 = 2;
        type MerkleTreeParameters = MerkleTreeTestParameters;
    }

    type TestSMTStore = SMTMemStore<MerkleTreeTestParameters>;
    type RedisTestSMTStore = SMTRedisStore<MerkleTreeTestParameters>;
    type TestMTAVDStore = MTAVDMemStore<MerkleTreeAVDTestParameters, TestSMTStore>;
    type RedisTestMTAVDStore = MTAVDRedisStore<MerkleTreeAVDTestParameters, RedisTestSMTStore>;
    type TestMerkleTreeAVD = MerkleTreeAVD<MerkleTreeAVDTestParameters, TestSMTStore, TestMTAVDStore>;
    type RedisTestMerkleTreeAVD = MerkleTreeAVD<MerkleTreeAVDTestParameters, RedisTestSMTStore, RedisTestMTAVDStore>;
    type TestHTStore = HTMemStore<MerkleTreeTestParameters, <H as FixedLengthCRH>::Output, TestSMTStore>;
    type RedisTestHTStore = HTRedisStore<MerkleTreeTestParameters, <H as FixedLengthCRH>::Output, RedisTestSMTStore>;
    type TestAVDWHStore = SingleStepAVDWithHistoryMemStore<TestMerkleTreeAVD, MerkleTreeTestParameters, TestSMTStore, TestHTStore>;
    type RedisTestAVDWHStore = SingleStepAVDWithHistoryRedisStore<RedisTestMerkleTreeAVD, MerkleTreeTestParameters, RedisTestSMTStore, RedisTestHTStore>;
    type TestAVDWithHistory = SingleStepAVDWithHistory<TestMerkleTreeAVD, MerkleTreeTestParameters, TestSMTStore, TestHTStore, TestAVDWHStore>;
    type RedisTestAVDWithHistory = SingleStepAVDWithHistory<RedisTestMerkleTreeAVD, MerkleTreeTestParameters, RedisTestSMTStore, RedisTestHTStore, RedisTestAVDWHStore>;

    #[test]
    fn lookup_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let (ssavd_pp, crh_pp) = TestAVDWithHistory::setup(&mut rng).unwrap();
        let mut avd = TestAVDWithHistory::new(&mut rng, &ssavd_pp, &crh_pp).unwrap();
        avd.update(&[1_u8; 32], &[2_u8; 32]).unwrap();
        let digest = avd.digest();

        let (value, lookup_proof) = avd.lookup(&[1_u8; 32]).unwrap();
        let result = TestAVDWithHistory::verify_lookup(
            &ssavd_pp,
            &crh_pp,
            &[1_u8; 32],
            &value,
            &digest,
            &lookup_proof,
        ).unwrap();
        assert!(result);
    }

    #[test]
    #[ignore]
    fn redis_lookup_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let (ssavd_pp, crh_pp) = RedisTestAVDWithHistory::setup(&mut rng).unwrap();
        let mut avd = RedisTestAVDWithHistory::new(&mut rng, &ssavd_pp, &crh_pp).unwrap();
        avd.update(&[1_u8; 32], &[2_u8; 32]).unwrap();
        let digest = avd.digest();

        let (value, lookup_proof) = avd.lookup(&[1_u8; 32]).unwrap();
        let result = RedisTestAVDWithHistory::verify_lookup(
            &ssavd_pp,
            &crh_pp,
            &[1_u8; 32],
            &value,
            &digest,
            &lookup_proof,
        ).unwrap();
        assert!(result);
    }

    #[test]
    fn history_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let (ssavd_pp, crh_pp) = TestAVDWithHistory::setup(&mut rng).unwrap();
        let mut avd = TestAVDWithHistory::new(&mut rng, &ssavd_pp, &crh_pp).unwrap();
        avd.update(&[1_u8; 32], &[2_u8; 32]).unwrap();
        let prev_digest = avd.digest();
        assert_eq!(prev_digest.epoch, 1);
        avd.update(&[1_u8; 32], &[3_u8; 32]).unwrap();
        let curr_digest = avd.digest();
        assert_eq!(curr_digest.epoch, 2);

        let (prev_digest_lookup, history_proof) = avd.lookup_history(1).unwrap();
        let result = TestAVDWithHistory::verify_history(
            &crh_pp,
            1,
            &prev_digest_lookup,
            &curr_digest,
            &history_proof,
        ).unwrap();
        assert!(result);
        assert!(prev_digest == prev_digest_lookup);
    }

    #[test]
    #[ignore]
    fn redis_history_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let (ssavd_pp, crh_pp) = RedisTestAVDWithHistory::setup(&mut rng).unwrap();
        let mut avd = RedisTestAVDWithHistory::new(&mut rng, &ssavd_pp, &crh_pp).unwrap();
        avd.update(&[1_u8; 32], &[2_u8; 32]).unwrap();
        let prev_digest = avd.digest();
        assert_eq!(prev_digest.epoch, 1);
        avd.update(&[1_u8; 32], &[3_u8; 32]).unwrap();
        let curr_digest = avd.digest();
        assert_eq!(curr_digest.epoch, 2);

        let (prev_digest_lookup, history_proof) = avd.lookup_history(1).unwrap();
        let result = RedisTestAVDWithHistory::verify_history(
            &crh_pp,
            1,
            &prev_digest_lookup,
            &curr_digest,
            &history_proof,
        ).unwrap();
        assert!(result);
        assert!(prev_digest == prev_digest_lookup);
    }

}
