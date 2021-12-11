use ark_ff::bytes::ToBytes;

use crypto_primitives::{
    sparse_merkle_tree::{
        store::Storer,
        MerkleIndex, MerkleTreeParameters, MerkleTreePath, SparseMerkleTree, MerkleTreeError,
    },
    hash::FixedLengthCRH,
};
use single_step_avd::SingleStepAVD;

use crate::Error;

use std::{
    collections::HashMap,
    io::{Write, Cursor, Result as IoResult},
};
use rand::Rng;

pub mod constraints;

pub struct HistoryTree<T: Storer, D: ToBytes + Eq + Clone> {
    pub tree: SparseMerkleTree<T>,
    digest_d: HashMap<MerkleIndex, D>,
    epoch: MerkleIndex,
}

impl<T: Storer, D: ToBytes + Eq + Clone> HistoryTree<T, D> {
    pub fn new(hash_parameters: &<<<T as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters) -> Result<Self, Error> {
        let initial_leaf = <[u8; 32]>::default();
        let store = T::new(&initial_leaf, hash_parameters).unwrap();
        let smt: SparseMerkleTree<T> = SparseMerkleTree::new(store);
        Ok(HistoryTree {
            tree: smt,
            digest_d: HashMap::new(),
            epoch: 0,
        })
    }

    // TODO: Manage digest lifetimes so as not to store clones
    pub fn append_digest(&mut self, digest: &D) -> Result<(), Error> {
        self.tree.update(self.epoch, &digest_to_bytes(digest)?)?;
        self.digest_d.insert(self.epoch, digest.clone());
        self.epoch += 1;
        Ok(())
    }

    pub fn lookup_path(&self, epoch: MerkleIndex) -> Result<MerkleTreePath<T::P>, Error> {
        self.tree.lookup(epoch)
    }

    pub fn lookup_digest(&self, epoch: MerkleIndex) -> Option<D> {
        self.digest_d.get(&epoch).cloned()
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

pub struct SingleStepAVDWithHistory<SSAVD: SingleStepAVD, HTStorer: Storer>{
    pub ssavd: SSAVD,
    pub history_tree: HistoryTree<HTStorer, <<<HTStorer as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output>,
    digest: <<<HTStorer as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Output,
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

impl<SSAVD: SingleStepAVD, HTStorer: Storer> SingleStepAVDWithHistory<SSAVD, HTStorer> {

    pub fn setup<R: Rng>(rng: &mut R)
        -> Result<(SSAVD::PublicParameters, <<<HTStorer as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters), Error> {
        let ssavd_pp = SSAVD::setup(rng)?;
        let crh_pp = <<<HTStorer as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::setup(rng)?;
        Ok((
            ssavd_pp,
            crh_pp,
        ))
    }

    //TODO: Double storing hash parameters if shared across SSAVD and history tree
    pub fn new<R: Rng>(
        rng: &mut R,
        ssavd_pp: &SSAVD::PublicParameters,
        history_tree_parameters: &<<<HTStorer as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters,
    ) -> Result<Self, Error>{
        let ssavd = SSAVD::new(rng, ssavd_pp)?;
        // TODO(z-tech): I think this is right from the comments but not sure:
        let store = HTStorer::new(ssavd_pp, history_tree_parameters).unwrap();
        let smt: SparseMerkleTree<HTStorer> = SparseMerkleTree::new(store);
        let history_tree = HistoryTree::new(&smt)?;
        let digest = hash_to_final_digest::<SSAVD, <<HTStorer as Storer>::P as MerkleTreeParameters>::H>(
            history_tree_parameters,
            &ssavd.digest()?,
            &history_tree.tree.store.get_root(),
            &history_tree.epoch,
        )?;
        Ok(SingleStepAVDWithHistory{
            ssavd: ssavd,
            history_tree: history_tree,
            digest: digest,
        })
    }

    pub fn digest(&self) -> Digest<HTStorer::P> {
        Digest {
            epoch: self.history_tree.epoch.clone(),
            digest: self.digest.clone(),
        }
    }

    pub fn update(
        &mut self,
        key: &[u8; 32],
        value: &[u8; 32],
    ) -> Result<SingleStepUpdateProof<SSAVD, HTStorer::P>, Error>{
        let prev_ssavd_digest = self.ssavd.digest()?;
        let (new_ssavd_digest, ssavd_proof) = self.ssavd.update(key, value)?;
        let prev_epoch = self.history_tree.epoch.clone();
        let prev_digest = self.digest.clone();
        self.history_tree.append_digest(&prev_digest)?;
        let history_tree_proof = self.history_tree.lookup_path(prev_epoch)?;

        // Update digest
        self.digest = hash_to_final_digest::<SSAVD, <<HTStorer as Storer>::P as MerkleTreeParameters>::H>(
            &self.history_tree.tree.store.get_hash_parameters(),
            &new_ssavd_digest,
            &self.history_tree.tree.store.get_root(),
            &self.history_tree.epoch,
        )?;

        Ok(SingleStepUpdateProof{
            ssavd_proof: ssavd_proof,
            history_tree_proof: history_tree_proof,
            prev_ssavd_digest: prev_ssavd_digest,
            new_ssavd_digest: new_ssavd_digest,
            prev_digest: prev_digest,
            new_digest: self.digest.clone(),
            prev_epoch: prev_epoch,
        })
    }

    pub fn batch_update(
        &mut self,
        kvs: &Vec<([u8; 32], [u8; 32])>,
    ) -> Result<SingleStepUpdateProof<SSAVD, HTStorer::P>, Error>{
        let prev_ssavd_digest = self.ssavd.digest()?;
        let (new_ssavd_digest, ssavd_proof) = self.ssavd.batch_update(kvs)?;
        let prev_epoch = self.history_tree.epoch.clone();
        let prev_digest = self.digest.clone();
        self.history_tree.append_digest(&prev_digest)?;
        let history_tree_proof = self.history_tree.lookup_path(prev_epoch)?;

        // Update digest
        self.digest = hash_to_final_digest::<SSAVD, <<HTStorer as Storer>::P as MerkleTreeParameters>::H>(
            &self.history_tree.tree.store.get_hash_parameters(),
            &new_ssavd_digest,
            &self.history_tree.tree.store.get_root(),
            &self.history_tree.epoch,
        )?;

        Ok(SingleStepUpdateProof{
            ssavd_proof: ssavd_proof,
            history_tree_proof: history_tree_proof,
            prev_ssavd_digest: prev_ssavd_digest,
            new_ssavd_digest: new_ssavd_digest,
            prev_digest: prev_digest,
            new_digest: self.digest.clone(),
            prev_epoch: prev_epoch,
        })
    }

    pub fn lookup(
        &mut self,
        key: &[u8; 32],
    ) -> Result<(Option<(u64, [u8; 32])>, LookupProof<SSAVD, HTStorer::P>), Error>{
        let (result, ssavd_digest, ssavd_proof) = self.ssavd.lookup(key)?;
        Ok((
            result,
            LookupProof {
                ssavd_proof: ssavd_proof,
                ssavd_digest: ssavd_digest,
                history_tree_digest: self.history_tree.tree.store.get_root().clone(),
            }
        ))
    }

    pub fn verify_lookup(
        ssavd_pp: &SSAVD::PublicParameters,
        history_tree_pp: &<<<HTStorer as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters,
        key: &[u8; 32],
        value: &Option<(u64, [u8; 32])>,
        digest: &Digest<HTStorer::P>,
        proof: &LookupProof<SSAVD, HTStorer::P>,
    ) -> Result<bool, Error>{
        Ok(
            SSAVD::verify_lookup(ssavd_pp, key, value, &proof.ssavd_digest, &proof.ssavd_proof)? &&
                digest.digest ==
                    hash_to_final_digest::<SSAVD, <<HTStorer as Storer>::P as MerkleTreeParameters>::H>(
                        history_tree_pp,
                        &proof.ssavd_digest,
                        &proof.history_tree_digest,
                        &digest.epoch,
                    )?
        )
    }

    pub fn lookup_history(
        &self,
        prev_epoch: usize,
    ) -> Result<(Digest<HTStorer::P>, HistoryProof<SSAVD, HTStorer::P>), Error> {
        if prev_epoch as u64 > self.history_tree.epoch {
            Err(Box::new(MerkleTreeError::LeafIndex(prev_epoch as u64)))
        } else if prev_epoch as u64 == self.history_tree.epoch {
            Ok((self.digest(), HistoryProof::CurrEpoch()))
        } else {
            Ok((
                   Digest { digest: self.history_tree.lookup_digest(prev_epoch as u64).unwrap(), epoch: prev_epoch as u64 },
                   HistoryProof::PrevEpoch(
                        PrevEpochHistoryProof {
                            path: self.history_tree.lookup_path(prev_epoch as u64)?,
                            ssavd_digest: self.ssavd.digest()?,
                            history_tree_digest: self.history_tree.tree.store.get_root().clone(),
                        }
                   )
            ))
        }
    }

    pub fn verify_history(
        history_tree_pp: &<<<HTStorer as Storer>::P as MerkleTreeParameters>::H as FixedLengthCRH>::Parameters,
        prev_epoch: usize,
        prev_digest: &Digest<HTStorer::P>,
        digest: &Digest<HTStorer::P>,
        proof: &HistoryProof<SSAVD, HTStorer::P>,
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
                            hash_to_final_digest::<SSAVD, <<HTStorer as Storer>::P as MerkleTreeParameters>::H>(
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

    use single_step_avd::{
        merkle_tree_avd::{
            MerkleTreeAVDParameters,
            MerkleTreeAVD,
        },
    };
    use crypto_primitives::sparse_merkle_tree::{
        MerkleDepth,
        store::mem_store::MemStore
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
        type Storer = MemStore<MerkleTreeTestParameters>;
    }

    type TestMerkleTreeAVD = MerkleTreeAVD<MerkleTreeAVDTestParameters>;
    type TestAVDWithHistory = SingleStepAVDWithHistory<TestMerkleTreeAVD, MerkleTreeTestParameters>;

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

}
