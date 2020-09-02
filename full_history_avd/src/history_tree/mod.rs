use algebra::bytes::ToBytes;
use zexe_cp::crh::FixedLengthCRH;

use crypto_primitives::sparse_merkle_tree::{
    MerkleIndex, MerkleTreeParameters, MerkleTreePath, SparseMerkleTree,
};
use single_step_avd::SingleStepAVD;

use crate::Error;

use std::{collections::HashMap, hash::Hash, io::{Write, Cursor}};
use rand::Rng;

pub mod constraints;

pub struct HistoryTree<P: MerkleTreeParameters, D: Hash + ToBytes + Eq + Clone> {
    tree: SparseMerkleTree<P>,
    digest_d: HashMap<D, MerkleIndex>,
    epoch: MerkleIndex,
}

impl<P: MerkleTreeParameters, D: Hash + ToBytes + Eq + Clone> HistoryTree<P, D> {
    pub fn new(hash_parameters: &<P::H as FixedLengthCRH>::Parameters) -> Result<Self, Error> {
        Ok(HistoryTree {
            tree: SparseMerkleTree::<P>::new(&<[u8; 32]>::default(), hash_parameters)?,
            digest_d: HashMap::new(),
            epoch: 0,
        })
    }

    // TODO: Manage digest lifetimes so as not to store clones
    pub fn append_digest(&mut self, digest: &D) -> Result<(), Error> {
        self.tree.update(self.epoch, &ssavd_digest_to_bytes(digest)?)?;
        self.digest_d.insert(digest.clone(), self.epoch);
        self.epoch += 1;
        Ok(())
    }

    pub fn lookup_path(&mut self, epoch: MerkleIndex) -> Result<MerkleTreePath<P>, Error> {
        self.tree.lookup(epoch)
    }

    pub fn lookup_digest(&mut self, digest: &D) -> Option<MerkleIndex> {
        self.digest_d.get(digest).cloned()
    }
}

pub struct SingleStepUpdateProof<SSAVD: SingleStepAVD, HTParams: MerkleTreeParameters>
{
    ssavd_pp: SSAVD::PublicParameters,
    history_tree_pp: <HTParams::H as FixedLengthCRH>::Parameters,
    ssavd_proof: SSAVD::UpdateProof,
    history_tree_proof: MerkleTreePath<HTParams>,
    prev_ssavd_digest: SSAVD::Digest,
    new_ssavd_digest: SSAVD::Digest,
    prev_digest: <<HTParams as MerkleTreeParameters>::H as FixedLengthCRH>::Output,
    new_digest: <<HTParams as MerkleTreeParameters>::H as FixedLengthCRH>::Output,
    prev_epoch: u64,
}

pub struct SingleStepAVDWithHistory<SSAVD: SingleStepAVD, HTParams: MerkleTreeParameters>{
    ssavd_pp: SSAVD::PublicParameters,
    ssavd: SSAVD,
    history_tree: HistoryTree<HTParams, SSAVD::Digest>,
    digest: <HTParams::H as FixedLengthCRH>::Output,
}

impl<SSAVD: SingleStepAVD, HTParams: MerkleTreeParameters> SingleStepAVDWithHistory<SSAVD, HTParams> {

    pub fn setup<R: Rng>(rng: &mut R)
        -> Result<(SSAVD::PublicParameters, <HTParams::H as FixedLengthCRH>::Parameters), Error> {
        Ok((
            SSAVD::setup(rng)?,
            <HTParams::H as FixedLengthCRH>::setup(rng)?,
        ))
    }

    //TODO: Double storing SSAVD public parameters (also stored in MerkleTreeAVD)
    //TODO: Double storing hash parameters if shared across SSAVD and history tree
    pub fn new<R: Rng>(
        rng: &mut R,
        ssavd_pp: &SSAVD::PublicParameters,
        history_tree_parameters: &<HTParams::H as FixedLengthCRH>::Parameters,
    ) -> Result<Self, Error>{
        let ssavd = SSAVD::new(rng, ssavd_pp)?;
        let history_tree = HistoryTree::new(history_tree_parameters)?;
        let digest = hash_to_final_digest::<SSAVD, HTParams::H>(
            history_tree_parameters,
            &ssavd.digest()?,
            &history_tree.tree.root,
            &history_tree.epoch,
        )?;
        Ok(SingleStepAVDWithHistory{
            ssavd_pp: ssavd_pp.clone(),
            ssavd: ssavd,
            history_tree: history_tree,
            digest: digest,
        })
    }

    pub fn update(
        &mut self,
        key: &[u8; 32],
        value: &[u8; 32],
    ) -> Result<SingleStepUpdateProof<SSAVD, HTParams>, Error>{
        let prev_ssavd_digest = self.ssavd.digest()?;
        let (new_ssavd_digest, ssavd_proof) = self.ssavd.update(key, value)?;
        let prev_epoch = self.history_tree.epoch.clone();
        self.history_tree.append_digest(&prev_ssavd_digest)?;
        let history_tree_proof = self.history_tree.lookup_path(prev_epoch)?;
        let prev_digest = self.digest.clone();

        // Update digest
        self.digest = hash_to_final_digest::<SSAVD, HTParams::H>(
            &self.history_tree.tree.hash_parameters,
            &new_ssavd_digest,
            &self.history_tree.tree.root,
            &self.history_tree.epoch,
        )?;

        Ok(SingleStepUpdateProof{
            ssavd_pp: self.ssavd_pp.clone(),
            history_tree_pp: self.history_tree.tree.hash_parameters.clone(),
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
    ) -> Result<SingleStepUpdateProof<SSAVD, HTParams>, Error>{
        let prev_ssavd_digest = self.ssavd.digest()?;
        let (new_ssavd_digest, ssavd_proof) = self.ssavd.batch_update(kvs)?;
        let prev_epoch = self.history_tree.epoch.clone();
        self.history_tree.append_digest(&prev_ssavd_digest)?;
        let history_tree_proof = self.history_tree.lookup_path(prev_epoch)?;
        let prev_digest = self.digest.clone();

        // Update digest
        self.digest = hash_to_final_digest::<SSAVD, HTParams::H>(
            &self.history_tree.tree.hash_parameters,
            &new_ssavd_digest,
            &self.history_tree.tree.root,
            &self.history_tree.epoch,
        )?;

        Ok(SingleStepUpdateProof{
            ssavd_pp: self.ssavd_pp.clone(),
            history_tree_pp: self.history_tree.tree.hash_parameters.clone(),
            ssavd_proof: ssavd_proof,
            history_tree_proof: history_tree_proof,
            prev_ssavd_digest: prev_ssavd_digest,
            new_ssavd_digest: new_ssavd_digest,
            prev_digest: prev_digest,
            new_digest: self.digest.clone(),
            prev_epoch: prev_epoch,
        })
    }

}


//TODO: Optimization: Pick a hash function compatible with digest sizes and epoch size -- current fix for PedersenHash is hash twice
pub fn hash_to_final_digest<SSAVD: SingleStepAVD, H: FixedLengthCRH>(
    parameters: &H::Parameters,
    ssavd_digest: &SSAVD::Digest,
    history_tree_digest: &H::Output,
    epoch: &u64,
) -> Result<H::Output, Error> {
    // Hash together digests
    let mut buffer1 = [0u8; 128];
    let mut writer1 = Cursor::new(&mut buffer1[..]);
    ssavd_digest.write(&mut writer1)?;
    history_tree_digest.write(&mut writer1)?;
    let digests_hash = H::evaluate(&parameters, &buffer1[..(H::INPUT_SIZE_BITS / 8)])?;

    // Hash in epoch
    let mut buffer2 = [0u8; 128];
    let mut writer2 = Cursor::new(&mut buffer2[..]);
    writer2.write(&epoch.to_le_bytes())?;
    digests_hash.write(&mut writer2)?;
    H::evaluate(&parameters, &buffer2[..(H::INPUT_SIZE_BITS / 8)])
}

pub fn ssavd_digest_to_bytes<D: ToBytes>(digest: &D) -> Result<[u8; 128], Error> {
    let mut buffer = [0_u8; 128];
    let mut writer = Cursor::new(&mut buffer[..]);
    digest.write(&mut writer)?;
    Ok(buffer)
}
