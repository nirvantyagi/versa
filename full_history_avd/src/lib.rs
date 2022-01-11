use ark_ff::bytes::ToBytes;
use std::{error::Error as ErrorTrait};

use rand::{Rng, CryptoRng};

pub mod history_tree;
// pub mod aggregation;
// pub mod recursion;
pub mod rsa_algebraic;

pub type Error = Box<dyn ErrorTrait>;

pub trait FullHistoryAVD: Sized {
    type Digest: ToBytes + Clone + Eq;
    //TODO: Can create separate verification parameters
    type PublicParameters: Clone + Send + Sync;
    type LookupProof;
    type AuditProof;
    type Store: FHAVDStorer<Self>;

    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self::PublicParameters, Error>;

    fn new<R: Rng + CryptoRng>(rng: &mut R, store: Self::Store) -> Result<Self, Error>;

    fn digest(&self) -> Result<Self::Digest, Error>;

    fn lookup(
        &mut self,
        key: &[u8; 32],
    ) -> Result<(Option<(u64, [u8; 32])>, Self::Digest, Self::LookupProof), Error>;

    fn update<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        key: &[u8; 32],
        value: &[u8; 32],
    ) -> Result<Self::Digest, Error>;

    fn batch_update<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        kvs: &Vec<([u8; 32], [u8; 32])>,
    ) -> Result<Self::Digest, Error>;

    fn verify_lookup(
        pp: &Self::PublicParameters,
        key: &[u8; 32],
        value: &Option<(u64, [u8; 32])>,
        digest: &Self::Digest,
        proof: &Self::LookupProof,
    ) -> Result<bool, Error>;

    fn audit(
        &self,
        start_epoch: usize,
        end_epoch: usize,
    ) -> Result<(Self::Digest, Self::AuditProof), Error>;

    fn verify_audit(
        pp: &Self::PublicParameters,
        start_epoch: usize,
        end_epoch: usize,
        digest: &Self::Digest,
        proof: &Self::AuditProof,
    ) -> Result<bool, Error>;
}

pub fn get_checkpoint_epochs(
    start_epoch: usize,
    end_epoch: usize,
) -> (Vec<usize>, Vec<usize>) {
    let mut checkpoints = vec![];
    let mut checkpoint_ranges = vec![];
    // Climb left path
    let mut curr_height = 0;
    let mut moving_right = true;
    let mut only_climbed_right = true;
    loop {
        let parent_prefix = start_epoch >> (curr_height + 1);
        let is_left_child = (start_epoch >> curr_height) & 1 == 0;

        if !is_left_child && moving_right {
            if only_climbed_right {
                checkpoints.push(start_epoch);
                checkpoint_ranges.push(curr_height);
            } else {
                let checkpoint = ((parent_prefix << 2) + 3) << (curr_height - 1);
                checkpoints.push(checkpoint);
                checkpoint_ranges.push(curr_height - 1);
            }
        }

        if is_left_child && moving_right && !only_climbed_right {
            let checkpoint = ((parent_prefix << 2) + 1) << (curr_height - 1);
            checkpoints.push(checkpoint);
            checkpoint_ranges.push(curr_height - 1);
        }

        // Found the max height between start and end epoch?
        if parent_prefix == end_epoch >> (curr_height + 1) {
            if only_climbed_right {
                checkpoints.push(start_epoch);
                checkpoint_ranges.push(curr_height);
            }
            break;
        }
        moving_right = is_left_child;
        only_climbed_right &= is_left_child;
        curr_height += 1;
    }
    // Descend right path
    loop {
        if curr_height == 0 { break }
        curr_height -= 1;
        let parent_prefix = end_epoch >> (curr_height + 1);
        let is_right_child = (end_epoch >> curr_height) & 1 == 1;
        if is_right_child {
            let checkpoint = parent_prefix << (curr_height + 1);
            checkpoints.push(checkpoint);
            checkpoint_ranges.push(curr_height);
        }
    }
    checkpoints.push(end_epoch);
    (checkpoints, checkpoint_ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_epochs_test() {
        assert_eq!(
            get_checkpoint_epochs(16, 24).0,
            vec![16, 24],
        );

        assert_eq!(
            get_checkpoint_epochs(17, 24).0,
            vec![17, 18, 20, 24],
        );

        assert_eq!(
            get_checkpoint_epochs(22, 24).0,
            vec![22, 24],
        );

        assert_eq!(
            get_checkpoint_epochs(4, 23).0,
            vec![4, 8, 16, 20, 22, 23],
        );

        assert_eq!(
            get_checkpoint_epochs(5, 23).0,
            vec![5, 6, 8, 16, 20, 22, 23],
        );

        assert_eq!(
            get_checkpoint_epochs(4, 23).1,
            vec![2, 3, 2, 1, 0],
        );

        assert_eq!(
            get_checkpoint_epochs(5, 23).1,
            vec![0, 1, 3, 2, 1, 0],
        );
    }
}

pub trait FHAVDStorer<FHAVD: FullHistoryAVD> {}
