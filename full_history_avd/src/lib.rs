use algebra::bytes::ToBytes;
use rand::Rng;
use std::{error::Error as ErrorTrait, hash::Hash};

pub mod history_tree;
pub mod aggregation;

pub type Error = Box<dyn ErrorTrait>;

pub trait FullHistoryAVD: Sized {
    type Digest: ToBytes + Clone + Eq + Hash;
    type PublicParameters: Clone + Default;
    type LookupProof;
    type DigestProof;
    type HistoryProof;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::PublicParameters, Error>;

    fn new<R: Rng>(rng: &mut R, pp: &Self::PublicParameters) -> Result<Self, Error>;

    fn digest(&self) -> Result<Self::Digest, Error>;

    fn lookup(
        &self,
        key: &[u8; 32],
    ) -> Result<(Option<(u32, [u8; 32])>, Self::Digest, Self::LookupProof), Error>;

    fn update(
        &mut self,
        key: &[u8; 32],
        value: &[u8; 32],
    ) -> Result<(Self::Digest, Self::DigestProof), Error>;

    fn batch_update(
        &mut self,
        kvs: &Vec<([u8; 32], [u8; 32])>,
    ) -> Result<(Self::Digest, Self::DigestProof), Error>;

    fn verify_digest(
        pp: &Self::PublicParameters,
        digest: &Self::Digest,
        proof: &Self::DigestProof,
    ) -> Result<bool, Error>;

    fn verify_lookup(
        pp: &Self::PublicParameters,
        key: &[u8; 32],
        value: &Option<(u32, [u8; 32])>,
        digest: &Self::Digest,
        proof: &Self::LookupProof,
    ) -> Result<bool, Error>;

    fn lookup_history(
        &self,
        prev_digest: &Self::Digest,
    ) -> Result<(Self::Digest, Option<Self::HistoryProof>), Error>;

    fn verify_history(
        pp: &Self::PublicParameters,
        prev_digest: &Self::Digest,
        current_digest: &Self::Digest,
        proof: &Self::HistoryProof,
    ) -> Result<bool, Error>;
}
