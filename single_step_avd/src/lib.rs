use algebra::bytes::ToBytes;
use rand::Rng;
use std::error::Error as ErrorTrait;

pub mod merkle_tree_avd;

pub type Error = Box<dyn ErrorTrait>;

pub trait SingleStepAVD: Sized {
    type Digest: ToBytes + Clone + Eq;
    type PublicParameters: Clone + Default;
    type LookupProof;
    type UpdateProof;

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
    ) -> Result<(Self::Digest, Self::UpdateProof), Error>;

    fn batch_update(
        &mut self,
        kvs: &Vec<([u8; 32], [u8; 32])>,
    ) -> Result<(Self::Digest, Self::UpdateProof), Error>;

    fn verify_update(
        pp: &Self::PublicParameters,
        prev_digest: &Self::Digest,
        new_digest: &Self::Digest,
        proof: &Self::UpdateProof,
    ) -> Result<bool, Error>;

    fn verify_lookup(
        pp: &Self::PublicParameters,
        key: &[u8; 32],
        value: &Option<(u32, [u8; 32])>,
        digest: &Self::Digest,
        proof: &Self::LookupProof,
    ) -> Result<bool, Error>;
}