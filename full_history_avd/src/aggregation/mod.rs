use single_step_avd::{
    SingleStepAVD,
    constraints::SingleStepAVDGadget,
};
use crypto_primitives::sparse_merkle_tree::{MerkleTreeParameters};

use zexe_cp::{
    crh::{FixedLengthCRH, FixedLengthCRHGadget},
    nizk::{groth16::Groth16, NIZK},
};
use algebra::{
    fields::Field,
    curves::PairingEngine,
    ToConstraintField,
};
use ip_proofs::applications::groth16_aggregation::{AggregateProof, aggregate_proofs, verify_aggregate_proof};

use rand::Rng;
use digest::Digest as HashDigest;
use crate::{history_tree::SingleStepAVDWithHistory, FullHistoryAVD, Error};

pub mod constraints;

use constraints::{SingleStepProofCircuit, SingleStepProofVerifierInput};


pub struct AggregatedFullHistoryAVD<SSAVD, SSAVDGadget, HTParams, HGadget, Pairing, FastH>
where
    SSAVD: SingleStepAVD,
    SSAVDGadget: SingleStepAVDGadget<SSAVD, Pairing::Fr>,
    HTParams: MerkleTreeParameters,
    HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, Pairing::Fr>,
    Pairing: PairingEngine,
    FastH: HashDigest,
    <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<Pairing::Fr>,
{
    history_ssavd: SingleStepAVDWithHistory<SSAVD, HTParams>,
    proofs: Vec<
        <Groth16<
            Pairing,
            SingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Pairing::Fr>,
            SingleStepProofVerifierInput<HTParams>,
            > as NIZK
        >::Proof
    >,
    aggregated_proofs: Vec<AggregateProof<Pairing, FastH>>,
}


#[derive(Clone)]
pub struct PublicParameters<SSAVD: SingleStepAVD, HTParams: MerkleTreeParameters> {
    ssavd_pp: SSAVD::PublicParameters,
    history_tree_pp: <HTParams::H as FixedLengthCRH>::Parameters,
}



impl<SSAVD, SSAVDGadget, HTParams, HGadget, Pairing, FastH> FullHistoryAVD for
AggregatedFullHistoryAVD<SSAVD, SSAVDGadget, HTParams, HGadget, Pairing, FastH>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, Pairing::Fr>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, Pairing::Fr>,
        Pairing: PairingEngine,
        FastH: HashDigest,
        <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<Pairing::Fr>,
{
    type Digest = ();
    type PublicParameters = ();
    type VerificationParameters = ();
    type LookupProof = ();
    type DigestProof = ();
    type HistoryProof = ();

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::PublicParameters, Error> {
        unimplemented!()
    }

    fn new<R: Rng>(rng: &mut R, pp: &Self::PublicParameters) -> Result<Self, Error> {
        unimplemented!()
    }

    fn digest(&self) -> Result<Self::Digest, Error> {
        unimplemented!()
    }

    fn lookup(&self, key: &[u8; 32]) -> Result<(Option<(u64, [u8; 32])>, Self::Digest, Self::LookupProof), Error> {
        unimplemented!()
    }

    fn update(&mut self, key: &[u8; 32], value: &[u8; 32]) -> Result<(Self::Digest, Self::DigestProof), Error> {
        unimplemented!()
    }

    fn batch_update(&mut self, kvs: &Vec<([u8; 32], [u8; 32])>) -> Result<(Self::Digest, Self::DigestProof), Error> {
        unimplemented!()
    }

    fn verify_digest(pp: &Self::PublicParameters, digest: &Self::Digest, proof: &Self::DigestProof) -> Result<bool, Error> {
        unimplemented!()
    }

    fn verify_lookup(pp: &Self::PublicParameters, key: &[u8; 32], value: &Option<(u64, [u8; 32])>, digest: &Self::Digest, proof: &Self::LookupProof) -> Result<bool, Error> {
        unimplemented!()
    }

    fn lookup_history(&self, prev_digest: &Self::Digest) -> Result<(Self::Digest, Option<Self::HistoryProof>), Error> {
        unimplemented!()
    }

    fn verify_history(pp: &Self::PublicParameters, prev_digest: &Self::Digest, current_digest: &Self::Digest, proof: &Self::HistoryProof) -> Result<bool, Error> {
        unimplemented!()
    }
}
