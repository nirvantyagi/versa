use crate::SingleStepAVD;
use ark_ff::Field;
use ark_relations::r1cs::{SynthesisError};
use ark_r1cs_std::prelude::*;

pub trait SingleStepAVDGadget<AVD: SingleStepAVD, ConstraintF: Field>: Sized {
    type PublicParametersVar: AllocVar<AVD::PublicParameters, ConstraintF> + Clone;

    type DigestVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<AVD::Digest, ConstraintF>
        + R1CSVar<ConstraintF>
        + Clone
        + Sized;

    type UpdateProofVar: AllocVar<AVD::UpdateProof, ConstraintF>;

    fn check_update_proof(
        pp: &Self::PublicParametersVar,
        prev_digest: &Self::DigestVar,
        new_digest: &Self::DigestVar,
        proof: &Self::UpdateProofVar,
    ) -> Result<(), SynthesisError> {
        Self::conditional_check_update_proof(
           pp, prev_digest, new_digest, proof, &Boolean::TRUE,
        )
    }

    fn conditional_check_update_proof(
        pp: &Self::PublicParametersVar,
        prev_digest: &Self::DigestVar,
        new_digest: &Self::DigestVar,
        proof: &Self::UpdateProofVar,
        condition: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError>;
}
