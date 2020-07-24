use crate::SingleStepAVD;
use algebra::Field;
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::{
    alloc::AllocGadget,
    bits::ToBytesGadget,
    eq::{ConditionalEqGadget, EqGadget},
    select::CondSelectGadget,
};
use std::fmt::Debug;

pub trait SingleStepAVDGadget<AVD: SingleStepAVD, ConstraintF: Field>: Sized {
    type PublicParametersGadget: AllocGadget<AVD::PublicParameters, ConstraintF> + Clone;

    type DigestGadget: ConditionalEqGadget<ConstraintF>
        + EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocGadget<AVD::Digest, ConstraintF>
        + Debug
        + Clone
        + Sized;

    type UpdateProofGadget: AllocGadget<AVD::UpdateProof, ConstraintF>;

    fn check_update_proof<CS: ConstraintSystem<ConstraintF>>(
        cs: CS,
        pp: &Self::PublicParametersGadget,
        prev_digest: &Self::DigestGadget,
        new_digest: &Self::DigestGadget,
        proof: &Self::UpdateProofGadget,
    ) -> Result<(), SynthesisError>;
}
