use algebra::Field;
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::{
    uint64::UInt64,
    uint8::UInt8,
    bits::ToBytesGadget,
    eq::EqGadget,
    select::CondSelectGadget,
};
use zexe_cp::{
    crh::{FixedLengthCRH, FixedLengthCRHGadget},
};

use super::{MerkleTreeParameters};
use std::marker::PhantomData;

pub struct MerkleTreePathGadget<H, P, HGadget, ConstraintF>
    where
        H: FixedLengthCRH,
        P: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<H, ConstraintF>,
        ConstraintF: Field,
{
    path: Vec<HGadget::OutputGadget>,
    _parameters: PhantomData<P>,
}

impl<H, P, HGadget, ConstraintF> MerkleTreePathGadget<H, P, HGadget, ConstraintF>
    where
        H: FixedLengthCRH,
        P: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<H, ConstraintF>,
        ConstraintF: Field,
{
    pub fn check_path<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
        root: &HGadget::OutputGadget,
        leaf: &Vec<UInt8>,
        index: &UInt64,
        hash_parameters: &HGadget::ParametersGadget,
    ) -> Result<(), SynthesisError> {
        let mut current_hash = hash_leaf_gadget::<H, HGadget, ConstraintF, _>(
            &mut cs.ns(|| "hash_leaf"),
            hash_parameters,
            leaf,
        )?;
        for (i, b) in index.to_bits_le().iter().take(P::DEPTH as usize).enumerate() {
            let lc = HGadget::OutputGadget::conditionally_select(
                &mut cs.ns(|| format!("left_child_index_{}", P::DEPTH as usize - i)),
                b,
                &self.path[i],
                &current_hash,
            )?;
            let rc = HGadget::OutputGadget::conditionally_select(
                &mut cs.ns(|| format!("right_child_index_{}", P::DEPTH as usize - i)),
                b,
                &current_hash,
                &self.path[i],
            )?;
            current_hash = hash_inner_node_gadget::<H, HGadget, ConstraintF, _>(
                &mut cs.ns(|| format!("hash_inner_node_{}", P::DEPTH as usize - i)),
                hash_parameters,
                &lc,
                &rc,
            )?;
        }
        root.enforce_equal(
            &mut cs.ns(|| "root_equal"),
            &current_hash,
        )?;
        Ok(())
    }
}

pub fn hash_leaf_gadget<H, HGadget, ConstraintF, CS>(
    cs: CS,
    parameters: &HGadget::ParametersGadget,
    leaf: &Vec<UInt8>,
) -> Result<HGadget::OutputGadget, SynthesisError>
    where
        H: FixedLengthCRH,
        HGadget: FixedLengthCRHGadget<H, ConstraintF>,
        ConstraintF: Field,
        CS: ConstraintSystem<ConstraintF>,
{
    let mut buffer = leaf.clone();
    buffer.resize(H::INPUT_SIZE_BITS / 8, UInt8::constant(0u8));
    HGadget::check_evaluation_gadget(cs, parameters, &buffer)
}

pub fn hash_inner_node_gadget<H, HGadget, ConstraintF, CS>(
    mut cs: CS,
    parameters: &HGadget::ParametersGadget,
    left: &HGadget::OutputGadget,
    right: &HGadget::OutputGadget,
) -> Result<HGadget::OutputGadget, SynthesisError>
    where
        H: FixedLengthCRH,
        HGadget: FixedLengthCRHGadget<H, ConstraintF>,
        ConstraintF: Field,
        CS: ConstraintSystem<ConstraintF>,
{
    let mut buffer = left.to_bytes(&mut cs.ns(|| "left_to_bytes"))?;
    buffer.extend_from_slice(&right.to_bytes(&mut cs.ns(|| "right_to_bytes"))?);
    buffer.resize(H::INPUT_SIZE_BITS / 8, UInt8::constant(0u8));
    HGadget::check_evaluation_gadget(cs, parameters, &buffer)
}
