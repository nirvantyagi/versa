use single_step_avd::{
    SingleStepAVD,
    constraints::SingleStepAVDGadget,
};
use crypto_primitives::sparse_merkle_tree::{MerkleTreeParameters};

use zexe_cp::crh::{
    FixedLengthCRHGadget,
};
use algebra::{
    Field,
};

use std::{
    marker::PhantomData,
};


mod groth16_aggregation;


pub struct AggregatedFullHistoryAVD<SSAVD, SSAVDGadget, HTParams, HGadget, ConstraintF>
where
    SSAVD: SingleStepAVD,
    SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
    HTParams: MerkleTreeParameters,
    HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, ConstraintF>,
    ConstraintF: Field,
{
    _ssavd: PhantomData<SSAVD>,
    _ssavd_gadget: PhantomData<SSAVDGadget>,
    _history_tree_params: PhantomData<HTParams>,
    _hash_gadget: PhantomData<HGadget>,
    _field: PhantomData<ConstraintF>,
}

