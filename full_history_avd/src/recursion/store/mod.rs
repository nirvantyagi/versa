pub mod mem_store;

use rand::{Rng, CryptoRng};
use single_step_avd::{
    SingleStepAVD,
    constraints::SingleStepAVDGadget,
};
use crypto_primitives::{
    sparse_merkle_tree::{
        MerkleTreeParameters,
        store::SMTStorer,
    },
    hash::{
        FixedLengthCRH,
        constraints::FixedLengthCRHGadget
    },
};
use crate::{
    recursion::{
        CycleEngine,
        PairingEngine,
        PairingVar,
        MulAssign,
        ToConstraintField,
        ToConstraintFieldGadget,
        PublicParameters,
    },
    history_tree::{
        Digest,
        store::{
            HTStorer,
            SingleStepAVDWithHistoryStorer,
        },
    },
    Error,
};

pub trait RecursionFullHistoryAVDStorer<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U>
where
    SSAVD: SingleStepAVD,
    SSAVDGadget: SingleStepAVDGadget<SSAVD, <Cycle::E1 as PairingEngine>::Fr>,
    HTParams: MerkleTreeParameters,
    HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, <Cycle::E1 as PairingEngine>::Fr>,
    Cycle: CycleEngine,
    E1Gadget: PairingVar<Cycle::E1, <Cycle::E1 as PairingEngine>::Fq>,
    E2Gadget: PairingVar<Cycle::E2, <Cycle::E2 as PairingEngine>::Fq>,
    <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
    <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
    <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<<Cycle::E1 as PairingEngine>::Fr>,
    <HGadget as FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, <Cycle::E2 as PairingEngine>::Fq>>::OutputVar: ToConstraintFieldGadget<<Cycle::E2 as PairingEngine>::Fq>,
    S: SMTStorer<HTParams>,
    T: HTStorer<HTParams, <HTParams::H as FixedLengthCRH>::Output, S>,
    U: SingleStepAVDWithHistoryStorer<SSAVD, HTParams, S, T>,
{

    fn new<R: Rng + CryptoRng>(_rng: &mut R, pp: &PublicParameters<SSAVD, HTParams, Cycle>, s: U) -> Result<Self, Error> where Self: Sized;
    fn history_ssavd_get_digest(&self) -> Result<SSAVD::Digest, Error>;
    fn history_ssavd_lookup(&mut self, key: &[u8; 32],) -> Result<(Option<(u64, [u8; 32])>, SSAVD::Digest, SSAVD::LookupProof), Error>;
    fn history_ssavd_update(&mut self, key: &[u8; 32], value: &[u8; 32]) -> Result<(SSAVD::Digest, SSAVD::UpdateProof), Error>;
    fn history_ssavd_batch_update(&mut self, kvs: &Vec<([u8; 32], [u8; 32])>) -> Result<(SSAVD::Digest, SSAVD::UpdateProof), Error>;

    // fn new(initial_leaf: &[u8], hash_parameters: &<P::H as FixedLengthCRH>::Parameters) -> Result<Self, Error> where Self: Sized;
    // fn smt_lookup(&mut self, index: MerkleIndex) -> Result<MerkleTreePath<P>, Error>;
    // fn smt_update(&mut self, index: MerkleIndex, leaf_value: &[u8]) -> Result<(), Error>;
    // fn smt_get_hash_parameters(&self) -> <P::H as FixedLengthCRH>::Parameters;
    // fn smt_get_root(&self) -> <P::H as FixedLengthCRH>::Output;
    //
    // fn get_epoch(&self) -> MerkleIndex;
    // fn set_epoch(&mut self, index: MerkleIndex) -> Result<(), Error>;
    //
    // fn digest_d_get(&self, key: &MerkleIndex) -> Option<&D>;
    // fn digest_d_insert(&mut self, index: MerkleIndex, digest: D) -> Option<D>;
}
