pub mod mem_store;

use ark_groth16::{Proof, ProvingKey};
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
    FHAVDStorer,
    recursion::{
        CycleEngine,
        PairingEngine,
        PairingVar,
        MulAssign,
        ToConstraintField,
        ToConstraintFieldGadget,
        PublicParameters,
        RecursionFullHistoryAVD,
    },
    history_tree::{
        Digest,
        LookupProof,
        SingleStepUpdateProof,
        HistoryProof,
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

    fn new<R: Rng + CryptoRng>(rng: &mut R, pp: &PublicParameters<SSAVD, HTParams, Cycle>) -> Result<Self, Error> where Self: Sized;
    fn history_ssavd_get_digest(&self) -> Digest<HTParams>;
    fn history_ssavd_lookup(&mut self, key: &[u8; 32]) -> Result<(Option<(u64, [u8; 32])>, LookupProof<SSAVD, HTParams>), Error>;
    fn history_ssavd_update(&mut self, key: &[u8; 32], value: &[u8; 32]) -> Result<SingleStepUpdateProof<SSAVD, HTParams>, Error>;
    fn history_ssavd_batch_update(&mut self, kvs: &Vec<([u8; 32], [u8; 32])>) -> Result<SingleStepUpdateProof<SSAVD, HTParams>, Error>;
    fn history_ssavd_lookup_history(&mut self, prev_epoch: usize) -> Result<(Digest<HTParams>, HistoryProof<SSAVD, HTParams>), Error>;
    fn history_ssavd_get_hash_parameters(&self) -> <HTParams::H as FixedLengthCRH>::Parameters;

    fn inner_proof_get(&self) -> Proof<<Cycle as ark_ec::CycleEngine>::E1>;
    fn inner_proof_set(&mut self, val: Proof<<Cycle as ark_ec::CycleEngine>::E1>);
    fn ssavd_pp_get(&self) -> SSAVD::PublicParameters;
    fn outer_groth16_pp_get(&self) -> ProvingKey<<Cycle as ark_ec::CycleEngine>::E2>;
    fn inner_groth16_pp_get(&self) -> ProvingKey<<Cycle as ark_ec::CycleEngine>::E1>;
}

impl<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U, V> FHAVDStorer<RecursionFullHistoryAVD<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U, V>> for V
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
    V: RecursionFullHistoryAVDStorer<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U>,
{}
