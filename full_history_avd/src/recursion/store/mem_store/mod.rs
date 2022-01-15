use std::{
    marker::PhantomData,
};
use rand::{Rng, CryptoRng};
use ark_ff::bytes::ToBytes;
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
        store::{
            RecursionFullHistoryAVDStorer,
        },
        InnerSingleStepProofCircuit,
    },
    history_tree::{
        store::{
            HTStorer,
            SingleStepAVDWithHistoryStorer,
        },
        SingleStepAVDWithHistory,
    },
    Error,
};
use ark_crypto_primitives::{
    snark::{SNARK},
};
use ark_groth16::{Groth16, Proof};

pub struct RecursionFullHistoryAVDMemStore<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U>
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
    pub history_ssavd: SingleStepAVDWithHistory<SSAVD, HTParams, S, T, U>,
    inner_proof: <Groth16<Cycle::E1> as SNARK<<Cycle::E1 as PairingEngine>::Fr>>::Proof,
    ssavd_pp: SSAVD::PublicParameters,
    inner_groth16_pp: <Groth16<Cycle::E1> as SNARK<<Cycle::E1 as PairingEngine>::Fr>>::ProvingKey,
    outer_groth16_pp: <Groth16<Cycle::E2> as SNARK<<Cycle::E2 as PairingEngine>::Fr>>::ProvingKey,
    _ssavd_gadget: PhantomData<SSAVDGadget>,
    _hash_gadget: PhantomData<HGadget>,
    _e1_gadget: PhantomData<E1Gadget>,
    _e2_gadget: PhantomData<E2Gadget>,
}

impl<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U> RecursionFullHistoryAVDStorer<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U> for RecursionFullHistoryAVDMemStore<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U>
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
    fn new<R: Rng + CryptoRng>(rng: &mut R, s: U) -> Result<Self, Error> where Self: Sized {
        let history_ssavd = SingleStepAVDWithHistory::<SSAVD, HTParams, S, T, U>::new(rng, s)?;
        let inner_genesis_proof = Groth16::<Cycle::E1>::prove(
            &pp.inner_groth16_pp,
            InnerSingleStepProofCircuit::<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>::new(
                true,
                &pp.ssavd_pp,
                &pp.history_tree_pp,
                Default::default(),
                pp.outer_groth16_pp.vk.clone(),
                Proof {
                    a: <Cycle::E2 as PairingEngine>::G1Affine::prime_subgroup_generator(),
                    b: <Cycle::E2 as PairingEngine>::G2Affine::prime_subgroup_generator(),
                    c: <Cycle::E2 as PairingEngine>::G1Affine::prime_subgroup_generator(),
                },
            ),
            rng,
        )?;
        Ok(Self {
            history_ssavd: history_ssavd,
            inner_proof: inner_genesis_proof,
            ssavd_pp: pp.ssavd_pp.clone(),
            inner_groth16_pp: pp.inner_groth16_pp.clone(),
            outer_groth16_pp: pp.outer_groth16_pp.clone(),
            _ssavd_gadget: PhantomData,
            _hash_gadget: PhantomData,
            _e1_gadget: PhantomData,
            _e2_gadget: PhantomData,
        })
    }
    fn history_ssavd_get_digest(&self) -> Result<SSAVD::Digest, Error> {
        return self.history_ssavd.store.ssavd_digest();
    }
    fn history_ssavd_lookup(&mut self, key: &[u8; 32],) -> Result<(Option<(u64, [u8; 32])>, SSAVD::Digest, SSAVD::LookupProof), Error> {
        return self.history_ssavd.store.ssavd_lookup(key);
    }
    fn history_ssavd_update(&mut self, key: &[u8; 32], value: &[u8; 32]) -> Result<(SSAVD::Digest, SSAVD::UpdateProof), Error> {
        return self.history_ssavd.store.ssavd_update(key, value);
    }
    fn history_ssavd_batch_update(&mut self, kvs: &Vec<([u8; 32], [u8; 32])>) -> Result<(SSAVD::Digest, SSAVD::UpdateProof), Error> {
        return self.history_ssavd.store.ssavd_batch_update(kvs);
    }


}
