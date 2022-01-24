use std::{
    marker::PhantomData,
};
use ark_groth16::{Groth16, Proof, ProvingKey};
use rand::{Rng, CryptoRng, rngs::StdRng, SeedableRng};
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
    FullHistoryAVD,
    recursion::{
        AffineCurve,
        CycleEngine,
        PairingEngine,
        PairingVar,
        MulAssign,
        ToConstraintField,
        ToConstraintFieldGadget,
        InnerSingleStepProofCircuit,
        PublicParameters,
        store::RecursionFullHistoryAVDStorer,
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
        SingleStepAVDWithHistory,
    },
    Error,
};
use ark_crypto_primitives::{
    snark::{SNARK},
};
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
    fn new<R: Rng + CryptoRng>(rng: &mut R, pp: &PublicParameters<SSAVD, HTParams, Cycle>) -> Result<Self, Error> where Self: Sized {
        let history_ssavd = SingleStepAVDWithHistory::<SSAVD, HTParams, S, T, U>::new(rng, &pp.ssavd_pp, &pp.history_tree_pp).unwrap();
        let inner_genesis_proof = Groth16::<Cycle::E1>::prove(
            &pp.inner_groth16_pp,
            InnerSingleStepProofCircuit::<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U>::new(
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
    fn make_copy(&self) -> Result<Self, Error> where Self: Sized {
        // THIS IS A DUMMY FUNC
        let mut rng = StdRng::seed_from_u64(0_u64);
        let pp = RecursionFullHistoryAVD::<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U, Self>::setup(&mut rng).unwrap();
        Self::new(&mut rng, &pp)
    }
    fn history_ssavd_get_digest(&self) -> Digest<HTParams> {
        return self.history_ssavd.digest();
    }
    fn history_ssavd_lookup(&mut self, key: &[u8; 32]) -> Result<(Option<(u64, [u8; 32])>, LookupProof<SSAVD, HTParams>), Error> {
        return self.history_ssavd.lookup(key);
    }
    fn history_ssavd_update(&mut self, key: &[u8; 32], value: &[u8; 32]) -> Result<SingleStepUpdateProof<SSAVD, HTParams>, Error> {
        return self.history_ssavd.update(key, value);
    }
    fn history_ssavd_batch_update(&mut self, kvs: &Vec<([u8; 32], [u8; 32])>) -> Result<SingleStepUpdateProof<SSAVD, HTParams>, Error> {
        return self.history_ssavd.batch_update(kvs);
    }
    fn history_ssavd_lookup_history(&mut self, prev_epoch: usize) -> Result<(Digest<HTParams>, HistoryProof<SSAVD, HTParams>), Error> {
        return self.history_ssavd.lookup_history(prev_epoch);
    }
    fn history_ssavd_get_hash_parameters(&self) -> <HTParams::H as FixedLengthCRH>::Parameters {
        return self.history_ssavd.store.history_tree_get_hash_parameters();
    }
    fn inner_proof_set(&mut self, val: Proof<<Cycle as ark_ec::CycleEngine>::E1>) {
        self.inner_proof = val;
    }
    fn inner_proof_get(&self) -> Proof<<Cycle as ark_ec::CycleEngine>::E1> {
        return self.inner_proof.clone();
    }
    fn ssavd_pp_get(&self) -> SSAVD::PublicParameters {
        return self.ssavd_pp.clone();
    }
    fn outer_groth16_pp_get(&self) -> ProvingKey<<Cycle as ark_ec::CycleEngine>::E2> {
        return self.outer_groth16_pp.clone();
    }
    fn inner_groth16_pp_get(&self) -> ProvingKey<<Cycle as ark_ec::CycleEngine>::E1> {
        return self.inner_groth16_pp.clone();
    }
}
