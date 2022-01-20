#![allow(deprecated)]
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
use ark_crypto_primitives::{
    snark::{SNARK},
};
use ark_groth16::{Groth16, verifier::prepare_verifying_key};
use ark_ff::{
    ToConstraintField,
};
//TODO: Switch to PairingFriendlyCycle
use ark_ec:: {
    CycleEngine, PairingEngine, AffineCurve,
};
use ark_r1cs_std::{
    pairing::PairingVar,
    ToConstraintFieldGadget,
};
use ark_std::{end_timer, start_timer};
use rand::{Rng, CryptoRng};
use std::{
    ops::MulAssign,
    marker::PhantomData,
};
use crate::{
    history_tree::{
        SingleStepAVDWithHistory,
        Digest,
        LookupProof,
        HistoryProof,
        SingleStepUpdateProof,
        store::{
            HTStorer,
            SingleStepAVDWithHistoryStorer,
        },
    },
    FullHistoryAVD, Error,
    get_checkpoint_epochs,
};

pub mod store;
pub mod constraints;
use constraints::{
    InnerSingleStepProofCircuit, InnerSingleStepProofVerifierInput,
    OuterCircuit,
};

//TODO: Double storing SSAVD_pp (also stored in MerkleTreeAVD) since need for update
pub struct RecursionFullHistoryAVD<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U, V>
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
    V: store::RecursionFullHistoryAVDStorer<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U>,
{
    store: V,
    _history_ssavd: PhantomData<SingleStepAVDWithHistory<SSAVD, HTParams, S, T, U>>,
    _inner_proof: PhantomData<<Groth16<Cycle::E1> as SNARK<<Cycle::E1 as PairingEngine>::Fr>>::Proof>,
    _ssavd_pp: PhantomData<SSAVD::PublicParameters>,
    _inner_groth16_pp: PhantomData<<Groth16<Cycle::E1> as SNARK<<Cycle::E1 as PairingEngine>::Fr>>::ProvingKey>,
    _outer_groth16_pp: PhantomData<<Groth16<Cycle::E2> as SNARK<<Cycle::E2 as PairingEngine>::Fr>>::ProvingKey>,
    _ssavd_gadget: PhantomData<SSAVDGadget>,
    _hash_gadget: PhantomData<HGadget>,
    _e1_gadget: PhantomData<E1Gadget>,
    _e2_gadget: PhantomData<E2Gadget>,
    _s: PhantomData<S>,
    _t: PhantomData<T>,
    _u: PhantomData<U>,
}


//TODO: Can separate out verification parameters
pub struct PublicParameters<SSAVD, HTParams, Cycle>
    where
        SSAVD: SingleStepAVD,
        HTParams: MerkleTreeParameters,
        Cycle: CycleEngine,
        <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<<Cycle::E1 as PairingEngine>::Fr>,
{
    ssavd_pp: SSAVD::PublicParameters,
    history_tree_pp: <HTParams::H as FixedLengthCRH>::Parameters,
    inner_groth16_pp: <Groth16<Cycle::E1> as SNARK<<Cycle::E1 as PairingEngine>::Fr>>::ProvingKey,
    outer_groth16_pp: <Groth16<Cycle::E2> as SNARK<<Cycle::E2 as PairingEngine>::Fr>>::ProvingKey,
}

impl<SSAVD, HTParams, Cycle> Clone for PublicParameters<SSAVD, HTParams, Cycle>
    where
        SSAVD: SingleStepAVD,
        HTParams: MerkleTreeParameters,
        Cycle: CycleEngine,
        <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
        <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<<Cycle::E1 as PairingEngine>::Fr>,
{
    fn clone(&self) -> Self {
        Self {
            ssavd_pp: self.ssavd_pp.clone(),
            history_tree_pp: self.history_tree_pp.clone(),
            inner_groth16_pp: self.inner_groth16_pp.clone(),
            outer_groth16_pp: self.outer_groth16_pp.clone(),
        }
    }
}

pub struct AuditProof<SSAVD, HTParams, Cycle>
where
    SSAVD: SingleStepAVD,
    HTParams: MerkleTreeParameters,
    Cycle: CycleEngine,
    <Cycle::E2 as PairingEngine>::G1Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
    <Cycle::E2 as PairingEngine>::G2Projective: MulAssign<<Cycle::E1 as PairingEngine>::Fq>,
    <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<<Cycle::E1 as PairingEngine>::Fr>,
{
    groth_proof: <Groth16<Cycle::E1> as SNARK<<Cycle::E1 as PairingEngine>::Fr>>::Proof,
    checkpoint_paths: Vec<HistoryProof<SSAVD, HTParams>>,
    checkpoint_digests: Vec<Digest<HTParams>>,
}


impl<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U, V> FullHistoryAVD for
RecursionFullHistoryAVD<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U, V>
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
        V: store::RecursionFullHistoryAVDStorer<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U>,
{
    type Digest = Digest<HTParams>;
    type PublicParameters = PublicParameters<SSAVD, HTParams, Cycle>;
    type LookupProof = LookupProof<SSAVD, HTParams>;
    type AuditProof = AuditProof<SSAVD, HTParams, Cycle>;
    type Store = V;

    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self::PublicParameters, Error> {
        let (ssavd_pp, history_tree_pp) = SingleStepAVDWithHistory::<SSAVD, HTParams, S, T, U>::setup(rng)?;
        let inner_blank_circuit = InnerSingleStepProofCircuit::<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U>::blank(
            &ssavd_pp,
            &history_tree_pp,
        );
        let (inner_groth16_pp, _) = Groth16::<Cycle::E1>::circuit_specific_setup(inner_blank_circuit, rng)?;
        let outer_blank_circuit = OuterCircuit::<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U>::blank(
            inner_groth16_pp.vk.clone(),
        );
        let (outer_groth16_pp, _) = Groth16::<Cycle::E2>::circuit_specific_setup(outer_blank_circuit, rng)?;
        Ok(PublicParameters {
            ssavd_pp,
            history_tree_pp,
            inner_groth16_pp,
            outer_groth16_pp,
        })
    }

    fn new<R: Rng + CryptoRng>(rng: &mut R, pp: &Self::PublicParameters) -> Result<Self, Error> {
        let s = V::new(rng, pp).unwrap();
        Ok(Self {
            store: s,
            _history_ssavd: PhantomData,
            _inner_proof: PhantomData,
            _ssavd_pp: PhantomData,
            _inner_groth16_pp: PhantomData,
            _outer_groth16_pp: PhantomData,
            _ssavd_gadget: PhantomData,
            _hash_gadget: PhantomData,
            _e1_gadget: PhantomData,
            _e2_gadget: PhantomData,
            _s: PhantomData,
            _t: PhantomData,
            _u: PhantomData,
        })
    }

    fn digest(&self) -> Result<Self::Digest, Error> {
        return Ok(self.store.history_ssavd_get_digest());
    }

    fn lookup(&mut self, key: &[u8; 32]) -> Result<(Option<(u64, [u8; 32])>, Self::Digest, Self::LookupProof), Error> {
        let (value, proof) = self.store.history_ssavd_lookup(key)?;
        Ok((value, self.digest()?, proof))
    }

    fn update<R: Rng + CryptoRng>(&mut self, rng: &mut R, key: &[u8; 32], value: &[u8; 32]) -> Result<Self::Digest, Error> {
        // Compute new step proof
        let prev_digest = self.store.history_ssavd_get_digest();
        let update = self.store.history_ssavd_update(key, value)?;
        self._update(rng, update, prev_digest)
    }

    fn batch_update<R: Rng + CryptoRng>(&mut self, rng: &mut R, kvs: &Vec<([u8; 32], [u8; 32])>) -> Result<Self::Digest, Error> {
        // Compute new step proof
        let prev_digest = self.store.history_ssavd_get_digest();
        let update = self.store.history_ssavd_batch_update(kvs)?;
        self._update(rng, update, prev_digest)
    }

    fn verify_lookup(pp: &Self::PublicParameters, key: &[u8; 32], value: &Option<(u64, [u8; 32])>, digest: &Self::Digest, proof: &Self::LookupProof) -> Result<bool, Error> {
        SingleStepAVDWithHistory::<SSAVD, HTParams, S, T, U>::verify_lookup(
            &pp.ssavd_pp,
            &pp.history_tree_pp,
            key,
            value,
            digest,
            proof,
        )
    }

    fn audit(&self, start_epoch: usize, end_epoch: usize) -> Result<(Self::Digest, Self::AuditProof), Error> {
        let (d, history_proof) = get_checkpoint_epochs(start_epoch, end_epoch).0.iter()
            .map(|epoch| self.store.history_ssavd_lookup_history(*epoch))
            .collect::<Result<Vec<(Digest<HTParams>, HistoryProof<SSAVD, HTParams>)>, Error>>()?
            .iter().cloned().unzip::<_, _, Vec<_>, Vec<_>>();
        Ok((
            self.store.history_ssavd_get_digest(),
            AuditProof {
                groth_proof: self.store.inner_proof_get(),
                checkpoint_paths: history_proof,
                checkpoint_digests: d,
            }
        ))
    }

    fn verify_audit(
        pp: &Self::PublicParameters,
        start_epoch: usize,
        end_epoch: usize,
        digest: &Self::Digest,
        proof: &Self::AuditProof,
    ) -> Result<bool, Error> {
        let groth_proof_valid = Groth16::<Cycle::E1>::verify_with_processed_vk(
            &prepare_verifying_key(&pp.inner_groth16_pp.vk),
            &InnerSingleStepProofVerifierInput::<HTParams> {
                new_digest: digest.digest.clone(),
                new_epoch: digest.epoch,
            }.to_field_elements().unwrap(),
            &proof.groth_proof,
        ).unwrap();
        let checkpoint_paths_valid = proof.checkpoint_paths.iter()
            .zip(&proof.checkpoint_digests)
            .zip(get_checkpoint_epochs(start_epoch, end_epoch).0)
            .map(|((checkpoint_proof, checkpoint_digest), epoch)|
                     SingleStepAVDWithHistory::<SSAVD, HTParams, S, T, U>::verify_history(
                         &pp.history_tree_pp,
                         epoch,
                         checkpoint_digest,
                         digest,
                         checkpoint_proof,
                     )
            ).collect::<Result<Vec<bool>, Error>>()?
            .iter()
            .all(|b| *b);
        Ok(groth_proof_valid && checkpoint_paths_valid)
    }
}

impl<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U, V>
RecursionFullHistoryAVD<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U, V>
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
        V: store::RecursionFullHistoryAVDStorer<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U>,
{
    fn _update<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        update: SingleStepUpdateProof<SSAVD, HTParams>,
        prev_digest: Digest<HTParams>,
    ) -> Result<Digest<HTParams>, Error> {
        // Compute outer proof of previous inner proof
        let check = start_timer!(|| "Compute outer proof");
        let outer_proof = Groth16::<Cycle::E2>::prove(
            &self.store.outer_groth16_pp_get(),
            OuterCircuit::<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U>::new(
                self.store.inner_proof_get(),
                InnerSingleStepProofVerifierInput {
                    new_digest: prev_digest.digest.clone(),
                    new_epoch: prev_digest.epoch,
                },
                self.store.inner_groth16_pp_get().vk.clone(),
            ),
            rng,
        )?;
        end_timer!(check);
        // Compute new inner proof
        let check = start_timer!(|| "Compute inner proof");
        let new_inner_proof = Groth16::<Cycle::E1>::prove(
            &self.store.inner_groth16_pp_get(),
            InnerSingleStepProofCircuit::<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, S, T, U>::new(
                false,
                &self.store.ssavd_pp_get(),
                &self.store.history_ssavd_get_hash_parameters(),
                update,
                self.store.outer_groth16_pp_get().vk.clone(),
                outer_proof,
            ),
            rng,
        )?;
        end_timer!(check);
        self.store.inner_proof_set(new_inner_proof.clone());
        Ok(self.digest()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_mnt4_298::{EdwardsProjective, Fq, constraints::EdwardsVar};
    use ark_mnt4_298::{MNT4_298, constraints::PairingVar as MNT4PairingVar};
    use ark_mnt6_298::{MNT6_298, constraints::PairingVar as MNT6PairingVar};
    use rand::{rngs::StdRng, SeedableRng};
    use ark_crypto_primitives::{
        crh::pedersen::{constraints::CRHGadget, CRH, Window},
    };
    use crate::history_tree::{
        store::{
            mem_store::{
                HTMemStore,
                SingleStepAVDWithHistoryMemStore,
            },
        },
        SingleStepAVDWithHistory,
    };
    use single_step_avd::{
        merkle_tree_avd::{
            MerkleTreeAVDParameters,
            MerkleTreeAVD,
            constraints::MerkleTreeAVDGadget,
            store::{
                mem_store::MTAVDMemStore,
            }
        },
        rsa_avd::{
            RsaAVD,
            constraints::RsaAVDGadget,
            store::{
                mem_store::RSAAVDMemStore,
            },
        }
    };
    use crypto_primitives::{
        sparse_merkle_tree::{
            MerkleDepth,
            store::{
                mem_store::SMTMemStore,
            },
        },
        hash::poseidon::{PoseidonSponge, constraints::PoseidonSpongeVar},
    };
    use rsa::{
        bignat::constraints::BigNatCircuitParams,
        kvac::{
            RsaKVAC,
            RsaKVACParams,
            store::{
                mem_store::RsaKVACMemStore,
            }
        },
        poker::{PoKERParams},
        hog::{RsaGroupParams},
        hash::{
            HasherFromDigest, PoseidonHasher, constraints::PoseidonHasherGadget,
        },
    };

    use std::{
        time::Instant,
    };

    #[derive(Clone, Copy, Debug)]
    pub struct MNT298Cycle;
    impl CycleEngine for MNT298Cycle {
        type E1 = MNT4_298;
        type E2 = MNT6_298;
    }

    #[derive(Clone)]
    pub struct Window4x256;

    impl Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = CRH<EdwardsProjective, Window4x256>;
    type HG = CRHGadget<EdwardsProjective, EdwardsVar, Window4x256>;

    #[derive(Clone)]
    pub struct MerkleTreeTestParameters;

    impl MerkleTreeParameters for MerkleTreeTestParameters {
        const DEPTH: MerkleDepth = 4;
        type H = H;
    }

    #[derive(Clone)]
    pub struct MerkleTreeAVDTestParameters;

    impl MerkleTreeAVDParameters for MerkleTreeAVDTestParameters {
        const MAX_UPDATE_BATCH_SIZE: u64 = 3;
        const MAX_OPEN_ADDRESSING_PROBES: u8 = 2;
        type MerkleTreeParameters = MerkleTreeTestParameters;
    }

    type TestSMTStore = SMTMemStore<MerkleTreeTestParameters>;
    type TestMTAVDStore = MTAVDMemStore<MerkleTreeAVDTestParameters, TestSMTStore>;
    type TestMerkleTreeAVD = MerkleTreeAVD<MerkleTreeAVDTestParameters, TestSMTStore, TestMTAVDStore>;
    type TestMerkleTreeAVDGadget = MerkleTreeAVDGadget<MerkleTreeAVDTestParameters, HG, Fq, TestSMTStore, TestMTAVDStore>;
    type TestAVDWHStore = SingleStepAVDWithHistoryMemStore<TestMerkleTreeAVD, MerkleTreeTestParameters, TestSMTStore, TestHTStore>;
    type TestAVDWithHistory = SingleStepAVDWithHistory<TestMerkleTreeAVD, MerkleTreeTestParameters, TestSMTStore, TestHTStore, TestAVDWHStore>;
    type TestHTStore = HTMemStore<MerkleTreeTestParameters, <H as FixedLengthCRH>::Output, TestSMTStore>;
    type TestRecursionFHAVDStore = store::mem_store::RecursionFullHistoryAVDMemStore<
        TestMerkleTreeAVD,
        TestMerkleTreeAVDGadget,
        MerkleTreeTestParameters,
        HG,
        MNT298Cycle,
        MNT4PairingVar,
        MNT6PairingVar,
        TestSMTStore,
        TestHTStore,
        TestAVDWHStore,
    >;
    type TestRecursionFHAVD = RecursionFullHistoryAVD<
        TestMerkleTreeAVD,
        TestMerkleTreeAVDGadget,
        MerkleTreeTestParameters,
        HG,
        MNT298Cycle,
        MNT4PairingVar,
        MNT6PairingVar,
        TestSMTStore,
        TestHTStore,
        TestAVDWHStore,
        TestRecursionFHAVDStore,
    >;

    // Parameters for Merkle Tree AVD with Poseidon hash
    #[derive(Clone)]
    pub struct PoseidonMerkleTreeTestParameters;

    impl MerkleTreeParameters for PoseidonMerkleTreeTestParameters {
        const DEPTH: MerkleDepth = 4;
        type H = PoseidonSponge<Fq>;
    }

    #[derive(Clone)]
    pub struct PoseidonMerkleTreeAVDTestParameters;

    impl MerkleTreeAVDParameters for PoseidonMerkleTreeAVDTestParameters {
        const MAX_UPDATE_BATCH_SIZE: u64 = 3;
        const MAX_OPEN_ADDRESSING_PROBES: u8 = 2;
        type MerkleTreeParameters = PoseidonMerkleTreeTestParameters;
    }

    type PoseidonTestSMTStore = SMTMemStore<PoseidonMerkleTreeTestParameters>;
    type PoseidonTestMTAVDStore = MTAVDMemStore<PoseidonMerkleTreeAVDTestParameters, PoseidonTestSMTStore>;
    type PoseidonTestMerkleTreeAVD = MerkleTreeAVD<PoseidonMerkleTreeAVDTestParameters, PoseidonTestSMTStore, PoseidonTestMTAVDStore>;
    type PoseidonTestHTStore = HTMemStore<PoseidonMerkleTreeTestParameters, <PoseidonSponge<Fq> as FixedLengthCRH>::Output, PoseidonTestSMTStore>;
    type PoseidonTestAVDWHStore = SingleStepAVDWithHistoryMemStore<PoseidonTestMerkleTreeAVD, PoseidonMerkleTreeTestParameters, PoseidonTestSMTStore, PoseidonTestHTStore>;
    type PoseidonTestAVDWithHistory = SingleStepAVDWithHistory<PoseidonTestMerkleTreeAVD, PoseidonMerkleTreeTestParameters, PoseidonTestSMTStore, PoseidonTestHTStore, PoseidonTestAVDWHStore>;
    type PoseidonTestMerkleTreeAVDGadget = MerkleTreeAVDGadget<PoseidonMerkleTreeAVDTestParameters, PoseidonSpongeVar<Fq>, Fq, PoseidonTestSMTStore, PoseidonTestMTAVDStore>;

    type PoseidonTestRecursionFHAVDStore = store::mem_store::RecursionFullHistoryAVDMemStore<
        PoseidonTestMerkleTreeAVD,
        PoseidonTestMerkleTreeAVDGadget,
        PoseidonMerkleTreeTestParameters,
        PoseidonSpongeVar<Fq>,
        MNT298Cycle,
        MNT4PairingVar,
        MNT6PairingVar,
        PoseidonTestSMTStore,
        PoseidonTestHTStore,
        PoseidonTestAVDWHStore,
    >;

    type PoseidonTestRecursionFHAVD = RecursionFullHistoryAVD<
        PoseidonTestMerkleTreeAVD,
        PoseidonTestMerkleTreeAVDGadget,
        PoseidonMerkleTreeTestParameters,
        PoseidonSpongeVar<Fq>,
        MNT298Cycle,
        MNT4PairingVar,
        MNT6PairingVar,
        PoseidonTestSMTStore,
        PoseidonTestHTStore,
        PoseidonTestAVDWHStore,
        PoseidonTestRecursionFHAVDStore,
    >;


    // Parameters for RSA AVD
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestRsa64Params;
    impl RsaGroupParams for TestRsa64Params {
        const RAW_G: usize = 2;
        const RAW_M: &'static str = "17839761582542106619";
    }


    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct BigNatTestParams;
    impl BigNatCircuitParams for BigNatTestParams {
        const LIMB_WIDTH: usize = 32;
        const N_LIMBS: usize = 2;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestPokerParams;
    impl PoKERParams for TestPokerParams {
        const HASH_TO_PRIME_ENTROPY: usize = 32;
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct TestKVACParams;
    impl RsaKVACParams for TestKVACParams {
        const KEY_LEN: usize = 64;
        const VALUE_LEN: usize = 64;
        const PRIME_LEN: usize = 72;
        type RsaGroupParams = TestRsa64Params;
        type PoKERParams = TestPokerParams;
    }

    pub type PoseidonH = PoseidonHasher<Fq>;
    pub type PoseidonHG = PoseidonHasherGadget<Fq>;

    // make RSA AVD
    type TestKvacStore = RsaKVACMemStore<TestKVACParams, HasherFromDigest<Fq, blake3::Hasher>, PoseidonH, BigNatTestParams>;
    type TestRSAKVAC = RsaKVAC<TestKVACParams, HasherFromDigest<Fq, blake3::Hasher>, PoseidonH, BigNatTestParams, TestKvacStore>;
    type TestRSAAVDStore = RSAAVDMemStore<TestKVACParams, HasherFromDigest<Fq, blake3::Hasher>, PoseidonH, BigNatTestParams, TestKvacStore>;
    pub type TestRsaAVD = RsaAVD<TestKVACParams, HasherFromDigest<Fq, blake3::Hasher>, PoseidonH, BigNatTestParams, TestKvacStore, TestRSAAVDStore>;
    // make RSA HT
    type TestRsaSMTStore = SMTMemStore<MerkleTreeTestParameters>;
    type TestRsaHTStore = HTMemStore<MerkleTreeTestParameters, <H as FixedLengthCRH>::Output, TestRsaSMTStore>;
    // make rsa AVD WH
    type TestRSAAVDWHStore = SingleStepAVDWithHistoryMemStore<TestRsaAVD, MerkleTreeTestParameters, TestRsaSMTStore, TestRsaHTStore>;
    type TestRsaAVDWithHistory = SingleStepAVDWithHistory<TestRsaAVD, MerkleTreeTestParameters, TestRsaSMTStore, TestRsaHTStore, TestRSAAVDWHStore>;
    // other
    pub type TestRsaAVDGadget = RsaAVDGadget<Fq, TestKVACParams, HasherFromDigest<Fq, blake3::Hasher>, PoseidonH, PoseidonHG, BigNatTestParams, TestKvacStore, TestRSAAVDStore>;

    type TestRsaRecursionFHAVDStore = store::mem_store::RecursionFullHistoryAVDMemStore<
        TestRsaAVD,
        TestRsaAVDGadget,
        MerkleTreeTestParameters,
        HG,
        MNT298Cycle,
        MNT4PairingVar,
        MNT6PairingVar,
        TestRsaSMTStore,
        TestRsaHTStore,
        TestRSAAVDWHStore,
    >;

    type TestRsaRecursionFHAVD = RecursionFullHistoryAVD<
        TestRsaAVD,
        TestRsaAVDGadget,
        MerkleTreeTestParameters,
        HG,
        MNT298Cycle,
        MNT4PairingVar,
        MNT6PairingVar,
        TestRsaSMTStore,
        TestRsaHTStore,
        TestRSAAVDWHStore,
        TestRsaRecursionFHAVDStore,
    >;

    #[test]
    #[ignore] // Expensive test, run with ``cargo test mt_update_and_verify_recursion_full_history_test --release -- --ignored --nocapture``
    fn mt_update_and_verify_recursion_full_history_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let start = Instant::now();
        let pp = TestRecursionFHAVD::setup(&mut rng).unwrap();
        let mut avd: TestRecursionFHAVD = TestRecursionFHAVD::new(&mut rng, &pp).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t setup time: {} s", bench);

        let epoch1_update = &vec![
            ([1_u8; 32], [2_u8; 32]),
            ([11_u8; 32], [12_u8; 32]),
            ([21_u8; 32], [22_u8; 32]),
        ];
        let epoch2_update = &vec![
            ([1_u8; 32], [3_u8; 32]),
            ([11_u8; 32], [13_u8; 32]),
            ([21_u8; 32], [23_u8; 32]),
        ];
        let epoch3_update = &vec![
            ([1_u8; 32], [4_u8; 32]),
            ([11_u8; 32], [14_u8; 32]),
            ([21_u8; 32], [24_u8; 32]),
        ];
        let epoch4_update = &vec![
            ([1_u8; 32], [5_u8; 32]),
            ([11_u8; 32], [15_u8; 32]),
            ([31_u8; 32], [35_u8; 32]),
        ];
        let epoch5_update = &vec![
            ([1_u8; 32], [6_u8; 32]),
            ([11_u8; 32], [16_u8; 32]),
            ([31_u8; 32], [36_u8; 32]),
        ];

        let start = Instant::now();
        let d1 = avd.batch_update(&mut rng, &epoch1_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 1 proving time: {} s", bench);

        let (_, audit_proof) = avd.audit(0, 1).unwrap();
        let verify_audit = TestRecursionFHAVD::verify_audit(&pp, 0, 1, &d1, &audit_proof).unwrap();
        assert!(verify_audit);

        let start = Instant::now();
        let _d2 = avd.batch_update(&mut rng, &epoch2_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 2 proving time: {} s", bench);

        let start = Instant::now();
        let _d3 = avd.batch_update(&mut rng, &epoch3_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 3 proving time: {} s", bench);

        let start = Instant::now();
        let _d4 = avd.batch_update(&mut rng, &epoch4_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 4 proving time: {} s", bench);

        let start = Instant::now();
        let d5 = avd.batch_update(&mut rng, &epoch5_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 5 proving time: {} s", bench);

        let (_, audit_proof) = avd.audit(2, 5).unwrap();
        let verify_audit = TestRecursionFHAVD::verify_audit(&pp, 2, 5, &d5, &audit_proof).unwrap();
        assert!(verify_audit);
    }


    #[test]
    #[ignore] // Expensive test, run with ``cargo test mt_poseidon_update_and_verify_recursion_full_history_test --release -- --ignored --nocapture``
    fn mt_poseidon_update_and_verify_recursion_full_history_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let start = Instant::now();
        let pp = PoseidonTestRecursionFHAVD::setup(&mut rng).unwrap();
        let mut avd: PoseidonTestRecursionFHAVD = PoseidonTestRecursionFHAVD::new(&mut rng, &pp).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t setup time: {} s", bench);

        let epoch1_update = &vec![
            ([1_u8; 32], [2_u8; 32]),
            ([11_u8; 32], [12_u8; 32]),
            ([21_u8; 32], [22_u8; 32]),
        ];
        let epoch2_update = &vec![
            ([1_u8; 32], [3_u8; 32]),
            ([11_u8; 32], [13_u8; 32]),
            ([21_u8; 32], [23_u8; 32]),
        ];
        let epoch3_update = &vec![
            ([1_u8; 32], [4_u8; 32]),
            ([11_u8; 32], [14_u8; 32]),
            ([21_u8; 32], [24_u8; 32]),
        ];
        let epoch4_update = &vec![
            ([1_u8; 32], [5_u8; 32]),
            ([11_u8; 32], [15_u8; 32]),
            ([31_u8; 32], [35_u8; 32]),
        ];
        let epoch5_update = &vec![
            ([1_u8; 32], [6_u8; 32]),
            ([11_u8; 32], [16_u8; 32]),
            ([31_u8; 32], [36_u8; 32]),
        ];

        let start = Instant::now();
        let d1 = avd.batch_update(&mut rng, &epoch1_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 1 proving time: {} s", bench);

        let (_, audit_proof) = avd.audit(0, 1).unwrap();
        let verify_audit = PoseidonTestRecursionFHAVD::verify_audit(&pp, 0, 1, &d1, &audit_proof).unwrap();
        assert!(verify_audit);

        let start = Instant::now();
        let _d2 = avd.batch_update(&mut rng, &epoch2_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 2 proving time: {} s", bench);

        let start = Instant::now();
        let _d3 = avd.batch_update(&mut rng, &epoch3_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 3 proving time: {} s", bench);

        let start = Instant::now();
        let _d4 = avd.batch_update(&mut rng, &epoch4_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 4 proving time: {} s", bench);

        let start = Instant::now();
        let d5 = avd.batch_update(&mut rng, &epoch5_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 5 proving time: {} s", bench);

        let (_, audit_proof) = avd.audit(2, 5).unwrap();
        let verify_audit = PoseidonTestRecursionFHAVD::verify_audit(&pp, 2, 5, &d5, &audit_proof).unwrap();
        assert!(verify_audit);
    }

    #[test]
    #[ignore] // Expensive test, run with ``cargo test update_and_verify_rsa_recursion_full_history_test --release -- --ignored --nocapture``
    fn update_and_verify_rsa_recursion_full_history_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let start = Instant::now();
        let pp = TestRsaRecursionFHAVD::setup(&mut rng).unwrap();
        let mut avd  = TestRsaRecursionFHAVD::new(&mut rng, &pp).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t setup time: {} s", bench);

        fn u8_to_array(n: u8) -> [u8; 32] {
            let mut arr = [0_u8; 32];
            arr[31] = n;
            arr
        }

        let epoch1_update = &vec![
            (u8_to_array(1), u8_to_array(2)),
            (u8_to_array(11), u8_to_array(12)),
            (u8_to_array(21), u8_to_array(22)),
        ];
        let epoch2_update = &vec![
            (u8_to_array(1), u8_to_array(3)),
            (u8_to_array(11), u8_to_array(13)),
            (u8_to_array(21), u8_to_array(23)),
        ];
        let epoch3_update = &vec![
            (u8_to_array(1), u8_to_array(4)),
            (u8_to_array(11), u8_to_array(14)),
            (u8_to_array(21), u8_to_array(24)),
        ];
        let epoch4_update = &vec![
            (u8_to_array(1), u8_to_array(5)),
            (u8_to_array(11), u8_to_array(15)),
            (u8_to_array(31), u8_to_array(35)),
        ];
        let epoch5_update = &vec![
            (u8_to_array(1), u8_to_array(6)),
            (u8_to_array(11), u8_to_array(16)),
            (u8_to_array(31), u8_to_array(36)),
        ];

        let start = Instant::now();
        let d1 = avd.batch_update(&mut rng, &epoch1_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 1 proving time: {} s", bench);

        let (_, audit_proof) = avd.audit(0, 1).unwrap();
        let verify_audit = TestRsaRecursionFHAVD::verify_audit(&pp, 0, 1, &d1, &audit_proof).unwrap();
        assert!(verify_audit);

        let start = Instant::now();
        let _d2 = avd.batch_update(&mut rng, &epoch2_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 2 proving time: {} s", bench);

        let start = Instant::now();
        let _d3 = avd.batch_update(&mut rng, &epoch3_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 3 proving time: {} s", bench);

        let start = Instant::now();
        let _d4 = avd.batch_update(&mut rng, &epoch4_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 4 proving time: {} s", bench);

        let start = Instant::now();
        let d5 = avd.batch_update(&mut rng, &epoch5_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 5 proving time: {} s", bench);

        let (_, audit_proof) = avd.audit(1, 5).unwrap();
        let verify_audit = TestRsaRecursionFHAVD::verify_audit(&pp, 1, 5, &d5, &audit_proof).unwrap();
        assert!(verify_audit);
    }
}
