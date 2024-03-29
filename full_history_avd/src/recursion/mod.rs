#![allow(deprecated)]
use single_step_avd::{
    SingleStepAVD,
    constraints::SingleStepAVDGadget,
};
use crypto_primitives::{
    sparse_merkle_tree::{MerkleTreeParameters},
    hash::{FixedLengthCRH, constraints::FixedLengthCRHGadget},
};

use ark_crypto_primitives::{
    snark::{SNARK},
};
use ark_groth16::{Groth16, Proof, verifier::prepare_verifying_key};
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
    history_tree::{SingleStepAVDWithHistory, Digest, LookupProof, HistoryProof, SingleStepUpdateProof},
    FullHistoryAVD, Error,
    get_checkpoint_epochs,
};

pub mod constraints;
use constraints::{
    InnerSingleStepProofCircuit, InnerSingleStepProofVerifierInput,
    OuterCircuit,
};

//TODO: Double storing SSAVD_pp (also stored in MerkleTreeAVD) since need for update
pub struct RecursionFullHistoryAVD<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>
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
{
    history_ssavd: SingleStepAVDWithHistory<SSAVD, HTParams>,
    inner_proof: <Groth16<Cycle::E1> as SNARK<<Cycle::E1 as PairingEngine>::Fr>>::Proof,
    ssavd_pp: SSAVD::PublicParameters,
    inner_groth16_pp: <Groth16<Cycle::E1> as SNARK<<Cycle::E1 as PairingEngine>::Fr>>::ProvingKey,
    outer_groth16_pp: <Groth16<Cycle::E2> as SNARK<<Cycle::E2 as PairingEngine>::Fr>>::ProvingKey,
    _ssavd_gadget: PhantomData<SSAVDGadget>,
    _hash_gadget: PhantomData<HGadget>,
    _e1_gadget: PhantomData<E1Gadget>,
    _e2_gadget: PhantomData<E2Gadget>,
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


impl<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget> FullHistoryAVD for
RecursionFullHistoryAVD<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>
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
{
    type Digest = Digest<HTParams>;
    type PublicParameters = PublicParameters<SSAVD, HTParams, Cycle>;
    type LookupProof = LookupProof<SSAVD, HTParams>;
    type AuditProof = AuditProof<SSAVD, HTParams, Cycle>;

    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self::PublicParameters, Error> {
        let (ssavd_pp, history_tree_pp) = SingleStepAVDWithHistory::<SSAVD, HTParams>::setup(rng)?;
        let inner_blank_circuit = InnerSingleStepProofCircuit::<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>::blank(
            &ssavd_pp,
            &history_tree_pp,
        );
        let (inner_groth16_pp, _) = Groth16::<Cycle::E1>::circuit_specific_setup(inner_blank_circuit, rng)?;
        let outer_blank_circuit = OuterCircuit::<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>::blank(
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
        let history_ssavd = SingleStepAVDWithHistory::<SSAVD, HTParams>::new(rng, &pp.ssavd_pp, &pp.history_tree_pp)?;
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

    fn digest(&self) -> Result<Self::Digest, Error> {
        Ok(self.history_ssavd.digest())
    }

    fn lookup(&mut self, key: &[u8; 32]) -> Result<(Option<(u64, [u8; 32])>, Self::Digest, Self::LookupProof), Error> {
        let (value, proof) = self.history_ssavd.lookup(key)?;
        Ok((value, self.digest()?, proof))
    }

    fn update<R: Rng + CryptoRng>(&mut self, rng: &mut R, key: &[u8; 32], value: &[u8; 32]) -> Result<Self::Digest, Error> {
        // Compute new step proof
        let prev_digest = self.history_ssavd.digest();
        let update = self.history_ssavd.update(key, value)?;
        self._update(rng, update, prev_digest)
    }

    fn batch_update<R: Rng + CryptoRng>(&mut self, rng: &mut R, kvs: &Vec<([u8; 32], [u8; 32])>) -> Result<Self::Digest, Error> {
        // Compute new step proof
        let prev_digest = self.history_ssavd.digest();
        let update = self.history_ssavd.batch_update(kvs)?;
        self._update(rng, update, prev_digest)
    }

    fn verify_lookup(pp: &Self::PublicParameters, key: &[u8; 32], value: &Option<(u64, [u8; 32])>, digest: &Self::Digest, proof: &Self::LookupProof) -> Result<bool, Error> {
        SingleStepAVDWithHistory::<SSAVD, HTParams>::verify_lookup(
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
            .map(|epoch| self.history_ssavd.lookup_history(*epoch))
            .collect::<Result<Vec<(Digest<HTParams>, HistoryProof<SSAVD, HTParams>)>, Error>>()?
            .iter().cloned().unzip::<_, _, Vec<_>, Vec<_>>();
        Ok((
            self.history_ssavd.digest(),
            AuditProof {
                groth_proof: self.inner_proof.clone(),
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
                     SingleStepAVDWithHistory::<SSAVD, HTParams>::verify_history(
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



impl<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>
RecursionFullHistoryAVD<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>
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
            &self.outer_groth16_pp,
            OuterCircuit::<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>::new(
                self.inner_proof.clone(),
                InnerSingleStepProofVerifierInput {
                    new_digest: prev_digest.digest.clone(),
                    new_epoch: prev_digest.epoch,
                },
                self.inner_groth16_pp.vk.clone(),
            ),
            rng,
        )?;
        end_timer!(check);
        // Compute new inner proof
        let check = start_timer!(|| "Compute inner proof");
        let new_inner_proof = Groth16::<Cycle::E1>::prove(
            &self.inner_groth16_pp,
            InnerSingleStepProofCircuit::<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget>::new(
                false,
                &self.ssavd_pp,
                &self.history_ssavd.history_tree.tree.hash_parameters,
                update,
                self.outer_groth16_pp.vk.clone(),
                outer_proof,
            ),
            rng,
        )?;
        end_timer!(check);
        self.inner_proof = new_inner_proof.clone();
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

    use single_step_avd::{
        merkle_tree_avd::{
            MerkleTreeAVDParameters,
            MerkleTreeAVD,
            constraints::MerkleTreeAVDGadget,
        },
        rsa_avd::{
            RsaAVD, constraints::RsaAVDGadget,
        }
    };
    use crypto_primitives::{
        sparse_merkle_tree::MerkleDepth,
        hash::poseidon::{PoseidonSponge, constraints::PoseidonSpongeVar},
    };
    use rsa::{
        bignat::constraints::BigNatCircuitParams,
        kvac::RsaKVACParams,
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

    type TestMerkleTreeAVD = MerkleTreeAVD<MerkleTreeAVDTestParameters>;
    type TestMerkleTreeAVDGadget = MerkleTreeAVDGadget<MerkleTreeAVDTestParameters, HG, Fq>;

    type TestRecursionFHAVD = RecursionFullHistoryAVD<
        TestMerkleTreeAVD,
        TestMerkleTreeAVDGadget,
        MerkleTreeTestParameters,
        HG,
        MNT298Cycle,
        MNT4PairingVar,
        MNT6PairingVar,
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
    type PoseidonTestMerkleTreeAVD = MerkleTreeAVD<PoseidonMerkleTreeAVDTestParameters>;
    type PoseidonTestMerkleTreeAVDGadget = MerkleTreeAVDGadget<PoseidonMerkleTreeAVDTestParameters, PoseidonSpongeVar<Fq>, Fq>;

    type PoseidonTestRecursionFHAVD = RecursionFullHistoryAVD<
        PoseidonTestMerkleTreeAVD,
        PoseidonTestMerkleTreeAVDGadget,
        PoseidonMerkleTreeTestParameters,
        PoseidonSpongeVar<Fq>,
        MNT298Cycle,
        MNT4PairingVar,
        MNT6PairingVar,
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

    pub type TestRsaAVD = RsaAVD<
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        PoseidonH,
        BigNatTestParams,
    >;

    pub type TestRsaAVDGadget = RsaAVDGadget<
        Fq,
        TestKVACParams,
        HasherFromDigest<Fq, blake3::Hasher>,
        PoseidonH,
        PoseidonHG,
        BigNatTestParams,
    >;

    type TestRecursionRsaFHAVD = RecursionFullHistoryAVD<
        TestRsaAVD,
        TestRsaAVDGadget,
        MerkleTreeTestParameters,
        HG,
        MNT298Cycle,
        MNT4PairingVar,
        MNT6PairingVar,
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
        let pp = TestRecursionRsaFHAVD::setup(&mut rng).unwrap();
        let mut avd  = TestRecursionRsaFHAVD::new(&mut rng, &pp).unwrap();
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
        let verify_audit = TestRecursionRsaFHAVD::verify_audit(&pp, 0, 1, &d1, &audit_proof).unwrap();
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
        let verify_audit = TestRecursionRsaFHAVD::verify_audit(&pp, 1, 5, &d5, &audit_proof).unwrap();
        assert!(verify_audit);
    }
}