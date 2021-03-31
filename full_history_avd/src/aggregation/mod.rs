use single_step_avd::{
    SingleStepAVD,
    constraints::SingleStepAVDGadget,
};

use ark_crypto_primitives::{
    snark::{SNARK},
};
use ark_groth16::{
    Groth16,
    verifier::prepare_verifying_key,
};
use ark_ff::{
    ToConstraintField,
};
use ark_ec:: {
    PairingEngine,
};
use ark_ip_proofs::{
    tipa::{SRS},
};

use rand::{Rng, CryptoRng};

use digest::Digest as HashDigest;
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    marker::PhantomData,
    error::Error as ErrorTrait,
};
use crate::{
    FullHistoryAVD, Error,
    get_checkpoint_epochs,
};

pub mod constraints;
use constraints::{SingleStepProofCircuit, SingleStepProofVerifierInput};
pub mod groth16_aggregation;
use groth16_aggregation::*;


pub trait AggregatedFullHistoryAVDParameters {
    const MAX_EPOCH_LOG_2: u8;

    fn is_valid() -> Result<bool, Error> {
        //TODO: Only supports epoch in u64
        if Self::MAX_EPOCH_LOG_2 < 1 || Self::MAX_EPOCH_LOG_2 > 63 {
            return Err(Box::new(AggregatedFullHistoryAVDError::MaxEpochSize(Self::MAX_EPOCH_LOG_2)));
        }
        Ok(true)
    }
}


//TODO: Double storing SSAVD_pp (also stored in MerkleTreeAVD) since need for update
pub struct AggregatedFullHistoryAVD<Params, SSAVD, SSAVDGadget, Pairing, FastH>
where
    Params: AggregatedFullHistoryAVDParameters,
    SSAVD: SingleStepAVD,
    SSAVDGadget: SingleStepAVDGadget<SSAVD, Pairing::Fr>,
    Pairing: PairingEngine,
    FastH: HashDigest,
    SSAVD::Digest: ToConstraintField<Pairing::Fr>,
{
    ssavd: SSAVD,
    proofs: Vec<<Groth16<Pairing> as SNARK<Pairing::Fr>>::Proof>,
    aggregated_proofs: Vec<Vec<AggregateDigestProof<Pairing, FastH>>>,
    digests: Vec<SSAVD::Digest>,
    ssavd_pp: SSAVD::PublicParameters,
    groth16_pp: <Groth16<Pairing> as SNARK<Pairing::Fr>>::ProvingKey,
    ip_pp: SRS<Pairing>,
    _params: PhantomData<Params>,
    _ssavd_gadget: PhantomData<SSAVDGadget>,
}


//TODO: Can separate out verification parameters
//TODO: Can add genesis digest as constant to parameters instead of recalculating on verify
//TODO: Optimization: Groth16 and Inner Product public parameters may be shared
pub struct PublicParameters<SSAVD, Pairing>
    where
        SSAVD: SingleStepAVD,
        Pairing: PairingEngine,
        SSAVD::Digest: ToConstraintField<Pairing::Fr>,
{
    ssavd_pp: SSAVD::PublicParameters,
    groth16_pp: <Groth16<Pairing> as SNARK<Pairing::Fr>>::ProvingKey,
    ip_pp: SRS<Pairing>,
}

impl<SSAVD, Pairing> Clone for PublicParameters<SSAVD, Pairing>
    where
        SSAVD: SingleStepAVD,
        Pairing: PairingEngine,
        SSAVD::Digest: ToConstraintField<Pairing::Fr>,
{
    fn clone(&self) -> Self {
        Self {
            ssavd_pp: self.ssavd_pp.clone(),
            groth16_pp: self.groth16_pp.clone(),
            ip_pp: self.ip_pp.clone(),
        }
    }
}

pub enum CheckpointRangeProof<Pairing, FastH>
    where
        Pairing: PairingEngine,
        FastH: HashDigest,
{
    Single(<Groth16<Pairing> as SNARK<Pairing::Fr>>::Proof),
    Range(AggregateDigestProof<Pairing, FastH>),
}

pub struct AuditProof<SSAVD, Pairing, FastH>
    where
        SSAVD: SingleStepAVD,
        Pairing: PairingEngine,
        FastH: HashDigest,
        SSAVD::Digest: ToConstraintField<Pairing::Fr>,
{
    aggregated_proofs: Vec<CheckpointRangeProof<Pairing, FastH>>,
    checkpoint_digests: Vec<SSAVD::Digest>,
}



impl<Params, SSAVD, SSAVDGadget, Pairing, FastH> FullHistoryAVD for
AggregatedFullHistoryAVD<Params, SSAVD, SSAVDGadget, Pairing, FastH>
    where
        Params: AggregatedFullHistoryAVDParameters,
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, Pairing::Fr>,
        Pairing: PairingEngine,
        FastH: HashDigest,
        SSAVD::Digest: ToConstraintField<Pairing::Fr>,
{
    type Digest = SSAVD::Digest;
    type PublicParameters = PublicParameters<SSAVD, Pairing>;
    type LookupProof = SSAVD::LookupProof;
    type AuditProof = AuditProof<SSAVD, Pairing, FastH>;

    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self::PublicParameters, Error> {
        let ssavd_pp = SSAVD::setup(rng)?;
        let blank_circuit = SingleStepProofCircuit::<SSAVD, SSAVDGadget, Pairing::Fr>::blank(
            &ssavd_pp,
        );
        let (groth16_pp, _) = Groth16::<Pairing>::circuit_specific_setup::<
                SingleStepProofCircuit<SSAVD, SSAVDGadget, Pairing::Fr>, _
            >(blank_circuit, rng)?;
        let ip_pp = Self::setup_inner_product(rng, (1_u64 << (Params::MAX_EPOCH_LOG_2 as u64)) as usize)?;
        Ok(PublicParameters {
            ssavd_pp,
            groth16_pp,
            ip_pp,
        })
    }

    fn new<R: Rng + CryptoRng>(rng: &mut R, pp: &Self::PublicParameters) -> Result<Self, Error> {
        let ssavd = SSAVD::new(rng, &pp.ssavd_pp)?;
        let digests = vec![ssavd.digest()?];
        Ok(Self {
            ssavd: ssavd,
            proofs: Vec::new(),
            aggregated_proofs: Vec::new(),
            digests: digests,
            ssavd_pp: pp.ssavd_pp.clone(),
            groth16_pp: pp.groth16_pp.clone(),
            ip_pp: pp.ip_pp.clone(),
            _params: PhantomData,
            _ssavd_gadget: PhantomData,
        })
    }

    fn digest(&self) -> Result<Self::Digest, Error> {
        self.ssavd.digest()
    }

    fn lookup(&mut self, key: &[u8; 32]) -> Result<(Option<(u64, [u8; 32])>, Self::Digest, Self::LookupProof), Error> {
        self.ssavd.lookup(key)
    }

    fn update<R: Rng + CryptoRng>(&mut self, rng: &mut R, key: &[u8; 32], value: &[u8; 32]) -> Result<Self::Digest, Error> {
        if self.proofs.len() >= 1 << (Params::MAX_EPOCH_LOG_2 as u64) {
            return Err(Box::new(AggregatedFullHistoryAVDError::MaxEpochExceeded));
        }
        // Compute new step proof
        let (d, update) = self.ssavd.update(key, value)?;
        self._update(rng, update)?;
        Ok(d)
    }

    fn batch_update<R: Rng + CryptoRng>(&mut self, rng: &mut R, kvs: &Vec<([u8; 32], [u8; 32])>) -> Result<Self::Digest, Error> {
        if self.proofs.len() >= 1 << (Params::MAX_EPOCH_LOG_2 as u64) {
            return Err(Box::new(AggregatedFullHistoryAVDError::MaxEpochExceeded));
        }
        // Compute new step proof
        let (d, update) = self.ssavd.batch_update(kvs)?;
        self._update(rng, update)?;
        Ok(d)
    }

    fn verify_lookup(pp: &Self::PublicParameters, key: &[u8; 32], value: &Option<(u64, [u8; 32])>, digest: &Self::Digest, proof: &Self::LookupProof) -> Result<bool, Error> {
        SSAVD::verify_lookup(
            &pp.ssavd_pp,
            key,
            value,
            digest,
            proof,
        )
    }

    fn audit(
        &self,
        start_epoch: usize,
        end_epoch: usize,
    ) -> Result<(Self::Digest, Self::AuditProof), Error> {
        let (checkpoints, checkpoint_ranges) = get_checkpoint_epochs(start_epoch, end_epoch);
        let checkpoint_digests = checkpoints.iter()
            .map(|i| self.digests[*i].clone())
            .collect::<Vec<_>>();
        let range_proofs = checkpoints.iter().zip(&checkpoint_ranges)
            .map(|(ckpt, ckpt_level)| {
                match ckpt_level {
                    0 => CheckpointRangeProof::Single(self.proofs[*ckpt].clone()),
                    _ => CheckpointRangeProof::Range(self.aggregated_proofs[ckpt_level-1][ckpt >> ckpt_level].clone()),
                }
            }).collect::<Vec<_>>();
        Ok((
            self.digest()?,
            AuditProof {
                aggregated_proofs: range_proofs,
                checkpoint_digests: checkpoint_digests,
            },
        ))
    }

    fn verify_audit(
        pp: &Self::PublicParameters,
        start_epoch: usize,
        end_epoch: usize,
        _digest: &Self::Digest,
        proof: &Self::AuditProof,
    ) -> Result<bool, Error> {
        Ok(proof.aggregated_proofs.iter()
            .zip(get_checkpoint_epochs(start_epoch, end_epoch).1)
            .enumerate()
            .map(|(i, (range_proof, ckpt_level))| {
                match range_proof {
                    CheckpointRangeProof::Single(groth_proof) =>
                        Groth16::<Pairing>::verify_with_processed_vk(
                            &prepare_verifying_key(&pp.groth16_pp.vk),
                            &SingleStepProofVerifierInput::<SSAVD>{
                                prev_digest: proof.checkpoint_digests[i].clone(),
                                new_digest: proof.checkpoint_digests[i+1].clone(),
                            }.to_field_elements().unwrap(),
                            groth_proof,
                        ).unwrap(),
                    CheckpointRangeProof::Range(agg_proof) =>
                        Self::verify_aggregate_proof(
                            &pp.ip_pp.get_verifier_key(),
                            &pp.groth16_pp.vk,
                            &proof.checkpoint_digests[i].clone(),
                            &proof.checkpoint_digests[i+1].clone(),
                            &agg_proof,
                            1 << ckpt_level,
                        ).unwrap(),
                }
            }).all(|b| b)
        )
    }

}

impl<Params, SSAVD, SSAVDGadget, Pairing, FastH>
AggregatedFullHistoryAVD<Params, SSAVD, SSAVDGadget, Pairing, FastH>
    where
        Params: AggregatedFullHistoryAVDParameters,
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, Pairing::Fr>,
        Pairing: PairingEngine,
        FastH: HashDigest,
        SSAVD::Digest: ToConstraintField<Pairing::Fr>,
{
    fn _update<R: Rng + CryptoRng>(&mut self, rng: &mut R, update: SSAVD::UpdateProof)
        -> Result<(), Error> {
        let prev_digest = self.digests.last().unwrap().clone();
        let new_digest = self.digest()?;
        self.digests.push(new_digest.clone());

        let groth16_proof = Groth16::<Pairing>::prove(
            &self.groth16_pp,
            SingleStepProofCircuit::<SSAVD, SSAVDGadget, Pairing::Fr>::new(
                &self.ssavd_pp, update,
                SingleStepProofVerifierInput {
                    prev_digest: prev_digest,
                    new_digest: new_digest,
                },
            ),
            rng,
        )?;
        self.proofs.push(groth16_proof);

        // Compute aggregated proofs if necessary
        let new_epoch = self.proofs.len();
        let mut aggr_level = new_epoch.trailing_zeros() as usize;
        if aggr_level > self.aggregated_proofs.len() {
            self.aggregated_proofs.push(vec![]);
        }
        while aggr_level > 0 {  // Aggregate
            let start_epoch = new_epoch - (1 << aggr_level);
            let proof = self.aggregate_proofs(
                start_epoch,
                new_epoch,
            )?;
            self.aggregated_proofs[aggr_level - 1].push(proof);
            aggr_level -= 1;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum AggregatedFullHistoryAVDError {
    MaxEpochSize(u8),
    MaxEpochExceeded,
    Verification,
}

impl ErrorTrait for AggregatedFullHistoryAVDError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        None
    }
}

impl Display for AggregatedFullHistoryAVDError {
    fn fmt(self: &Self, f: &mut Formatter<'_>) -> FmtResult {
        let msg = match self {
            AggregatedFullHistoryAVDError::MaxEpochSize(h) => format!("max num epochs is invalid: {}", h),
            AggregatedFullHistoryAVDError::MaxEpochExceeded => "max num epochs exceeded".to_string(),
            AggregatedFullHistoryAVDError::Verification => "unexpected proof format for verification".to_string(),
        };
        write!(f, "{}", msg)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::{EdwardsProjective as JubJub, Fq, constraints::EdwardsVar};
    use ark_bls12_381::Bls12_381;
    use rand::{rngs::StdRng, SeedableRng};
    use ark_crypto_primitives::{
        crh::pedersen::{constraints::CRHGadget, CRH, Window},
    };
    use blake2::Blake2b;

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
    use crypto_primitives::sparse_merkle_tree::{MerkleDepth, MerkleTreeParameters};
    use rsa::{
        bignat::constraints::BigNatCircuitParams,
        kvac::RsaKVACParams,
        poker::{PoKERParams},
        hog::{RsaGroupParams},
        hash::{
            HasherFromDigest, PoseidonHasher, constraints::PoseidonHasherGadget,
        },
    };

    use std::time::Instant;

    #[derive(Clone)]
    pub struct Window4x256;

    impl Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type H = CRH<JubJub, Window4x256>;
    type HG = CRHGadget<JubJub, EdwardsVar, Window4x256>;

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

    #[derive(Clone)]
    pub struct AggregatedFHAVDTestParameters;

    impl AggregatedFullHistoryAVDParameters for AggregatedFHAVDTestParameters {
        const MAX_EPOCH_LOG_2: u8 = 8;
    }

    type TestAggregatedFHAVD = AggregatedFullHistoryAVD<
        AggregatedFHAVDTestParameters,
        TestMerkleTreeAVD,
        TestMerkleTreeAVDGadget,
        Bls12_381,
        Blake2b,
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
    type TestRsaAggregatedFHAVD = AggregatedFullHistoryAVD<
        AggregatedFHAVDTestParameters,
        TestRsaAVD,
        TestRsaAVDGadget,
        Bls12_381,
        Blake2b,
    >;


    #[test]
    #[ignore] // Expensive test, run with ``cargo test mt_update_and_verify_aggregated_full_history_test --release -- --ignored --nocapture``
    fn mt_update_and_verify_aggregated_full_history_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let start = Instant::now();
        let pp = TestAggregatedFHAVD::setup(&mut rng).unwrap();
        let mut avd: TestAggregatedFHAVD = TestAggregatedFHAVD::new(&mut rng, &pp).unwrap();
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
        let verify_audit = TestAggregatedFHAVD::verify_audit(&pp, 0, 1, &d1, &audit_proof).unwrap();
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
        let verify_audit = TestAggregatedFHAVD::verify_audit(&pp, 2, 5, &d5, &audit_proof).unwrap();
        assert!(verify_audit);
    }

    #[test]
    #[ignore] // Expensive test, run with ``cargo test rsa_update_and_verify_aggregated_full_history_test --release -- --ignored --nocapture``
    fn rsa_update_and_verify_aggregated_full_history_test() {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let start = Instant::now();
        let pp = TestRsaAggregatedFHAVD::setup(&mut rng).unwrap();
        let mut avd  = TestRsaAggregatedFHAVD::new(&mut rng, &pp).unwrap();
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
        let verify_audit = TestRsaAggregatedFHAVD::verify_audit(&pp, 0, 1, &d1, &audit_proof).unwrap();
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
        let verify_audit = TestRsaAggregatedFHAVD::verify_audit(&pp, 1, 5, &d5, &audit_proof).unwrap();
        assert!(verify_audit);
    }
}
