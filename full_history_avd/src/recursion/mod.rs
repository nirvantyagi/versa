use single_step_avd::{
    SingleStepAVD,
    constraints::SingleStepAVDGadget,
};
use crypto_primitives::sparse_merkle_tree::{MerkleTreeParameters};

use zexe_cp::{
    crh::{FixedLengthCRH, FixedLengthCRHGadget},
    nizk::{groth16::Groth16, NIZK},
};
use groth16::verifier::prepare_verifying_key;
use algebra::{
    curves::{CycleEngine, PairingEngine},
    ToConstraintField,
};
use r1cs_std::pairing::PairingVar;
use ip_proofs::{
    tipa::{SRS},
};

use rand::{Rng, rngs::mock::StepRng};

use digest::Digest as HashDigest;
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    marker::PhantomData,
    error::Error as ErrorTrait,
};
use crate::{
    history_tree::{SingleStepAVDWithHistory, Digest, LookupProof, HistoryProof, SingleStepUpdateProof},
    FullHistoryAVD, Error,
};

pub mod constraints;
use constraints::{
    InnerSingleStepProofCircuit, InnerSingleStepProofVerifierInput,
    //OuterCircuit, OuterVerifierInput,
};

/*
//TODO: Double storing SSAVD_pp (also stored in MerkleTreeAVD) since need for update
pub struct RecursionFullHistoryAVD<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, E1Gadget, E2Gadget, FastH>
where
    SSAVD: SingleStepAVD,
    SSAVDGadget: SingleStepAVDGadget<SSAVD, Cycle::E1::Fr>,
    HTParams: MerkleTreeParameters,
    HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, Cycle::E1::Fr>,
    Cycle: CycleEngine,
    E1Gadget: PairingVar<Cycle::E1, Cycle::E1::Fq>,
    E2Gadget: PairingVar<Cycle::E2, Cycle::E2::Fq>,
    FastH: HashDigest,
    <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<Cycle::E1::Fr>,
{
    history_ssavd: SingleStepAVDWithHistory<SSAVD, HTParams>,
    inner_proof: <Groth16<
            Cycle::E1::Fr,
            InnerSingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle::E1::Fr>,
            InnerSingleStepProofVerifierInput<HTParams>,
            > as NIZK
        >::Proof,
    digests: Vec<<<HTParams as MerkleTreeParameters>::H as FixedLengthCRH>::Output>,
    digest_openings: Vec<(SSAVD::Digest, <HTParams::H as FixedLengthCRH>::Output)>,
    ssavd_pp: SSAVD::PublicParameters,
    inner_groth16_pp: <Groth16<
        Cycle::E1,
        InnerSingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle::E1::Fr>,
        InnerSingleStepProofVerifierInput<HTParams>,
    > as NIZK>::ProvingParameters,
    outer_groth16_pp: <Groth16<
        Cycle::E2,
        OuterProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle::E2::Fr>,
        OuterProofVerifierInput<HTParams>,
    > as NIZK>::ProvingParameters,
}


//TODO: Can separate out verification parameters
//TODO: Can add genesis digest as constant to parameters instead of recalculating on verify
//TODO: Optimization: Groth16 and Inner Product public parameters may be shared
pub struct PublicParameters<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, Cycle::E1::Fr>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, Cycle::E1::Fr>,
        Cycle: CycleEngine,
        <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<Cycle::E1::Fr>,
{
    ssavd_pp: SSAVD::PublicParameters,
    history_tree_pp: <HTParams::H as FixedLengthCRH>::Parameters,
    inner_groth16_pp: <Groth16<
        Cycle::E1,
        InnerSingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle::E1::Fr>,
        InnerSingleStepProofVerifierInput<HTParams>,
    > as NIZK>::ProvingParameters,
    outer_groth16_pp: <Groth16<
        Cycle::E2,
        OuterProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle::E2::Fr>,
        OuterProofVerifierInput<HTParams>,
    > as NIZK>::ProvingParameters,
}

impl<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle> Clone for PublicParameters<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, Cycle::E1::Fr>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, Cycle::E1::Fr>,
        Cycle: CycleEngine,
        <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<Cycle::E1::Fr>,
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


impl<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, FastH> FullHistoryAVD for
RecursionFullHistoryAVD<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle, FastH>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, Cycle::E1::Fr>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, Cycle::E1::Fr>,
        Cycle: CycleEngine,
        FastH: HashDigest,
        <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<Cycle::E1::Fr>,
{
    type Digest = Digest<HTParams>;
    type PublicParameters = PublicParameters<SSAVD, SSAVDGadget, HTParams, HGadget, Pairing>;
    type LookupProof = LookupProof<SSAVD, HTParams>;
    type HistoryProof = HistoryProof<SSAVD, HTParams>;
    type DigestProof = <Groth16<
            Cycle::E1::Fr,
            InnerSingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle::E1::Fr>,
            InnerSingleStepProofVerifierInput<HTParams>,
        > as NIZK>::Proof;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::PublicParameters, Error> {
        let (ssavd_pp, history_tree_pp) = SingleStepAVDWithHistory::<SSAVD, HTParams>::setup(rng)?;
        let inner_blank_circuit = InnerSingleStepProofCircuit::<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle::E1::Fr>::blank(
            &ssavd_pp,
            &history_tree_pp,
        );
        let (inner_groth16_pp, _) = Groth16::<
            Cycle::E1,
            InnerSingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle::E1::Fr>,
            InnerSingleStepProofVerifierInput<HTParams>,
        >::setup(blank_circuit, rng)?;
        let outer_blank_circuit = OuterProofCircuit::<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle::E2::Fr>::blank(
            &ssavd_pp,
            &history_tree_pp,
        );
        let (outer_groth16_pp, _) = Groth16::<
            Cycle::E2,
            OuterProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Cycle::E2::Fr>,
            OuterProofVerifierInput<HTParams>,
        >::setup(blank_circuit, rng)?;
        Ok(PublicParameters {
            ssavd_pp,
            history_tree_pp,
            inner_groth16_pp,
            outer_groth16_pp,
        })
    }

    fn new<R: Rng>(rng: &mut R, pp: &Self::PublicParameters) -> Result<Self, Error> {
        let history_ssavd = SingleStepAVDWithHistory::<SSAVD, HTParams>::new(rng, &pp.ssavd_pp, &pp.history_tree_pp)?;
        let digests = vec![history_ssavd.digest().digest];
        let digest_openings = vec![(history_ssavd.ssavd.digest()?, history_ssavd.history_tree.tree.root.clone())];
        Ok(Self {
            history_ssavd: history_ssavd,
            proofs: Vec::new(),
            aggregated_proofs: Vec::new(),
            digests: digests,
            digest_openings: digest_openings,
            ssavd_pp: pp.ssavd_pp.clone(),
            groth16_pp: pp.groth16_pp.clone(),
            ip_pp: pp.ip_pp.clone(),
            _params: PhantomData,
        })
    }

    fn digest(&self) -> Result<Self::Digest, Error> {
        Ok(self.history_ssavd.digest())
    }

    fn lookup(&self, key: &[u8; 32]) -> Result<(Option<(u64, [u8; 32])>, Self::Digest, Self::LookupProof), Error> {
        let (value, proof) = self.history_ssavd.lookup(key)?;
        Ok((value, self.digest()?, proof))
    }

    fn update<R: Rng>(&mut self, rng: &mut R, key: &[u8; 32], value: &[u8; 32]) -> Result<(Self::Digest, Self::DigestProof), Error> {
        if self.digest()?.epoch >= 1_u64 << (Params::MAX_EPOCH_LOG_2 as u64) {
            return Err(Box::new(AggregatedFullHistoryAVDError::MaxEpochExceeded));
        }
        // Compute new step proof
        let update = self.history_ssavd.update(key, value)?;
        self._update(rng, update)
    }

    fn batch_update<R: Rng>(&mut self, rng: &mut R, kvs: &Vec<([u8; 32], [u8; 32])>) -> Result<(Self::Digest, Self::DigestProof), Error> {
        if self.digest()?.epoch >= 1_u64 << (Params::MAX_EPOCH_LOG_2 as u64) {
            return Err(Box::new(AggregatedFullHistoryAVDError::MaxEpochExceeded));
        }
        // Compute new step proof
        let update = self.history_ssavd.batch_update(kvs)?;
        self._update(rng, update)
    }


    fn verify_digest(pp: &Self::PublicParameters, digest: &Self::Digest, proof: &Self::DigestProof) -> Result<bool, Error> {
        let epoch = digest.epoch;
        let mut proof_counter = 0;
        //TODO: Assumes new AVD initialization is deterministic with dummy Rng
        let mut prev_digest =
            SingleStepAVDWithHistory::<SSAVD, HTParams>::new(&mut StepRng::new(1, 1), &pp.ssavd_pp, &pp.history_tree_pp)?
                .digest().digest;
        let mut prev_epoch = 0;
        let valid_aggregate_proofs = (1..Params::MAX_EPOCH_LOG_2).rev().map(|n| {
            if (epoch & (1 << n)) == (1 << n) {
                let aggregate_proof = &proof.aggregated_proofs[proof_counter];
                let proof_start_i = (epoch & (!0 << (n + 1))) as usize;
                let proof_end_i = proof_start_i + (1 << n);
                //println!("\t\t checking aggregate proof of size: {:?}: {}-{} epochs", n, proof_start_i, proof_end_i);
                let valid_trailing_epoch = proof_end_i as u64 == aggregate_proof.trailing_digest_opening.0;
                let valid_aggregate_proof = Self::verify_aggregate_proof(
                    &pp.history_tree_pp,
                    &pp.ip_pp.get_verifier_key(),
                    &pp.groth16_pp.vk,
                    &prev_digest,
                    aggregate_proof,
                    1 << n,
                )?;
                // Set up verification of next batch of proofs
                proof_counter += 1;
                prev_digest = aggregate_proof.trailing_digest.clone();
                prev_epoch = aggregate_proof.trailing_digest_opening.0;
                Ok(valid_trailing_epoch && valid_aggregate_proof)
            } else {
                Ok(true)
            }
        })
            .collect::<Result<Vec<bool>, Error>>()?
            .iter()
            .all(|b| *b);
        //TODO: May not be last epoch but second to last epoch
        let valid_last_epoch = if (epoch & 1) == 1 {
            let base_proof = proof.base_proof.as_ref().ok_or(Box::new(AggregatedFullHistoryAVDError::Verification))?;
            (epoch - 1 == prev_epoch) &&
                Groth16::<
                    Pairing,
                    SingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Pairing::Fr>,
                    SingleStepProofVerifierInput<HTParams>,
                >::verify(
                    &prepare_verifying_key(&pp.groth16_pp.vk),
                    &SingleStepProofVerifierInput{
                        prev_digest: prev_digest,
                        new_digest: digest.digest.clone(),
                    },
                    base_proof,
                )?
        } else {
            digest.digest == prev_digest
        };
        Ok(valid_aggregate_proofs && valid_last_epoch)
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

    fn lookup_history(&self, prev_digest: &Self::Digest) -> Result<(Self::Digest, Option<Self::HistoryProof>), Error> {
        Ok((self.digest()?, self.history_ssavd.lookup_history(prev_digest)?))
    }

    fn verify_history(pp: &Self::PublicParameters, prev_digest: &Self::Digest, current_digest: &Self::Digest, proof: &Self::HistoryProof) -> Result<bool, Error> {
        SingleStepAVDWithHistory::<SSAVD, HTParams>::verify_history(
            &pp.history_tree_pp,
            prev_digest,
            current_digest,
            proof,
        )
    }
}



impl<Params, SSAVD, SSAVDGadget, HTParams, HGadget, Pairing, FastH>
AggregatedFullHistoryAVD<Params, SSAVD, SSAVDGadget, HTParams, HGadget, Pairing, FastH>
    where
        Params: AggregatedFullHistoryAVDParameters,
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, Pairing::Fr>,
        HTParams: MerkleTreeParameters,
        HGadget: FixedLengthCRHGadget<<HTParams as MerkleTreeParameters>::H, Pairing::Fr>,
        Pairing: PairingEngine,
        FastH: HashDigest,
        <HTParams::H as FixedLengthCRH>::Output: ToConstraintField<Pairing::Fr>,
{
    fn _update<R: Rng>(&mut self, rng: &mut R, update: SingleStepUpdateProof<SSAVD, HTParams>)
        -> Result<(Digest<HTParams>, DigestProof<SSAVD, SSAVDGadget, HTParams, HGadget, Pairing, FastH>), Error> {
        let groth16_proof = Groth16::<
            Pairing,
            SingleStepProofCircuit<SSAVD, SSAVDGadget, HTParams, HGadget, Pairing::Fr>,
            SingleStepProofVerifierInput<HTParams>,
        >::prove(
            &self.groth16_pp,
            SingleStepProofCircuit::<SSAVD, SSAVDGadget, HTParams, HGadget, Pairing::Fr>::new(
                &self.ssavd_pp, &self.history_ssavd.history_tree.tree.hash_parameters, update,
            ),
            rng,
        )?;

        let base_proof = match (self.digest()?.epoch & 1) == 1 {
            true => Some(groth16_proof.clone()),
            false => None,
        };
        self.proofs.push(groth16_proof);
        self.digests.push(self.history_ssavd.digest().digest);
        //TODO: Optimization: Don't need to keep around all digest openings once it won't be a sentinel anymore
        self.digest_openings.push((self.history_ssavd.ssavd.digest()?, self.history_ssavd.history_tree.tree.root.clone()));

        // Compute necessary aggregated proofs
        let new_epoch = self.digest()?.epoch;
        let prev_proof_positions_aggregated = new_epoch - 1;
        for n in 1..Params::MAX_EPOCH_LOG_2 {
            match (
                (new_epoch & (1 << n)) == (1 << n),
                (prev_proof_positions_aggregated & (1 << n)) == (1 << n),
            ) {
                (false, true) => {
                    self.aggregated_proofs.pop();
                },
                (true, false) => {
                    // Create aggregate proof of proofs
                    // This case should be hit at most once and afterwards bits should be equal
                    let proof_start_i = (new_epoch & (!0 << (n + 1))) as usize;
                    let proof_end_i = proof_start_i + (1 << n);
                    //println!("\t\t creating aggregate proof of size: {:?}: {}-{} epochs", n, proof_start_i, proof_end_i);
                    let proof = self.aggregate_proofs(
                        proof_start_i,
                        proof_end_i
                    )?;
                    self.aggregated_proofs.push(proof);
                },
                _ => (), //TODO: Optimization: Can break early in this case
            }
        }
        Ok((
            self.digest()?,
            DigestProof {
                aggregated_proofs: self.aggregated_proofs.clone(),
                base_proof: base_proof,
            },
        ))
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
mod test {
    use super::*;
    use algebra::{
        ed_on_bls12_381::{EdwardsProjective as JubJub, Fq},
        bls12_381::Bls12_381,
    };
    use r1cs_std::{ed_on_bls12_381::EdwardsVar};
    use rand::{rngs::StdRng, SeedableRng};
    use zexe_cp::{
        crh::pedersen::{constraints::CRHGadget, CRH, Window},
    };
    use blake2::Blake2b;

    use single_step_avd::{
        merkle_tree_avd::{
            MerkleTreeAVDParameters,
            MerkleTreeAVD,
            constraints::MerkleTreeAVDGadget,
        },
    };
    use crypto_primitives::sparse_merkle_tree::MerkleDepth;
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
        MerkleTreeTestParameters,
        HG,
        Bls12_381,
        Blake2b,
    >;

    #[test]
    #[ignore] // Expensive test, run with ``cargo test update_and_verify_aggregated_full_history_test --release -- --ignored --nocapture``
    fn update_and_verify_aggregated_full_history_test() {
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
        let (d1, proof1) = avd.batch_update(&mut rng, &epoch1_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 1 proving time: {} s", bench);

        let start = Instant::now();
        let verify1 = TestAggregatedFHAVD::verify_digest(&pp, &d1, &proof1).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 1 verification time: {} s", bench);
        assert!(verify1);

        let start = Instant::now();
        let (d2, proof2) = avd.batch_update(&mut rng, &epoch2_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 2 proving time: {} s", bench);

        let start = Instant::now();
        let verify2 = TestAggregatedFHAVD::verify_digest(&pp, &d2, &proof2).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 2 verification time: {} s", bench);
        assert!(verify2);

        let start = Instant::now();
        let (d3, proof3) = avd.batch_update(&mut rng, &epoch3_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 3 proving time: {} s", bench);

        let start = Instant::now();
        let verify3 = TestAggregatedFHAVD::verify_digest(&pp, &d3, &proof3).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 3 verification time: {} s", bench);
        assert!(verify3);

        let start = Instant::now();
        let (d4, proof4) = avd.batch_update(&mut rng, &epoch4_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 4 proving time: {} s", bench);

        let start = Instant::now();
        let verify4 = TestAggregatedFHAVD::verify_digest(&pp, &d4, &proof4).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 4 verification time: {} s", bench);
        assert!(verify4);

        let start = Instant::now();
        let (d5, proof5) = avd.batch_update(&mut rng, &epoch5_update).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 5 proving time: {} s", bench);

        let start = Instant::now();
        let verify5 = TestAggregatedFHAVD::verify_digest(&pp, &d5, &proof5).unwrap();
        let bench = start.elapsed().as_secs();
        println!("\t epoch 5 verification time: {} s", bench);
        assert!(verify5);
    }
}
*/