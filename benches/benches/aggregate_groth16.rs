#![allow(deprecated)]
use ark_ed_on_bls12_381::{Fq as BLS381Fr, EdwardsProjective, constraints::EdwardsVar};
use ark_bls12_381::Bls12_381;
use ark_ff::{PrimeField, ToConstraintField};
use ark_ec::{PairingEngine};
use ark_crypto_primitives::{
    crh::pedersen::{constraints::CRHGadget, CRH, Window},
    snark::{SNARK},
};
use ark_r1cs_std::{prelude::*};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
};
use ark_groth16::{Groth16};
use ark_ip_proofs::{tipa::{SRS}};

use single_step_avd::{
    SingleStepAVD, constraints::SingleStepAVDGadget,
    merkle_tree_avd::{
        MerkleTreeAVD, MerkleTreeAVDParameters, constraints::MerkleTreeAVDGadget,
    },
    rsa_avd::{
        RsaAVD, constraints::RsaAVDGadget,
    }
};
use crypto_primitives::{
    sparse_merkle_tree::{MerkleDepth, MerkleTreeParameters},
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
use full_history_avd::{
    FullHistoryAVD,
    aggregation::{AggregatedFullHistoryAVD, AggregatedFullHistoryAVDParameters},
};

use rand::{rngs::StdRng, SeedableRng};
use digest::Digest as HashDigest;
use csv::Writer;

use std::{
    string::String,
    io::stdout,
    time::{Instant},
    marker::PhantomData,
};


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
    const DEPTH: MerkleDepth = 32;
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
type TestMerkleTreeAVDGadget = MerkleTreeAVDGadget<MerkleTreeAVDTestParameters, HG, BLS381Fr>;


#[derive(Clone)]
pub struct PoseidonMerkleTreeTestParameters;

impl MerkleTreeParameters for PoseidonMerkleTreeTestParameters {
    const DEPTH: MerkleDepth = 4;
    type H = PoseidonSponge<BLS381Fr>;
}

#[derive(Clone)]
pub struct PoseidonMerkleTreeAVDTestParameters;

impl MerkleTreeAVDParameters for PoseidonMerkleTreeAVDTestParameters {
    const MAX_UPDATE_BATCH_SIZE: u64 = 3;
    const MAX_OPEN_ADDRESSING_PROBES: u8 = 2;
    type MerkleTreeParameters = PoseidonMerkleTreeTestParameters;
}
type PoseidonTestMerkleTreeAVD = MerkleTreeAVD<PoseidonMerkleTreeAVDTestParameters>;
type PoseidonTestMerkleTreeAVDGadget = MerkleTreeAVDGadget<PoseidonMerkleTreeAVDTestParameters, PoseidonSpongeVar<BLS381Fr>, BLS381Fr>;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestRsaParams;

impl RsaGroupParams for TestRsaParams {
    const RAW_G: usize = 2;
    const RAW_M: &'static str = "2519590847565789349402718324004839857142928212620403202777713783604366202070\
                          7595556264018525880784406918290641249515082189298559149176184502808489120072\
                          8449926873928072877767359714183472702618963750149718246911650776133798590957\
                          0009733045974880842840179742910064245869181719511874612151517265463228221686\
                          9987549182422433637259085141865462043576798423387184774447920739934236584823\
                          8242811981638150106748104516603773060562016196762561338441436038339044149526\
                          3443219011465754445417842402092461651572335077870774981712577246796292638635\
                          6373289912154831438167899885040445364023527381951378636564391212010397122822\
                          120720357";
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BigNatTestParams;

impl BigNatCircuitParams for BigNatTestParams {
    const LIMB_WIDTH: usize = 32;
    const N_LIMBS: usize = 64;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestPokerParams;

impl PoKERParams for TestPokerParams {
    const HASH_TO_PRIME_ENTROPY: usize = 128;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestKVACParams;

impl RsaKVACParams for TestKVACParams {
    const KEY_LEN: usize = 256;
    const VALUE_LEN: usize = 256;
    const PRIME_LEN: usize = 264;
    type RsaGroupParams = TestRsaParams;
    type PoKERParams = TestPokerParams;
}

#[derive(Clone)]
pub struct AggregatedFHAVDTestParameters;

impl AggregatedFullHistoryAVDParameters for AggregatedFHAVDTestParameters {
    const MAX_EPOCH_LOG_2: u8 = 32;
}

pub type TestRsaAVD<F> = RsaAVD<
    TestKVACParams,
    HasherFromDigest<BLS381Fr, blake3::Hasher>,
    PoseidonHasher<F>,
    BigNatTestParams,
>;

pub type TestRsaAVDGadget<F> = RsaAVDGadget<
    F,
    TestKVACParams,
    HasherFromDigest<BLS381Fr, blake3::Hasher>,
    PoseidonHasher<F>,
    PoseidonHasherGadget<F>,
    BigNatTestParams,
>;


pub struct DummyCircuit<SSAVD, SSAVDGadget, ConstraintF>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        ConstraintF: PrimeField,
{
    _ssavd: PhantomData<SSAVD>,
    _ssavd_gadget: PhantomData<SSAVDGadget>,
    _field: PhantomData<ConstraintF>,
}

pub struct VerifierInput<SSAVD: SingleStepAVD> {
    _ssavd: PhantomData<SSAVD>,
}

impl<SSAVD, SSAVDGadget, ConstraintF> ConstraintSynthesizer<ConstraintF> for DummyCircuit<SSAVD, SSAVDGadget, ConstraintF>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        ConstraintF: PrimeField,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let d = SSAVD::Digest::default();
        let d1 = SSAVDGadget::DigestVar::new_input(
            ark_relations::ns!(cs, "prev_digest"),
            || Ok(&d),
        )?;
        let d2 = SSAVDGadget::DigestVar::new_input(
            ark_relations::ns!(cs, "new_digest"),
            || Ok(&d),
        )?;
        d1.enforce_equal(&d2)?;
        Ok(())
    }
}

impl<SSAVD, SSAVDGadget, ConstraintF> Default for DummyCircuit<SSAVD, SSAVDGadget, ConstraintF>
    where
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, ConstraintF>,
        ConstraintF: PrimeField,
{
    fn default() -> Self {
        Self { _ssavd: PhantomData, _ssavd_gadget: PhantomData, _field: PhantomData }
    }
}


impl <SSAVD, ConstraintF> ToConstraintField<ConstraintF> for VerifierInput<SSAVD>
    where
        SSAVD: SingleStepAVD,
        ConstraintF: PrimeField,
        SSAVD::Digest: ToConstraintField<ConstraintF>,
{
    fn to_field_elements(&self) -> Option<Vec<ConstraintF>> {
        let mut v = Vec::new();
        v.extend_from_slice(&SSAVD::Digest::default().to_field_elements().unwrap_or_default());
        v.extend_from_slice(&SSAVD::Digest::default().to_field_elements().unwrap_or_default());
        Some(v)
    }
}

impl <SSAVD: SingleStepAVD> Clone for VerifierInput<SSAVD> {
    fn clone(&self) -> Self {
        Self { _ssavd: PhantomData }
    }
}

impl <SSAVD: SingleStepAVD> Default for VerifierInput<SSAVD> {
    fn default() -> Self {
        Self { _ssavd: PhantomData }
    }
}


fn benchmark<Params, SSAVD, SSAVDGadget, Pairing, FastH>
(
    scheme_name: String,
    range_lengths: &Vec<usize>,
    cores: &Vec<usize>,
)
    where
        Params: AggregatedFullHistoryAVDParameters,
        SSAVD: SingleStepAVD,
        SSAVDGadget: SingleStepAVDGadget<SSAVD, Pairing::Fr>,
        Pairing: PairingEngine,
        FastH: HashDigest,
        SSAVD::Digest: ToConstraintField<Pairing::Fr>,
{
    let mut rng = StdRng::seed_from_u64(0_u64);
    let mut csv_writer = Writer::from_writer(stdout());
    csv_writer
        .write_record(&["scheme", "operation", "log_range_size", "num_cores", "time"])
        .unwrap();
    csv_writer.flush().unwrap();

    let max_range = range_lengths.iter().max().cloned().unwrap();

    let mut pp = Option::None;
    { // Setup
        let setup_pool = rayon::ThreadPoolBuilder::new().num_threads(num_cpus::get_physical()).build().unwrap();
        setup_pool.install(|| {
            let ip_pp = AggregatedFullHistoryAVD::<Params, SSAVD, SSAVDGadget, Pairing, FastH>::setup_inner_product(&mut rng, (1_u64 << (max_range as u64)) as usize).unwrap();
            let (groth16_pp, groth16_vk) = Groth16::<Pairing>::circuit_specific_setup::<DummyCircuit<SSAVD, SSAVDGadget, Pairing::Fr>, _>(Default::default(), &mut rng).unwrap();

            let groth16_proof = Groth16::<Pairing>::prove(
                &groth16_pp,
                DummyCircuit::<SSAVD, SSAVDGadget, Pairing::Fr>::default(),
                &mut rng,
            ).unwrap();
            pp = Some((ip_pp, groth16_pp, groth16_vk, groth16_proof));
        });
    }

    { // Update
        let (ip_pp, _groth16_pp, groth16_vk, groth16_proof) = pp.unwrap();

        for log_len in range_lengths.iter() {
            let len = 1_usize << *log_len;
            let proofs = vec![groth16_proof.clone(); len];
            let ip_srs = SRS{
                g_alpha_powers: ip_pp.g_alpha_powers[0..(2*len - 1)].to_vec(),
                h_beta_powers: ip_pp.h_beta_powers[0..(2*len - 1)].to_vec(),
                g_beta: ip_pp.g_beta.clone(),
                h_alpha: ip_pp.h_alpha.clone(),
            };
            let kzg_srs = &ip_srs.g_alpha_powers[0..len];
            let (mut ck_1, mut ck_2) = ip_pp.get_commitment_keys();
            ck_1.truncate(len);
            ck_2.truncate(len);
            let v_srs = ip_srs.get_verifier_key();

            for num_cores in cores.iter() {
                if *num_cores > num_cpus::get_physical() {
                    continue;
                }
                let update_pool = rayon::ThreadPoolBuilder::new().num_threads(*num_cores as usize).build().unwrap();
                update_pool.install(|| {
                    let digests = vec![<AggregatedFullHistoryAVD::<Params, SSAVD, SSAVDGadget, Pairing, FastH> as FullHistoryAVD>::Digest::default(); len];
                    let start = Instant::now();
                    let agg_proof = AggregatedFullHistoryAVD::<Params, SSAVD, SSAVDGadget, Pairing, FastH>::_aggregate_proofs(
                        &ip_srs, kzg_srs, &ck_1, &ck_2, &proofs, &digests).unwrap();
                    let end = start.elapsed().as_secs();
                    csv_writer.write_record(&[
                        scheme_name.clone(),
                        "aggregate".to_string(),
                        log_len.to_string(),
                        num_cores.to_string(),
                        end.to_string(),
                    ]).unwrap();
                    csv_writer.flush().unwrap();

                    let start = Instant::now();
                    let _ = AggregatedFullHistoryAVD::<Params, SSAVD, SSAVDGadget, Pairing, FastH>::verify_aggregate_proof(
                        &v_srs, &groth16_vk, &Default::default(), &Default::default(), &agg_proof, len as u64).unwrap();
                    let end = start.elapsed().as_millis();
                    csv_writer.write_record(&[
                        scheme_name.clone(),
                        "verify".to_string(),
                        log_len.to_string(),
                        num_cores.to_string(),
                        end.to_string(),
                    ]).unwrap();
                    csv_writer.flush().unwrap();
                });
            }
        }
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    if args.last().unwrap() == "--bench" {
        args.pop();
    }
    let (mut range_lengths, mut num_cores): (Vec<usize>, Vec<usize>) = if args.len() > 1 && (args[1] == "-h" || args[1] == "--help")
    {
        println!("Usage: ``cargo bench --bench aggregate_groth16 --  [--ranges <RANGE_LEN>...][--num_cores <NUM_CORES>...]``");
        return;
    } else {
        let mut args = args.into_iter().skip(1);
        let mut next_arg = args.next();
        let mut range_lengths = vec![];
        let mut num_cores = vec![];
        while let Some(arg) = next_arg.clone() {
            match arg.as_str() {
                "--ranges" => {
                    next_arg = args.next();
                    'subargs: while let Some(subarg) = next_arg.clone() {
                        match subarg.parse::<usize>() {
                            Ok(range) => range_lengths.push(range),
                            Err(_) => break 'subargs,
                        }
                        next_arg = args.next();
                    }
                },
                "--num_cores" => {
                    next_arg = args.next();
                    'num_cores: while let Some(cores_arg) = next_arg.clone() {
                        match cores_arg.parse::<usize>() {
                            Ok(cores) => num_cores.push(cores),
                            Err(_) => break 'num_cores,
                        }
                        next_arg = args.next();
                    }
                },
                _ => {
                    println!("Invalid argument: {}", arg);
                    return
                }
            }
        }
        (range_lengths, num_cores)
    };
    if range_lengths.len() == 0 {
        range_lengths.push(5);
    }
    if num_cores.len() == 0 {
        num_cores.push(num_cpus::get_physical());
    }

    benchmark::<
        AggregatedFHAVDTestParameters,
        TestMerkleTreeAVD,
        TestMerkleTreeAVDGadget,
        Bls12_381,
        blake3::Hasher,
    >(
        "ca_mt_pedersen_aggr".to_string(),
        &range_lengths,
        &num_cores,
    );
    benchmark::<
        AggregatedFHAVDTestParameters,
        PoseidonTestMerkleTreeAVD,
        PoseidonTestMerkleTreeAVDGadget,
        Bls12_381,
        blake3::Hasher,
    >(
        "ca_mt_poseidon_aggr".to_string(),
        &range_lengths,
        &num_cores,
    );
    benchmark::<
        AggregatedFHAVDTestParameters,
        TestRsaAVD<BLS381Fr>,
        TestRsaAVDGadget<BLS381Fr>,
        Bls12_381,
        blake3::Hasher,
    >(
        "ca_rsa_aggr".to_string(),
        &range_lengths,
        &num_cores,
    );
}
