#![allow(deprecated)]
use ark_ff::{PrimeField};
use ark_ed_on_mnt4_298::{EdwardsProjective, Fq as MNT4Fr, constraints::EdwardsVar};
use ark_mnt4_298::{MNT4_298, constraints::PairingVar as MNT4PairingVar};
use ark_mnt6_298::{MNT6_298, constraints::PairingVar as MNT6PairingVar};
use ark_ed_on_bls12_381::{Fq as BLS381Fr, EdwardsProjective as JubJub, constraints::EdwardsVar as JubJubVar};
use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{
    crh::pedersen::{constraints::CRHGadget, CRH, Window},
};
use ark_ec::{CycleEngine};

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
    sparse_merkle_tree::{MerkleDepth, MerkleTreeParameters},
    hash::poseidon::{PoseidonSponge, constraints::PoseidonSpongeVar},
};

use full_history_avd::{
    FullHistoryAVD,
    recursion::RecursionFullHistoryAVD,
    aggregation::{AggregatedFullHistoryAVD, AggregatedFullHistoryAVDParameters},
};

use rand::{rngs::StdRng, SeedableRng};
use csv::Writer;

use std::{
    string::String,
    io::stdout,
    time::{Instant},
    marker::PhantomData,
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
type JJH = CRH<JubJub, Window4x256>;
type JJHG = CRHGadget<JubJub, JubJubVar, Window4x256>;

#[derive(Clone)]
pub struct MerkleTreeTestParameters;

#[cfg(feature = "local")]
impl MerkleTreeParameters for MerkleTreeTestParameters {
    const DEPTH: MerkleDepth = 4;
    type H = H;
}

#[cfg(not(feature = "local"))]
impl MerkleTreeParameters for MerkleTreeTestParameters {
    const DEPTH: MerkleDepth = 32;
    type H = H;
}

#[derive(Clone)]
pub struct JubJubTreeTestParameters;

#[cfg(feature = "local")]
impl MerkleTreeParameters for JubJubTreeTestParameters {
    const DEPTH: MerkleDepth = 4;
    type H = JJH;
}

#[cfg(not(feature = "local"))]
impl MerkleTreeParameters for JubJubTreeTestParameters {
    const DEPTH: MerkleDepth = 32;
    type H = JJH;
}

#[derive(Clone)]
pub struct AggregatedFHAVDTestParameters;

#[cfg(feature = "local")]
impl AggregatedFullHistoryAVDParameters for AggregatedFHAVDTestParameters {
    const MAX_EPOCH_LOG_2: u8 = 8;
}

#[cfg(not(feature = "local"))]
impl AggregatedFullHistoryAVDParameters for AggregatedFHAVDTestParameters {
    const MAX_EPOCH_LOG_2: u8 = 32;
}


macro_rules! mt_pedersen_recurse_avd_impl {
    ($avd_params:ident, $avd:ident, $avd_gadget:ident, $fhavd:ident, $batch_size:expr) => {
        #[derive(Clone)]
        pub struct $avd_params;

        impl MerkleTreeAVDParameters for $avd_params {
            const MAX_UPDATE_BATCH_SIZE: u64 = $batch_size;
            const MAX_OPEN_ADDRESSING_PROBES: u8 = 16;
            type MerkleTreeParameters = MerkleTreeTestParameters;
        }

        type $avd = MerkleTreeAVD<$avd_params>;
        type $avd_gadget = MerkleTreeAVDGadget<$avd_params, HG, MNT4Fr>;

        type $fhavd = RecursionFullHistoryAVD<
            $avd,
            $avd_gadget,
            MerkleTreeTestParameters,
            HG,
            MNT298Cycle,
            MNT4PairingVar,
            MNT6PairingVar,
        >;
    };
}

macro_rules! mt_pedersen_aggr_avd_impl {
    ($avd_params:ident, $avd:ident, $avd_gadget:ident, $fhavd:ident, $batch_size:expr) => {
        #[derive(Clone)]
        pub struct $avd_params;

        impl MerkleTreeAVDParameters for $avd_params {
            const MAX_UPDATE_BATCH_SIZE: u64 = $batch_size;
            const MAX_OPEN_ADDRESSING_PROBES: u8 = 16;
            type MerkleTreeParameters = JubJubTreeTestParameters;
        }

        type $avd = MerkleTreeAVD<$avd_params>;
        type $avd_gadget = MerkleTreeAVDGadget<$avd_params, JJHG, BLS381Fr>;

        type $fhavd = AggregatedFullHistoryAVD<
            AggregatedFHAVDTestParameters,
            $avd,
            $avd_gadget,
            Bls12_381,
            blake3::Hasher,
        >;
    };
}


// Parameters for Merkle Tree AVD with Poseidon hash
#[derive(Clone)]
pub struct PoseidonMerkleTreeTestParameters<F: PrimeField>{
    _f: PhantomData<F>,
}

#[cfg(feature = "local")]
impl<F: PrimeField> MerkleTreeParameters for PoseidonMerkleTreeTestParameters<F> {
    const DEPTH: MerkleDepth = 4;
    type H = PoseidonSponge<F>;
}

#[cfg(not(feature = "local"))]
impl<F: PrimeField> MerkleTreeParameters for PoseidonMerkleTreeTestParameters<F> {
    const DEPTH: MerkleDepth = 4;
    type H = PoseidonSponge<F>;
}

macro_rules! mt_poseidon_avd_impl {
    ($avd_params:ident, $avd:ident, $avd_gadget:ident, $rfhavd:ident, $afhavd:ident, $batch_size:expr) => {
        #[derive(Clone)]
        pub struct $avd_params<F: PrimeField>{
            _f: PhantomData<F>,
        }

        impl<F: PrimeField> MerkleTreeAVDParameters for $avd_params<F> {
            const MAX_UPDATE_BATCH_SIZE: u64 = $batch_size;
            const MAX_OPEN_ADDRESSING_PROBES: u8 = 16;
            type MerkleTreeParameters = PoseidonMerkleTreeTestParameters<F>;
        }

        type $avd<F> = MerkleTreeAVD<$avd_params<F>>;
        type $avd_gadget<F> = MerkleTreeAVDGadget<$avd_params<F>, PoseidonSpongeVar<F>, F>;

        type $rfhavd = RecursionFullHistoryAVD<
            $avd<MNT4Fr>,
            $avd_gadget<MNT4Fr>,
            PoseidonMerkleTreeTestParameters<MNT4Fr>,
            PoseidonSpongeVar<MNT4Fr>,
            MNT298Cycle,
            MNT4PairingVar,
            MNT6PairingVar,
        >;

        type $afhavd = AggregatedFullHistoryAVD<
            AggregatedFHAVDTestParameters,
            $avd<BLS381Fr>,
            $avd_gadget<BLS381Fr>,
            Bls12_381,
            blake3::Hasher,
        >;
    };
}

// Type declarations and implementations for different batch sizes
mt_pedersen_recurse_avd_impl!(RPed3P, RPed3AVD, RPed3AVDG, PedersenRecurseBatch3, 3);
mt_pedersen_aggr_avd_impl!(APed3P, APed3AVD, APed3AVDG, PedersenAggrBatch3, 3);
mt_poseidon_avd_impl!(Pos3P, Pos3AVD, Pos3AVDG, PoseidonRecurseBatch3, PoseidonAggrBatch3, 3);

mt_pedersen_recurse_avd_impl!(RPed100P, RPed100AVD, RPed100AVDG, PedersenRecurseBatch100, 100);
mt_pedersen_aggr_avd_impl!(APed100P, APed100AVD, APed100AVDG, PedersenAggrBatch100, 100);
mt_poseidon_avd_impl!(Pos100P, Pos100AVD, Pos100AVDG, PoseidonRecurseBatch100, PoseidonAggrBatch100, 100);

fn benchmark<AVD: FullHistoryAVD, P: MerkleTreeAVDParameters>(
    scheme_name: String,
    cores: &Vec<usize>,
) {
    let mut rng = StdRng::seed_from_u64(0_u64);
    let mut csv_writer = Writer::from_writer(stdout());
    csv_writer
        .write_record(&["scheme", "operation", "batch_size", "num_cores", "time"])
        .unwrap();
    csv_writer.flush().unwrap();

    let mut pp = Option::None;
    { // Setup
        let setup_pool = rayon::ThreadPoolBuilder::new().num_threads(num_cpus::get_physical()).build().unwrap();
        setup_pool.install(|| {
            let start = Instant::now();
            pp = Some(AVD::setup(&mut rng).unwrap());
            let end = start.elapsed().as_secs();

            csv_writer.write_record(&[
                scheme_name.clone(),
                "setup".to_string(),
                "0".to_string(),
                setup_pool.current_num_threads().to_string(),
                end.to_string(),
            ]).unwrap();
            csv_writer.flush().unwrap();
        });
    }

    { // Update
        let mut epoch_update = vec![];
        for i in 0..P::MAX_UPDATE_BATCH_SIZE {
            let mut arr = [0_u8; 32];
            for (j, b) in (i as u32).to_be_bytes().iter().enumerate() {
                arr[28 + j] = b.clone();
            }
            epoch_update.push((arr.clone(), arr.clone()));
        }
        for num_cores in cores.iter() {
            if *num_cores > num_cpus::get_physical() {
                continue;
            }
            let update_pool = rayon::ThreadPoolBuilder::new().num_threads(*num_cores as usize).build().unwrap();
            update_pool.install(|| {
                let mut avd = AVD::new(&mut rng, &pp.clone().unwrap()).unwrap();
                let start = Instant::now();
                let d = avd.batch_update(&mut rng, &epoch_update).unwrap();
                let end = start.elapsed().as_secs();

                csv_writer.write_record(&[
                    scheme_name.clone(),
                    "update".to_string(),
                    P::MAX_UPDATE_BATCH_SIZE.to_string(),
                    num_cores.to_string(),
                    end.to_string(),
                ]).unwrap();
                csv_writer.flush().unwrap();

                let (_, proof) = avd.audit(0, 1).unwrap();
                let start = Instant::now();
                let b = AVD::verify_audit(
                    pp.as_ref().unwrap(), 0, 1, &d, &proof,
                ).unwrap();
                let end = start.elapsed().as_millis();
                assert!(b);
                csv_writer.write_record(&[
                    scheme_name.clone(),
                    "verify".to_string(),
                    P::MAX_UPDATE_BATCH_SIZE.to_string(),
                    num_cores.to_string(),
                    end.to_string(),
                ]).unwrap();
                csv_writer.flush().unwrap();
            });
        }
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    if args.last().unwrap() == "--bench" {
        args.pop();
    }
    let (mut batch_sizes, mut num_cores): (Vec<usize>, Vec<usize>) = if args.len() > 1 && (args[1] == "-h" || args[1] == "--help")
    {
        println!("Usage: ``cargo bench --bench update_epoch_0_rsa --  [--batch_size <batch_size1>...][--num_cores <num_cores1>...]``");
        return;
    } else {
        let mut args = args.into_iter().skip(1);
        let mut next_arg = args.next();
        let mut batch_sizes = vec![];
        let mut num_cores = vec![];
        while let Some(arg) = next_arg.clone() {
            match arg.as_str() {
                "--batch_size" => {
                    next_arg = args.next();
                    'batch_size: while let Some(batch_arg) = next_arg.clone() {
                        match batch_arg.parse::<usize>() {
                            Ok(batch_size) => batch_sizes.push(batch_size),
                            Err(_) => break 'batch_size,
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
        (batch_sizes, num_cores)
    };
    if batch_sizes.len() == 0 {
        if cfg!(feature = "local") {
            batch_sizes.push(3);
        } else {
            batch_sizes.push(100);
        }
    }
    if num_cores.len() == 0 {
        num_cores.push(num_cpus::get_physical());
    }

    for batch_size in batch_sizes.into_iter() {
        match batch_size {
            3 => {
                benchmark::<PedersenRecurseBatch3, RPed3P>(
                    "ca_mt_pedersen_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PedersenAggrBatch3, APed3P>(
                    "ca_mt_pedersen_aggr".to_string(),
                    &num_cores,
                );
                benchmark::<PoseidonRecurseBatch3, Pos3P<MNT4Fr>>(
                    "ca_mt_poseidon_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PoseidonAggrBatch3, Pos3P<BLS381Fr>>(
                    "ca_mt_poseidon_aggr".to_string(),
                    &num_cores,
                );
            },
            100 => {
                benchmark::<PedersenRecurseBatch100, RPed100P>(
                    "ca_mt_pedersen_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PedersenAggrBatch100, APed100P>(
                    "ca_mt_pedersen_aggr".to_string(),
                    &num_cores,
                );
                benchmark::<PoseidonRecurseBatch100, Pos100P<MNT4Fr>>(
                    "ca_mt_poseidon_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PoseidonAggrBatch100, Pos100P<BLS381Fr>>(
                    "ca_mt_poseidon_aggr".to_string(),
                    &num_cores,
                );
            },
            _ => println!("Batch size not supported: {}", batch_size),
        }
    }
}

