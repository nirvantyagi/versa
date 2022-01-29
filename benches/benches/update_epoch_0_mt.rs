#![allow(deprecated)]
use ark_ff::PrimeField;

#[cfg(feature = "local")]
use ark_ed_on_mnt4_298::{constraints::EdwardsVar, EdwardsProjective, Fq as MNT4Fr};
#[cfg(feature = "local")]
use ark_mnt4_298::{constraints::PairingVar as MNT4PairingVar, MNT4_298};
#[cfg(feature = "local")]
use ark_mnt6_298::{constraints::PairingVar as MNT6PairingVar, MNT6_298};

#[cfg(not(feature = "local"))]
use ark_ed_on_mnt4_753::{constraints::EdwardsVar, EdwardsProjective, Fq as MNT4Fr};
#[cfg(not(feature = "local"))]
use ark_mnt4_753::{constraints::PairingVar as MNT4PairingVar, MNT4_753};
#[cfg(not(feature = "local"))]
use ark_mnt6_753::{constraints::PairingVar as MNT6PairingVar, MNT6_753};

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::crh::pedersen::{constraints::CRHGadget, Window, CRH};
use ark_ec::CycleEngine;
use ark_ed_on_bls12_381::{
    constraints::EdwardsVar as JubJubVar, EdwardsProjective as JubJub, Fq as BLS381Fr,
};

use crypto_primitives::{
    hash::poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
    sparse_merkle_tree::{MerkleDepth, MerkleTreeParameters},
};
use single_step_avd::merkle_tree_avd::{
    constraints::MerkleTreeAVDGadget, MerkleTreeAVD, MerkleTreeAVDParameters,
};

use full_history_avd::{
    aggregation::{AggregatedFullHistoryAVD, AggregatedFullHistoryAVDParameters},
    recursion::RecursionFullHistoryAVD,
    FullHistoryAVD,
};

use csv::Writer;
use rand::{rngs::StdRng, SeedableRng};

use std::{io::stdout, marker::PhantomData, string::String, time::Instant};

#[derive(Clone, Copy, Debug)]
pub struct MNTCycle;

#[cfg(feature = "local")]
impl CycleEngine for MNTCycle {
    type E1 = MNT4_298;
    type E2 = MNT6_298;
}

#[cfg(not(feature = "local"))]
impl CycleEngine for MNTCycle {
    type E1 = MNT4_753;
    type E2 = MNT6_753;
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
    const MAX_EPOCH_LOG_2: u8 = 16;
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
            MNTCycle,
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
pub struct PoseidonMerkleTreeTestParameters<F: PrimeField> {
    _f: PhantomData<F>,
}

#[cfg(feature = "local")]
impl<F: PrimeField> MerkleTreeParameters for PoseidonMerkleTreeTestParameters<F> {
    const DEPTH: MerkleDepth = 4;
    type H = PoseidonSponge<F>;
}

#[cfg(not(feature = "local"))]
impl<F: PrimeField> MerkleTreeParameters for PoseidonMerkleTreeTestParameters<F> {
    const DEPTH: MerkleDepth = 32;
    type H = PoseidonSponge<F>;
}

macro_rules! mt_poseidon_avd_impl {
    ($avd_params:ident, $avd:ident, $avd_gadget:ident, $rfhavd:ident, $afhavd:ident, $batch_size:expr) => {
        #[derive(Clone)]
        pub struct $avd_params<F: PrimeField> {
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
            MNTCycle,
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
mt_pedersen_recurse_avd_impl!(RPed1P, RPed1AVD, RPed1AVDG, PedersenRecurseBatch1, 1);
mt_pedersen_aggr_avd_impl!(APed1P, APed1AVD, APed1AVDG, PedersenAggrBatch1, 1);
mt_poseidon_avd_impl!(
    Pos1P,
    Pos1AVD,
    Pos1AVDG,
    PoseidonRecurseBatch1,
    PoseidonAggrBatch1,
    1
);

mt_pedersen_recurse_avd_impl!(RPed50P, RPed50AVD, RPed50AVDG, PedersenRecurseBatch50, 50);
mt_pedersen_aggr_avd_impl!(APed50P, APed50AVD, APed50AVDG, PedersenAggrBatch50, 50);
//mt_poseidon_avd_impl!(Pos50P, Pos50AVD, Pos50AVDG, PoseidonRecurseBatch50, PoseidonAggrBatch50, 50);

mt_pedersen_recurse_avd_impl!(
    RPed100P,
    RPed100AVD,
    RPed100AVDG,
    PedersenRecurseBatch100,
    100
);
mt_pedersen_aggr_avd_impl!(APed100P, APed100AVD, APed100AVDG, PedersenAggrBatch100, 100);
//mt_poseidon_avd_impl!(Pos100P, Pos100AVD, Pos100AVDG, PoseidonRecurseBatch100, PoseidonAggrBatch100, 100);

mt_pedersen_recurse_avd_impl!(
    RPed150P,
    RPed150AVD,
    RPed150AVDG,
    PedersenRecurseBatch150,
    150
);
mt_pedersen_aggr_avd_impl!(APed150P, APed150AVD, APed150AVDG, PedersenAggrBatch150, 150);
//mt_poseidon_avd_impl!(Pos150P, Pos150AVD, Pos150AVDG, PoseidonRecurseBatch150, PoseidonAggrBatch150, 150);

mt_pedersen_recurse_avd_impl!(
    RPed200P,
    RPed200AVD,
    RPed200AVDG,
    PedersenRecurseBatch200,
    200
);
mt_pedersen_aggr_avd_impl!(APed200P, APed200AVD, APed200AVDG, PedersenAggrBatch200, 200);
//mt_poseidon_avd_impl!(Pos200P, Pos200AVD, Pos200AVDG, PoseidonRecurseBatch200, PoseidonAggrBatch200, 200);

//mt_pedersen_recurse_avd_impl!(RPed500P, RPed500AVD, RPed500AVDG, PedersenRecurseBatch500, 500);
//mt_pedersen_aggr_avd_impl!(APed500P, APed500AVD, APed500AVDG, PedersenAggrBatch500, 500);
mt_poseidon_avd_impl!(
    Pos500P,
    Pos500AVD,
    Pos500AVDG,
    PoseidonRecurseBatch500,
    PoseidonAggrBatch500,
    500
);

//mt_pedersen_recurse_avd_impl!(RPed1000P, RPed1000AVD, RPed1000AVDG, PedersenRecurseBatch1000, 1000);
//mt_pedersen_aggr_avd_impl!(APed1000P, APed1000AVD, APed1000AVDG, PedersenAggrBatch1000, 1000);
mt_poseidon_avd_impl!(
    Pos1000P,
    Pos1000AVD,
    Pos1000AVDG,
    PoseidonRecurseBatch1000,
    PoseidonAggrBatch1000,
    1000
);

//mt_pedersen_recurse_avd_impl!(RPed1500P, RPed1500AVD, RPed1500AVDG, PedersenRecurseBatch1500, 1500);
//mt_pedersen_aggr_avd_impl!(APed1500P, APed1500AVD, APed1500AVDG, PedersenAggrBatch1500, 1500);
mt_poseidon_avd_impl!(
    Pos1500P,
    Pos1500AVD,
    Pos1500AVDG,
    PoseidonRecurseBatch1500,
    PoseidonAggrBatch1500,
    1500
);

//mt_pedersen_recurse_avd_impl!(RPed2000P, RPed2000AVD, RPed2000AVDG, PedersenRecurseBatch2000, 2000);
//mt_pedersen_aggr_avd_impl!(APed2000P, APed2000AVD, APed2000AVDG, PedersenAggrBatch2000, 2000);
mt_poseidon_avd_impl!(
    Pos2000P,
    Pos2000AVD,
    Pos2000AVDG,
    PoseidonRecurseBatch2000,
    PoseidonAggrBatch2000,
    2000
);

//mt_pedersen_recurse_avd_impl!(RPed3000P, RPed3000AVD, RPed3000AVDG, PedersenRecurseBatch3000, 3000);
//mt_pedersen_aggr_avd_impl!(APed3000P, APed3000AVD, APed3000AVDG, PedersenAggrBatch3000, 3000);
mt_poseidon_avd_impl!(
    Pos3000P,
    Pos3000AVD,
    Pos3000AVDG,
    PoseidonRecurseBatch3000,
    PoseidonAggrBatch3000,
    3000
);

//mt_pedersen_recurse_avd_impl!(RPed4000P, RPed4000AVD, RPed4000AVDG, PedersenRecurseBatch4000, 4000);
//mt_pedersen_aggr_avd_impl!(APed4000P, APed4000AVD, APed4000AVDG, PedersenAggrBatch4000, 4000);
//mt_poseidon_avd_impl!(Pos4000P, Pos4000AVD, Pos4000AVDG, PoseidonRecurseBatch4000, PoseidonAggrBatch4000, 4000);

//mt_pedersen_recurse_avd_impl!(RPed5000P, RPed5000AVD, RPed5000AVDG, PedersenRecurseBatch5000, 5000);
//mt_pedersen_aggr_avd_impl!(APed5000P, APed5000AVD, APed5000AVDG, PedersenAggrBatch5000, 5000);
//mt_poseidon_avd_impl!(Pos5000P, Pos5000AVD, Pos5000AVDG, PoseidonRecurseBatch5000, PoseidonAggrBatch5000, 5000);

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
    {
        // Setup
        let setup_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_cpus::get_physical())
            .build()
            .unwrap();
        setup_pool.install(|| {
            let start = Instant::now();
            pp = Some(AVD::setup(&mut rng).unwrap());
            let end = start.elapsed().as_secs();

            csv_writer
                .write_record(&[
                    scheme_name.clone(),
                    "setup".to_string(),
                    "0".to_string(),
                    setup_pool.current_num_threads().to_string(),
                    end.to_string(),
                ])
                .unwrap();
            csv_writer.flush().unwrap();
        });
    }

    {
        // Update
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
            let update_pool = rayon::ThreadPoolBuilder::new()
                .num_threads(*num_cores as usize)
                .build()
                .unwrap();
            update_pool.install(|| {
                let mut avd = AVD::new(&mut rng, &pp.clone().unwrap()).unwrap();
                let start = Instant::now();
                let d = avd.batch_update(&mut rng, &epoch_update).unwrap();
                let end = start.elapsed().as_secs();

                csv_writer
                    .write_record(&[
                        scheme_name.clone(),
                        "update".to_string(),
                        P::MAX_UPDATE_BATCH_SIZE.to_string(),
                        num_cores.to_string(),
                        end.to_string(),
                    ])
                    .unwrap();
                csv_writer.flush().unwrap();

                let (_, proof) = avd.audit(0, 1).unwrap();
                let start = Instant::now();
                let b = AVD::verify_audit(pp.as_ref().unwrap(), 0, 1, &d, &proof).unwrap();
                let end = start.elapsed().as_millis();
                assert!(b);
                csv_writer
                    .write_record(&[
                        scheme_name.clone(),
                        "verify".to_string(),
                        P::MAX_UPDATE_BATCH_SIZE.to_string(),
                        num_cores.to_string(),
                        end.to_string(),
                    ])
                    .unwrap();
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
    let (mut batch_sizes, mut num_cores): (Vec<usize>, Vec<usize>) = if args.len() > 1
        && (args[1] == "-h" || args[1] == "--help")
    {
        println!("Usage: ``cargo bench --bench update_epoch_0_mt --  [--batch_size <batch_size1>...][--num_cores <num_cores1>...]``");
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
                }
                "--num_cores" => {
                    next_arg = args.next();
                    'num_cores: while let Some(cores_arg) = next_arg.clone() {
                        match cores_arg.parse::<usize>() {
                            Ok(cores) => num_cores.push(cores),
                            Err(_) => break 'num_cores,
                        }
                        next_arg = args.next();
                    }
                }
                _ => {
                    println!("Invalid argument: {}", arg);
                    return;
                }
            }
        }
        (batch_sizes, num_cores)
    };
    if batch_sizes.len() == 0 {
        if cfg!(feature = "local") {
            batch_sizes.push(1);
        } else {
            batch_sizes.push(100);
        }
    }
    if num_cores.len() == 0 {
        num_cores.push(num_cpus::get_physical());
    }

    for batch_size in batch_sizes.into_iter() {
        match batch_size {
            1 => {
                benchmark::<PedersenRecurseBatch1, RPed1P>(
                    "ca_mt_pedersen_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PedersenAggrBatch1, APed1P>(
                    "ca_mt_pedersen_aggr".to_string(),
                    &num_cores,
                );
                benchmark::<PoseidonRecurseBatch1, Pos1P<MNT4Fr>>(
                    "ca_mt_poseidon_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PoseidonAggrBatch1, Pos1P<BLS381Fr>>(
                    "ca_mt_poseidon_aggr".to_string(),
                    &num_cores,
                );
            }
            50 => {
                benchmark::<PedersenRecurseBatch50, RPed50P>(
                    "ca_mt_pedersen_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PedersenAggrBatch50, APed50P>(
                    "ca_mt_pedersen_aggr".to_string(),
                    &num_cores,
                );
                //benchmark::<PoseidonRecurseBatch50, Pos50P<MNT4Fr>>(
                //    "ca_mt_poseidon_recurse".to_string(),
                //    &num_cores,
                //);
                //benchmark::<PoseidonAggrBatch50, Pos50P<BLS381Fr>>(
                //    "ca_mt_poseidon_aggr".to_string(),
                //    &num_cores,
                //);
            }
            100 => {
                benchmark::<PedersenRecurseBatch100, RPed100P>(
                    "ca_mt_pedersen_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PedersenAggrBatch100, APed100P>(
                    "ca_mt_pedersen_aggr".to_string(),
                    &num_cores,
                );
                //benchmark::<PoseidonRecurseBatch100, Pos100P<MNT4Fr>>(
                //    "ca_mt_poseidon_recurse".to_string(),
                //    &num_cores,
                //);
                //benchmark::<PoseidonAggrBatch100, Pos100P<BLS381Fr>>(
                //    "ca_mt_poseidon_aggr".to_string(),
                //    &num_cores,
                //);
            }
            150 => {
                benchmark::<PedersenRecurseBatch150, RPed150P>(
                    "ca_mt_pedersen_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PedersenAggrBatch150, APed150P>(
                    "ca_mt_pedersen_aggr".to_string(),
                    &num_cores,
                );
                //benchmark::<PoseidonRecurseBatch150, Pos150P<MNT4Fr>>(
                //    "ca_mt_poseidon_recurse".to_string(),
                //    &num_cores,
                //);
                //benchmark::<PoseidonAggrBatch150, Pos150P<BLS381Fr>>(
                //    "ca_mt_poseidon_aggr".to_string(),
                //    &num_cores,
                //);
            }
            200 => {
                benchmark::<PedersenRecurseBatch200, RPed200P>(
                    "ca_mt_pedersen_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PedersenAggrBatch200, APed200P>(
                    "ca_mt_pedersen_aggr".to_string(),
                    &num_cores,
                );
                //benchmark::<PoseidonRecurseBatch200, Pos200P<MNT4Fr>>(
                //    "ca_mt_poseidon_recurse".to_string(),
                //    &num_cores,
                //);
                //benchmark::<PoseidonAggrBatch200, Pos200P<BLS381Fr>>(
                //    "ca_mt_poseidon_aggr".to_string(),
                //    &num_cores,
                //);
            }
            500 => {
                //benchmark::<PedersenRecurseBatch500, RPed500P>(
                //    "ca_mt_pedersen_recurse".to_string(),
                //    &num_cores,
                //);
                //benchmark::<PedersenAggrBatch500, APed500P>(
                //    "ca_mt_pedersen_aggr".to_string(),
                //    &num_cores,
                //);
                benchmark::<PoseidonRecurseBatch500, Pos500P<MNT4Fr>>(
                    "ca_mt_poseidon_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PoseidonAggrBatch500, Pos500P<BLS381Fr>>(
                    "ca_mt_poseidon_aggr".to_string(),
                    &num_cores,
                );
            }
            1000 => {
                //benchmark::<PedersenRecurseBatch1000, RPed1000P>(
                //    "ca_mt_pedersen_recurse".to_string(),
                //    &num_cores,
                //);
                //benchmark::<PedersenAggrBatch1000, APed1000P>(
                //    "ca_mt_pedersen_aggr".to_string(),
                //    &num_cores,
                //);
                benchmark::<PoseidonRecurseBatch1000, Pos1000P<MNT4Fr>>(
                    "ca_mt_poseidon_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PoseidonAggrBatch1000, Pos1000P<BLS381Fr>>(
                    "ca_mt_poseidon_aggr".to_string(),
                    &num_cores,
                );
            }
            1500 => {
                //benchmark::<PedersenRecurseBatch1500, RPed1500P>(
                //    "ca_mt_pedersen_recurse".to_string(),
                //    &num_cores,
                //);
                //benchmark::<PedersenAggrBatch1500, APed1500P>(
                //    "ca_mt_pedersen_aggr".to_string(),
                //    &num_cores,
                //);
                benchmark::<PoseidonRecurseBatch1500, Pos1500P<MNT4Fr>>(
                    "ca_mt_poseidon_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PoseidonAggrBatch1500, Pos1500P<BLS381Fr>>(
                    "ca_mt_poseidon_aggr".to_string(),
                    &num_cores,
                );
            }
            2000 => {
                //benchmark::<PedersenRecurseBatch2000, RPed2000P>(
                //    "ca_mt_pedersen_recurse".to_string(),
                //    &num_cores,
                //);
                //benchmark::<PedersenAggrBatch2000, APed2000P>(
                //    "ca_mt_pedersen_aggr".to_string(),
                //    &num_cores,
                //);
                benchmark::<PoseidonRecurseBatch2000, Pos2000P<MNT4Fr>>(
                    "ca_mt_poseidon_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PoseidonAggrBatch2000, Pos2000P<BLS381Fr>>(
                    "ca_mt_poseidon_aggr".to_string(),
                    &num_cores,
                );
            }
            3000 => {
                //benchmark::<PedersenRecurseBatch3000, RPed3000P>(
                //    "ca_mt_pedersen_recurse".to_string(),
                //    &num_cores,
                //);
                //benchmark::<PedersenAggrBatch3000, APed3000P>(
                //    "ca_mt_pedersen_aggr".to_string(),
                //    &num_cores,
                //);
                benchmark::<PoseidonRecurseBatch3000, Pos3000P<MNT4Fr>>(
                    "ca_mt_poseidon_recurse".to_string(),
                    &num_cores,
                );
                benchmark::<PoseidonAggrBatch3000, Pos3000P<BLS381Fr>>(
                    "ca_mt_poseidon_aggr".to_string(),
                    &num_cores,
                );
            }
            //4000 => {
            //    benchmark::<PedersenRecurseBatch4000, RPed4000P>(
            //        "ca_mt_pedersen_recurse".to_string(),
            //        &num_cores,
            //    );
            //    benchmark::<PedersenAggrBatch4000, APed4000P>(
            //        "ca_mt_pedersen_aggr".to_string(),
            //        &num_cores,
            //    );
            //    benchmark::<PoseidonRecurseBatch4000, Pos4000P<MNT4Fr>>(
            //        "ca_mt_poseidon_recurse".to_string(),
            //        &num_cores,
            //    );
            //    benchmark::<PoseidonAggrBatch4000, Pos4000P<BLS381Fr>>(
            //        "ca_mt_poseidon_aggr".to_string(),
            //        &num_cores,
            //    );
            //},
            //5000 => {
            //    benchmark::<PedersenRecurseBatch5000, RPed5000P>(
            //        "ca_mt_pedersen_recurse".to_string(),
            //        &num_cores,
            //    );
            //    benchmark::<PedersenAggrBatch5000, APed5000P>(
            //        "ca_mt_pedersen_aggr".to_string(),
            //        &num_cores,
            //    );
            //    benchmark::<PoseidonRecurseBatch5000, Pos5000P<MNT4Fr>>(
            //        "ca_mt_poseidon_recurse".to_string(),
            //        &num_cores,
            //    );
            //    benchmark::<PoseidonAggrBatch5000, Pos5000P<BLS381Fr>>(
            //        "ca_mt_poseidon_aggr".to_string(),
            //        &num_cores,
            //    );
            //},
            _ => println!("Batch size not supported: {}", batch_size),
        }
    }
}
