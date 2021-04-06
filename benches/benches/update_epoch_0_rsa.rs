#![allow(deprecated)]
use ark_ed_on_mnt4_298::{EdwardsProjective, Fq as MNT4Fr, constraints::EdwardsVar};
use ark_mnt4_298::{MNT4_298, constraints::PairingVar as MNT4PairingVar};
use ark_mnt6_298::{MNT6_298, constraints::PairingVar as MNT6PairingVar};
use ark_ed_on_bls12_381::{Fq as BLS381Fr};
use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{
    crh::pedersen::{constraints::CRHGadget, CRH, Window},
};
use ark_ec::{CycleEngine};

use single_step_avd::{
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
    recursion::RecursionFullHistoryAVD,
    aggregation::{AggregatedFullHistoryAVD, AggregatedFullHistoryAVDParameters},
    rsa_algebraic::RsaFullHistoryAVD,
};

use rand::{rngs::StdRng, SeedableRng};
use csv::Writer;

use std::{
    string::String,
    io::stdout,
    time::{Instant},
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
pub struct PoseidonMerkleTreeTestParameters;

#[cfg(feature = "local")]
impl MerkleTreeParameters for PoseidonMerkleTreeTestParameters {
    const DEPTH: MerkleDepth = 4;
    type H = PoseidonSponge<MNT4Fr>;
}

#[cfg(not(feature = "local"))]
impl MerkleTreeParameters for PoseidonMerkleTreeTestParameters {
    const DEPTH: MerkleDepth = 4;
    type H = PoseidonSponge<MNT4Fr>;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestRsaParams;

#[cfg(feature = "local")]
impl RsaGroupParams for TestRsaParams {
    const RAW_G: usize = 2;
    const RAW_M: &'static str = "17839761582542106619";
}

#[cfg(not(feature = "local"))]
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

#[cfg(feature = "local")]
impl BigNatCircuitParams for BigNatTestParams {
    const LIMB_WIDTH: usize = 32;
    const N_LIMBS: usize = 2;
}

#[cfg(not(feature = "local"))]
impl BigNatCircuitParams for BigNatTestParams {
    const LIMB_WIDTH: usize = 32;
    const N_LIMBS: usize = 64;
}


#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestPokerParams;

#[cfg(feature = "local")]
impl PoKERParams for TestPokerParams {
    const HASH_TO_PRIME_ENTROPY: usize = 32;
}

#[cfg(not(feature = "local"))]
impl PoKERParams for TestPokerParams {
    const HASH_TO_PRIME_ENTROPY: usize = 128;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestKVACParams;

#[cfg(feature = "local")]
impl RsaKVACParams for TestKVACParams {
    const KEY_LEN: usize = 64;
    const VALUE_LEN: usize = 64;
    const PRIME_LEN: usize = 72;
    type RsaGroupParams = TestRsaParams;
    type PoKERParams = TestPokerParams;
}

#[cfg(not(feature = "local"))]
impl RsaKVACParams for TestKVACParams {
    const KEY_LEN: usize = 256;
    const VALUE_LEN: usize = 256;
    const PRIME_LEN: usize = 264;
    type RsaGroupParams = TestRsaParams;
    type PoKERParams = TestPokerParams;
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

type TestRecursionRsaFHAVD = RecursionFullHistoryAVD<
    TestRsaAVD<MNT4Fr>,
    TestRsaAVDGadget<MNT4Fr>,
    MerkleTreeTestParameters,
    HG,
    MNT298Cycle,
    MNT4PairingVar,
    MNT6PairingVar,
>;

type TestPoseidonRecursionRsaFHAVD = RecursionFullHistoryAVD<
    TestRsaAVD<MNT4Fr>,
    TestRsaAVDGadget<MNT4Fr>,
    PoseidonMerkleTreeTestParameters,
    PoseidonSpongeVar<MNT4Fr>,
    MNT298Cycle,
    MNT4PairingVar,
    MNT6PairingVar,
>;

type TestRsaAggregatedFHAVD = AggregatedFullHistoryAVD<
    AggregatedFHAVDTestParameters,
    TestRsaAVD<BLS381Fr>,
    TestRsaAVDGadget<BLS381Fr>,
    Bls12_381,
    blake3::Hasher,
>;

pub type TestRsaFHAVD = RsaFullHistoryAVD<
    TestKVACParams,
    HasherFromDigest<BLS381Fr, blake3::Hasher>,
    HasherFromDigest<BLS381Fr, blake3::Hasher>,
    BigNatTestParams,
>;

fn benchmark<AVD: FullHistoryAVD>(
    scheme_name: String,
    batch_sizes: &Vec<usize>,
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
        for batch_size in batch_sizes.iter() {
            let mut epoch_update = vec![];
            for i in 0..*batch_size {
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
                    let _ = avd.batch_update(&mut rng, &epoch_update).unwrap();
                    let end = start.elapsed().as_secs();

                    csv_writer.write_record(&[
                        scheme_name.clone(),
                        "update".to_string(),
                        batch_size.to_string(),
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
    println!("args: {:?}", args);
    if args.last().unwrap() == "--bench" {
        args.pop();
    }
    let (mut batch_sizes, mut num_cores): (Vec<usize>, Vec<usize>) = if args.len() > 0 && (args[1] == "-h" || args[1] == "--help")
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
            batch_sizes.push(4);
        } else {
            batch_sizes.push(100);
        }
    }
    if num_cores.len() == 0 {
        num_cores.push(num_cpus::get_physical());
    }

    benchmark::<TestRecursionRsaFHAVD>(
        "ca_rsa_pedersen_recurse".to_string(),
        &batch_sizes,
        &num_cores,
    );
    benchmark::<TestPoseidonRecursionRsaFHAVD>(
        "ca_rsa_poseidon_recurse".to_string(),
        &batch_sizes,
        &num_cores,
    );
    benchmark::<TestRsaAggregatedFHAVD>(
        "ca_rsa_aggr".to_string(),
        &batch_sizes,
        &num_cores,
    );
    benchmark::<TestRsaFHAVD>(
        "ca_rsa_alg".to_string(),
        &batch_sizes,
        &num_cores,
    );
}
