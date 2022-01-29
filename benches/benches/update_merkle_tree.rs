use crypto_primitives::{
    sparse_merkle_tree::{MerkleDepth, MerkleTreeParameters},
    hash::hash_from_digest::CRHFromDigest,
};

use single_step_avd::{
    merkle_tree_avd::{MerkleTreeAVD, MerkleTreeAVDParameters},
    SingleStepAVD,
};

use sha3::Sha3_256;
use csv::Writer;
use rand::{rngs::StdRng, Rng, SeedableRng};

use std::{io::stdout, string::String, time::Instant};

pub type H = CRHFromDigest<Sha3_256>;

#[derive(Clone)]
pub struct MerkleTreeTestParameters;

impl MerkleTreeParameters for MerkleTreeTestParameters {
    const DEPTH: MerkleDepth = 32;
    type H = H;
}

macro_rules! mt_avd_impl {
    ($avd_params:ident, $avd:ident, $batch_size:expr) => {
        #[derive(Clone)]
        pub struct $avd_params;

        impl MerkleTreeAVDParameters for $avd_params {
            const MAX_UPDATE_BATCH_SIZE: u64 = $batch_size;
            const MAX_OPEN_ADDRESSING_PROBES: u8 = 16;
            type MerkleTreeParameters = MerkleTreeTestParameters;
        }

        type $avd = MerkleTreeAVD<$avd_params>;
    };
}

mt_avd_impl!(AVD1P, AVD1, 1);
mt_avd_impl!(AVD10P, AVD10, 10000);
mt_avd_impl!(AVD20P, AVD20, 20000);
mt_avd_impl!(AVD30P, AVD30, 30000);
mt_avd_impl!(AVD40P, AVD40, 40000);
mt_avd_impl!(AVD50P, AVD50, 50000);
mt_avd_impl!(AVD60P, AVD60, 60000);
mt_avd_impl!(AVD70P, AVD70, 70000);
mt_avd_impl!(AVD80P, AVD80, 80000);
mt_avd_impl!(AVD90P, AVD90, 90000);
mt_avd_impl!(AVD100P, AVD100, 100000);

fn benchmark<AVD: SingleStepAVD>(batch_size: u64) {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    pool.install(|| {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let mut csv_writer = Writer::from_writer(stdout());
        let start = Instant::now();
        let params = <AVD>::setup(&mut rng).unwrap();
        let mut avd = <AVD>::new(&mut rng, &params).unwrap();
        let mut kvs = vec![];
        for _ in 0..batch_size {
            kvs.push((rng.gen::<[u8; 32]>(), rng.gen::<[u8; 32]>()));
        }
        let end = start.elapsed().as_secs();
        csv_writer
            .write_record(&[
                "sha3".to_string(),
                "setup".to_string(),
                batch_size.to_string(),
                end.to_string(),
            ])
            .unwrap();
        csv_writer.flush().unwrap();

        let start = Instant::now();
        let _ = avd.batch_update(&kvs).unwrap();
        let end = start.elapsed().as_millis();
        csv_writer
            .write_record(&[
                "sha3".to_string(),
                "update".to_string(),
                batch_size.to_string(),
                end.to_string(),
            ])
            .unwrap();
        csv_writer.flush().unwrap();
    })
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    if args.last().unwrap() == "--bench" {
        args.pop();
    }
    let mut batch_sizes: Vec<usize> = if args.len() > 1 && (args[1] == "-h" || args[1] == "--help")
    {
        println!("Usage: ``cargo bench --bench update_merkle_tree --  [--batch_size <BATCH_SIZE>...]``");
        return;
    } else {
        let mut args = args.into_iter().skip(1);
        let mut next_arg = args.next();
        let mut batch_sizes = vec![];
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
                _ => {
                    println!("Invalid argument: {}", arg);
                    return;
                }
            }
        }
        batch_sizes
    };
    if batch_sizes.len() == 0 {
        batch_sizes.push(10000);
    }
    {
        let mut csv_writer = Writer::from_writer(stdout());
        csv_writer
            .write_record(&["scheme", "operation", "batch_size", "time"])
            .unwrap();
        csv_writer.flush().unwrap();
    }

    for batch_size in batch_sizes.into_iter() {
        match batch_size {
            1 => {
                benchmark::<AVD1>(1);
            }
            10000 => {
                benchmark::<AVD10>(10000);
            }
            20000 => {
                benchmark::<AVD20>(20000);
            }
            30000 => {
                benchmark::<AVD30>(30000);
            }
            40000 => {
                benchmark::<AVD40>(40000);
            }
            50000 => {
                benchmark::<AVD50>(50000);
            }
            60000 => {
                benchmark::<AVD60>(60000);
            }
            70000 => {
                benchmark::<AVD70>(70000);
            }
            80000 => {
                benchmark::<AVD80>(80000);
            }
            90000 => {
                benchmark::<AVD90>(90000);
            }
            100000 => {
                benchmark::<AVD100>(100000);
            }
            _ => println!("Batch size not supported: {}", batch_size),
        }
    }
}
