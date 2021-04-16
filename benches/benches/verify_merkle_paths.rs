use ark_ed_on_bls12_381::{Fq as BLS381Fr, EdwardsProjective};
use ark_crypto_primitives::{
    crh::pedersen::{CRH, Window},
};
use crypto_primitives::{
    sparse_merkle_tree::{MerkleDepth, MerkleTreeParameters, MerkleTreePath},
    hash::{FixedLengthCRH, poseidon::{PoseidonSponge}},
};

use rand::{rngs::StdRng, SeedableRng, Rng};
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

#[derive(Clone)]
pub struct MerkleTreeTestParameters;

impl MerkleTreeParameters for MerkleTreeTestParameters {
    const DEPTH: MerkleDepth = 32;
    type H = H;
}

#[derive(Clone)]
pub struct PoseidonMerkleTreeTestParameters;

impl MerkleTreeParameters for PoseidonMerkleTreeTestParameters {
    const DEPTH: MerkleDepth = 32;
    type H = PoseidonSponge<BLS381Fr>;
}


fn benchmark<P: MerkleTreeParameters>
(
    scheme_name: String,
    range_lengths: &Vec<usize>,
    batch_sizes: &Vec<usize>,
) {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    pool.install(|| {
        let mut rng = StdRng::seed_from_u64(0_u64);
        let mut csv_writer = Writer::from_writer(stdout());
        csv_writer
            .write_record(&["scheme", "operation", "log_range_size", "batch_size", "time"])
            .unwrap();
        csv_writer.flush().unwrap();
        let params = <P::H as FixedLengthCRH>::setup(&mut rng).unwrap();
        let max_range = range_lengths.iter().max().cloned().unwrap();
        let max_batch_size = batch_sizes.iter().max().cloned().unwrap();
        let mut merkle_paths = vec![];
        let mut indices = vec![];
        for i in 0..(max_range * max_batch_size) {
            let mut hashs = vec![];
            for j in 0..(P::DEPTH as usize) {
                let mut b = i.to_le_bytes().to_vec();
                b.extend_from_slice(&j.to_le_bytes());
                hashs.push(<P::H as FixedLengthCRH>::evaluate_variable_length(&params, &b).unwrap());
            }
            merkle_paths.push(MerkleTreePath::<P> {
                path: hashs,
                _parameters: PhantomData,
            });
            indices.push(rng.gen::<u32>() as u64);
        }


        { // Verify
            for log_len in range_lengths.iter() {
                let len = 1_usize << *log_len;
                for batch_size in batch_sizes.iter() {
                    let start = Instant::now();
                    for (path, index) in merkle_paths.iter().zip(&indices).take(batch_size * len) {
                        path.verify(&Default::default(), &[0], *index, &params).unwrap();
                    }
                    let end = start.elapsed().as_millis();
                    csv_writer.write_record(&[
                        scheme_name.clone(),
                        "verify".to_string(),
                        log_len.to_string(),
                        batch_size.to_string(),
                        end.to_string(),
                    ]).unwrap();
                    csv_writer.flush().unwrap();
                }
            }
        }
    })
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    if args.last().unwrap() == "--bench" {
        args.pop();
    }
    let (mut range_lengths, mut batch_sizes): (Vec<usize>, Vec<usize>) = if args.len() > 1 && (args[1] == "-h" || args[1] == "--help")
    {
        println!("Usage: ``cargo bench --bench verify_merkle_paths --  [--ranges <RANGE_LEN>...][--batch_size <BATCH_SIZE>...]``");
        return;
    } else {
        let mut args = args.into_iter().skip(1);
        let mut next_arg = args.next();
        let mut range_lengths = vec![];
        let mut batch_sizes = vec![];
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
                _ => {
                    println!("Invalid argument: {}", arg);
                    return
                }
            }
        }
        (range_lengths, batch_sizes)
    };
    if range_lengths.len() == 0 {
        range_lengths.push(8);
    }
    if batch_sizes.len() == 0 {
        batch_sizes.push(1000);
    }

    benchmark::<MerkleTreeTestParameters>(
        "pedersen".to_string(),
        &range_lengths,
        &batch_sizes,
    );
    benchmark::<PoseidonMerkleTreeTestParameters>(
        "poseidon".to_string(),
        &range_lengths,
        &batch_sizes,
    );
}
