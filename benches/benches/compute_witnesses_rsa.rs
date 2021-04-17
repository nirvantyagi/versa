use ark_ed_on_bls12_381::{Fq as BLS381Fr};

use rsa::{
    bignat::constraints::BigNatCircuitParams,
    kvac::{RsaKVACParams, RsaKVAC},
    poker::{
        PoKERParams,
    },
    hog::{RsaGroupParams, RsaHiddenOrderGroup},
    hash::{
        HasherFromDigest, hash_to_integer::hash_to_integer,
    },
};

use csv::Writer;

use std::{
    string::String,
    io::stdout,
    time::{Instant},
};

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

pub type RsaParams<P> = <P as RsaKVACParams>::RsaGroupParams;
pub type PoKParams<P> = <P as RsaKVACParams>::PoKERParams;
pub type Hog<P> = RsaHiddenOrderGroup<RsaParams<P>>;
pub type H = HasherFromDigest<BLS381Fr, blake3::Hasher>;

fn benchmark<P: RsaKVACParams>
(
    scheme_name: String,
    range_lengths: &Vec<usize>,
    cores: &Vec<usize>,
) where <P as RsaKVACParams>::RsaGroupParams: Sync {
    let mut csv_writer = Writer::from_writer(stdout());
    csv_writer
        .write_record(&["scheme", "operation", "log_range_size", "num_cores", "time"])
        .unwrap();
    csv_writer.flush().unwrap();

    // Create key-values
    let max_range = range_lengths.iter().max().cloned().unwrap();
    let len = 1_usize << max_range;
    let start = Instant::now();
    let mut kvs = vec![];
    for i in 0..len {
        kvs.push((hash_to_integer::<H>(&[BLS381Fr::from(i as u32)], P::KEY_LEN),
                  hash_to_integer::<H>(&[BLS381Fr::from(i as u32)], P::VALUE_LEN),
                  1,
        ))
    }
    let end = start.elapsed().as_secs();
    csv_writer.write_record(&[
        scheme_name.clone(),
        "setup".to_string(),
        max_range.to_string(),
        "0".to_string(),
        end.to_string(),
    ]).unwrap();
    csv_writer.flush().unwrap();

    for log_len in range_lengths.iter() {
        let len = 1_usize << *log_len;
        for num_cores in cores.iter() {
            if *num_cores > num_cpus::get_physical() {
                continue;
            }
            let update_pool = rayon::ThreadPoolBuilder::new().num_threads(*num_cores as usize).build().unwrap();
            update_pool.install(|| {
                let start = Instant::now();
                let _ = RsaKVAC::<P, H, H, BigNatTestParams>::_batch_update_membership_witnesses(kvs.iter().cloned().take(len), None).unwrap();
                let end = start.elapsed().as_millis();
                csv_writer.write_record(&[
                    scheme_name.clone(),
                    "witness_compute".to_string(),
                    log_len.to_string(),
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
    let (mut range_lengths, mut num_cores): (Vec<usize>, Vec<usize>) = if args.len() > 1 && (args[1] == "-h" || args[1] == "--help")
    {
        println!("Usage: ``cargo bench --bench compute_witnesses_rsa --  [--ranges <RANGE_LEN>...][--num_cores <NUM_CORES>...]``");
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
        range_lengths.push(10);
    }
    if num_cores.len() == 0 {
        num_cores.push(num_cpus::get_physical());
    }

    benchmark::<TestKVACParams>(
        "ca_rsa_alg".to_string(),
        &range_lengths,
        &num_cores,
    );
}
