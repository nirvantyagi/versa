use ark_ed_on_bls12_381::{Fq as BLS381Fr};

use rsa::{
    bignat::constraints::BigNatCircuitParams,
    kvac::RsaKVACParams,
    poker::{
        PoKERParams,
        PoKER,
        Statement as PoKERStatement,
        Witness as PoKERWitness,
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
    const LIMB_WIDTH: usize = 254;
    const N_LIMBS: usize = 9;
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
    batch_sizes: &Vec<usize>,
    cores: &Vec<usize>,
) where <P as RsaKVACParams>::RsaGroupParams: Sync {
    let mut csv_writer = Writer::from_writer(stdout());
    csv_writer
        .write_record(&["scheme", "operation", "log_range_size", "batch_size", "num_cores", "time"])
        .unwrap();
    csv_writer.flush().unwrap();

    let c1 = Hog::<P>::generator().power(&hash_to_integer::<H>(&[BLS381Fr::from(1 as u8)], 256));
    let c2 = Hog::<P>::generator().power(&hash_to_integer::<H>(&[BLS381Fr::from(2 as u8)], 256));
    for batch_size in batch_sizes.iter() {
        for log_len in range_lengths.iter() {
            let len = 1_usize << *log_len;
            let half_len = len >> 1;

            // Create dummy exponents of proper size
            let start = Instant::now();
            let int_len = half_len * batch_size * P::PRIME_LEN;
            let z1 = hash_to_integer::<H>(&[BLS381Fr::from(1 as u8)], int_len);
            let z2 = hash_to_integer::<H>(&[BLS381Fr::from(2 as u8)], int_len);
            let delta1 = hash_to_integer::<H>(&[BLS381Fr::from(3 as u8)], int_len);
            let delta2 = hash_to_integer::<H>(&[BLS381Fr::from(4 as u8)], int_len);

            let c1_new = c1.power(&z1).power(&z2)
                .op(&c2.power(&z1).power(&delta2).op(&c2.power(&z2).power(&delta1)));
            let c2_new = c2.power(&z1).power(&z2);
            let statement = PoKERStatement {
                u1: c1.clone(),
                u2: c2.clone(),
                w1: c1_new,
                w2: c2_new,
            };
            let end = start.elapsed().as_secs();
            csv_writer.write_record(&[
                scheme_name.clone(),
                "setup".to_string(),
                log_len.to_string(),
                batch_size.to_string(),
                "0".to_string(),
                end.to_string(),
            ]).unwrap();
            csv_writer.flush().unwrap();

            for num_cores in cores.iter() {
                if *num_cores > num_cpus::get_physical() {
                    continue;
                }
                let update_pool = rayon::ThreadPoolBuilder::new().num_threads(*num_cores as usize).build().unwrap();
                update_pool.install(|| {
                    let start = Instant::now();
                    let witness = PoKERWitness {
                        a: z1.clone() * z2.clone(),
                        b: z1.clone() * delta2.clone() + z2.clone() * delta1.clone(),
                    };
                    let proof = PoKER::<PoKParams<P>, RsaParams<P>, H, BigNatTestParams>::prove(&statement, &witness).unwrap();
                    let end = start.elapsed().as_millis();
                    csv_writer.write_record(&[
                        scheme_name.clone(),
                        "aggregate".to_string(),
                        log_len.to_string(),
                        batch_size.to_string(),
                        num_cores.to_string(),
                        end.to_string(),
                    ]).unwrap();
                    csv_writer.flush().unwrap();

                    let start = Instant::now();
                    let b = PoKER::<PoKParams<P>, RsaParams<P>, HasherFromDigest<BLS381Fr, blake3::Hasher>, BigNatTestParams>::verify(&statement, &proof).unwrap();
                    let end = start.elapsed().as_millis();
                    assert!(b);
                    csv_writer.write_record(&[
                        scheme_name.clone(),
                        "verify".to_string(),
                        log_len.to_string(),
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
    if args.last().unwrap() == "--bench" {
        args.pop();
    }
    let (mut range_lengths, mut batch_sizes, mut num_cores): (Vec<usize>, Vec<usize>, Vec<usize>) = if args.len() > 1 && (args[1] == "-h" || args[1] == "--help")
    {
        println!("Usage: ``cargo bench --bench aggregate_rsa --  [--ranges <RANGE_LEN>...][--batch_sizes <SIZE>...][--num_cores <NUM_CORES>...]``");
        return;
    } else {
        let mut args = args.into_iter().skip(1);
        let mut next_arg = args.next();
        let mut range_lengths = vec![];
        let mut batch_sizes = vec![];
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
        (range_lengths, batch_sizes, num_cores)
    };
    if range_lengths.len() == 0 {
        range_lengths.push(5);
    }
    if batch_sizes.len() == 0 {
        batch_sizes.push(50);
    }
    if num_cores.len() == 0 {
        num_cores.push(num_cpus::get_physical());
    }

    benchmark::<TestKVACParams>(
        "ca_rsa_alg".to_string(),
        &range_lengths,
        &batch_sizes,
        &num_cores,
    );
}
