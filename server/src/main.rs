#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use serde::{Serialize, Deserialize};
use rocket_contrib::{
    json,
    json::Json,
    json::JsonValue
};
use ark_ed_on_mnt4_298::{EdwardsProjective, Fq, constraints::EdwardsVar};
use ark_mnt4_298::{MNT4_298, constraints::PairingVar as MNT4PairingVar};
use ark_mnt6_298::{MNT6_298, constraints::PairingVar as MNT6PairingVar};
#[allow(deprecated)]
use ark_ec::CycleEngine;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_crypto_primitives::{
    crh::pedersen::{constraints::CRHGadget, CRH, Window},
};
use crypto_primitives::{
    sparse_merkle_tree::{
        MerkleDepth,
        MerkleTreeParameters,
        store::redis_store::SMTRedisStore
    },
    hash::{
        FixedLengthCRH,
    },
};
use single_step_avd::{
    merkle_tree_avd::{
        MerkleTreeAVDParameters,
        MerkleTreeAVD,
        constraints::MerkleTreeAVDGadget,
        store::{
            redis_store::MTAVDRedisStore,
        }
    },
};
use full_history_avd::{
    recursion::{
        RecursionFullHistoryAVD,
        store::redis_store::RecursionFullHistoryAVDRedisStore
    },
    history_tree::{
        SingleStepAVDWithHistory,
        store::{
            redis_store::{
                HTRedisStore,
                SingleStepAVDWithHistoryRedisStore,
            }
        }
    },
    FullHistoryAVD
};

#[derive(Clone, Copy, Debug)]
pub struct MNT298Cycle;
#[allow(deprecated)]
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

type RedisTestSMTStore = SMTRedisStore<MerkleTreeTestParameters>;
type RedisTestMTAVDStore = MTAVDRedisStore<MerkleTreeAVDTestParameters, RedisTestSMTStore>;
type RedisTestMerkleTreeAVD = MerkleTreeAVD<MerkleTreeAVDTestParameters, RedisTestSMTStore, RedisTestMTAVDStore>;
type RedisTestMerkleTreeAVDGadget = MerkleTreeAVDGadget<MerkleTreeAVDTestParameters, HG, Fq, RedisTestSMTStore, RedisTestMTAVDStore>;
type RedisTestAVDWHStore = SingleStepAVDWithHistoryRedisStore<RedisTestMerkleTreeAVD, MerkleTreeTestParameters, RedisTestSMTStore, RedisTestHTStore>;
type RedisTestSingleStepAVDWithHistory = SingleStepAVDWithHistory<RedisTestMerkleTreeAVD, MerkleTreeTestParameters, RedisTestSMTStore, RedisTestHTStore, RedisTestAVDWHStore>;
type RedisTestHTStore = HTRedisStore<MerkleTreeTestParameters, <H as FixedLengthCRH>::Output, RedisTestSMTStore>;
type RedisTestRecursionFHAVDStore = RecursionFullHistoryAVDRedisStore<RedisTestMerkleTreeAVD, RedisTestMerkleTreeAVDGadget, MerkleTreeTestParameters, HG, MNT298Cycle, MNT4PairingVar, MNT6PairingVar, RedisTestSMTStore, RedisTestHTStore, RedisTestAVDWHStore>;
type RedisTestRecursionFHAVD = RecursionFullHistoryAVD<RedisTestMerkleTreeAVD, RedisTestMerkleTreeAVDGadget, MerkleTreeTestParameters, HG, MNT298Cycle, MNT4PairingVar, MNT6PairingVar, RedisTestSMTStore, RedisTestHTStore, RedisTestAVDWHStore, RedisTestRecursionFHAVDStore>;

#[derive(Serialize, Deserialize)]
struct Entry {
    key: [u8; 32],
    value: [u8; 32],
}

static EPOCHS: Lazy<Mutex<Vec<RedisTestRecursionFHAVD>>> = Lazy::new(|| {
    Mutex::new(vec![])
});
static QUEUE: Lazy<Mutex<Vec<([u8; 32], [u8; 32])>>> = Lazy::new(|| {
    Mutex::new(vec![])
});

#[post("/", data = "<entry>")]
fn commit(entry: Json<Entry>) -> JsonValue {
    // all we do is write this entry into the list of kvs to be included
    QUEUE.lock().unwrap().push((entry.key, entry.value));
    // this... could be put in redis obv.
    json!({ "status": "ok" })
}

#[post("/", data = "<entry>")]
fn prove(entry: Json<Entry>) -> JsonValue {
    // we lookup the key based on the current state
    let _lkup: (
        Option<(u64, [u8; 32])>,
        <RedisTestRecursionFHAVD as FullHistoryAVD>::Digest,
        <RedisTestRecursionFHAVD as FullHistoryAVD>::LookupProof
    ) = EPOCHS.lock().unwrap()[0].lookup(&entry.key).unwrap();
    // can return one or all these values obv.
    json!({ "status": "ok" })
}

#[post("/")]
fn epoch() -> JsonValue {
    // make copy of current state
    let mut future = EPOCHS.lock().unwrap()[0].make_copy().unwrap();
    // grab the list of kvs to be included in next state
    let kvs = QUEUE.lock().unwrap().clone();
    // Question: does it have to be the same rng instantiation? No?
    future.batch_update(&mut StdRng::seed_from_u64(0u64), &kvs).unwrap();
    // push the new state into the global so reads will start occuring off of it
    EPOCHS.lock().unwrap().push(future);
    json!({ "status": "ok" })
}

fn main() {
    println!("Setting up FHAVD");
    let mut rng = StdRng::seed_from_u64(0u64);
    let pp = RedisTestRecursionFHAVD::setup(&mut rng).unwrap();
    let fhavd = RedisTestRecursionFHAVD::new(&mut rng, &pp).unwrap();
    EPOCHS.lock().unwrap().push(fhavd);
    println!("Setup Complete");
    rocket::ignite().mount("/commit", routes![commit]).launch();
    rocket::ignite().mount("/prove", routes![prove]).launch();
    rocket::ignite().mount("/epoch", routes![epoch]).launch();
}
