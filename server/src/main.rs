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
type RedisTestHTStore = HTRedisStore<MerkleTreeTestParameters, <H as FixedLengthCRH>::Output, RedisTestSMTStore>;
type RedisTestRecursionFHAVDStore = RecursionFullHistoryAVDRedisStore<RedisTestMerkleTreeAVD, RedisTestMerkleTreeAVDGadget, MerkleTreeTestParameters, HG, MNT298Cycle, MNT4PairingVar, MNT6PairingVar, RedisTestSMTStore, RedisTestHTStore, RedisTestAVDWHStore>;
type RedisTestRecursionFHAVD = RecursionFullHistoryAVD<RedisTestMerkleTreeAVD, RedisTestMerkleTreeAVDGadget, MerkleTreeTestParameters, HG, MNT298Cycle, MNT4PairingVar, MNT6PairingVar, RedisTestSMTStore, RedisTestHTStore, RedisTestAVDWHStore, RedisTestRecursionFHAVDStore>;

static EPOCHS: Lazy<Mutex<Vec<RedisTestRecursionFHAVD>>> = Lazy::new(|| {
    let mut rng = StdRng::seed_from_u64(0u64);
    let pp = RedisTestRecursionFHAVD::setup(&mut rng).unwrap();
    Mutex::new(vec![RedisTestRecursionFHAVD::new(&mut rng, &pp)])
});

#[derive(Serialize, Deserialize)]
struct Entry {
    key: [u8; 32],
    value: String,
}

#[post("/", data = "<entry>")]
fn commit(entry: Json<Entry>) -> JsonValue {
    // TODO: just write entry into queue (redis) to be included when epoch() is called
    json!({ "status": "ok" })
}

#[post("/", data = "<entry>")]
fn prove(entry: Json<Entry>) -> JsonValue {
    let sumthin = EPOCHS.unwrap()[0].lookup(&entry.key);
    json!({ "status": "ok" })
}

#[post("/")]
fn epoch() -> JsonValue {

    let future = EPOCHS.unwrap()[0].make_copy().unwrap();
    // future.batch_update(... queue);
    EPOCHS.lock().unwrap().push(future);
    // TODO: current = future;
    json!({ "status": "ok" })
}

fn main() {
    rocket::ignite().mount("/commit", routes![commit]).launch();
    rocket::ignite().mount("/prove", routes![prove]).launch();
    rocket::ignite().mount("/epoch", routes![epoch]).launch();
}
