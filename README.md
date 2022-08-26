# VeRSA: Verifiable Registries with Efficient Client Audits from RSA Authenticated Dictionaries

_Rust implementation of the VeRSA family of verifiable registries_ 

**ACM CCS 2022:**
Nirvan Tyagi, Ben Fisch, Andrew Zitek, Joseph Bonneau, Stefano Tessaro. _VeRSA: Verifiable Registries with Efficient Client Audits from RSA Authenticated Dictionaries_. ACM CCS 2022.

**ePrint (full version):**
Nirvan Tyagi, Ben Fisch, Andrew Zitek, Joseph Bonneau, Stefano Tessaro. _VeRSA: Verifiable Registries with Efficient Client Audits from RSA Authenticated Dictionaries_. Cryptology ePrint Archive, Report 2021/627. https://eprint.iacr.org/2021/627. 2021.

## Overview

This repository is organized as a Rust workspace with a number of modular packages.
The following packages make up the core of the implementation for the VeRSA verifiable registries:
* [`crypto_primitives`](crypto_primitives): Implementation of various helper cryptographic primitives.
  * [`sparse_merkle_tree`](crypto_primitives/src/sparse_merkle_tree): Implementation and constraints for a sparse Merkle tree.
* [`rsa`](rsa): Implementation of RSA primitives and constraints.
  * [`bignat`](rsa/src/bignat): Wrapper around [`rug`](https://docs.rs/rug/latest/rug/) crate for integer arithmetic using GMP and constraints ported from [`bellman-bignat`](https://github.com/alex-ozdemir/bellman-bignat) (implementing optimizations from [`xJsnark`](https://github.com/akosba/xjsnark)).
  * [`hog`](rsa/src/hog): Implementation and constraints for RSA groups of hidden order.
  * [`hash`](rsa/src/hash): Implementation and constraints for hash-to-integer and hash-to-prime using optimized Pocklington certificate circuit encodings ported from [`bellman-bignat`](https://github.com/alex-ozdemir/bellman-bignat).
  * [`poker`](rsa/src/poker): Implementation and constraints of the generalized proof of knowledge of exponent representation for integers proposed by [[BBF19]](https://eprint.iacr.org/2018/1188).
  * [`kvac`](rsa/src/kvac): Implementation of RSA-based key-value commitment originally proposed by [[AR20]](https://eprint.iacr.org/2020/1161) with extensions from VeRSA.
* [`single_step_avd`](single_step_avd): Interface for authenticated dictionary along with various implementations. 
  * [`merkle_tree_avd`](single_step_avd/src/merkle_tree_avd): Implementation and constraints for an authenticated dictionary from a sparse Merkle tree (with open addressing optimization).
  * [`rsa_avd`](single_step_avd/src/rsa_avd): Implementation and constraints for an authenticated dictionary from an RSA key-value commitment. 
* [`full_history_avd`](full_history_avd): Interface for authenticated history dictionary along with various implementations.
  * [`history_tree`](full_history_avd/src/history_tree): Implementation and constraints for a vector commitment from a sparse Merkle tree.
  * [`recursion`](full_history_avd/src/recursion): Implementation of an authenticated history dictionary using SNARK recursion.
  * [`aggregation`](full_history_avd/src/aggregation): Implementation of an authenticated history dictionary using SNARK aggregation [[BMMTV21]](https://eprint.iacr.org/2019/1177).
  * [`rsa_algebraic`](full_history_avd/src/rsa_algebraic): Implementation of an authenticated history dictionary using algebraic update proofs for an RSA authenticated dictionary.

We provide a number of tests and benchmarks which we expand on below.
Benchmarks are co-located in a separate package while tests are interspersed across the above packages.
* [`benches`](benches): Microbenchmarks for VeRSA authenticated history dictionaries.

We also evaluate the costs of running a public bulletin board via a smart contract on Ethereum (or any blockchain supporting EVM).
* [`bulletin_board`](bulletin_board): Smart contracts and benchmarks for publishing digests to the blockchain.
* [`ethereum_test_utils`](ethereum_test_utils): Helper methods for compiling solidity and benchmarking gas costs.

Lastly, the above implementations for authenticated (history) dictionaries store state in-memory using standard Rust structs.
We implement a storage interface allowing for the data structures to store state persistently in an external database like Redis in an experimental branch [`storage-layer`](https://github.com/nirvantyagi/versa/tree/storage-layer-poc/).

## Installation/Build

The packages and benchmarks are easy to compile from source using the stable toolchain of the Rust compiler.
Install the Rust toolchain manager `rustup` by following the instructions [here](https://rustup.rs/).

Clone the repository:
```bash
git clone https://github.com/nirvantyagi/versa.git
cd versa/
```

Install prerequisites for [`rug`](https://docs.rs/gmp-mpfr-sys/1.4.4/gmp_mpfr_sys/index.html):
```bash
sudo apt-get update
sudo apt install diffutils gcc m4 make
```

Build using `cargo`:
```bash
cargo build
```

If running on a fresh Ubuntu machine, you may need to install additional dependencies for `libc`:
```bash
sudo apt install build-essential
```

## Tests and Benchmarks

The `versa` packages come with a suite of tests and benchmarks.

### Running Tests

To run the tests:
```bash
cargo test
```

Some expensive tests have been omitted from the default test run.
To run an expensive test, specify it by name as follows:
```bash
cargo test name_of_expensive_test --release -- --ignored --nocapture
```

### Running Benchmarks

To run a benchmark:
```bash
cargo bench --bench name_of_benchmark -- [--optional-arg arg1 arg2...]
```

We provide the following benchmarks:
* [`update_epoch_0_mt`](benches/benches/update_epoch_0_mt.rs): Cost to prove and verify update from epoch 0 to 1 for registries based off of Merkle tree authenticated dictionaries.
* [`update_epoch_0_rsa`](benches/benches/update_epoch_0_rsa.rs): Cost to prove and verify update from epoch 0 to 1 for registries based off of RSA authenticated dictionaries.
* [`aggregate_rsa`](benches/benches/aggregate_rsa.rs): Cost to prove and verify algebraic update proof for RSA authenticated dictionary.
* [`aggregate_groth16`](benches/benches/aggregate_groth16.rs): Cost to prove and verify Groth16 SNARK aggregation.
* [`compute_witnesses_rsa`](benches/benches/compute_witnesses_rsa.rs): Cost to compute witness proofs for all entries in RSA authenticated dictionary.
* [`update_witness_rsa`](benches/benches/update_witness_rsa.rs): Cost to maintain witness for RSA authenticated dictionary over many dictionary updates.
* [`verify_witnesses_rsa`](benches/benches/verify_witnesses_rsa.rs): Cost to verify witness for RSA authenticated dictionary.
* [`update_merkle_tree`](benches/benches/update_merkle_tree.rs): Cost to prove update from epoch 0 to 1 for baseline Merkle tree authenticated dictionary without efficient history.
* [`verify_merkle_paths`](benches/benches/verify_merkle_paths.rs): Cost to verify update from epoch 0 to 1 for baseline Merkle tree authenticated dictionary without efficient history.
