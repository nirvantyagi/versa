use ethabi::Token;
use primitive_types::U256;

use rand::{rngs::StdRng, SeedableRng};
use csv::Writer;

use std::{
    io::stdout,
};

use ethereum_test_utils::{
    address::Address,
    contract::Contract,
    evm::{Evm},
};

fn to_be_bytes(n: &U256) -> [u8; 32] {
    let mut input_bytes: [u8; 32] = [0; 32];
    n.to_big_endian(&mut input_bytes);
    input_bytes
}

fn main() {
    let mut rng = StdRng::seed_from_u64(0_u64);
    let mut csv_writer = Writer::from_writer(stdout());
    csv_writer
        .write_record(&["contract", "deploy", "post"])
        .unwrap();
    csv_writer.flush().unwrap();

    // Setup EVM
    let mut evm = Evm::new();
    let deployer = Address::random(&mut rng);
    evm.create_account(&deployer, 0);

    // Index bulletin board contract benchmarks
    let contract_path = format!(
        "{}/contracts/index_board.sol",
        env!("CARGO_MANIFEST_DIR")
    );
    let contract =
        Contract::compile_from_solidity_file(contract_path, "IndexBulletinBoard", true).unwrap();
    let create_result = evm.deploy(contract.encode_create_contract_bytes(&[]).unwrap(), &deployer).unwrap();
    let contract_addr = create_result.addr.clone();
    let post_result = evm.call(contract.encode_call_contract_bytes("post", &[Token::FixedBytes(to_be_bytes(&U256::from(40)).to_vec())]).unwrap(), &contract_addr, &deployer).unwrap();
    csv_writer
        .write_record(&["index".to_string(), create_result.gas.to_string(), post_result.gas.to_string()])
        .unwrap();
    csv_writer.flush().unwrap();

    // Hash chain bulletin board contract benchmarks
    let contract_path = format!(
        "{}/contracts/hashchain_board.sol",
        env!("CARGO_MANIFEST_DIR")
    );
    let contract =
        Contract::compile_from_solidity_file(contract_path, "HashchainBulletinBoard", true).unwrap();
    let create_result = evm.deploy(contract.encode_create_contract_bytes(&[]).unwrap(), &deployer).unwrap();
    let contract_addr = create_result.addr.clone();
    let post_result = evm.call(contract.encode_call_contract_bytes("post", &[Token::FixedBytes(to_be_bytes(&U256::from(40)).to_vec())]).unwrap(), &contract_addr, &deployer).unwrap();
    csv_writer
        .write_record(&["hashchain".to_string(), create_result.gas.to_string(), post_result.gas.to_string()])
        .unwrap();
    csv_writer.flush().unwrap();
}
