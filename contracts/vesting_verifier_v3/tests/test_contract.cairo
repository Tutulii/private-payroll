use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use vesting_verifier_v3::vesting_bundle_verifier::{
    IVestingBookV3BundleVerifierDispatcher, IVestingBookV3BundleVerifierDispatcherTrait,
};

fn deploy_real_bundle() -> (ContractAddress, ContractAddress) {
    let verifier_class = declare("PayoVestingBookV3Verifier").unwrap().contract_class();
    let (verifier, _) = verifier_class.deploy(@array![]).unwrap();
    let bundle_class = declare("PayoVestingBookV3BundleVerifier").unwrap().contract_class();
    let (bundle, _) = bundle_class.deploy(@array![verifier.into()]).unwrap();
    (verifier, bundle)
}

#[test]
fn real_vesting_v3_pair_passes_the_deployable_bundle_interface() {
    let (underlying, bundle) = deploy_real_bundle();
    let verifier = IVestingBookV3BundleVerifierDispatcher { contract_address: bundle };
    let shard_0 = read_txt(@FileTrait::new("tests/proof_calldata_0.txt"));
    let shard_1 = read_txt(@FileTrait::new("tests/proof_calldata_1.txt"));
    let result = verifier.verify_payroll_integrity_bundle(shard_0.span(), shard_1.span());
    assert(result.is_ok(), 'vesting bundle failed');
    let public_inputs = result.unwrap();
    assert(public_inputs.len() == 116, 'wrong bundled input count');
    assert(*public_inputs.at(2) == u256 { low: 3, high: 0 }, 'wrong proof version');
    assert(*public_inputs.at(4) == u256 { low: 1, high: 0 }, 'wrong entry kind');
    assert(*public_inputs.at(57) == u256 { low: 0, high: 0 }, 'wrong shard zero');
    assert(*public_inputs.at(115) == u256 { low: 1, high: 0 }, 'wrong shard one');
    assert(verifier.get_underlying_verifier() == underlying, 'wrong underlying verifier');
}

#[test]
fn real_vesting_v3_pair_rejects_reversed_shards() {
    let (_, bundle) = deploy_real_bundle();
    let verifier = IVestingBookV3BundleVerifierDispatcher { contract_address: bundle };
    let shard_0 = read_txt(@FileTrait::new("tests/proof_calldata_0.txt"));
    let shard_1 = read_txt(@FileTrait::new("tests/proof_calldata_1.txt"));
    match verifier.verify_payroll_integrity_bundle(shard_1.span(), shard_0.span()) {
        Result::Err(error) => assert(error == 'PAYO_VEST_INPUTS', 'wrong bundle error'),
        Result::Ok(_) => panic!("vesting bundle accepted reversed shards"),
    }
}
