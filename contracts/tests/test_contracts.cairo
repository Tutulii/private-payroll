use core::serde::Serde;
use payo_contracts::commitments::{
    build_fixed_merkle_root_v1, derive_run_nullifier_v1, hash_deductions_commitment,
    hash_payroll_leaf_v1, hash_recipient_commitment, hash_text_commitment,
};
use payo_contracts::integrity_bundle_verifier::{
    IIntegrityBundleVerifierDispatcher, IIntegrityBundleVerifierDispatcherTrait,
};
use payo_contracts::payroll_seal::{IPayoPayrollSealDispatcher, IPayoPayrollSealDispatcherTrait};
use payo_contracts::policy_registry::{
    IPayoPolicyRegistryDispatcher, IPayoPolicyRegistryDispatcherTrait,
};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp,
    start_cheat_caller_address, start_mock_call,
};
use starknet::ContractAddress;

fn address(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

#[test]
fn cairo_commitments_match_typescript_and_noir_golden_vector() {
    let agreement_id: ByteArray = "agreement-0001";
    let agreement_domain: ByteArray = "PAYO_AGREEMENT_ID_V1";
    let policy_id: ByteArray = "us-reference-2026";
    let policy_domain: ByteArray = "PAYO_POLICY_ID_V1";
    let agreement = hash_text_commitment(@agreement_domain, @agreement_id);
    let recipient = hash_recipient_commitment(
        0x123, 0x2222222222222222222222222222222222222222222222222222222222222222,
    );
    let deductions = hash_deductions_commitment(array![100000_u128].span());
    let policy = hash_text_commitment(@policy_domain, @policy_id);

    assert(
        agreement == 0xd6bc9793865951208b221948860299f08890e5c6feabbadb2ae9f032765185d8,
        'agreement vector',
    );
    assert(
        recipient == 0x048f6be0cd5ce871550de4d16d62e348f5b7921c5d91f88fc9208f9511561657,
        'recipient vector',
    );
    assert(
        deductions == 0x9291605e0e11b42a504afc2584de5e8441dc8e3cbc53b764f91de8158a57bbc6,
        'deduction vector',
    );
    assert(
        policy == 0x832ef507641982f4aeb40961659420fa2d322541aae98b3a1c10a8d27af101f5,
        'policy vector',
    );

    let leaf = hash_payroll_leaf_v1(
        1,
        agreement,
        recipient,
        1250000,
        deductions,
        1150000,
        0x033068f6539f8e6e6b131e6b2b814e6c34a5224bc66947c47dab9dfee93b35fb,
        policy,
        0x1111111111111111111111111111111111111111111111111111111111111111,
        0x2222222222222222222222222222222222222222222222222222222222222222,
    );
    assert(
        leaf == 0xe394b47d5c724e6465a5e1a522d59c20f23aa7873dad33b2cac8b50272212601, 'leaf vector',
    );
    assert(
        build_fixed_merkle_root_v1(
            array![leaf].span(),
        ) == 0x55da98eff253e037ce7bf03f8f94b12054798583aba812138ca6624d924f3285,
        'root vector',
    );
    let cycle_id: ByteArray = "2026-08";
    assert(
        derive_run_nullifier_v1(
            0x3333333333333333333333333333333333333333333333333333333333333333, @cycle_id, 1,
        ) == 0x3ede22d5b89481904d24ad09eae7666c741f14346daf50c5832a5b4aad4ab9ca,
        'nullifier vector',
    );
}

fn deploy_seal(
    pool: ContractAddress, verifier: ContractAddress, chain_id: felt252,
) -> ContractAddress {
    let contract = declare("PayoPayrollSeal").unwrap().contract_class();
    let mut calldata = array![];
    pool.serialize(ref calldata);
    verifier.serialize(ref calldata);
    chain_id.serialize(ref calldata);
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    contract_address
}

fn deploy_bundle_verifier(underlying: ContractAddress) -> ContractAddress {
    let contract = declare("PayoIntegrityBundleVerifier").unwrap().contract_class();
    let mut calldata = array![];
    underlying.serialize(ref calldata);
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    contract_address
}

#[test]
fn bundle_verifier_calls_the_proof_bound_verifier_for_both_shards() {
    let underlying = address(2000);
    let bundle = deploy_bundle_verifier(underlying);
    let shard_inputs: Array<u256> = array![11_u256, 22_u256];
    start_mock_call(
        underlying,
        selector!("verify_ultra_keccak_zk_honk_proof"),
        Result::<Span<u256>, felt252>::Ok(shard_inputs.span()),
    );

    let dispatcher = IIntegrityBundleVerifierDispatcher { contract_address: bundle };
    let proof: Array<felt252> = array![123];
    let combined = dispatcher.verify_payroll_integrity_bundle(proof.span(), proof.span()).unwrap();
    assert(combined.len() == 4, 'bundle input count');
    assert(*combined.at(0) == 11, 'shard zero first');
    assert(*combined.at(1) == 22, 'shard zero second');
    assert(*combined.at(2) == 11, 'shard one first');
    assert(*combined.at(3) == 22, 'shard one second');
    assert(dispatcher.get_underlying_verifier() == underlying, 'wrong underlying verifier');
}

#[test]
fn bundle_verifier_propagates_the_underlying_verifier_error() {
    let underlying = address(2000);
    let bundle = deploy_bundle_verifier(underlying);
    start_mock_call(
        underlying,
        selector!("verify_ultra_keccak_zk_honk_proof"),
        Result::<Span<u256>, felt252>::Err('INVALID_PROOF'),
    );

    let dispatcher = IIntegrityBundleVerifierDispatcher { contract_address: bundle };
    let proof: Array<felt252> = array![];
    match dispatcher.verify_payroll_integrity_bundle(proof.span(), proof.span()) {
        Result::Err(error) => assert(error == 'INVALID_PROOF', 'wrong verifier error'),
        Result::Ok(_) => panic!("bundle accepted an invalid proof"),
    }
}

#[test]
// Foundry surfaces constructor assertion failures through the deploy Result.
#[should_panic(expected: ('Result::unwrap failed.',))]
fn bundle_verifier_rejects_a_zero_underlying_address() {
    let _ = deploy_bundle_verifier(address(0));
}

fn valid_public_inputs(seal: ContractAddress, chain_id: felt252, shard_index: u8) -> Array<u256> {
    let seal_felt: felt252 = seal.into();
    array![
        chain_id.into(), seal_felt.into(), 1_u32.into(), 1_u32.into(), 11_u128.into(),
        12_u128.into(), 21_u128.into(), 22_u128.into(), 41_u128.into(), 42_u128.into(),
        51_u128.into(), 52_u128.into(), 31_u128.into(), 32_u128.into(), 100_u64.into(),
        200_u64.into(), shard_index.into(),
    ]
}

fn valid_bundle_inputs(seal: ContractAddress, chain_id: felt252) -> Array<u256> {
    let shard_0 = valid_public_inputs(seal, chain_id, 0);
    let shard_1 = valid_public_inputs(seal, chain_id, 1);
    let mut bundle = array![];
    for input in shard_0 {
        bundle.append(input);
    }
    for input in shard_1 {
        bundle.append(input);
    }
    bundle
}

fn duplicate_shard_zero_inputs(seal: ContractAddress, chain_id: felt252) -> Array<u256> {
    let shard_0 = valid_public_inputs(seal, chain_id, 0);
    let mut bundle = array![];
    for input in shard_0 {
        bundle.append(input);
    }
    let duplicate = valid_public_inputs(seal, chain_id, 0);
    for input in duplicate {
        bundle.append(input);
    }
    bundle
}

#[test]
fn pool_can_seal_a_valid_proof_and_nullifier() {
    let pool = address(1000);
    let verifier = address(2000);
    let chain_id = 'SN_MAIN';
    let seal = deploy_seal(pool, verifier, chain_id);
    let inputs = valid_bundle_inputs(seal, chain_id);
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_bundle"),
        Result::<Span<u256>, felt252>::Ok(inputs.span()),
    );
    start_cheat_caller_address(seal, pool);
    start_cheat_block_timestamp(seal, 150);

    let dispatcher = IPayoPayrollSealDispatcher { contract_address: seal };
    let proof: Array<felt252> = array![];
    let deposits = dispatcher
        .privacy_invoke(
            0, 1, 1, 11, 12, 21, 22, 41, 42, 51, 52, 31, 32, 100, 200, proof.span(), proof.span(),
        );

    assert(deposits.is_empty(), 'seal must not custody');
    assert(dispatcher.get_run_status(31, 32) == 1, 'run not proven');
}

#[test]
#[should_panic(expected: ('PAYO_PUBLIC_INPUTS',))]
fn rejects_proof_with_mismatched_public_inputs() {
    let pool = address(1000);
    let verifier = address(2000);
    let chain_id = 'SN_MAIN';
    let seal = deploy_seal(pool, verifier, chain_id);
    let valid_inputs = valid_bundle_inputs(seal, chain_id);
    let mut inputs: Array<u256> = array![];
    for index in 0..valid_inputs.len() {
        inputs.append(if index == 6 {
            999_u256
        } else {
            *valid_inputs.at(index)
        });
    }
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_bundle"),
        Result::<Span<u256>, felt252>::Ok(inputs.span()),
    );
    start_cheat_caller_address(seal, pool);
    start_cheat_block_timestamp(seal, 150);

    let dispatcher = IPayoPayrollSealDispatcher { contract_address: seal };
    let proof: Array<felt252> = array![];
    dispatcher
        .privacy_invoke(
            0, 1, 1, 11, 12, 21, 22, 41, 42, 51, 52, 31, 32, 100, 200, proof.span(), proof.span(),
        );
}

#[test]
#[should_panic(expected: ('PAYO_PUBLIC_INPUTS',))]
fn rejects_proof_with_wrong_public_input_count() {
    let pool = address(1000);
    let verifier = address(2000);
    let seal = deploy_seal(pool, verifier, 'SN_MAIN');
    let short_inputs: Array<u256> = array![1_u256];
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_bundle"),
        Result::<Span<u256>, felt252>::Ok(short_inputs.span()),
    );
    start_cheat_caller_address(seal, pool);
    start_cheat_block_timestamp(seal, 150);

    let dispatcher = IPayoPayrollSealDispatcher { contract_address: seal };
    let proof: Array<felt252> = array![];
    dispatcher
        .privacy_invoke(
            0, 1, 1, 11, 12, 21, 22, 41, 42, 51, 52, 31, 32, 100, 200, proof.span(), proof.span(),
        );
}

#[test]
#[should_panic(expected: ('PAYO_PUBLIC_INPUTS',))]
fn rejects_duplicate_shard_zero_bundle() {
    let pool = address(1000);
    let verifier = address(2000);
    let chain_id = 'SN_MAIN';
    let seal = deploy_seal(pool, verifier, chain_id);
    let inputs = duplicate_shard_zero_inputs(seal, chain_id);
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_bundle"),
        Result::<Span<u256>, felt252>::Ok(inputs.span()),
    );
    start_cheat_caller_address(seal, pool);
    start_cheat_block_timestamp(seal, 150);

    let dispatcher = IPayoPayrollSealDispatcher { contract_address: seal };
    let proof: Array<felt252> = array![];
    dispatcher
        .privacy_invoke(
            0, 1, 1, 11, 12, 21, 22, 41, 42, 51, 52, 31, 32, 100, 200, proof.span(), proof.span(),
        );
}

#[test]
#[should_panic(expected: ('PAYO_PROOF_FAILED',))]
fn rejects_verifier_failure() {
    let pool = address(1000);
    let verifier = address(2000);
    let seal = deploy_seal(pool, verifier, 'SN_MAIN');
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_bundle"),
        Result::<Span<u256>, felt252>::Err('INVALID_PROOF'),
    );
    start_cheat_caller_address(seal, pool);
    start_cheat_block_timestamp(seal, 150);

    let dispatcher = IPayoPayrollSealDispatcher { contract_address: seal };
    let proof: Array<felt252> = array![];
    dispatcher
        .privacy_invoke(
            0, 1, 1, 11, 12, 21, 22, 41, 42, 51, 52, 31, 32, 100, 200, proof.span(), proof.span(),
        );
}

#[test]
#[should_panic(expected: ('PAYO_BAD_POOL',))]
fn rejects_direct_non_pool_calls() {
    let pool = address(1000);
    let verifier = address(2000);
    let seal = deploy_seal(pool, verifier, 'SN_MAIN');
    start_cheat_caller_address(seal, address(9999));
    start_cheat_block_timestamp(seal, 150);
    let dispatcher = IPayoPayrollSealDispatcher { contract_address: seal };
    let proof: Array<felt252> = array![];
    dispatcher
        .privacy_invoke(
            0, 1, 1, 11, 12, 21, 22, 41, 42, 51, 52, 31, 32, 100, 200, proof.span(), proof.span(),
        );
}

#[test]
#[should_panic(expected: ('PAYO_REPLAY',))]
fn rejects_replayed_run_nullifiers() {
    let pool = address(1000);
    let verifier = address(2000);
    let chain_id = 'SN_MAIN';
    let seal = deploy_seal(pool, verifier, chain_id);
    let inputs = valid_bundle_inputs(seal, chain_id);
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_bundle"),
        Result::<Span<u256>, felt252>::Ok(inputs.span()),
    );
    start_cheat_caller_address(seal, pool);
    start_cheat_block_timestamp(seal, 150);
    let dispatcher = IPayoPayrollSealDispatcher { contract_address: seal };
    let proof: Array<felt252> = array![];
    dispatcher
        .privacy_invoke(
            0, 1, 1, 11, 12, 21, 22, 41, 42, 51, 52, 31, 32, 100, 200, proof.span(), proof.span(),
        );
    dispatcher
        .privacy_invoke(
            0, 1, 1, 11, 12, 21, 22, 41, 42, 51, 52, 31, 32, 100, 200, proof.span(), proof.span(),
        );
}

#[test]
fn policy_roots_activate_only_inside_their_window() {
    let admin = address(1234);
    let contract = declare("PayoPolicyRegistry").unwrap().contract_class();
    let mut calldata = array![];
    admin.serialize(ref calldata);
    let (registry, _) = contract.deploy(@calldata).unwrap();
    start_cheat_caller_address(registry, admin);
    start_cheat_block_timestamp(registry, 100);
    let dispatcher = IPayoPolicyRegistryDispatcher { contract_address: registry };
    dispatcher.schedule_policy_root(1, 2, 86500, 90000);

    assert(!dispatcher.is_policy_root_valid(1, 2), 'root active before delay');
    start_cheat_block_timestamp(registry, 87000);
    assert(dispatcher.is_policy_root_valid(1, 2), 'root not active');
    dispatcher.revoke_policy_root(1, 2);
    assert(!dispatcher.is_policy_root_valid(1, 2), 'revocation ignored');
}
