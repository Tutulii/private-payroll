use core::serde::Serde;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp,
    start_cheat_caller_address, start_mock_call,
};
use starknet::ContractAddress;
use payo_contracts::payroll_seal::{IPayoPayrollSealDispatcher, IPayoPayrollSealDispatcherTrait};
use payo_contracts::policy_registry::{
    IPayoPolicyRegistryDispatcher, IPayoPolicyRegistryDispatcherTrait,
};

fn address(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

fn deploy_seal(pool: ContractAddress, verifier: ContractAddress, chain_id: felt252) -> ContractAddress {
    let contract = declare("PayoPayrollSeal").unwrap().contract_class();
    let mut calldata = array![];
    pool.serialize(ref calldata);
    verifier.serialize(ref calldata);
    chain_id.serialize(ref calldata);
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    contract_address
}

fn valid_public_inputs(seal: ContractAddress, chain_id: felt252) -> Array<u256> {
    let seal_felt: felt252 = seal.into();
    array![
        chain_id.into(),
        seal_felt.into(),
        1_u32.into(),
        11_u128.into(),
        12_u128.into(),
        21_u128.into(),
        22_u128.into(),
        31_u128.into(),
        32_u128.into(),
        100_u64.into(),
        200_u64.into(),
    ]
}

#[test]
fn pool_can_seal_a_valid_proof_and_nullifier() {
    let pool = address(1000);
    let verifier = address(2000);
    let chain_id = 'SN_MAIN';
    let seal = deploy_seal(pool, verifier, chain_id);
    let inputs = valid_public_inputs(seal, chain_id);
    start_mock_call(
        verifier,
        selector!("verify_ultra_keccak_zk_honk_proof"),
        Result::<Span<u256>, felt252>::Ok(inputs.span()),
    );
    start_cheat_caller_address(seal, pool);
    start_cheat_block_timestamp(seal, 150);

    let dispatcher = IPayoPayrollSealDispatcher { contract_address: seal };
    let proof: Array<felt252> = array![];
    let deposits = dispatcher.privacy_invoke(0, 1, 11, 12, 21, 22, 31, 32, 100, 200, proof.span());

    assert(deposits.is_empty(), 'seal must not custody');
    assert(dispatcher.get_run_status(31, 32) == 1, 'run not proven');
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
    dispatcher.privacy_invoke(0, 1, 11, 12, 21, 22, 31, 32, 100, 200, proof.span());
}

#[test]
#[should_panic(expected: ('PAYO_REPLAY',))]
fn rejects_replayed_run_nullifiers() {
    let pool = address(1000);
    let verifier = address(2000);
    let chain_id = 'SN_MAIN';
    let seal = deploy_seal(pool, verifier, chain_id);
    let inputs = valid_public_inputs(seal, chain_id);
    start_mock_call(
        verifier,
        selector!("verify_ultra_keccak_zk_honk_proof"),
        Result::<Span<u256>, felt252>::Ok(inputs.span()),
    );
    start_cheat_caller_address(seal, pool);
    start_cheat_block_timestamp(seal, 150);
    let dispatcher = IPayoPayrollSealDispatcher { contract_address: seal };
    let proof: Array<felt252> = array![];
    dispatcher.privacy_invoke(0, 1, 11, 12, 21, 22, 31, 32, 100, 200, proof.span());
    dispatcher.privacy_invoke(0, 1, 11, 12, 21, 22, 31, 32, 100, 200, proof.span());
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
