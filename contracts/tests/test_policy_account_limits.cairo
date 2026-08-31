use openzeppelin_interfaces::src9::OutsideExecution;
use payo_contracts::policy_account::{IPayoPolicyAccount, PolicyState};
use payo_contracts::policy_account::PayoPolicyAccount::{
    OutsideExecutionV2Impl, PolicyImpl,
};
use snforge_std::{start_cheat_block_timestamp_global, start_cheat_caller_address, test_address};
use starknet::account::Call;
use starknet::storage::{
    StorageMapWriteAccess, StoragePointerWriteAccess,
};

const POLICY_ID: felt252 = 0x5041594f;

fn policy(used: u32, period_used: u32) -> PolicyState {
    PolicyState {
        configured: true,
        revoked: false,
        session_public_key: 11,
        pool: 22.try_into().unwrap(),
        seal: 33.try_into().unwrap(),
        seal_mode: 0,
        proof_version: 1,
        schema_version: 1,
        payroll_policy_root_high: 1,
        payroll_policy_root_low: 2,
        token_set_commitment: 3,
        recipient_set_commitment: 4,
        purpose_commitment: 5,
        amount_limit_commitment: 6,
        authorized_runs_root: 7,
        valid_after: 900,
        valid_before: 2_000,
        period_seconds: 600,
        max_calls_per_period: 1,
        max_call_count: 1,
        period_started_at: 900,
        period_call_count: period_used,
        used_call_count: used,
    }
}

#[test]
#[should_panic(expected: 'PAYO_POLICY_CALL_LIMIT')]
fn total_call_limit_fails_before_signature_or_execution() {
    let mut state = payo_contracts::policy_account::PayoPolicyAccount::contract_state_for_testing();
    state.policies.write(POLICY_ID, policy(1, 0));
    start_cheat_block_timestamp_global(1_000);
    let calldata = array![POLICY_ID];
    let call = Call {
        to: test_address(),
        selector: selector!("execute_policy_intent"),
        calldata: calldata.span(),
    };
    let calls = array![call];
    let execution = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 1,
        execute_after: 900,
        execute_before: 1_100,
        calls: calls.span(),
    };
    state.execute_from_outside_v2(execution, array![].span());
}

#[test]
#[should_panic(expected: 'PAYO_POLICY_PERIOD_LIMIT')]
fn period_limit_fails_before_run_or_pool_processing() {
    let mut state = payo_contracts::policy_account::PayoPolicyAccount::contract_state_for_testing();
    state.policies.write(POLICY_ID, policy(0, 1));
    state.executing.write(true);
    state.active_policy_id.write(POLICY_ID);
    start_cheat_block_timestamp_global(1_000);
    start_cheat_caller_address(test_address(), test_address());
    state.execute_policy_intent(
        POLICY_ID,
        1,
        2,
        3,
        4,
        5,
        6,
        0,
        array![].span(),
        array![].span(),
        array![].span(),
    );
}
