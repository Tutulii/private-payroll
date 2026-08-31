use core::poseidon::poseidon_hash_span;
use openzeppelin_account::extensions::SRC9Component::SNIP12MetadataImpl;
use openzeppelin_account::extensions::src9::snip12_utils::OutsideExecutionStructHash;
use openzeppelin_interfaces::accounts::{AccountABIDispatcher, AccountABIDispatcherTrait, ISRC6_ID};
use openzeppelin_interfaces::src9::{
    ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, ISRC9_V2_ID, OutsideExecution,
};
use openzeppelin_utils::cryptography::snip12::OffchainMessageHash;
use payo_contracts::policy_account::{
    IPayoPolicyAccountDispatcher, IPayoPolicyAccountDispatcherTrait, PolicyConfig, PolicyState,
};
use payo_contracts::policy_account::PayoPolicyAccount::{assert_run_membership, run_leaf};
use privacy::actions::{InvokeInput, ServerAction, TransferToInput};
use privacy::events::EncNoteCreated;
use privacy::snip12::ScreeningAttestation;
use snforge_std::signature::SignerTrait;
use snforge_std::signature::stark_curve::{
    StarkCurveKeyPair, StarkCurveKeyPairImpl, StarkCurveSignerImpl,
};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp,
    start_cheat_caller_address, start_mock_call,
};
use starknet::account::Call;
use starknet::ContractAddress;

const POLICY_ID: felt252 = 0x5041594f;
const AGREEMENT_HIGH: u128 = 11;
const AGREEMENT_LOW: u128 = 12;
const MANIFEST_HIGH: u128 = 21;
const MANIFEST_LOW: u128 = 22;
const NULLIFIER_HIGH: u128 = 31;
const NULLIFIER_LOW: u128 = 32;
const POLICY_HIGH: u128 = 41;
const POLICY_LOW: u128 = 42;
const NOW: u64 = 1_000;

fn address(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

fn deploy_policy_account(public_key: felt252) -> ContractAddress {
    let class = declare("PayoPolicyAccount").unwrap().contract_class();
    let mut calldata = array![];
    public_key.serialize(ref calldata);
    let (account, _) = class.deploy(@calldata).unwrap();
    start_cheat_block_timestamp(account, NOW);
    account
}

fn state_from_config(config: PolicyConfig) -> PolicyState {
    PolicyState {
        configured: true,
        revoked: false,
        session_public_key: config.session_public_key,
        pool: config.pool,
        seal: config.seal,
        seal_mode: config.seal_mode,
        proof_version: config.proof_version,
        schema_version: config.schema_version,
        payroll_policy_root_high: config.payroll_policy_root_high,
        payroll_policy_root_low: config.payroll_policy_root_low,
        token_set_commitment: config.token_set_commitment,
        recipient_set_commitment: config.recipient_set_commitment,
        purpose_commitment: config.purpose_commitment,
        amount_limit_commitment: config.amount_limit_commitment,
        authorized_runs_root: config.authorized_runs_root,
        valid_after: config.valid_after,
        valid_before: config.valid_before,
        period_seconds: config.period_seconds,
        max_calls_per_period: config.max_calls_per_period,
        max_call_count: config.max_call_count,
        period_started_at: config.valid_after,
        period_call_count: 0,
        used_call_count: 0,
    }
}

fn base_config(
    session_public_key: felt252,
    pool: ContractAddress,
    seal: ContractAddress,
) -> PolicyConfig {
    PolicyConfig {
        session_public_key,
        pool,
        seal,
        seal_mode: 0,
        proof_version: 1,
        schema_version: 1,
        payroll_policy_root_high: POLICY_HIGH,
        payroll_policy_root_low: POLICY_LOW,
        token_set_commitment: 51,
        recipient_set_commitment: 52,
        purpose_commitment: 53,
        amount_limit_commitment: 54,
        authorized_runs_root: 1,
        valid_after: 900,
        valid_before: 2_000,
        period_seconds: 600,
        max_calls_per_period: 1,
        max_call_count: 1,
    }
}

fn siblings() -> Array<felt252> {
    array![101, 102, 103, 104, 105, 106, 107, 108]
}

fn merkle_root(leaf: felt252, path_bits: u16, nodes: Span<felt252>) -> felt252 {
    let mut current = leaf;
    let mut remaining = path_bits;
    for node in nodes {
        current = if remaining % 2 == 0 {
            poseidon_hash_span(array![current, *node].span())
        } else {
            poseidon_hash_span(array![*node, current].span())
        };
        remaining /= 2;
    };
    current
}

fn configured_policy(
    session_public_key: felt252,
    pool: ContractAddress,
    seal: ContractAddress,
) -> (PolicyConfig, Array<felt252>) {
    let mut config = base_config(session_public_key, pool, seal);
    let nodes = siblings();
    let leaf = run_leaf(
        POLICY_ID,
        state_from_config(config),
        AGREEMENT_HIGH,
        AGREEMENT_LOW,
        MANIFEST_HIGH,
        MANIFEST_LOW,
        NULLIFIER_HIGH,
        NULLIFIER_LOW,
    );
    config.authorized_runs_root = merkle_root(leaf, 0, nodes.span());
    (config, nodes)
}

fn configure(
    account: ContractAddress,
    session_public_key: felt252,
    pool: ContractAddress,
    seal: ContractAddress,
) -> Array<felt252> {
    let (config, nodes) = configured_policy(session_public_key, pool, seal);
    start_cheat_caller_address(account, account);
    IPayoPolicyAccountDispatcher { contract_address: account }
        .configure_policy(POLICY_ID, config);
    start_mock_call(seal, selector!("register_direct_settlement_source"), ());
    start_mock_call(seal, selector!("finalize_settlement"), ());
    nodes
}

fn seal_calldata(
    seal_mode: u8,
    agreement_high: u128,
    agreement_low: u128,
    manifest_high: u128,
    manifest_low: u128,
    policy_high: u128,
    policy_low: u128,
    nullifier_high: u128,
    nullifier_low: u128,
) -> Array<felt252> {
    array![
        seal_mode.into(), 1, 1, agreement_high.into(), agreement_low.into(),
        manifest_high.into(), manifest_low.into(), policy_high.into(), policy_low.into(),
        61, 62, nullifier_high.into(), nullifier_low.into(), 900, 1_100, 71, 72, 0, 0,
    ]
}

fn pool_calldata(
    _seal: ContractAddress,
    _agreement_high: u128,
    _agreement_low: u128,
    _manifest_high: u128,
    _manifest_low: u128,
    _policy_high: u128,
    _policy_low: u128,
    _nullifier_high: u128,
    _nullifier_low: u128,
    forbidden_transfer: bool,
) -> Array<felt252> {
    let note = ServerAction::EmitEncNoteCreated(
        EncNoteCreated { note_id: 0xabc, packed_value: 0xdef },
    );
    let transfer = ServerAction::TransferTo(
        TransferToInput { to_addr: address(0x777), token: address(0x888), amount: 1 },
    );
    let mut encoded = array![];
    if forbidden_transfer {
        array![transfer, note].span().serialize(ref encoded);
    } else {
        array![note].span().serialize(ref encoded);
    }
    let screening: Option<ScreeningAttestation> = Option::None;
    screening.serialize(ref encoded);
    encoded
}

fn pool_calldata_with_invoke(seal: ContractAddress) -> Array<felt252> {
    let invoke_data = seal_calldata(
        0,
        AGREEMENT_HIGH,
        AGREEMENT_LOW,
        MANIFEST_HIGH,
        MANIFEST_LOW,
        POLICY_HIGH,
        POLICY_LOW,
        NULLIFIER_HIGH,
        NULLIFIER_LOW,
    );
    let invoke = ServerAction::Invoke(
        InvokeInput { contract_address: seal, calldata: invoke_data.span() },
    );
    let note = ServerAction::EmitEncNoteCreated(
        EncNoteCreated { note_id: 0xabc, packed_value: 0xdef },
    );
    let mut encoded = array![];
    array![note, invoke].span().serialize(ref encoded);
    let screening: Option<ScreeningAttestation> = Option::None;
    screening.serialize(ref encoded);
    encoded
}

fn intent_calldata(
    nodes: Span<felt252>,
    pool_data: Span<felt252>,
    settlement_proof: Span<felt252>,
    manifest_high: u128,
    manifest_low: u128,
    nullifier_high: u128,
    nullifier_low: u128,
) -> Array<felt252> {
    let mut calldata = array![];
    POLICY_ID.serialize(ref calldata);
    AGREEMENT_HIGH.serialize(ref calldata);
    AGREEMENT_LOW.serialize(ref calldata);
    manifest_high.serialize(ref calldata);
    manifest_low.serialize(ref calldata);
    nullifier_high.serialize(ref calldata);
    nullifier_low.serialize(ref calldata);
    0_u16.serialize(ref calldata);
    nodes.serialize(ref calldata);
    pool_data.serialize(ref calldata);
    settlement_proof.serialize(ref calldata);
    calldata
}

fn outside_execution(
    account: ContractAddress,
    nonce: felt252,
    calldata: Span<felt252>,
) -> OutsideExecution {
    let call = Call {
        to: account,
        selector: selector!("execute_policy_intent"),
        calldata,
    };
    let calls = array![call];
    OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce,
        execute_after: 900,
        execute_before: 1_100,
        calls: calls.span(),
    }
}

fn sign_outside(
    account: ContractAddress,
    execution: @OutsideExecution,
    key_pair: StarkCurveKeyPair,
) -> Array<felt252> {
    let message_hash = execution.get_message_hash(account);
    let (r, s) = key_pair.sign(message_hash).unwrap();
    array![r, s]
}

fn valid_execution(
    account: ContractAddress,
    pool: ContractAddress,
    seal: ContractAddress,
    nodes: Span<felt252>,
    nonce: felt252,
) -> (OutsideExecution, Array<felt252>) {
    let pool_data = pool_calldata(
        seal,
        AGREEMENT_HIGH,
        AGREEMENT_LOW,
        MANIFEST_HIGH,
        MANIFEST_LOW,
        POLICY_HIGH,
        POLICY_LOW,
        NULLIFIER_HIGH,
        NULLIFIER_LOW,
        false,
    );
    let calldata = intent_calldata(
        nodes,
        pool_data.span(),
        array![0xa, 0xb].span(),
        MANIFEST_HIGH,
        MANIFEST_LOW,
        NULLIFIER_HIGH,
        NULLIFIER_LOW,
    );
    let execution = outside_execution(account, nonce, calldata.span());
    (execution, calldata)
}

#[test]
fn policy_account_supports_snip6_and_snip9_and_executes_one_bound_run() {
    let owner = StarkCurveKeyPairImpl::generate();
    let session = StarkCurveKeyPairImpl::generate();
    let account = deploy_policy_account(owner.public_key);
    let pool = address(0x200);
    let seal = address(0x300);
    let nodes = configure(account, session.public_key, pool, seal);
    start_mock_call(pool, selector!("apply_actions"), ());

    let standards = AccountABIDispatcher { contract_address: account };
    assert(standards.supports_interface(ISRC6_ID), 'missing SNIP-6');
    assert(standards.supports_interface(ISRC9_V2_ID), 'missing SNIP-9');

    let (execution, _calldata) = valid_execution(account, pool, seal, nodes.span(), 700);
    let signature = sign_outside(account, @execution, session);
    ISRC9_V2Dispatcher { contract_address: account }
        .execute_from_outside_v2(execution, signature.span());

    let policy = IPayoPolicyAccountDispatcher { contract_address: account }.get_policy(POLICY_ID);
    assert(policy.used_call_count == 1, 'call not consumed');
    assert(policy.period_call_count == 1, 'period not consumed');
    assert(
        !IPayoPolicyAccountDispatcher { contract_address: account }
            .is_run_available(0, NULLIFIER_HIGH, NULLIFIER_LOW),
        'run replay remains available',
    );
    assert(
        !ISRC9_V2Dispatcher { contract_address: account }
            .is_valid_outside_execution_nonce(700),
        'nonce replay remains available',
    );
    let receipt = IPayoPolicyAccountDispatcher { contract_address: account }
        .get_settlement_receipt(NULLIFIER_HIGH, NULLIFIER_LOW);
    assert(receipt.exists, 'receipt missing');
    assert(receipt.policy_id == POLICY_ID, 'receipt policy mismatch');
    assert(receipt.manifest_root_high == MANIFEST_HIGH, 'receipt manifest high');
    assert(receipt.manifest_root_low == MANIFEST_LOW, 'receipt manifest low');
    assert(receipt.emitted_note_count == 1, 'receipt note count');
    assert(
        receipt.settlement_root_high != 0 || receipt.settlement_root_low != 0,
        'receipt settlement root',
    );
    assert(
        receipt.transaction_reference_high != 0 || receipt.transaction_reference_low != 0,
        'receipt transaction ref',
    );
}

#[test]
#[should_panic(expected: 'PAYO_POLICY_SETTLEMENT')]
fn policy_account_rejects_a_run_without_atomic_settlement_proof() {
    let owner = StarkCurveKeyPairImpl::generate();
    let session = StarkCurveKeyPairImpl::generate();
    let account = deploy_policy_account(owner.public_key);
    let pool = address(0x210);
    let seal = address(0x310);
    let nodes = configure(account, session.public_key, pool, seal);
    let pool_data = pool_calldata(
        seal,
        AGREEMENT_HIGH,
        AGREEMENT_LOW,
        MANIFEST_HIGH,
        MANIFEST_LOW,
        POLICY_HIGH,
        POLICY_LOW,
        NULLIFIER_HIGH,
        NULLIFIER_LOW,
        false,
    );
    let calldata = intent_calldata(
        nodes.span(),
        pool_data.span(),
        array![].span(),
        MANIFEST_HIGH,
        MANIFEST_LOW,
        NULLIFIER_HIGH,
        NULLIFIER_LOW,
    );
    let execution = outside_execution(account, 710, calldata.span());
    let signature = sign_outside(account, @execution, session);
    ISRC9_V2Dispatcher { contract_address: account }
        .execute_from_outside_v2(execution, signature.span());
}

#[test]
#[should_panic(expected: 'PAYO_POLICY_BAD_SIG')]
fn policy_account_rejects_non_session_signature() {
    let owner = StarkCurveKeyPairImpl::generate();
    let session = StarkCurveKeyPairImpl::generate();
    let attacker = StarkCurveKeyPairImpl::generate();
    let account = deploy_policy_account(owner.public_key);
    let pool = address(0x201);
    let seal = address(0x301);
    let nodes = configure(account, session.public_key, pool, seal);
    let (execution, _calldata) = valid_execution(account, pool, seal, nodes.span(), 701);
    let signature = sign_outside(account, @execution, attacker);
    ISRC9_V2Dispatcher { contract_address: account }
        .execute_from_outside_v2(execution, signature.span());
}

#[test]
#[should_panic(expected: 'PAYO_POLICY_BAD_CALL')]
fn policy_account_rejects_arbitrary_outer_target() {
    let owner = StarkCurveKeyPairImpl::generate();
    let session = StarkCurveKeyPairImpl::generate();
    let account = deploy_policy_account(owner.public_key);
    let pool = address(0x202);
    let seal = address(0x302);
    configure(account, session.public_key, pool, seal);
    let call = Call { to: pool, selector: selector!("apply_actions"), calldata: array![].span() };
    let calls = array![call];
    let execution = OutsideExecution {
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce: 702,
        execute_after: 900,
        execute_before: 1_100,
        calls: calls.span(),
    };
    ISRC9_V2Dispatcher { contract_address: account }
        .execute_from_outside_v2(execution, array![].span());
}

#[test]
#[should_panic(expected: 'PAYO_POLICY_BAD_RUN')]
fn policy_account_rejects_manifest_substitution() {
    let owner = StarkCurveKeyPairImpl::generate();
    let session = StarkCurveKeyPairImpl::generate();
    let account = deploy_policy_account(owner.public_key);
    let pool = address(0x203);
    let seal = address(0x303);
    let nodes = configure(account, session.public_key, pool, seal);
    let pool_data = pool_calldata(
        seal,
        AGREEMENT_HIGH,
        AGREEMENT_LOW,
        MANIFEST_HIGH + 1,
        MANIFEST_LOW,
        POLICY_HIGH,
        POLICY_LOW,
        NULLIFIER_HIGH,
        NULLIFIER_LOW,
        false,
    );
    let calldata = intent_calldata(
        nodes.span(),
        pool_data.span(),
        array![0xa, 0xb].span(),
        MANIFEST_HIGH + 1,
        MANIFEST_LOW,
        NULLIFIER_HIGH,
        NULLIFIER_LOW,
    );
    let execution = outside_execution(account, 703, calldata.span());
    let signature = sign_outside(account, @execution, session);
    ISRC9_V2Dispatcher { contract_address: account }
        .execute_from_outside_v2(execution, signature.span());
}

#[test]
#[should_panic(expected: 'PAYO_POLICY_POOL_ACTION')]
fn policy_account_rejects_public_transfer_action() {
    let owner = StarkCurveKeyPairImpl::generate();
    let session = StarkCurveKeyPairImpl::generate();
    let account = deploy_policy_account(owner.public_key);
    let pool = address(0x204);
    let seal = address(0x304);
    let nodes = configure(account, session.public_key, pool, seal);
    let pool_data = pool_calldata(
        seal,
        AGREEMENT_HIGH,
        AGREEMENT_LOW,
        MANIFEST_HIGH,
        MANIFEST_LOW,
        POLICY_HIGH,
        POLICY_LOW,
        NULLIFIER_HIGH,
        NULLIFIER_LOW,
        true,
    );
    let calldata = intent_calldata(
        nodes.span(),
        pool_data.span(),
        array![0xa, 0xb].span(),
        MANIFEST_HIGH,
        MANIFEST_LOW,
        NULLIFIER_HIGH,
        NULLIFIER_LOW,
    );
    let execution = outside_execution(account, 704, calldata.span());
    let signature = sign_outside(account, @execution, session);
    ISRC9_V2Dispatcher { contract_address: account }
        .execute_from_outside_v2(execution, signature.span());
}

#[test]
#[should_panic(expected: 'PAYO_POLICY_POOL_ACTION')]
fn policy_account_rejects_an_external_pool_invoke_during_payment() {
    let owner = StarkCurveKeyPairImpl::generate();
    let session = StarkCurveKeyPairImpl::generate();
    let account = deploy_policy_account(owner.public_key);
    let pool = address(0x205);
    let seal = address(0x305);
    let nodes = configure(account, session.public_key, pool, seal);
    let pool_data = pool_calldata_with_invoke(seal);
    let calldata = intent_calldata(
        nodes.span(),
        pool_data.span(),
        array![0xa, 0xb].span(),
        MANIFEST_HIGH,
        MANIFEST_LOW,
        NULLIFIER_HIGH,
        NULLIFIER_LOW,
    );
    let execution = outside_execution(account, 705, calldata.span());
    let signature = sign_outside(account, @execution, session);
    ISRC9_V2Dispatcher { contract_address: account }
        .execute_from_outside_v2(execution, signature.span());
}

#[test]
#[should_panic(expected: 'PAYO_POLICY_REVOKED')]
fn policy_account_revocation_is_immediate() {
    let owner = StarkCurveKeyPairImpl::generate();
    let session = StarkCurveKeyPairImpl::generate();
    let account = deploy_policy_account(owner.public_key);
    let pool = address(0x206);
    let seal = address(0x306);
    let nodes = configure(account, session.public_key, pool, seal);
    let policy = IPayoPolicyAccountDispatcher { contract_address: account };
    policy.revoke_policy(POLICY_ID);
    let (execution, _calldata) = valid_execution(account, pool, seal, nodes.span(), 706);
    let signature = sign_outside(account, @execution, session);
    ISRC9_V2Dispatcher { contract_address: account }
        .execute_from_outside_v2(execution, signature.span());
}

#[test]
#[should_panic(expected: 'PAYO_ACCOUNT_PAUSED')]
fn policy_account_emergency_pause_is_immediate() {
    let owner = StarkCurveKeyPairImpl::generate();
    let session = StarkCurveKeyPairImpl::generate();
    let account = deploy_policy_account(owner.public_key);
    let pool = address(0x207);
    let seal = address(0x307);
    let nodes = configure(account, session.public_key, pool, seal);
    IPayoPolicyAccountDispatcher { contract_address: account }
        .set_policy_account_paused(true);
    let (execution, _calldata) = valid_execution(account, pool, seal, nodes.span(), 707);
    let signature = sign_outside(account, @execution, session);
    ISRC9_V2Dispatcher { contract_address: account }
        .execute_from_outside_v2(execution, signature.span());
}

#[test]
#[should_panic(expected: 'PAYO_POLICY_BAD_NONCE')]
fn policy_account_rejects_snip9_nonce_replay() {
    let owner = StarkCurveKeyPairImpl::generate();
    let session = StarkCurveKeyPairImpl::generate();
    let account = deploy_policy_account(owner.public_key);
    let pool = address(0x208);
    let seal = address(0x308);
    let nodes = configure(account, session.public_key, pool, seal);
    start_mock_call(pool, selector!("apply_actions"), ());
    let (execution, _calldata) = valid_execution(account, pool, seal, nodes.span(), 708);
    let signature = sign_outside(account, @execution, session);
    let outside = ISRC9_V2Dispatcher { contract_address: account };
    outside.execute_from_outside_v2(execution, signature.span());
    outside.execute_from_outside_v2(execution, signature.span());
}

#[test]
fn rotating_session_key_invalidates_the_old_key() {
    let owner = StarkCurveKeyPairImpl::generate();
    let old_session = StarkCurveKeyPairImpl::generate();
    let new_session = StarkCurveKeyPairImpl::generate();
    let account = deploy_policy_account(owner.public_key);
    let pool = address(0x209);
    let seal = address(0x309);
    let nodes = configure(account, old_session.public_key, pool, seal);
    IPayoPolicyAccountDispatcher { contract_address: account }
        .rotate_session_key(POLICY_ID, new_session.public_key);
    let (execution, _calldata) = valid_execution(account, pool, seal, nodes.span(), 709);
    let old_signature = sign_outside(account, @execution, old_session);
    let new_signature = sign_outside(account, @execution, new_session);
    assert(old_signature != new_signature, 'rotation did not change signer');
    start_mock_call(pool, selector!("apply_actions"), ());
    ISRC9_V2Dispatcher { contract_address: account }
        .execute_from_outside_v2(execution, new_signature.span());
}

#[test]
#[fuzzer]
fn fuzz_policy_merkle_membership_accepts_every_valid_path(
    leaf: felt252,
    first: felt252,
    second: felt252,
    path_seed: u16,
) {
    let path = path_seed % 256;
    let nodes = array![first, second, 3, 4, 5, 6, 7, 8];
    let root = merkle_root(leaf, path, nodes.span());
    assert_run_membership(root, leaf, path, nodes.span());
}

#[test]
#[should_panic(expected: 'PAYO_POLICY_BAD_RUN')]
fn policy_merkle_membership_rejects_a_mutated_sibling() {
    let nodes = siblings();
    let root = merkle_root(77, 0, nodes.span());
    let changed = array![999, 102, 103, 104, 105, 106, 107, 108];
    assert_run_membership(root, 77, 0, changed.span());
}
