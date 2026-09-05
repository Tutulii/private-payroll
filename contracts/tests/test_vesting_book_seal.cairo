use core::poseidon::poseidon_hash_span;
use core::serde::Serde;
use payo_contracts::vesting_book_seal::{
    IPayoVestingBookSealDispatcher, IPayoVestingBookSealDispatcherTrait,
    VestingPayrollProofState, VestingTransitionProofState,
};
use payo_contracts::payroll_exception_seal::{
    AcceptedClaimRecord, ObligationSnapshotRecord, RemediationAttemptRecord,
};
use payo_contracts::policy_registry::{
    IPayoPolicyRegistryDispatcher, IPayoPolicyRegistryDispatcherTrait,
};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp,
    start_cheat_caller_address, start_mock_call,
};
use starknet::ContractAddress;

fn address(value: felt252) -> ContractAddress { value.try_into().unwrap() }

fn deploy_seal(
    pool: ContractAddress, verifier: ContractAddress, owner: ContractAddress,
) -> ContractAddress {
    let contract = declare("PayoVestingBookSeal").unwrap().contract_class();
    let catalog = address(9300);
    let obligations = address(9400);
    let exception_seal = address(9450);
    let mut calldata = array![];
    pool.serialize(ref calldata);
    catalog.serialize(ref calldata);
    obligations.serialize(ref calldata);
    exception_seal.serialize(ref calldata);
    'SN_MAIN'.serialize(ref calldata);
    let (seal, _) = contract.deploy(@calldata).unwrap();
    start_mock_call(catalog, selector!("is_policy_root_valid"), true);
    start_mock_call(catalog, selector!("is_fx_root_valid"), true);
    start_mock_call(catalog, selector!("is_verifier_valid"), true);
    start_mock_call(catalog, selector!("get_verifier"), verifier);
    start_mock_call(obligations, selector!("is_obligation_root_valid"), true);
    start_mock_call(obligations, selector!("get_obligation_root_owner"), owner);
    start_cheat_block_timestamp(seal, 150);
    seal
}

fn deploy_seal_with_real_catalog(
    pool: ContractAddress,
    verifier: ContractAddress,
    owner: ContractAddress,
    admin: ContractAddress,
) -> (ContractAddress, ContractAddress) {
    let registry_class = declare("PayoPolicyRegistry").unwrap().contract_class();
    let mut registry_calldata = array![];
    admin.serialize(ref registry_calldata);
    let (catalog, _) = registry_class.deploy(@registry_calldata).unwrap();
    start_cheat_block_timestamp(catalog, 150);
    start_cheat_caller_address(catalog, admin);
    let registry = IPayoPolicyRegistryDispatcher { contract_address: catalog };
    registry.schedule_policy_root(31, 32, 0, 1000);
    registry.schedule_policy_root(201, 202, 0, 1000);
    registry.schedule_fx_root(41, 42, 0, 1000);
    registry.schedule_verifier(0, 2, verifier, 0, 1000);
    registry.schedule_verifier(0, 3, verifier, 0, 1000);

    let contract = declare("PayoVestingBookSeal").unwrap().contract_class();
    let obligations = address(9400);
    let exception_seal = address(9450);
    let mut calldata = array![];
    pool.serialize(ref calldata);
    catalog.serialize(ref calldata);
    obligations.serialize(ref calldata);
    exception_seal.serialize(ref calldata);
    'SN_MAIN'.serialize(ref calldata);
    let (seal, _) = contract.deploy(@calldata).unwrap();
    start_mock_call(obligations, selector!("is_obligation_root_valid"), true);
    start_mock_call(obligations, selector!("get_obligation_root_owner"), owner);
    start_cheat_block_timestamp(seal, 150);
    (seal, catalog)
}

fn payroll(run_low: u128) -> VestingPayrollProofState {
    VestingPayrollProofState {
        proof_version: 2,
        schema_version: 1,
        agreement_root_high: 11,
        agreement_root_low: 12,
        manifest_root_high: 21,
        manifest_root_low: 22,
        policy_root_high: 31,
        policy_root_low: 32,
        fx_root_high: 41,
        fx_root_low: 42,
        run_nullifier_high: 51,
        run_nullifier_low: run_low,
        validity_start: 100,
        validity_expiry: 200,
    }
}

fn transition(
    seal: ContractAddress,
    owner: ContractAddress,
    run_low: u128,
    previous_high: u128,
    previous_low: u128,
    next_high: u128,
    next_low: u128,
) -> VestingTransitionProofState {
    VestingTransitionProofState {
        proof_version: 3,
        schema_version: 1,
        entry_kind: 1,
        agreement_root_high: 11,
        agreement_root_low: 12,
        manifest_root_high: 21,
        manifest_root_low: 22,
        policy_root_high: 31,
        policy_root_low: 32,
        fx_root_high: 41,
        fx_root_low: 42,
        run_nullifier_high: 51,
        run_nullifier_low: run_low,
        subject_nullifier_high: 51,
        subject_nullifier_low: run_low,
        parent_fact_high: 0,
        parent_fact_low: 0,
        fact_high: 0,
        fact_low: 0,
        owner,
        source_seal: seal,
        source_proof_version: 2,
        attestation_root_high: 0,
        attestation_root_low: 0,
        shard_0_contributor_count: 1,
        shard_1_contributor_count: 0,
        totals_disclosed: 1,
        totals_commitment_high: 101,
        totals_commitment_low: 102,
        shard_0_strk_gross: 100,
        shard_0_strk_deductions: 10,
        shard_0_strk_net: 90,
        shard_0_usdc_gross: 0,
        shard_0_usdc_deductions: 0,
        shard_0_usdc_net: 0,
        shard_1_strk_gross: 0,
        shard_1_strk_deductions: 0,
        shard_1_strk_net: 0,
        shard_1_usdc_gross: 0,
        shard_1_usdc_deductions: 0,
        shard_1_usdc_net: 0,
        schedule_id_high: 61,
        schedule_id_low: 62,
        previous_state_high: previous_high,
        previous_state_low: previous_low,
        next_state_high: next_high,
        next_state_low: next_low,
        release_nullifier_high: 71,
        release_nullifier_low: run_low,
        book_entry_high: 81,
        book_entry_low: run_low,
        period_start: 1,
        period_end: 1000,
        validity_start: 100,
        validity_expiry: 200,
    }
}

fn payroll_inputs(
    seal: ContractAddress, state: VestingPayrollProofState, shard: u8,
) -> Array<u256> {
    let seal_felt: felt252 = seal.into();
    array![
        'SN_MAIN'.into(), seal_felt.into(), state.proof_version.into(), state.schema_version.into(),
        state.agreement_root_high.into(), state.agreement_root_low.into(),
        state.manifest_root_high.into(), state.manifest_root_low.into(),
        state.policy_root_high.into(), state.policy_root_low.into(),
        state.fx_root_high.into(), state.fx_root_low.into(),
        state.run_nullifier_high.into(), state.run_nullifier_low.into(),
        state.validity_start.into(), state.validity_expiry.into(), shard.into(),
    ]
}

fn transition_inputs(
    seal: ContractAddress, state: VestingTransitionProofState, shard: u8,
) -> Array<u256> {
    let seal_felt: felt252 = seal.into();
    let owner_felt: felt252 = state.owner.into();
    let source_seal_felt: felt252 = state.source_seal.into();
    array![
        'SN_MAIN'.into(), seal_felt.into(), state.proof_version.into(), state.schema_version.into(),
        state.entry_kind.into(), state.agreement_root_high.into(), state.agreement_root_low.into(),
        state.manifest_root_high.into(), state.manifest_root_low.into(),
        state.policy_root_high.into(), state.policy_root_low.into(),
        state.fx_root_high.into(), state.fx_root_low.into(),
        state.run_nullifier_high.into(), state.run_nullifier_low.into(),
        state.subject_nullifier_high.into(), state.subject_nullifier_low.into(),
        state.parent_fact_high.into(), state.parent_fact_low.into(),
        state.fact_high.into(), state.fact_low.into(), owner_felt.into(), source_seal_felt.into(),
        state.source_proof_version.into(), state.attestation_root_high.into(),
        state.attestation_root_low.into(), state.shard_0_contributor_count.into(),
        state.shard_1_contributor_count.into(), state.totals_disclosed.into(),
        state.totals_commitment_high.into(), state.totals_commitment_low.into(),
        state.shard_0_strk_gross.into(), state.shard_0_strk_deductions.into(),
        state.shard_0_strk_net.into(), state.shard_0_usdc_gross.into(),
        state.shard_0_usdc_deductions.into(), state.shard_0_usdc_net.into(),
        state.shard_1_strk_gross.into(), state.shard_1_strk_deductions.into(),
        state.shard_1_strk_net.into(), state.shard_1_usdc_gross.into(),
        state.shard_1_usdc_deductions.into(), state.shard_1_usdc_net.into(),
        state.schedule_id_high.into(), state.schedule_id_low.into(),
        state.previous_state_high.into(), state.previous_state_low.into(),
        state.next_state_high.into(), state.next_state_low.into(),
        state.release_nullifier_high.into(), state.release_nullifier_low.into(),
        state.book_entry_high.into(), state.book_entry_low.into(),
        state.period_start.into(), state.period_end.into(), state.validity_start.into(),
        state.validity_expiry.into(), shard.into(),
    ]
}

fn begin(
    seal: ContractAddress,
    payroll_state: VestingPayrollProofState,
    transition_state: VestingTransitionProofState,
) -> (felt252, felt252, felt252, felt252) {
    let proof_0: felt252 = 101;
    let proof_1: felt252 = 102;
    let proof_2: felt252 = 103;
    let proof_3: felt252 = 104;
    IPayoVestingBookSealDispatcher { contract_address: seal }.begin_vesting_authorization(
        payroll_state,
        transition_state,
        poseidon_hash_span(array![proof_0].span()),
        poseidon_hash_span(array![proof_1].span()),
        poseidon_hash_span(array![proof_2].span()),
        poseidon_hash_span(array![proof_3].span()),
    );
    (proof_0, proof_1, proof_2, proof_3)
}

fn verify_all(
    seal: ContractAddress,
    verifier: ContractAddress,
    payroll_state: VestingPayrollProofState,
    transition_state: VestingTransitionProofState,
    proof_0: felt252,
    proof_1: felt252,
    proof_2: felt252,
    proof_3: felt252,
) {
    let dispatcher = IPayoVestingBookSealDispatcher { contract_address: seal };
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(payroll_inputs(seal, payroll_state, 0).span()),
    );
    dispatcher.verify_vesting_authorization_proof(
        payroll_state.run_nullifier_high, payroll_state.run_nullifier_low, 0,
        array![proof_0].span(),
    );
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(payroll_inputs(seal, payroll_state, 1).span()),
    );
    dispatcher.verify_vesting_authorization_proof(
        payroll_state.run_nullifier_high, payroll_state.run_nullifier_low, 1,
        array![proof_1].span(),
    );
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(transition_inputs(seal, transition_state, 0).span()),
    );
    dispatcher.verify_vesting_authorization_proof(
        payroll_state.run_nullifier_high, payroll_state.run_nullifier_low, 2,
        array![proof_2].span(),
    );
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(transition_inputs(seal, transition_state, 1).span()),
    );
    dispatcher.verify_vesting_authorization_proof(
        payroll_state.run_nullifier_high, payroll_state.run_nullifier_low, 3,
        array![proof_3].span(),
    );
}

fn complete_first_release() -> (
    ContractAddress, ContractAddress, VestingPayrollProofState, VestingTransitionProofState,
) {
    let pool = address(9100);
    let verifier = address(9200);
    let owner = address(9500);
    let seal = deploy_seal(pool, verifier, owner);
    let payroll_state = payroll(52);
    let transition_state = transition(seal, owner, 52, 0, 0, 91, 92);
    let (proof_0, proof_1, proof_2, proof_3) = begin(seal, payroll_state, transition_state);
    verify_all(
        seal, verifier, payroll_state, transition_state,
        proof_0, proof_1, proof_2, proof_3,
    );
    let pending = IPayoVestingBookSealDispatcher { contract_address: seal }
        .get_pending_authorization(51, 52);
    assert(pending.status == 2, 'vesting not authorized');
    start_cheat_caller_address(seal, pool);
    IPayoVestingBookSealDispatcher { contract_address: seal }.privacy_invoke(
        51, 52, 71, 52, 81, 52,
    );
    (seal, pool, payroll_state, transition_state)
}

fn ordinary_transition(
    seal: ContractAddress, owner: ContractAddress, run_low: u128,
) -> VestingTransitionProofState {
    let mut state = transition(seal, owner, run_low, 0, 0, 0, 0);
    state.entry_kind = 0;
    state.schedule_id_high = 0;
    state.schedule_id_low = 0;
    state.release_nullifier_high = 0;
    state.release_nullifier_low = 0;
    state.book_entry_high = 82;
    state
}

#[test]
fn ordinary_payroll_appends_book_without_mutating_vesting_state() {
    let pool = address(9150);
    let verifier = address(9250);
    let owner = address(9550);
    let seal = deploy_seal(pool, verifier, owner);
    let payroll_state = payroll(56);
    let transition_state = ordinary_transition(seal, owner, 56);
    let (proof_0, proof_1, proof_2, proof_3) = begin(seal, payroll_state, transition_state);
    verify_all(
        seal, verifier, payroll_state, transition_state,
        proof_0, proof_1, proof_2, proof_3,
    );
    start_cheat_caller_address(seal, pool);
    let dispatcher = IPayoVestingBookSealDispatcher { contract_address: seal };
    dispatcher.privacy_invoke(51, 56, 0, 0, 82, 56);
    let book = dispatcher.get_payroll_book(owner, 1, 1000);
    assert(book.exists && book.entry_count == 1, 'ordinary book entry missing');
    assert(book.contributor_count == 1, 'ordinary contributor count');
    assert(book.disclosed_entry_count == 1 && book.undisclosed_entry_count == 0, 'book disclosure');
    assert(book.ordinary_entry_count == 1, 'ordinary kind count');
    assert(book.vesting_entry_count == 0 && book.agent_entry_count == 0, 'wrong kind count');
    assert(book.strk_gross == 100 && book.strk_deductions == 10, 'strk totals');
    assert(book.strk_net == 90 && book.usdc_net == 0, 'book net totals');
    assert(
        dispatcher.get_payroll_book_entry(owner, 1, 1000, 0)
            == u256 { high: 82, low: 56 },
        'ordinary book mismatch',
    );
    assert(!dispatcher.get_vesting_state(0, 0).exists, 'ordinary changed vesting');
    assert(!dispatcher.is_release_consumed(0, 0), 'ordinary consumed release');
}

#[test]
fn active_external_attestation_catalog_is_accepted() {
    let pool = address(9151);
    let verifier = address(9251);
    let owner = address(9551);
    let admin = address(9651);
    let (seal, _) = deploy_seal_with_real_catalog(pool, verifier, owner, admin);
    let payroll_state = payroll(61);
    let mut transition_state = ordinary_transition(seal, owner, 61);
    transition_state.attestation_root_high = 201;
    transition_state.attestation_root_low = 202;
    let _ = begin(seal, payroll_state, transition_state);
    assert(
        IPayoVestingBookSealDispatcher { contract_address: seal }
            .get_pending_authorization(51, 61).status == 1,
        'attested payroll not pending',
    );
}

#[test]
#[should_panic(expected: ('PAYO_ROOT_INACTIVE',))]
fn revoked_external_attestation_catalog_is_rejected() {
    let pool = address(9152);
    let verifier = address(9252);
    let owner = address(9552);
    let admin = address(9652);
    let (seal, catalog) = deploy_seal_with_real_catalog(pool, verifier, owner, admin);
    IPayoPolicyRegistryDispatcher { contract_address: catalog }
        .revoke_policy_root(201, 202);
    let payroll_state = payroll(62);
    let mut transition_state = ordinary_transition(seal, owner, 62);
    transition_state.attestation_root_high = 201;
    transition_state.attestation_root_low = 202;
    let _ = begin(seal, payroll_state, transition_state);
}

#[test]
fn four_bound_proofs_atomically_advance_state_and_append_the_book() {
    let (seal, _, _, transition_state) = complete_first_release();
    let dispatcher = IPayoVestingBookSealDispatcher { contract_address: seal };
    let pending = dispatcher.get_pending_authorization(51, 52);
    assert(pending.status == 3, 'vesting callback not consumed');
    let state = dispatcher.get_vesting_state(61, 62);
    assert(state.exists, 'vesting state missing');
    assert(state.state_high == 91 && state.state_low == 92, 'vesting state mismatch');
    assert(dispatcher.is_release_consumed(71, 52), 'release replay key missing');
    let book = dispatcher.get_payroll_book(transition_state.owner, 1, 1000);
    assert(book.exists && book.entry_count == 1, 'book entry missing');
    assert(book.contributor_count == 1, 'vesting contributor count');
    assert(book.disclosed_entry_count == 1 && book.undisclosed_entry_count == 0, 'book disclosure');
    assert(book.vesting_entry_count == 1 && book.ordinary_entry_count == 0, 'vesting kind count');
    assert(book.strk_gross == 100 && book.strk_deductions == 10, 'vesting strk totals');
    assert(book.strk_net == 90 && book.usdc_net == 0, 'vesting net totals');
    assert(
        dispatcher.get_payroll_book_entry(transition_state.owner, 1, 1000, 0)
            == u256 { high: 81, low: 52 },
        'book commitment mismatch',
    );
    // Fixed constants preserve the TypeScript/Cairo hash compatibility
    // vector independently of this test deployment's changing class hash.
    let vector_initial = poseidon_hash_span(
        array!['PAYO_BOOK_V1', 'SN_MAIN', 0x456, 0x123, 1, 1000].span(),
    );
    assert(
        vector_initial
            == 0x07bea589f92bbffe2718c60e970c29da3160dc9f7b23519b6baeef7010644fd8,
        'typescript initial vector',
    );
    let vector_append = poseidon_hash_span(
        array!['PAYO_BOOK_ADD_V1', vector_initial, 0x51, 0x34, 0].span(),
    );
    assert(
        vector_append
            == 0x05e96f9d434f47d636570b6583ab6f49a3c524b51a80be259d77d24d16b96544,
        'typescript append vector',
    );
    let seal_felt: felt252 = seal.into();
    let owner_felt: felt252 = transition_state.owner.into();
    let initial = poseidon_hash_span(
        array!['PAYO_BOOK_V1', 'SN_MAIN', seal_felt, owner_felt, 1, 1000].span(),
    );
    let expected = poseidon_hash_span(
        array!['PAYO_BOOK_ADD_V1', initial, 81, 52, 0].span(),
    );
    assert(book.accumulator_root == expected, 'book accumulator mismatch');
}


#[test]
fn two_entries_accumulate_exact_cross_token_totals() {
    let pool = address(9160);
    let verifier = address(9260);
    let owner = address(9560);
    let seal = deploy_seal(pool, verifier, owner);
    let dispatcher = IPayoVestingBookSealDispatcher { contract_address: seal };

    let first_payroll = payroll(57);
    let first = ordinary_transition(seal, owner, 57);
    let (a, b, c, d) = begin(seal, first_payroll, first);
    verify_all(seal, verifier, first_payroll, first, a, b, c, d);
    start_cheat_caller_address(seal, pool);
    dispatcher.privacy_invoke(51, 57, 0, 0, 82, 57);

    let second_payroll = payroll(58);
    let mut second = ordinary_transition(seal, owner, 58);
    second.book_entry_high = 83;
    second.shard_0_contributor_count = 1;
    second.shard_1_contributor_count = 2;
    second.shard_0_strk_gross = 0;
    second.shard_0_strk_deductions = 0;
    second.shard_0_strk_net = 0;
    second.shard_0_usdc_gross = 200;
    second.shard_0_usdc_deductions = 25;
    second.shard_0_usdc_net = 175;
    second.shard_1_usdc_gross = 50;
    second.shard_1_usdc_deductions = 25;
    second.shard_1_usdc_net = 25;
    let (e, f, g, h) = begin(seal, second_payroll, second);
    verify_all(seal, verifier, second_payroll, second, e, f, g, h);
    dispatcher.privacy_invoke(51, 58, 0, 0, 83, 58);

    let book = dispatcher.get_payroll_book(owner, 1, 1000);
    assert(book.entry_count == 2 && book.contributor_count == 4, 'cumulative count');
    assert(book.disclosed_entry_count == 2 && book.ordinary_entry_count == 2, 'entry counts');
    assert(book.strk_gross == 100 && book.strk_deductions == 10, 'strk aggregate');
    assert(book.strk_net == 90, 'strk net');
    assert(book.usdc_gross == 250 && book.usdc_deductions == 50, 'usdc aggregate');
    assert(book.usdc_net == 200, 'usdc net');
}

#[test]
fn hidden_entry_counts_contributors_without_publishing_amounts() {
    let pool = address(9170);
    let verifier = address(9270);
    let owner = address(9570);
    let seal = deploy_seal(pool, verifier, owner);
    let payroll_state = payroll(59);
    let mut hidden = ordinary_transition(seal, owner, 59);
    hidden.totals_disclosed = 0;
    hidden.shard_0_contributor_count = 2;
    hidden.shard_1_contributor_count = 1;
    hidden.shard_0_strk_gross = 0;
    hidden.shard_0_strk_deductions = 0;
    hidden.shard_0_strk_net = 0;
    let (a, b, c, d) = begin(seal, payroll_state, hidden);
    verify_all(seal, verifier, payroll_state, hidden, a, b, c, d);
    start_cheat_caller_address(seal, pool);
    let dispatcher = IPayoVestingBookSealDispatcher { contract_address: seal };
    dispatcher.privacy_invoke(51, 59, 0, 0, 82, 59);
    let book = dispatcher.get_payroll_book(owner, 1, 1000);
    assert(book.entry_count == 1 && book.contributor_count == 3, 'hidden count');
    assert(book.disclosed_entry_count == 0 && book.undisclosed_entry_count == 1, 'hidden mode');
    assert(book.strk_gross == 0 && book.strk_net == 0 && book.usdc_net == 0, 'hidden totals');
}

#[test]
#[should_panic(expected: ('PAYO_PUBLIC_INPUTS',))]
fn changed_verified_aggregate_cannot_attach_to_pending_book_entry() {
    let pool = address(9180);
    let verifier = address(9280);
    let owner = address(9580);
    let seal = deploy_seal(pool, verifier, owner);
    let payroll_state = payroll(60);
    let state = ordinary_transition(seal, owner, 60);
    let (proof_0, proof_1, proof_2, _) = begin(seal, payroll_state, state);
    let dispatcher = IPayoVestingBookSealDispatcher { contract_address: seal };
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(payroll_inputs(seal, payroll_state, 0).span()),
    );
    dispatcher.verify_vesting_authorization_proof(51, 60, 0, array![proof_0].span());
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(payroll_inputs(seal, payroll_state, 1).span()),
    );
    dispatcher.verify_vesting_authorization_proof(51, 60, 1, array![proof_1].span());
    let mut changed = state;
    changed.shard_0_strk_net = 89;
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(transition_inputs(seal, changed, 0).span()),
    );
    dispatcher.verify_vesting_authorization_proof(51, 60, 2, array![proof_2].span());
}

#[test]
#[should_panic(expected: ('PAYO_BAD_STATE',))]
fn the_same_private_release_cannot_be_invoked_twice() {
    let (seal, pool, _, _) = complete_first_release();
    start_cheat_caller_address(seal, pool);
    IPayoVestingBookSealDispatcher { contract_address: seal }.privacy_invoke(
        51, 52, 71, 52, 81, 52,
    );
}

#[test]
#[should_panic(expected: ('PAYO_STALE_STATE',))]
fn a_second_run_cannot_reuse_genesis_after_state_advanced() {
    let (seal, _, _, first) = complete_first_release();
    let next_payroll = payroll(53);
    let stale = transition(seal, first.owner, 53, 0, 0, 93, 94);
    let _ = begin(seal, next_payroll, stale);
}

#[test]
#[should_panic(expected: ('PAYO_BAD_OWNER',))]
fn a_different_tenant_cannot_attach_to_the_registered_root() {
    let pool = address(9600);
    let verifier = address(9700);
    let registered_owner = address(9800);
    let seal = deploy_seal(pool, verifier, registered_owner);
    let _ = begin(
        seal,
        payroll(55),
        transition(seal, address(9900), 55, 0, 0, 91, 92),
    );
}






fn exception_seal_address() -> ContractAddress { address(9450) }

fn accepted_claim(run_low: u128, status: u8) -> AcceptedClaimRecord {
    AcceptedClaimRecord {
        exists: true,
        status,
        run_nullifier_high: 51,
        run_nullifier_low: run_low,
        agreement_root_high: 11,
        agreement_root_low: 12,
        policy_root_high: 31,
        policy_root_low: 32,
        fact_commitment_high: 401,
        fact_commitment_low: 402,
        accepted_at: 140,
        has_active_attempt: status == 2,
        active_attempt_high: if status == 2 { 501 } else { 0 },
        active_attempt_low: if status == 2 { 502 } else { 0 },
    }
}

fn obligation_snapshot(owner: ContractAddress) -> ObligationSnapshotRecord {
    ObligationSnapshotRecord {
        exists: true,
        owner,
        base_agreement_root_high: 11,
        base_agreement_root_low: 12,
        claim_root_high: 111,
        claim_root_low: 112,
        policy_root_high: 31,
        policy_root_low: 32,
        snapshot_fact_high: 121,
        snapshot_fact_low: 122,
        due_at: 110,
        grace_ends_at: 120,
        claim_ends_at: 190,
        registered_at: 100,
        claim_count: 1,
    }
}

fn remediation_attempt(status: u8) -> RemediationAttemptRecord {
    RemediationAttemptRecord {
        exists: true,
        status,
        claim_subject_high: 301,
        claim_subject_low: 302,
        fact_commitment_high: 601,
        fact_commitment_low: 602,
        action_commitment_high: 701,
        action_commitment_low: 702,
        expires_at: 200,
        authorized_at: 145,
        invoked_at: if status == 2 { 150 } else { 0 },
    }
}

fn claim_transition(
    owner: ContractAddress, run_low: u128,
) -> VestingTransitionProofState {
    let mut state = ordinary_transition(address(1), owner, run_low);
    state.entry_kind = 3;
    state.manifest_root_high = 0;
    state.manifest_root_low = 0;
    state.fx_root_high = 0;
    state.fx_root_low = 0;
    state.subject_nullifier_high = 301;
    state.subject_nullifier_low = 302;
    state.fact_high = 401;
    state.fact_low = 402;
    state.source_seal = exception_seal_address();
    state.source_proof_version = 6;
    state.totals_disclosed = 0;
    state.shard_0_strk_gross = 0;
    state.shard_0_strk_deductions = 0;
    state.shard_0_strk_net = 0;
    state.book_entry_high = 801;
    state.book_entry_low = 802;
    state
}

fn remediation_transition(
    owner: ContractAddress, run_low: u128,
) -> VestingTransitionProofState {
    let mut state = claim_transition(owner, run_low);
    state.entry_kind = 4;
    state.manifest_root_high = 701;
    state.manifest_root_low = 702;
    state.subject_nullifier_high = 501;
    state.subject_nullifier_low = 502;
    state.parent_fact_high = 401;
    state.parent_fact_low = 402;
    state.fact_high = 601;
    state.fact_low = 602;
    state.source_proof_version = 7;
    state.totals_disclosed = 1;
    state.shard_0_strk_gross = 90;
    state.shard_0_strk_deductions = 0;
    state.shard_0_strk_net = 90;
    state.book_entry_high = 901;
    state.book_entry_low = 902;
    state
}

fn mock_claim_source(
    owner: ContractAddress, run_low: u128, claim_status: u8, attempt_status: u8,
) {
    let source = exception_seal_address();
    start_mock_call(source, selector!("get_snapshot"), obligation_snapshot(owner));
    start_mock_call(source, selector!("get_claim"), accepted_claim(run_low, claim_status));
    if attempt_status != 0 {
        start_mock_call(
            source, selector!("get_remediation_attempt"), remediation_attempt(attempt_status),
        );
    }
}

fn begin_exception(
    seal: ContractAddress, state: VestingTransitionProofState,
) -> (felt252, felt252) {
    let proof_0: felt252 = 203;
    let proof_1: felt252 = 204;
    IPayoVestingBookSealDispatcher { contract_address: seal }
        .begin_exception_book_authorization(
            state,
            poseidon_hash_span(array![proof_0].span()),
            poseidon_hash_span(array![proof_1].span()),
        );
    (proof_0, proof_1)
}

fn verify_exception(
    seal: ContractAddress,
    verifier: ContractAddress,
    state: VestingTransitionProofState,
    proof_0: felt252,
    proof_1: felt252,
) {
    let dispatcher = IPayoVestingBookSealDispatcher { contract_address: seal };
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(transition_inputs(seal, state, 0).span()),
    );
    dispatcher.verify_vesting_authorization_proof(
        state.subject_nullifier_high, state.subject_nullifier_low, 2,
        array![proof_0].span(),
    );
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(transition_inputs(seal, state, 1).span()),
    );
    dispatcher.verify_vesting_authorization_proof(
        state.subject_nullifier_high, state.subject_nullifier_low, 3,
        array![proof_1].span(),
    );
}

fn authorized_claim() -> (
    ContractAddress, ContractAddress, ContractAddress, VestingTransitionProofState,
) {
    let pool = address(10100);
    let verifier = address(10200);
    let owner = address(10300);
    let seal = deploy_seal(pool, verifier, owner);
    mock_claim_source(owner, 70, 1, 0);
    let state = claim_transition(owner, 70);
    let (proof_0, proof_1) = begin_exception(seal, state);
    verify_exception(seal, verifier, state, proof_0, proof_1);
    (seal, pool, owner, state)
}

#[test]
fn proved_claim_appends_one_hidden_zero_value_book_entry() {
    let (seal, _, owner, state) = authorized_claim();
    let dispatcher = IPayoVestingBookSealDispatcher { contract_address: seal };
    let pending = dispatcher.get_pending_authorization(301, 302);
    assert(pending.status == 2 && pending.verified_mask == 12, 'claim not authorized');
    dispatcher.finalize_claim_book_entry(301, 302, 801, 802);
    let book = dispatcher.get_payroll_book(owner, 1, 1000);
    assert(book.entry_count == 1 && book.claim_entry_count == 1, 'claim count');
    assert(book.remediation_entry_count == 0 && book.agent_entry_count == 0, 'claim kind');
    assert(book.undisclosed_entry_count == 1 && book.disclosed_entry_count == 0, 'claim privacy');
    assert(book.strk_net == 0 && book.usdc_net == 0, 'claim published value');
    assert(
        dispatcher.get_payroll_book_entry(owner, 1, 1000, 0)
            == u256 { high: state.book_entry_high, low: state.book_entry_low },
        'claim book entry',
    );
}

#[test]
#[should_panic(expected: ('PAYO_BAD_STATE',))]
fn proved_claim_cannot_append_twice() {
    let (seal, _, _, _) = authorized_claim();
    let dispatcher = IPayoVestingBookSealDispatcher { contract_address: seal };
    dispatcher.finalize_claim_book_entry(301, 302, 801, 802);
    dispatcher.finalize_claim_book_entry(301, 302, 801, 802);
}

#[test]
#[should_panic(expected: ('PAYO_BAD_ROOT',))]
fn claim_with_a_different_durable_fact_is_rejected() {
    let pool = address(10400);
    let verifier = address(10500);
    let owner = address(10600);
    let seal = deploy_seal(pool, verifier, owner);
    mock_claim_source(owner, 71, 1, 0);
    let mut changed = claim_transition(owner, 71);
    changed.fact_low = 499;
    let _ = begin_exception(seal, changed);
}

#[test]
#[should_panic(expected: ('PAYO_BAD_OWNER',))]
fn claim_cannot_enter_another_tenants_book() {
    let pool = address(10700);
    let verifier = address(10800);
    let owner = address(10900);
    let seal = deploy_seal(pool, verifier, owner);
    mock_claim_source(address(10901), 72, 1, 0);
    let _ = begin_exception(seal, claim_transition(owner, 72));
}

fn authorized_remediation(attempt_status: u8) -> (
    ContractAddress, ContractAddress, ContractAddress, VestingTransitionProofState,
) {
    let pool = address(11000);
    let verifier = address(11100);
    let owner = address(11200);
    let seal = deploy_seal(pool, verifier, owner);
    mock_claim_source(owner, 73, 1, attempt_status);
    let state = remediation_transition(owner, 73);
    let (proof_0, proof_1) = begin_exception(seal, state);
    verify_exception(seal, verifier, state, proof_0, proof_1);
    (seal, pool, owner, state)
}

#[test]
#[should_panic(expected: ('PAYO_BAD_STATE',))]
fn remediation_book_entry_cannot_precede_private_payment_invocation() {
    let (seal, pool, _, state) = authorized_remediation(1);
    start_cheat_caller_address(seal, pool);
    IPayoVestingBookSealDispatcher { contract_address: seal }.privacy_invoke(
        state.subject_nullifier_high, state.subject_nullifier_low, 0, 0,
        state.book_entry_high, state.book_entry_low,
    );
}

#[test]
fn invoked_remediation_atomically_appends_exact_book_entry() {
    let (seal, pool, owner, state) = authorized_remediation(1);
    mock_claim_source(owner, 73, 2, 2);
    start_cheat_caller_address(seal, pool);
    let dispatcher = IPayoVestingBookSealDispatcher { contract_address: seal };
    dispatcher.privacy_invoke(
        state.subject_nullifier_high, state.subject_nullifier_low, 0, 0,
        state.book_entry_high, state.book_entry_low,
    );
    let book = dispatcher.get_payroll_book(owner, 1, 1000);
    assert(book.entry_count == 1 && book.remediation_entry_count == 1, 'remediation count');
    assert(book.claim_entry_count == 0 && book.agent_entry_count == 0, 'remediation kind');
    assert(book.disclosed_entry_count == 1 && book.strk_net == 90, 'remediation value');
    assert(dispatcher.get_pending_authorization(501, 502).status == 3, 'not consumed');
}
