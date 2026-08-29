use core::serde::Serde;
use core::poseidon::poseidon_hash_span;
use payo_contracts::exception_commitments::{
    obligation_snapshot_commitment_v2, payroll_statement_commitment_v2,
};
use payo_contracts::payroll_exception_seal::{
    ExceptionProofStateV2, IPayoPayrollExceptionSealDispatcher,
    IPayoPayrollExceptionSealDispatcherTrait, PayrollProofStateV2,
};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp,
    start_cheat_caller_address, start_mock_call,
};
use starknet::ContractAddress;

fn address(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

fn deploy_exception_seal(
    pool: ContractAddress,
    verifier: ContractAddress,
    root_owner: ContractAddress,
    chain_id: felt252,
) -> ContractAddress {
    let contract = declare("PayoPayrollExceptionSeal").unwrap().contract_class();
    let catalog = address(7300);
    let obligations = address(7400);
    let mut calldata = array![];
    pool.serialize(ref calldata);
    catalog.serialize(ref calldata);
    obligations.serialize(ref calldata);
    chain_id.serialize(ref calldata);
    let (seal, _) = contract.deploy(@calldata).unwrap();
    start_mock_call(catalog, selector!("is_policy_root_valid"), true);
    start_mock_call(catalog, selector!("is_fx_root_valid"), true);
    start_mock_call(catalog, selector!("is_verifier_valid"), true);
    start_mock_call(catalog, selector!("get_verifier"), verifier);
    start_mock_call(obligations, selector!("is_obligation_root_valid"), true);
    start_mock_call(obligations, selector!("get_obligation_root_owner"), root_owner);
    seal
}

fn snapshot_fact(owner: ContractAddress) -> u256 {
    let owner_felt: felt252 = owner.into();
    obligation_snapshot_commitment_v2(
        2,
        u256 { high: 31, low: 32 },
        u256 { high: 11, low: 12 },
        u256 { high: 61, low: 62 },
        u256 { high: 41, low: 42 },
        owner_felt.into(),
        200,
        250,
        400,
        u256 { high: 61, low: 62 },
    )
}

fn register_snapshot(
    seal: ContractAddress, owner: ContractAddress,
) -> u256 {
    let fact = snapshot_fact(owner);
    start_cheat_caller_address(seal, owner);
    start_cheat_block_timestamp(seal, 100);
    IPayoPayrollExceptionSealDispatcher { contract_address: seal }
        .register_obligation_snapshot(
            31, 32, 11, 12, 61, 62, 41, 42, 200, 250, 400, fact.high, fact.low,
        );
    fact
}

fn payroll_state() -> PayrollProofStateV2 {
    PayrollProofStateV2 {
        proof_version: 2,
        schema_version: 1,
        agreement_root_high: 11,
        agreement_root_low: 12,
        manifest_root_high: 21,
        manifest_root_low: 22,
        policy_root_high: 41,
        policy_root_low: 42,
        fx_root_high: 51,
        fx_root_low: 52,
        run_nullifier_high: 31,
        run_nullifier_low: 32,
        validity_start: 150,
        validity_expiry: 200,
    }
}

fn payroll_inputs(
    seal: ContractAddress, chain_id: felt252, shard_index: u8,
) -> Array<u256> {
    let seal_felt: felt252 = seal.into();
    array![
        chain_id.into(), seal_felt.into(), 2_u32.into(), 1_u32.into(),
        11_u128.into(), 12_u128.into(), 21_u128.into(), 22_u128.into(),
        41_u128.into(), 42_u128.into(), 51_u128.into(), 52_u128.into(),
        31_u128.into(), 32_u128.into(), 150_u64.into(), 200_u64.into(),
        shard_index.into(),
    ]
}

fn payroll_bundle_inputs(seal: ContractAddress, chain_id: felt252) -> Array<u256> {
    let mut result = array![];
    for value in payroll_inputs(seal, chain_id, 0) { result.append(value); }
    for value in payroll_inputs(seal, chain_id, 1) { result.append(value); }
    result
}

fn exception_inputs(
    seal: ContractAddress, chain_id: felt252, state: ExceptionProofStateV2,
) -> Array<u256> {
    let seal_felt: felt252 = seal.into();
    array![
        chain_id.into(), seal_felt.into(), state.proof_version.into(),
        state.schema_version.into(), state.agreement_root_high.into(),
        state.agreement_root_low.into(), state.manifest_root_high.into(),
        state.manifest_root_low.into(), state.policy_root_high.into(),
        state.policy_root_low.into(), state.fx_root_high.into(), state.fx_root_low.into(),
        state.subject_nullifier_high.into(), state.subject_nullifier_low.into(),
        state.parent_nullifier_high.into(), state.parent_nullifier_low.into(),
        state.fact_commitment_high.into(), state.fact_commitment_low.into(),
        state.parent_fact_commitment_high.into(), state.parent_fact_commitment_low.into(),
        state.validity_start.into(), state.validity_expiry.into(), state.shard_index.into(),
    ]
}

fn snapshot_proof_state(fact: u256) -> ExceptionProofStateV2 {
    ExceptionProofStateV2 {
        proof_version: 5,
        schema_version: 2,
        agreement_root_high: 11,
        agreement_root_low: 12,
        manifest_root_high: 61,
        manifest_root_low: 62,
        policy_root_high: 41,
        policy_root_low: 42,
        fx_root_high: 0,
        fx_root_low: 0,
        subject_nullifier_high: 31,
        subject_nullifier_low: 32,
        parent_nullifier_high: 0,
        parent_nullifier_low: 0,
        fact_commitment_high: fact.high,
        fact_commitment_low: fact.low,
        parent_fact_commitment_high: 0,
        parent_fact_commitment_low: 0,
        validity_start: 150,
        validity_expiry: 200,
        shard_index: 0,
    }
}

fn claim_state(fact: u256) -> ExceptionProofStateV2 {
    ExceptionProofStateV2 {
        proof_version: 6,
        schema_version: 2,
        agreement_root_high: 11,
        agreement_root_low: 12,
        manifest_root_high: 0,
        manifest_root_low: 0,
        policy_root_high: 41,
        policy_root_low: 42,
        fx_root_high: 0,
        fx_root_low: 0,
        subject_nullifier_high: 81,
        subject_nullifier_low: 82,
        parent_nullifier_high: 31,
        parent_nullifier_low: 32,
        fact_commitment_high: 91,
        fact_commitment_low: 92,
        parent_fact_commitment_high: fact.high,
        parent_fact_commitment_low: fact.low,
        validity_start: 280,
        validity_expiry: 340,
        shard_index: 0,
    }
}

fn remediation_state() -> ExceptionProofStateV2 {
    ExceptionProofStateV2 {
        proof_version: 7,
        schema_version: 2,
        agreement_root_high: 11,
        agreement_root_low: 12,
        manifest_root_high: 111,
        manifest_root_low: 112,
        policy_root_high: 41,
        policy_root_low: 42,
        fx_root_high: 0,
        fx_root_low: 0,
        subject_nullifier_high: 101,
        subject_nullifier_low: 102,
        parent_nullifier_high: 81,
        parent_nullifier_low: 82,
        fact_commitment_high: 121,
        fact_commitment_low: 122,
        parent_fact_commitment_high: 91,
        parent_fact_commitment_low: 92,
        validity_start: 280,
        validity_expiry: 340,
        shard_index: 0,
    }
}

#[test]
fn snapshot_is_registered_by_the_tenant_root_owner_before_payday() {
    let owner = address(7000);
    let seal = deploy_exception_seal(address(7100), address(7200), owner, 'SN_MAIN');
    let fact = register_snapshot(seal, owner);
    let snapshot = IPayoPayrollExceptionSealDispatcher { contract_address: seal }
        .get_snapshot(31, 32);
    assert(snapshot.exists, 'snapshot missing');
    assert(snapshot.owner == owner, 'snapshot owner mismatch');
    assert(snapshot.snapshot_fact_high == fact.high, 'snapshot fact high');
    assert(snapshot.snapshot_fact_low == fact.low, 'snapshot fact low');
    assert(snapshot.registered_at == 100, 'snapshot time');
}

#[test]
#[should_panic(expected: ('PAYO_BAD_STATE',))]
fn pool_cannot_move_payroll_before_both_proofs_authorize_it() {
    let pool = address(7100);
    let seal = deploy_exception_seal(pool, address(7200), address(7000), 'SN_MAIN');
    start_cheat_caller_address(seal, pool);
    start_cheat_block_timestamp(seal, 160);
    IPayoPayrollExceptionSealDispatcher { contract_address: seal }
        .privacy_invoke(0, 31, 32, 1, 2, 21, 22);
}

#[test]
fn verified_payroll_authorization_is_consumed_once_by_the_pool() {
    let owner = address(7000);
    let pool = address(7100);
    let verifier = address(7200);
    let chain_id = 'SN_MAIN';
    let seal = deploy_exception_seal(pool, verifier, owner, chain_id);
    let fact = register_snapshot(seal, owner);
    let payroll = payroll_state();
    let snapshot = snapshot_proof_state(fact);
    let bundle = payroll_bundle_inputs(seal, chain_id);
    let snapshot_inputs = exception_inputs(seal, chain_id, snapshot);
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_bundle"),
        Result::<Span<u256>, felt252>::Ok(bundle.span()),
    );
    start_mock_call(
        verifier,
        selector!("verify_ultra_keccak_zk_honk_proof"),
        Result::<Span<u256>, felt252>::Ok(snapshot_inputs.span()),
    );
    start_cheat_caller_address(seal, address(7600));
    start_cheat_block_timestamp(seal, 160);
    let dispatcher = IPayoPayrollExceptionSealDispatcher { contract_address: seal };
    let proof: Array<felt252> = array![123];
    dispatcher.authorize_payroll(
        payroll, snapshot, proof.span(), proof.span(), proof.span(),
    );
    assert(!dispatcher.get_run_anchor(31, 32).invoked, 'payroll invoked before pool');
    start_cheat_caller_address(seal, pool);
    let deposits = dispatcher.privacy_invoke(0, 31, 32, fact.high, fact.low, 21, 22);
    assert(deposits.is_empty(), 'seal must not custody');
    assert(dispatcher.get_run_anchor(31, 32).invoked, 'pool did not consume');
}

#[test]
fn staged_payroll_authorization_writes_no_anchor_until_all_three_proofs_pass() {
    let owner = address(7000);
    let pool = address(7100);
    let verifier = address(7200);
    let chain_id = 'SN_MAIN';
    let seal = deploy_exception_seal(pool, verifier, owner, chain_id);
    let fact = register_snapshot(seal, owner);
    let payroll = payroll_state();
    let mut snapshot = snapshot_proof_state(fact);
    // Snapshot proof is deliberately completed before the later payroll window.
    snapshot.validity_start = 120;
    snapshot.validity_expiry = 140;
    let proof: Array<felt252> = array![123];
    let proof_hash = poseidon_hash_span(proof.span());
    start_cheat_block_timestamp(seal, 130);
    let dispatcher = IPayoPayrollExceptionSealDispatcher { contract_address: seal };
    dispatcher.begin_payroll_authorization(
        payroll, snapshot, proof_hash, proof_hash, proof_hash,
    );
    assert(!dispatcher.get_run_anchor(31, 32).exists, 'anchor exists before proof');

    let snapshot_inputs = exception_inputs(seal, chain_id, snapshot);
    start_mock_call(
        verifier,
        selector!("verify_ultra_keccak_zk_honk_proof"),
        Result::<Span<u256>, felt252>::Ok(snapshot_inputs.span()),
    );
    dispatcher.verify_payroll_authorization_proof(31, 32, 2, proof.span());
    assert(
        dispatcher.get_pending_payroll_authorization(31, 32).verified_mask == 4,
        'snapshot proof missing',
    );
    assert(!dispatcher.get_run_anchor(31, 32).exists, 'one proof authorized');

    start_cheat_block_timestamp(seal, 160);
    let shard_zero = payroll_inputs(seal, chain_id, 0);
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(shard_zero.span()),
    );
    dispatcher.verify_payroll_authorization_proof(31, 32, 0, proof.span());
    assert(
        dispatcher.get_pending_payroll_authorization(31, 32).verified_mask == 5,
        'shard zero missing',
    );
    assert(!dispatcher.get_run_anchor(31, 32).exists, 'two proofs authorized');

    let shard_one = payroll_inputs(seal, chain_id, 1);
    start_mock_call(
        verifier,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(shard_one.span()),
    );
    dispatcher.verify_payroll_authorization_proof(31, 32, 1, proof.span());
    let pending = dispatcher.get_pending_payroll_authorization(31, 32);
    assert(pending.verified_mask == 7 && pending.status == 2, 'proof set incomplete');
    assert(dispatcher.get_run_anchor(31, 32).exists, 'all proofs not authorized');

    start_cheat_caller_address(seal, pool);
    dispatcher.privacy_invoke(0, 31, 32, fact.high, fact.low, 21, 22);
    assert(dispatcher.get_run_anchor(31, 32).invoked, 'pool did not consume');
}

#[test]
fn employer_statement_is_bound_to_snapshot_owner_and_readable_by_fact() {
    let owner = address(7000);
    let seal = deploy_exception_seal(address(7100), address(7200), owner, 'SN_MAIN');
    let snapshot_fact = register_snapshot(seal, owner);
    let statement_fact = payroll_statement_commitment_v2(
        2,
        u256 { high: 31, low: 32 },
        snapshot_fact,
        u256 { high: 21, low: 22 },
        u256 { high: 51, low: 52 },
        u256 { high: 71, low: 72 },
        220,
        2,
    );
    start_cheat_caller_address(seal, owner);
    start_cheat_block_timestamp(seal, 230);
    let dispatcher = IPayoPayrollExceptionSealDispatcher { contract_address: seal };
    dispatcher.register_employer_statement(
        31, 32, 21, 22, 51, 52, 71, 72, 220, statement_fact.high, statement_fact.low,
    );
    let statement = dispatcher.get_statement(statement_fact.high, statement_fact.low);
    assert(statement.exists, 'statement missing');
    assert(statement.owner == owner, 'statement owner mismatch');
    assert(statement.snapshot_fact_high == snapshot_fact.high, 'statement snapshot high');
    assert(statement.snapshot_fact_low == snapshot_fact.low, 'statement snapshot low');
    assert(statement.manifest_root_high == 21, 'statement manifest high');
    assert(statement.fx_root_low == 52, 'statement fx low');
    assert(statement.source == 2, 'statement source');
}

#[test]
fn claim_and_remediation_use_distinct_subjects_and_honest_invoked_state() {
    let owner = address(7000);
    let pool = address(7100);
    let verifier = address(7200);
    let chain_id = 'SN_MAIN';
    let seal = deploy_exception_seal(pool, verifier, owner, chain_id);
    let snapshot_fact = register_snapshot(seal, owner);
    let claim = claim_state(snapshot_fact);
    let claim_inputs = exception_inputs(seal, chain_id, claim);
    start_mock_call(
        verifier,
        selector!("verify_ultra_keccak_zk_honk_proof"),
        Result::<Span<u256>, felt252>::Ok(claim_inputs.span()),
    );
    start_cheat_block_timestamp(seal, 300);
    let dispatcher = IPayoPayrollExceptionSealDispatcher { contract_address: seal };
    let proof: Array<felt252> = array![123];
    dispatcher.authorize_claim(claim, proof.span());
    assert(dispatcher.get_claim(81, 82).status == 1, 'claim not proved');

    let remediation = remediation_state();
    let remediation_inputs = exception_inputs(seal, chain_id, remediation);
    start_mock_call(
        verifier,
        selector!("verify_ultra_keccak_zk_honk_proof"),
        Result::<Span<u256>, felt252>::Ok(remediation_inputs.span()),
    );
    dispatcher.authorize_remediation(remediation, proof.span());
    assert(
        dispatcher.get_remediation_attempt(101, 102).status == 1,
        'remediation not authorized',
    );
    start_cheat_caller_address(seal, pool);
    dispatcher.privacy_invoke(3, 101, 102, 121, 122, 111, 112);
    assert(dispatcher.get_claim(81, 82).status == 2, 'claim payment not invoked');
    assert(
        dispatcher.get_remediation_attempt(101, 102).status == 2,
        'attempt not invoked',
    );
}


#[test]
#[should_panic(expected: ('PAYO_REPLAY',))]
fn accepted_claim_subject_cannot_be_replayed() {
    let owner = address(7000);
    let verifier = address(7200);
    let chain_id = 'SN_MAIN';
    let seal = deploy_exception_seal(address(7100), verifier, owner, chain_id);
    let snapshot_fact = register_snapshot(seal, owner);
    let claim = claim_state(snapshot_fact);
    let claim_inputs = exception_inputs(seal, chain_id, claim);
    start_mock_call(
        verifier,
        selector!("verify_ultra_keccak_zk_honk_proof"),
        Result::<Span<u256>, felt252>::Ok(claim_inputs.span()),
    );
    start_cheat_block_timestamp(seal, 300);
    let dispatcher = IPayoPayrollExceptionSealDispatcher { contract_address: seal };
    let proof: Array<felt252> = array![123];
    dispatcher.authorize_claim(claim, proof.span());
    dispatcher.authorize_claim(claim, proof.span());
}

#[test]
#[should_panic(expected: ('PAYO_BAD_WINDOW',))]
fn expired_claim_authorization_is_rejected_before_verification() {
    let owner = address(7000);
    let seal = deploy_exception_seal(address(7100), address(7200), owner, 'SN_MAIN');
    let snapshot_fact = register_snapshot(seal, owner);
    start_cheat_block_timestamp(seal, 341);
    let proof: Array<felt252> = array![123];
    IPayoPayrollExceptionSealDispatcher { contract_address: seal }
        .authorize_claim(claim_state(snapshot_fact), proof.span());
}

#[test]
#[should_panic(expected: ('PAYO_BAD_ROOT',))]
fn claim_cannot_substitute_another_agreement_root() {
    let owner = address(7000);
    let seal = deploy_exception_seal(address(7100), address(7200), owner, 'SN_MAIN');
    let snapshot_fact = register_snapshot(seal, owner);
    let mut claim = claim_state(snapshot_fact);
    claim.agreement_root_low += 1;
    start_cheat_block_timestamp(seal, 300);
    let proof: Array<felt252> = array![123];
    IPayoPayrollExceptionSealDispatcher { contract_address: seal }
        .authorize_claim(claim, proof.span());
}
