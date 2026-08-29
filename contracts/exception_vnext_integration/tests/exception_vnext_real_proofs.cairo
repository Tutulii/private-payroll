use claim_v6_verifier::honk_verifier::{
    IUltraKeccakZKHonkVerifierDispatcherTrait as ClaimVerifierDispatcherTrait,
    IUltraKeccakZKHonkVerifierLibraryDispatcher as ClaimVerifierLibraryDispatcher,
};
use core::poseidon::poseidon_hash_span;
use core::serde::Serde;
use payo_contracts::payroll_exception_seal::{
    ExceptionProofStateV2, IPayoPayrollExceptionSealDispatcher,
    IPayoPayrollExceptionSealDispatcherTrait, PayrollProofStateV2,
};
use payo_contracts::policy_registry::{
    IPayoPolicyRegistryDispatcher, IPayoPolicyRegistryDispatcherTrait,
};
use payo_contracts::tenant_obligation_registry::{
    IPayoTenantObligationRootRegistryDispatcher, IPayoTenantObligationRootRegistryDispatcherTrait,
};
use remediation_v7_verifier::honk_verifier::{
    IUltraKeccakZKHonkVerifierDispatcherTrait as RemediationVerifierDispatcherTrait,
    IUltraKeccakZKHonkVerifierLibraryDispatcher as RemediationVerifierLibraryDispatcher,
};
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp,
    start_cheat_caller_address, start_mock_call,
};
use starknet::ContractAddress;

const CHAIN_ID: felt252 = 1;
const SEAL_ADDRESS: felt252 = 0x12345;
const AGREEMENT_HIGH: u128 = 0x2a86543bef7135dff48c0a3790be02a2;
const AGREEMENT_LOW: u128 = 0x18630a505854efe76e6704c8de5f9ba;
const CLAIM_ROOT_HIGH: u128 = 0x305e1fe2931d5067b95ddfd746d31a8;
const CLAIM_ROOT_LOW: u128 = 0xccc5e6625204a745c17b0a5a0cfa667;
const POLICY_HIGH: u128 = 0x16575a4f2517b43a894ae1d8ad892448;
const POLICY_LOW: u128 = 0x892830da2cb8162b50354f396e3d6073;
const RUN_HIGH: u128 = 0x102bdeb8a00829c3f75a9f4444c8ce0c;
const RUN_LOW: u128 = 0x438299fc623bec20ea120661fb06bbd0;
const SNAPSHOT_FACT_HIGH: u128 = 0xce7f4f9aa3f9d0ab10434b625d14d9ab;
const SNAPSHOT_FACT_LOW: u128 = 0xa195efccd7e9ae3ea5710fdd6f58c654;
const CLAIM_HIGH: u128 = 0x7fee165336c657578a7593966fbff236;
const CLAIM_LOW: u128 = 0x864e44f394a67a85f6998f4adcf18ca6;
const CLAIM_FACT_HIGH: u128 = 0x768bac66b71a19dbfcab599616c1faa7;
const CLAIM_FACT_LOW: u128 = 0x76cf860fbb9fcc51048091b5edd423a6;
const ACTION_HIGH: u128 = 0x304fdc9bf66f0f18e96ac994f8d81841;
const ACTION_LOW: u128 = 0x2c6897e8ad992c54422fe61a4d274cd5;
const REMEDIATION_HIGH: u128 = 0xbbcf948bff3319934396e6ae2c931088;
const REMEDIATION_LOW: u128 = 0xd599cb287bc7814a187e098559f1c9ee;
const REMEDIATION_FACT_HIGH: u128 = 0x35996d2905d97e22a6d1bbce8afaf2c0;
const REMEDIATION_FACT_LOW: u128 = 0xc342e0311f09e75edccb4e1f6f2ab32f;

fn address(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

fn fixture(path: ByteArray) -> Array<felt252> {
    read_txt(@FileTrait::new(path))
}

fn fixture_with_corrupted_chain_id(path: ByteArray) -> Array<felt252> {
    let source = fixture(path);
    let mut corrupted = array![];
    for index in 0..source.len() {
        corrupted.append(if index == 1 {
            2
        } else {
            *source.at(index)
        });
    }
    corrupted
}

fn declare_deploy(name: ByteArray) -> ContractAddress {
    let class = declare(name).unwrap().contract_class();
    let calldata: Array<felt252> = array![];
    let (contract, _) = class.deploy(@calldata).unwrap();
    contract
}

fn deploy_topology() -> (
    ContractAddress,
    ContractAddress,
    ContractAddress,
    ContractAddress,
    ContractAddress,
    ContractAddress,
    ContractAddress,
) {
    let admin = address(0x9000);
    let owner = address(0xabc);
    let pool = address(0x1000);
    let snapshot_verifier = declare_deploy("PayoObligationSnapshotV5Verifier");
    let claim_verifier = declare_deploy("PayoWageClaimV6Verifier");
    let remediation_verifier = declare_deploy("PayoWageRemediationV7Verifier");

    let catalog_class = declare("PayoPolicyRegistry").unwrap().contract_class();
    let mut catalog_calldata = array![];
    admin.serialize(ref catalog_calldata);
    let (catalog, _) = catalog_class.deploy(@catalog_calldata).unwrap();

    let obligations_class = declare("PayoTenantObligationRootRegistry").unwrap().contract_class();
    let mut obligations_calldata = array![];
    admin.serialize(ref obligations_calldata);
    let (obligations, _) = obligations_class.deploy(@obligations_calldata).unwrap();

    let seal_class = declare("PayoPayrollExceptionSeal").unwrap().contract_class();
    let mut seal_calldata = array![];
    pool.serialize(ref seal_calldata);
    catalog.serialize(ref seal_calldata);
    obligations.serialize(ref seal_calldata);
    CHAIN_ID.serialize(ref seal_calldata);
    let seal_target = address(SEAL_ADDRESS);
    let (seal, _) = seal_class.deploy_at(@seal_calldata, seal_target).unwrap();

    start_cheat_caller_address(catalog, admin);
    start_cheat_block_timestamp(catalog, 900);
    let catalog_dispatcher = IPayoPolicyRegistryDispatcher { contract_address: catalog };
    catalog_dispatcher.schedule_policy_root(POLICY_HIGH, POLICY_LOW, 0, 2_000);
    catalog_dispatcher.schedule_fx_root(0x333, 0x444, 0, 2_000);
    catalog_dispatcher.schedule_verifier(0, 5, snapshot_verifier, 0, 2_000);
    catalog_dispatcher.schedule_verifier(2, 6, claim_verifier, 0, 2_000);
    catalog_dispatcher.schedule_verifier(3, 7, remediation_verifier, 0, 2_000);

    start_cheat_caller_address(obligations, owner);
    start_cheat_block_timestamp(obligations, 900);
    IPayoTenantObligationRootRegistryDispatcher { contract_address: obligations }
        .schedule_obligation_root(AGREEMENT_HIGH, AGREEMENT_LOW, 0, 2_000);

    start_cheat_caller_address(seal, owner);
    start_cheat_block_timestamp(seal, 900);
    IPayoPayrollExceptionSealDispatcher { contract_address: seal }
        .register_obligation_snapshot(
            RUN_HIGH,
            RUN_LOW,
            AGREEMENT_HIGH,
            AGREEMENT_LOW,
            CLAIM_ROOT_HIGH,
            CLAIM_ROOT_LOW,
            POLICY_HIGH,
            POLICY_LOW,
            1_000,
            1_100,
            1_500,
            SNAPSHOT_FACT_HIGH,
            SNAPSHOT_FACT_LOW,
        );

    (seal, catalog, obligations, admin, owner, pool, snapshot_verifier)
}

fn snapshot_state() -> ExceptionProofStateV2 {
    ExceptionProofStateV2 {
        proof_version: 5,
        schema_version: 2,
        agreement_root_high: AGREEMENT_HIGH,
        agreement_root_low: AGREEMENT_LOW,
        manifest_root_high: CLAIM_ROOT_HIGH,
        manifest_root_low: CLAIM_ROOT_LOW,
        policy_root_high: POLICY_HIGH,
        policy_root_low: POLICY_LOW,
        fx_root_high: 0,
        fx_root_low: 0,
        subject_nullifier_high: RUN_HIGH,
        subject_nullifier_low: RUN_LOW,
        parent_nullifier_high: 0,
        parent_nullifier_low: 0,
        fact_commitment_high: SNAPSHOT_FACT_HIGH,
        fact_commitment_low: SNAPSHOT_FACT_LOW,
        parent_fact_commitment_high: 0,
        parent_fact_commitment_low: 0,
        validity_start: 999,
        validity_expiry: 1_000,
        shard_index: 0,
    }
}

fn claim_state() -> ExceptionProofStateV2 {
    ExceptionProofStateV2 {
        proof_version: 6,
        schema_version: 2,
        agreement_root_high: AGREEMENT_HIGH,
        agreement_root_low: AGREEMENT_LOW,
        manifest_root_high: 0,
        manifest_root_low: 0,
        policy_root_high: POLICY_HIGH,
        policy_root_low: POLICY_LOW,
        fx_root_high: 0,
        fx_root_low: 0,
        subject_nullifier_high: CLAIM_HIGH,
        subject_nullifier_low: CLAIM_LOW,
        parent_nullifier_high: RUN_HIGH,
        parent_nullifier_low: RUN_LOW,
        fact_commitment_high: CLAIM_FACT_HIGH,
        fact_commitment_low: CLAIM_FACT_LOW,
        parent_fact_commitment_high: SNAPSHOT_FACT_HIGH,
        parent_fact_commitment_low: SNAPSHOT_FACT_LOW,
        validity_start: 1_150,
        validity_expiry: 1_200,
        shard_index: 0,
    }
}

fn remediation_state() -> ExceptionProofStateV2 {
    ExceptionProofStateV2 {
        proof_version: 7,
        schema_version: 2,
        agreement_root_high: AGREEMENT_HIGH,
        agreement_root_low: AGREEMENT_LOW,
        manifest_root_high: ACTION_HIGH,
        manifest_root_low: ACTION_LOW,
        policy_root_high: POLICY_HIGH,
        policy_root_low: POLICY_LOW,
        fx_root_high: 0,
        fx_root_low: 0,
        subject_nullifier_high: REMEDIATION_HIGH,
        subject_nullifier_low: REMEDIATION_LOW,
        parent_nullifier_high: CLAIM_HIGH,
        parent_nullifier_low: CLAIM_LOW,
        fact_commitment_high: REMEDIATION_FACT_HIGH,
        fact_commitment_low: REMEDIATION_FACT_LOW,
        parent_fact_commitment_high: CLAIM_FACT_HIGH,
        parent_fact_commitment_low: CLAIM_FACT_LOW,
        validity_start: 1_201,
        validity_expiry: 1_250,
        shard_index: 0,
    }
}

fn payroll_state() -> PayrollProofStateV2 {
    PayrollProofStateV2 {
        proof_version: 2,
        schema_version: 1,
        agreement_root_high: AGREEMENT_HIGH,
        agreement_root_low: AGREEMENT_LOW,
        manifest_root_high: 0x111,
        manifest_root_low: 0x222,
        policy_root_high: POLICY_HIGH,
        policy_root_low: POLICY_LOW,
        fx_root_high: 0x333,
        fx_root_low: 0x444,
        run_nullifier_high: RUN_HIGH,
        run_nullifier_low: RUN_LOW,
        validity_start: 1_000,
        validity_expiry: 1_100,
    }
}

fn payroll_shard_inputs(seal: ContractAddress, shard: u8) -> Array<u256> {
    let seal_felt: felt252 = seal.into();
    array![
        CHAIN_ID.into(), seal_felt.into(), 2_u32.into(), 1_u32.into(), AGREEMENT_HIGH.into(),
        AGREEMENT_LOW.into(), 0x111_u128.into(), 0x222_u128.into(), POLICY_HIGH.into(),
        POLICY_LOW.into(), 0x333_u128.into(), 0x444_u128.into(), RUN_HIGH.into(), RUN_LOW.into(),
        1_000_u64.into(), 1_100_u64.into(), shard.into(),
    ]
}

#[test]
fn exact_snapshot_v5_verifier_authorizes_the_registered_payroll_snapshot() {
    let (seal, catalog, _, admin, _, _, _) = deploy_topology();
    let payroll_adapter = address(0x7777);
    start_cheat_caller_address(catalog, admin);
    IPayoPolicyRegistryDispatcher { contract_address: catalog }
        .schedule_verifier(0, 2, payroll_adapter, 0, 2_000);
    let dispatcher = IPayoPayrollExceptionSealDispatcher { contract_address: seal };
    let dummy: Array<felt252> = array![1];
    let snapshot_proof = fixture("tests/obligation_snapshot_v5.txt");
    start_cheat_block_timestamp(seal, 999);
    dispatcher
        .begin_payroll_authorization(
            payroll_state(),
            snapshot_state(),
            poseidon_hash_span(dummy.span()),
            poseidon_hash_span(dummy.span()),
            poseidon_hash_span(snapshot_proof.span()),
        );
    dispatcher.verify_payroll_authorization_proof(RUN_HIGH, RUN_LOW, 2, snapshot_proof.span());
    assert(!dispatcher.get_run_anchor(RUN_HIGH, RUN_LOW).exists, 'snapshot authorized alone');

    start_cheat_block_timestamp(seal, 1_000);
    let shard_zero_inputs = payroll_shard_inputs(seal, 0);
    start_mock_call(
        payroll_adapter,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(shard_zero_inputs.span()),
    );
    dispatcher.verify_payroll_authorization_proof(RUN_HIGH, RUN_LOW, 0, dummy.span());
    assert(!dispatcher.get_run_anchor(RUN_HIGH, RUN_LOW).exists, 'two proofs authorized');

    let shard_one_inputs = payroll_shard_inputs(seal, 1);
    start_mock_call(
        payroll_adapter,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(shard_one_inputs.span()),
    );
    dispatcher.verify_payroll_authorization_proof(RUN_HIGH, RUN_LOW, 1, dummy.span());
    assert(dispatcher.get_run_anchor(RUN_HIGH, RUN_LOW).exists, 'snapshot proof not linked');
}

#[test]
fn exact_claim_v6_and_remediation_v7_proofs_drive_private_settlement_state() {
    let (seal, _, _, _, _, pool, _) = deploy_topology();
    let dispatcher = IPayoPayrollExceptionSealDispatcher { contract_address: seal };

    start_cheat_block_timestamp(seal, 1_150);
    let claim_proof = fixture("tests/wage_claim_v6.txt");
    dispatcher.authorize_claim(claim_state(), claim_proof.span());
    assert(dispatcher.get_claim(CLAIM_HIGH, CLAIM_LOW).status == 1, 'claim was not proved');

    start_cheat_block_timestamp(seal, 1_201);
    let remediation_proof = fixture("tests/wage_remediation_v7.txt");
    dispatcher.authorize_remediation(remediation_state(), remediation_proof.span());
    assert(
        dispatcher.get_remediation_attempt(REMEDIATION_HIGH, REMEDIATION_LOW).status == 1,
        'remediation was not authorized',
    );

    start_cheat_caller_address(seal, pool);
    start_cheat_block_timestamp(seal, 1_202);
    let deposits = dispatcher
        .privacy_invoke(
            3,
            REMEDIATION_HIGH,
            REMEDIATION_LOW,
            REMEDIATION_FACT_HIGH,
            REMEDIATION_FACT_LOW,
            ACTION_HIGH,
            ACTION_LOW,
        );
    assert(deposits.is_empty(), 'exception seal became custodial');
    assert(dispatcher.get_claim(CLAIM_HIGH, CLAIM_LOW).status == 2, 'claim was not settled');
    assert(
        dispatcher.get_remediation_attempt(REMEDIATION_HIGH, REMEDIATION_LOW).status == 2,
        'remediation not invoked',
    );
}

#[test]
fn every_supported_claim_kind_passes_the_real_v6_cairo_verifier() {
    let class_hash = *declare("PayoWageClaimV6Verifier").unwrap().contract_class().class_hash;
    let dispatcher = ClaimVerifierLibraryDispatcher { class_hash };
    let missing_obligation = fixture("tests/wage_claim_v6.txt");
    assert(
        dispatcher.verify_ultra_keccak_zk_honk_proof(missing_obligation.span()).is_ok(),
        'missing claim rejected',
    );
    let fx_floor = fixture("tests/wage_claim_v6_fx_floor.txt");
    assert(
        dispatcher.verify_ultra_keccak_zk_honk_proof(fx_floor.span()).is_ok(),
        'fx claim rejected',
    );
    let final_pay = fixture("tests/wage_claim_v6_final_pay.txt");
    assert(
        dispatcher.verify_ultra_keccak_zk_honk_proof(final_pay.span()).is_ok(),
        'final claim rejected',
    );
}

#[test]
fn both_supported_remediation_paths_pass_the_real_v7_cairo_verifier() {
    let class_hash = *declare("PayoWageRemediationV7Verifier").unwrap().contract_class().class_hash;
    let dispatcher = RemediationVerifierLibraryDispatcher { class_hash };
    let token_payment = fixture("tests/wage_remediation_v7.txt");
    assert(
        dispatcher.verify_ultra_keccak_zk_honk_proof(token_payment.span()).is_ok(),
        'token remedy rejected',
    );
    let fx_conversion = fixture("tests/wage_remediation_v7_fx_floor.txt");
    assert(
        dispatcher.verify_ultra_keccak_zk_honk_proof(fx_conversion.span()).is_ok(),
        'fx remedy rejected',
    );
}

#[test]
// Garaga may reject malformed proof hints before returning its Result, so the
// security invariant is an unconditional transaction revert with no state write.
#[should_panic]
fn claim_v6_rejects_proof_calldata_with_a_corrupted_public_input() {
    let (seal, _, _, _, _, _, _) = deploy_topology();
    start_cheat_block_timestamp(seal, 1_150);
    let corrupted = fixture_with_corrupted_chain_id("tests/wage_claim_v6.txt");
    IPayoPayrollExceptionSealDispatcher { contract_address: seal }
        .authorize_claim(claim_state(), corrupted.span());
}

#[test]
#[should_panic(expected: ('PAYO_PUBLIC_INPUTS',))]
fn claim_v6_rejects_valid_proof_when_requested_state_is_not_proof_bound() {
    let (seal, _, _, _, _, _, _) = deploy_topology();
    start_cheat_block_timestamp(seal, 1_150);
    let mut mismatched = claim_state();
    mismatched.fact_commitment_low += 1;
    let proof = fixture("tests/wage_claim_v6.txt");
    IPayoPayrollExceptionSealDispatcher { contract_address: seal }
        .authorize_claim(mismatched, proof.span());
}
