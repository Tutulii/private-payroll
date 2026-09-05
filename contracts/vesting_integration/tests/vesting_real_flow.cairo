use core::poseidon::poseidon_hash_span;
use core::serde::Serde;
use payo_contracts::policy_registry::{
    IPayoPolicyRegistryDispatcher, IPayoPolicyRegistryDispatcherTrait,
};
use payo_contracts::tenant_obligation_registry::{
    IPayoTenantObligationRootRegistryDispatcher, IPayoTenantObligationRootRegistryDispatcherTrait,
};
use payo_contracts::vesting_book_seal::{
    IPayoVestingBookSealDispatcher, IPayoVestingBookSealDispatcherTrait, VestingPayrollProofState,
    VestingTransitionProofState,
};
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp,
    start_cheat_caller_address, start_mock_call,
};
use starknet::ContractAddress;
use vesting_verifier_v3::vesting_bundle_verifier::{
    IVestingBookV3BundleVerifierDispatcher, IVestingBookV3BundleVerifierDispatcherTrait,
};

const CHAIN_ID: felt252 = 'SN_MAIN';
const PROOF_SEAL_ADDRESS: felt252 = 0x456;
const OWNER_ADDRESS: felt252 = 0x123;
const AGREEMENT_HIGH: u128 = 0x0529212320c6132cf304d3d238216e29;
const AGREEMENT_LOW: u128 = 0xe2377075c1b7a41f092917f393612e3f;
const MANIFEST_HIGH: u128 = 0x2db5a4e9e7f2b20f4dbe170c3a2e5c41;
const MANIFEST_LOW: u128 = 0x9f4cbf611978b46238d621ee04e2dc85;
const POLICY_HIGH: u128 = 0x16575a4f2517b43a894ae1d8ad892448;
const POLICY_LOW: u128 = 0x892830da2cb8162b50354f396e3d6073;
const FX_HIGH: u128 = 0x0736e1f5e8a84d867cffe27b7f8ec401;
const FX_LOW: u128 = 0x9b1006167997dc9f013c899d3a8dc3bc;
const RUN_HIGH: u128 = 0x24f264a5e04c12c05b0a5c219c1162e3;
const RUN_LOW: u128 = 0x8d8d5e95c8d710aa3067c6ad9123392e;
const SCHEDULE_HIGH: u128 = 0x1223db51eda8f66cb31f190fb13fef90;
const SCHEDULE_LOW: u128 = 0x64de241bcb3c34799b69147f4cee601b;
const NEXT_HIGH: u128 = 0xbac95d662718f66a93c2a9fc55c9f1f2;
const NEXT_LOW: u128 = 0x1f2101dc57001962bd4300ff3f8e926d;
const RELEASE_HIGH: u128 = 0x38eb81e5f94cb05d9e2bf8da8deee937;
const RELEASE_LOW: u128 = 0x38b7afbbdb9241528007f62f97090780;
const BOOK_HIGH: u128 = 0xe2a03bd2b746cc54e587944fe7bad9ac;
const BOOK_LOW: u128 = 0x9317b9762387e80b4076f9e7eaf6b19a;
const ATTESTATION_HIGH: u128 = 0x05a649755746757000454e5d6fcbb954;
const ATTESTATION_LOW: u128 = 0x60522e05ba4c5469dfea413ce724818f;
const TOTALS_HIGH: u128 = 0x036ff64bd2e26819aef740cb41c86399;
const TOTALS_LOW: u128 = 0x525ac1ddc7f24728b82bd2613fd7f896;

fn address(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

fn payroll() -> VestingPayrollProofState {
    VestingPayrollProofState {
        proof_version: 2,
        schema_version: 1,
        agreement_root_high: AGREEMENT_HIGH,
        agreement_root_low: AGREEMENT_LOW,
        manifest_root_high: MANIFEST_HIGH,
        manifest_root_low: MANIFEST_LOW,
        policy_root_high: POLICY_HIGH,
        policy_root_low: POLICY_LOW,
        fx_root_high: FX_HIGH,
        fx_root_low: FX_LOW,
        run_nullifier_high: RUN_HIGH,
        run_nullifier_low: RUN_LOW,
        validity_start: 600,
        validity_expiry: 900,
    }
}

fn transition() -> VestingTransitionProofState {
    VestingTransitionProofState {
        proof_version: 3,
        schema_version: 1,
        entry_kind: 1,
        owner: address(OWNER_ADDRESS),
        agreement_root_high: AGREEMENT_HIGH,
        agreement_root_low: AGREEMENT_LOW,
        manifest_root_high: MANIFEST_HIGH,
        manifest_root_low: MANIFEST_LOW,
        policy_root_high: POLICY_HIGH,
        policy_root_low: POLICY_LOW,
        fx_root_high: FX_HIGH,
        fx_root_low: FX_LOW,
        run_nullifier_high: RUN_HIGH,
        run_nullifier_low: RUN_LOW,
        subject_nullifier_high: RUN_HIGH,
        subject_nullifier_low: RUN_LOW,
        parent_fact_high: 0,
        parent_fact_low: 0,
        fact_high: 0,
        fact_low: 0,
        source_seal: address(PROOF_SEAL_ADDRESS),
        source_proof_version: 2,
        attestation_root_high: ATTESTATION_HIGH,
        attestation_root_low: ATTESTATION_LOW,
        shard_0_contributor_count: 1,
        shard_1_contributor_count: 0,
        totals_disclosed: 1,
        totals_commitment_high: TOTALS_HIGH,
        totals_commitment_low: TOTALS_LOW,
        shard_0_strk_gross: 500,
        shard_0_strk_deductions: 0,
        shard_0_strk_net: 500,
        shard_0_usdc_gross: 0,
        shard_0_usdc_deductions: 0,
        shard_0_usdc_net: 0,
        shard_1_strk_gross: 0,
        shard_1_strk_deductions: 0,
        shard_1_strk_net: 0,
        shard_1_usdc_gross: 0,
        shard_1_usdc_deductions: 0,
        shard_1_usdc_net: 0,
        schedule_id_high: SCHEDULE_HIGH,
        schedule_id_low: SCHEDULE_LOW,
        previous_state_high: 0,
        previous_state_low: 0,
        next_state_high: NEXT_HIGH,
        next_state_low: NEXT_LOW,
        release_nullifier_high: RELEASE_HIGH,
        release_nullifier_low: RELEASE_LOW,
        book_entry_high: BOOK_HIGH,
        book_entry_low: BOOK_LOW,
        period_start: 1,
        period_end: 1000,
        validity_start: 600,
        validity_expiry: 900,
    }
}

fn payroll_inputs(shard: u8) -> Array<u256> {
    let state = payroll();
    array![
        CHAIN_ID.into(), PROOF_SEAL_ADDRESS.into(), state.proof_version.into(),
        state.schema_version.into(), state.agreement_root_high.into(),
        state.agreement_root_low.into(), state.manifest_root_high.into(),
        state.manifest_root_low.into(), state.policy_root_high.into(), state.policy_root_low.into(),
        state.fx_root_high.into(), state.fx_root_low.into(), state.run_nullifier_high.into(),
        state.run_nullifier_low.into(), state.validity_start.into(), state.validity_expiry.into(),
        shard.into(),
    ]
}

fn deploy_topology() -> (ContractAddress, ContractAddress, ContractAddress, ContractAddress) {
    let admin = address(0x900);
    let owner = address(OWNER_ADDRESS);
    let pool = address(0x1000);

    let verifier_class = declare("PayoVestingBookV3Verifier").unwrap().contract_class();
    let (verifier, _) = verifier_class.deploy(@array![]).unwrap();
    let bundle_class = declare("PayoVestingBookV3BundleVerifier").unwrap().contract_class();
    let (bundle, _) = bundle_class.deploy(@array![verifier.into()]).unwrap();

    let policy_class = declare("PayoPolicyRegistry").unwrap().contract_class();
    let mut policy_calldata = array![];
    admin.serialize(ref policy_calldata);
    let (catalog, _) = policy_class.deploy(@policy_calldata).unwrap();

    let obligation_class = declare("PayoTenantObligationRootRegistry").unwrap().contract_class();
    let mut obligation_calldata = array![];
    admin.serialize(ref obligation_calldata);
    let (obligations, _) = obligation_class.deploy(@obligation_calldata).unwrap();

    let seal_class = declare("PayoVestingBookSeal").unwrap().contract_class();
    let mut seal_calldata = array![];
    pool.serialize(ref seal_calldata);
    catalog.serialize(ref seal_calldata);
    obligations.serialize(ref seal_calldata);
    address(0x3000).serialize(ref seal_calldata);
    CHAIN_ID.serialize(ref seal_calldata);
    let (seal, _) = seal_class.deploy_at(@seal_calldata, address(PROOF_SEAL_ADDRESS)).unwrap();

    start_cheat_caller_address(catalog, admin);
    start_cheat_block_timestamp(catalog, 500);
    let catalog_dispatcher = IPayoPolicyRegistryDispatcher { contract_address: catalog };
    catalog_dispatcher.schedule_policy_root(POLICY_HIGH, POLICY_LOW, 500, 900);
    catalog_dispatcher
        .schedule_policy_root(ATTESTATION_HIGH, ATTESTATION_LOW, 500, 900);
    catalog_dispatcher.schedule_fx_root(FX_HIGH, FX_LOW, 500, 900);
    catalog_dispatcher.schedule_verifier(0, 2, address(0x2000), 500, 900);
    catalog_dispatcher.schedule_verifier(0, 3, bundle, 500, 900);

    start_cheat_caller_address(obligations, owner);
    start_cheat_block_timestamp(obligations, 500);
    IPayoTenantObligationRootRegistryDispatcher { contract_address: obligations }
        .schedule_obligation_root(AGREEMENT_HIGH, AGREEMENT_LOW, 500, 900);

    start_cheat_block_timestamp(seal, 700);
    (seal, bundle, address(0x2000), pool)
}

fn authorize_real_transition(
    seal: ContractAddress, payroll_verifier: ContractAddress,
) -> (Array<felt252>, Array<felt252>) {
    let vesting_0 = read_txt(@FileTrait::new("../vesting_verifier_v3/tests/proof_calldata_0.txt"));
    let vesting_1 = read_txt(@FileTrait::new("../vesting_verifier_v3/tests/proof_calldata_1.txt"));
    let payroll_0 = array![0x101];
    let payroll_1 = array![0x102];
    let dispatcher = IPayoVestingBookSealDispatcher { contract_address: seal };
    dispatcher
        .begin_vesting_authorization(
            payroll(),
            transition(),
            poseidon_hash_span(payroll_0.span()),
            poseidon_hash_span(payroll_1.span()),
            poseidon_hash_span(vesting_0.span()),
            poseidon_hash_span(vesting_1.span()),
        );

    start_mock_call(
        payroll_verifier,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(payroll_inputs(0).span()),
    );
    dispatcher.verify_vesting_authorization_proof(RUN_HIGH, RUN_LOW, 0, payroll_0.span());
    start_mock_call(
        payroll_verifier,
        selector!("verify_payroll_integrity_shard"),
        Result::<Span<u256>, felt252>::Ok(payroll_inputs(1).span()),
    );
    dispatcher.verify_vesting_authorization_proof(RUN_HIGH, RUN_LOW, 1, payroll_1.span());
    dispatcher.verify_vesting_authorization_proof(RUN_HIGH, RUN_LOW, 2, vesting_0.span());
    dispatcher.verify_vesting_authorization_proof(RUN_HIGH, RUN_LOW, 3, vesting_1.span());
    (vesting_0, vesting_1)
}

#[test]
fn real_v3_bundle_verifies_from_the_composed_package() {
    let verifier_class = declare("PayoVestingBookV3Verifier").unwrap().contract_class();
    let (verifier, _) = verifier_class.deploy(@array![]).unwrap();
    let bundle_class = declare("PayoVestingBookV3BundleVerifier").unwrap().contract_class();
    let (bundle, _) = bundle_class.deploy(@array![verifier.into()]).unwrap();
    let proof = read_txt(@FileTrait::new("../vesting_verifier_v3/tests/proof_calldata_0.txt"));
    let result = IVestingBookV3BundleVerifierDispatcher { contract_address: bundle }
        .verify_payroll_integrity_shard(proof.span());
    assert(result.is_ok(), 'composed verifier failed');
    assert(result.unwrap().len() == 58, 'wrong composed inputs');
}

#[test]
fn real_v3_authorization_header_is_accepted() {
    let (seal, _, _, _) = deploy_topology();
    let vesting_0 = read_txt(@FileTrait::new("../vesting_verifier_v3/tests/proof_calldata_0.txt"));
    let vesting_1 = read_txt(@FileTrait::new("../vesting_verifier_v3/tests/proof_calldata_1.txt"));
    let payroll_0 = array![0x101];
    let payroll_1 = array![0x102];
    let dispatcher = IPayoVestingBookSealDispatcher { contract_address: seal };
    dispatcher
        .begin_vesting_authorization(
            payroll(),
            transition(),
            poseidon_hash_span(payroll_0.span()),
            poseidon_hash_span(payroll_1.span()),
            poseidon_hash_span(vesting_0.span()),
            poseidon_hash_span(vesting_1.span()),
        );
    let pending = dispatcher.get_pending_authorization(RUN_HIGH, RUN_LOW);
    assert(pending.exists && pending.status == 1 && pending.verified_mask == 0, 'bad header');
}

#[test]
fn real_v3_proofs_advance_state_and_append_the_complete_book() {
    let (seal, _, payroll_verifier, pool) = deploy_topology();
    let _ = authorize_real_transition(seal, payroll_verifier);
    let dispatcher = IPayoVestingBookSealDispatcher { contract_address: seal };
    assert(dispatcher.get_pending_authorization(RUN_HIGH, RUN_LOW).status == 2, 'not authorized');
    start_cheat_caller_address(seal, pool);
    let notes = dispatcher
        .privacy_invoke(RUN_HIGH, RUN_LOW, RELEASE_HIGH, RELEASE_LOW, BOOK_HIGH, BOOK_LOW);
    assert(notes.is_empty(), 'vesting seal became custodial');
    let state = dispatcher.get_vesting_state(SCHEDULE_HIGH, SCHEDULE_LOW);
    assert(state.exists && state.owner == address(OWNER_ADDRESS), 'state owner missing');
    assert(state.state_high == NEXT_HIGH && state.state_low == NEXT_LOW, 'wrong state');
    assert(dispatcher.is_release_consumed(RELEASE_HIGH, RELEASE_LOW), 'release reusable');
    let book = dispatcher.get_payroll_book(address(OWNER_ADDRESS), 1, 1000);
    assert(book.exists && book.entry_count == 1, 'complete book not appended');
    assert(
        dispatcher
            .get_payroll_book_entry(
                address(OWNER_ADDRESS), 1, 1000, 0,
            ) == u256 { high: BOOK_HIGH, low: BOOK_LOW },
        'book entry mismatch',
    );
}

#[test]
#[should_panic(expected: ('PAYO_BAD_STATE',))]
fn real_v3_release_replay_is_rejected() {
    let (seal, _, payroll_verifier, pool) = deploy_topology();
    let _ = authorize_real_transition(seal, payroll_verifier);
    let dispatcher = IPayoVestingBookSealDispatcher { contract_address: seal };
    start_cheat_caller_address(seal, pool);
    dispatcher.privacy_invoke(RUN_HIGH, RUN_LOW, RELEASE_HIGH, RELEASE_LOW, BOOK_HIGH, BOOK_LOW);
    dispatcher.privacy_invoke(RUN_HIGH, RUN_LOW, RELEASE_HIGH, RELEASE_LOW, BOOK_HIGH, BOOK_LOW);
}

#[test]
#[should_panic(expected: ('PAYO_STALE_STATE',))]
fn advanced_schedule_rejects_a_second_genesis_transition() {
    let (seal, _, payroll_verifier, pool) = deploy_topology();
    let _ = authorize_real_transition(seal, payroll_verifier);
    start_cheat_caller_address(seal, pool);
    IPayoVestingBookSealDispatcher { contract_address: seal }
        .privacy_invoke(RUN_HIGH, RUN_LOW, RELEASE_HIGH, RELEASE_LOW, BOOK_HIGH, BOOK_LOW);
    let mut stale_payroll = payroll();
    stale_payroll.run_nullifier_low = RUN_LOW - 1;
    let mut stale_transition = transition();
    stale_transition.run_nullifier_low = RUN_LOW - 1;
    stale_transition.subject_nullifier_low = RUN_LOW - 1;
    stale_transition.release_nullifier_low = RELEASE_LOW - 1;
    IPayoVestingBookSealDispatcher { contract_address: seal }
        .begin_vesting_authorization(stale_payroll, stale_transition, 1, 2, 3, 4);
}
