use core::poseidon::poseidon_hash_span;
use core::serde::Serde;
use payo_contracts::obligation_registry::{
    IPayoObligationRootRegistryDispatcher, IPayoObligationRootRegistryDispatcherTrait,
};
use payo_contracts::payroll_seal::{IPayoPayrollSealDispatcher, IPayoPayrollSealDispatcherTrait};
use payo_contracts::policy_registry::{
    IPayoPolicyRegistryDispatcher, IPayoPolicyRegistryDispatcherTrait,
};
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp,
    start_cheat_caller_address,
};
use starknet::ContractAddress;

const CHAIN_ID: felt252 = 1;
const PROOF_SEAL_ADDRESS: felt252 = 0x12345;
const POLICY_HIGH: u128 = 0x16575a4f2517b43a894ae1d8ad892448;
const POLICY_LOW: u128 = 0x892830da2cb8162b50354f396e3d6073;
const FX_HIGH: u128 = 0x13e605b611bdc7228e541b8f12934de4;
const FX_LOW: u128 = 0x42cc50c996a6e0364b3381ccf63623fb;

fn read_fixture(path: ByteArray) -> Array<felt252> {
    read_txt(@FileTrait::new(path))
}

fn declare_deploy(name: ByteArray) -> ContractAddress {
    let class = declare(name).unwrap().contract_class();
    let calldata: Array<felt252> = array![];
    let (address, _) = class.deploy(@calldata).unwrap();
    address
}

fn deploy_bundle(verifier: ContractAddress) -> ContractAddress {
    let class = declare("PayoIntegrityBundleVerifier").unwrap().contract_class();
    let mut calldata = array![];
    verifier.serialize(ref calldata);
    let (address, _) = class.deploy(@calldata).unwrap();
    address
}

fn deploy_advanced_bundle(advanced_verifier: ContractAddress) -> ContractAddress {
    deploy_bundle(advanced_verifier)
}

fn deploy_topology(
    advanced_bundle: ContractAddress,
    claim_bundle: ContractAddress,
    remediation_bundle: ContractAddress,
) -> (ContractAddress, ContractAddress, ContractAddress, ContractAddress, ContractAddress) {
    let admin: ContractAddress = 9000.try_into().unwrap();
    let pool: ContractAddress = 1000.try_into().unwrap();
    let policy_class = declare("PayoPolicyRegistry").unwrap().contract_class();
    let mut policy_calldata = array![];
    admin.serialize(ref policy_calldata);
    let (catalog, _) = policy_class.deploy(@policy_calldata).unwrap();
    let obligation_class = declare("PayoObligationRootRegistry").unwrap().contract_class();
    let mut obligation_calldata = array![];
    admin.serialize(ref obligation_calldata);
    let (obligations, _) = obligation_class.deploy(@obligation_calldata).unwrap();
    let seal_class = declare("PayoPayrollSeal").unwrap().contract_class();
    let mut seal_calldata = array![];
    pool.serialize(ref seal_calldata);
    catalog.serialize(ref seal_calldata);
    obligations.serialize(ref seal_calldata);
    CHAIN_ID.serialize(ref seal_calldata);
    let proof_seal: ContractAddress = PROOF_SEAL_ADDRESS.try_into().unwrap();
    let (seal, _) = seal_class.deploy_at(@seal_calldata, proof_seal).unwrap();

    start_cheat_caller_address(catalog, admin);
    start_cheat_block_timestamp(catalog, 900);
    let catalog_dispatcher = IPayoPolicyRegistryDispatcher { contract_address: catalog };
    catalog_dispatcher.schedule_policy_root(POLICY_HIGH, POLICY_LOW, 900, 3000);
    catalog_dispatcher.schedule_fx_root(FX_HIGH, FX_LOW, 900, 3000);
    catalog_dispatcher.schedule_verifier(0, 2, advanced_bundle, 900, 3000);
    catalog_dispatcher.schedule_verifier(2, 3, claim_bundle, 900, 3000);
    catalog_dispatcher.schedule_verifier(3, 4, remediation_bundle, 900, 3000);
    (seal, catalog, obligations, admin, pool)
}

fn schedule_obligation(
    obligations: ContractAddress,
    admin: ContractAddress,
    high: u128,
    low: u128,
) {
    start_cheat_caller_address(obligations, admin);
    start_cheat_block_timestamp(obligations, 900);
    IPayoObligationRootRegistryDispatcher { contract_address: obligations }
        .schedule_obligation_root(high, low, 900, 3000);
}

fn seal_then_verify(
    seal: ContractAddress,
    pool: ContractAddress,
    mode: u8,
    proof_version: u32,
    agreement_high: u128,
    agreement_low: u128,
    manifest_high: u128,
    manifest_low: u128,
    nullifier_high: u128,
    nullifier_low: u128,
    shard_0: Array<felt252>,
    shard_1: Array<felt252>,
    expected_status: u8,
) {
    let empty: Array<felt252> = array![];
    start_cheat_caller_address(seal, pool);
    start_cheat_block_timestamp(seal, 1500);
    let dispatcher = IPayoPayrollSealDispatcher { contract_address: seal };
    let deposits = dispatcher
        .privacy_invoke(
            mode,
            proof_version,
            1,
            agreement_high,
            agreement_low,
            manifest_high,
            manifest_low,
            POLICY_HIGH,
            POLICY_LOW,
            FX_HIGH,
            FX_LOW,
            nullifier_high,
            nullifier_low,
            1000,
            2000,
            poseidon_hash_span(shard_0.span()),
            poseidon_hash_span(shard_1.span()),
            empty.span(),
            empty.span(),
        );
    assert(deposits.is_empty(), 'seal became custodial');
    assert(dispatcher.get_run_status(nullifier_high, nullifier_low) == 1, 'proof not sealed');
    dispatcher.verify_sealed_shard(nullifier_high, nullifier_low, 0, shard_0.span());
    assert(dispatcher.get_run_status(nullifier_high, nullifier_low) == 1, 'one shard finalized');
    dispatcher.verify_sealed_shard(nullifier_high, nullifier_low, 1, shard_1.span());
    assert(
        dispatcher.get_run_status(nullifier_high, nullifier_low) == expected_status,
        'wrong terminal status',
    );
}

#[test]
fn real_phase3_proofs_verify_and_drive_advanced_claim_and_remediation_states() {
    let advanced = declare_deploy("PayoAdvancedObligationVerifier");
    let claim = declare_deploy("PayoWageClaimVerifier");
    let remediation = declare_deploy("PayoWageRemediationVerifier");
    let advanced_bundle = deploy_advanced_bundle(advanced);
    let claim_bundle = deploy_bundle(claim);
    let remediation_bundle = deploy_bundle(remediation);
    let (seal, _catalog, obligations, admin, pool) =
        deploy_topology(advanced_bundle, claim_bundle, remediation_bundle);

    schedule_obligation(
        obligations,
        admin,
        0x25988261ec63350e1e723237dd22fe6d,
        0xb00c04d80d8f576a580c7a888502aa34,
    );
    seal_then_verify(
        seal,
        pool,
        0,
        2,
        0x25988261ec63350e1e723237dd22fe6d,
        0xb00c04d80d8f576a580c7a888502aa34,
        0x1b706303e78898b5b79f7f06e382dbef,
        0x218453d003921047a33bfd2e20a6559e,
        0x8c43d493dde16ceb80a2be21de81aebe,
        0x2248845c4ba40c0a4695b12796964cd2,
        read_fixture("tests/advanced-shard-0.txt"),
        read_fixture("tests/advanced-shard-1.txt"),
        2,
    );

    schedule_obligation(
        obligations,
        admin,
        0x2c8c77ef2b9e1a7202ae051998ae8f39,
        0x7f99148db6fb17a6cff69af5b70205c0,
    );
    seal_then_verify(
        seal,
        pool,
        2,
        3,
        0x2c8c77ef2b9e1a7202ae051998ae8f39,
        0x7f99148db6fb17a6cff69af5b70205c0,
        0x0b546bdb002be9756566fd9eff7e9cb9,
        0x8b06482163ca8f8285bc5f100e298675,
        0x8f61f6f615d064d9173a244761d8e659,
        0x27f034ecf728aa325626e79ecddb5e78,
        read_fixture("tests/claim-shard-0.txt"),
        read_fixture("tests/claim-shard-1.txt"),
        4,
    );
    seal_then_verify(
        seal,
        pool,
        3,
        4,
        0x2c8c77ef2b9e1a7202ae051998ae8f39,
        0x7f99148db6fb17a6cff69af5b70205c0,
        0x24c87f5d8173bd6af8502e947073a25f,
        0x8fe8ce250a12a00e3fa686cae746b637,
        0x8f61f6f615d064d9173a244761d8e659,
        0x27f034ecf728aa325626e79ecddb5e78,
        read_fixture("tests/remediation-shard-0.txt"),
        read_fixture("tests/remediation-shard-1.txt"),
        5,
    );
}
