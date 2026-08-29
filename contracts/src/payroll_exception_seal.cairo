use starknet::ContractAddress;

// Positionally compatible with privacy::objects::OpenNoteDeposit. PAYO never
// creates or custodies a note, so every successful path returns an empty span.
#[derive(Serde, Copy, Drop, PartialEq, Debug)]
pub struct ExceptionOpenNoteDeposit {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u128,
}

#[derive(Serde, Copy, Drop, PartialEq, starknet::Store)]
pub struct PayrollProofStateV2 {
    pub proof_version: u32,
    pub schema_version: u32,
    pub agreement_root_high: u128,
    pub agreement_root_low: u128,
    pub manifest_root_high: u128,
    pub manifest_root_low: u128,
    pub policy_root_high: u128,
    pub policy_root_low: u128,
    pub fx_root_high: u128,
    pub fx_root_low: u128,
    pub run_nullifier_high: u128,
    pub run_nullifier_low: u128,
    pub validity_start: u64,
    pub validity_expiry: u64,
}

#[derive(Serde, Copy, Drop, PartialEq, starknet::Store)]
pub struct ExceptionProofStateV2 {
    pub proof_version: u32,
    pub schema_version: u32,
    pub agreement_root_high: u128,
    pub agreement_root_low: u128,
    pub manifest_root_high: u128,
    pub manifest_root_low: u128,
    pub policy_root_high: u128,
    pub policy_root_low: u128,
    pub fx_root_high: u128,
    pub fx_root_low: u128,
    pub subject_nullifier_high: u128,
    pub subject_nullifier_low: u128,
    pub parent_nullifier_high: u128,
    pub parent_nullifier_low: u128,
    pub fact_commitment_high: u128,
    pub fact_commitment_low: u128,
    pub parent_fact_commitment_high: u128,
    pub parent_fact_commitment_low: u128,
    pub validity_start: u64,
    pub validity_expiry: u64,
    pub shard_index: u8,
}

#[derive(Serde, Copy, Drop, starknet::Store)]
pub struct ObligationSnapshotRecord {
    pub exists: bool,
    pub owner: ContractAddress,
    pub base_agreement_root_high: u128,
    pub base_agreement_root_low: u128,
    pub claim_root_high: u128,
    pub claim_root_low: u128,
    pub policy_root_high: u128,
    pub policy_root_low: u128,
    pub snapshot_fact_high: u128,
    pub snapshot_fact_low: u128,
    pub due_at: u64,
    pub grace_ends_at: u64,
    pub claim_ends_at: u64,
    pub registered_at: u64,
    pub claim_count: u32,
}

#[derive(Serde, Copy, Drop, starknet::Store)]
pub struct PayrollStatementRecord {
    pub exists: bool,
    pub owner: ContractAddress,
    pub run_nullifier_high: u128,
    pub run_nullifier_low: u128,
    pub snapshot_fact_high: u128,
    pub snapshot_fact_low: u128,
    pub manifest_root_high: u128,
    pub manifest_root_low: u128,
    pub fx_root_high: u128,
    pub fx_root_low: u128,
    pub availability_high: u128,
    pub availability_low: u128,
    pub observed_at: u64,
    pub source: u8,
}

#[derive(Serde, Copy, Drop, starknet::Store)]
pub struct RunAnchorRecord {
    pub exists: bool,
    pub invoked: bool,
    pub agreement_root_high: u128,
    pub agreement_root_low: u128,
    pub manifest_root_high: u128,
    pub manifest_root_low: u128,
    pub policy_root_high: u128,
    pub policy_root_low: u128,
    pub fx_root_high: u128,
    pub fx_root_low: u128,
    pub snapshot_fact_high: u128,
    pub snapshot_fact_low: u128,
    pub authorized_at: u64,
    pub invoked_at: u64,
}

#[derive(Serde, Copy, Drop, starknet::Store)]
pub struct AcceptedClaimRecord {
    pub exists: bool,
    // 1 = proved, 2 = remediation payment invoked. Invocation is not note reconciliation.
    pub status: u8,
    pub run_nullifier_high: u128,
    pub run_nullifier_low: u128,
    pub agreement_root_high: u128,
    pub agreement_root_low: u128,
    pub policy_root_high: u128,
    pub policy_root_low: u128,
    pub fact_commitment_high: u128,
    pub fact_commitment_low: u128,
    pub accepted_at: u64,
    pub has_active_attempt: bool,
    pub active_attempt_high: u128,
    pub active_attempt_low: u128,
}

#[derive(Serde, Copy, Drop, starknet::Store)]
pub struct RemediationAttemptRecord {
    pub exists: bool,
    // 1 = authorized, 2 = invoked, 3 = expired.
    pub status: u8,
    pub claim_subject_high: u128,
    pub claim_subject_low: u128,
    pub fact_commitment_high: u128,
    pub fact_commitment_low: u128,
    pub action_commitment_high: u128,
    pub action_commitment_low: u128,
    pub expires_at: u64,
    pub authorized_at: u64,
    pub invoked_at: u64,
}

#[derive(Serde, Copy, Drop, starknet::Store)]
pub struct ActionAuthorization {
    pub exists: bool,
    // 1 = authorized, 2 = consumed, 3 = expired.
    pub status: u8,
    pub fact_commitment_high: u128,
    pub fact_commitment_low: u128,
    pub action_commitment_high: u128,
    pub action_commitment_low: u128,
    pub expires_at: u64,
}

#[derive(Serde, Copy, Drop, starknet::Store)]
pub struct PendingPayrollAuthorization {
    pub exists: bool,
    // 1 = collecting proofs, 2 = authorized.
    pub status: u8,
    pub payroll: PayrollProofStateV2,
    pub snapshot: ExceptionProofStateV2,
    pub payroll_shard_0_hash: felt252,
    pub payroll_shard_1_hash: felt252,
    pub snapshot_proof_hash: felt252,
    // Bit 0 = payroll shard 0, bit 1 = payroll shard 1, bit 2 = snapshot v5.
    pub verified_mask: u8,
    pub created_at: u64,
    pub updated_at: u64,
}

#[starknet::interface]
pub trait IExceptionIntegrityVerifier<TContractState> {
    fn verify_payroll_integrity_bundle(
        self: @TContractState,
        shard_0_proof: Span<felt252>,
        shard_1_proof: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
    fn verify_payroll_integrity_shard(
        self: @TContractState, proof: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
}

/// Native Garaga verifier interface used by the proof-bound vNext exception circuits.
/// Keeping this separate from `IExceptionIntegrityVerifier` lets payroll v2 retain its
/// two-shard PAYO adapter while snapshot v5, claim v6 and remediation v7 call their
/// exact generated verifier classes directly.
#[starknet::interface]
pub trait IExceptionGaragaVerifier<TContractState> {
    fn verify_ultra_keccak_zk_honk_proof(
        self: @TContractState, full_proof_with_hints: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
}

#[starknet::interface]
pub trait IExceptionCatalogRegistry<TContractState> {
    fn is_policy_root_valid(self: @TContractState, root_high: u128, root_low: u128) -> bool;
    fn is_fx_root_valid(self: @TContractState, root_high: u128, root_low: u128) -> bool;
    fn is_verifier_valid(self: @TContractState, mode: u8, proof_version: u32) -> bool;
    fn get_verifier(
        self: @TContractState, mode: u8, proof_version: u32,
    ) -> ContractAddress;
}

#[starknet::interface]
pub trait IExceptionObligationRegistry<TContractState> {
    fn is_obligation_root_valid(
        self: @TContractState, root_high: u128, root_low: u128,
    ) -> bool;
    fn get_obligation_root_owner(
        self: @TContractState, root_high: u128, root_low: u128,
    ) -> ContractAddress;
}

#[starknet::interface]
pub trait IPayoPayrollExceptionSeal<TContractState> {
    fn register_obligation_snapshot(
        ref self: TContractState,
        run_nullifier_high: u128,
        run_nullifier_low: u128,
        base_agreement_root_high: u128,
        base_agreement_root_low: u128,
        claim_root_high: u128,
        claim_root_low: u128,
        policy_root_high: u128,
        policy_root_low: u128,
        due_at: u64,
        grace_ends_at: u64,
        claim_ends_at: u64,
        snapshot_fact_high: u128,
        snapshot_fact_low: u128,
    );
    fn register_employer_statement(
        ref self: TContractState,
        run_nullifier_high: u128,
        run_nullifier_low: u128,
        manifest_root_high: u128,
        manifest_root_low: u128,
        fx_root_high: u128,
        fx_root_low: u128,
        availability_high: u128,
        availability_low: u128,
        observed_at: u64,
        statement_fact_high: u128,
        statement_fact_low: u128,
    );
    fn authorize_payroll(
        ref self: TContractState,
        payroll: PayrollProofStateV2,
        snapshot: ExceptionProofStateV2,
        payroll_shard_0: Span<felt252>,
        payroll_shard_1: Span<felt252>,
        snapshot_proof: Span<felt252>,
    );
    fn begin_payroll_authorization(
        ref self: TContractState,
        payroll: PayrollProofStateV2,
        snapshot: ExceptionProofStateV2,
        payroll_shard_0_hash: felt252,
        payroll_shard_1_hash: felt252,
        snapshot_proof_hash: felt252,
    );
    fn verify_payroll_authorization_proof(
        ref self: TContractState,
        run_nullifier_high: u128,
        run_nullifier_low: u128,
        proof_kind: u8,
        proof_calldata: Span<felt252>,
    );
    fn authorize_claim(
        ref self: TContractState,
        claim: ExceptionProofStateV2,
        claim_proof: Span<felt252>,
    );
    fn authorize_remediation(
        ref self: TContractState,
        remediation: ExceptionProofStateV2,
        remediation_proof: Span<felt252>,
    );
    fn expire_remediation_attempt(
        ref self: TContractState, subject_high: u128, subject_low: u128,
    );
    fn privacy_invoke(
        ref self: TContractState,
        mode: u8,
        subject_high: u128,
        subject_low: u128,
        fact_high: u128,
        fact_low: u128,
        action_high: u128,
        action_low: u128,
    ) -> Span<ExceptionOpenNoteDeposit>;
    fn get_snapshot(
        self: @TContractState, run_high: u128, run_low: u128,
    ) -> ObligationSnapshotRecord;
    fn get_statement(
        self: @TContractState, fact_high: u128, fact_low: u128,
    ) -> PayrollStatementRecord;
    fn get_run_anchor(
        self: @TContractState, run_high: u128, run_low: u128,
    ) -> RunAnchorRecord;
    fn get_pending_payroll_authorization(
        self: @TContractState, run_high: u128, run_low: u128,
    ) -> PendingPayrollAuthorization;
    fn get_claim(
        self: @TContractState, subject_high: u128, subject_low: u128,
    ) -> AcceptedClaimRecord;
    fn get_remediation_attempt(
        self: @TContractState, subject_high: u128, subject_low: u128,
    ) -> RemediationAttemptRecord;
}

#[starknet::contract]
pub mod PayoPayrollExceptionSeal {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_info, get_caller_address, get_contract_address};
    use payo_contracts::exception_commitments::{
        obligation_snapshot_commitment_v2, payroll_statement_commitment_v2,
    };
    use super::{
        AcceptedClaimRecord, ActionAuthorization, ExceptionOpenNoteDeposit,
        ExceptionProofStateV2, IExceptionCatalogRegistryDispatcher,
        IExceptionCatalogRegistryDispatcherTrait, IExceptionIntegrityVerifierDispatcher,
        IExceptionIntegrityVerifierDispatcherTrait, IExceptionObligationRegistryDispatcher,
        IExceptionObligationRegistryDispatcherTrait, ObligationSnapshotRecord,
        IExceptionGaragaVerifierDispatcher, IExceptionGaragaVerifierDispatcherTrait,
        PayrollProofStateV2, PayrollStatementRecord, PendingPayrollAuthorization,
        RemediationAttemptRecord,
        RunAnchorRecord,
    };

    pub const MODE_PAYROLL: u8 = 0;
    pub const MODE_CLAIM: u8 = 2;
    pub const MODE_REMEDIATE: u8 = 3;
    pub const PAYROLL_PROOF_VERSION: u32 = 2;
    pub const SNAPSHOT_PROOF_VERSION: u32 = 5;
    pub const CLAIM_PROOF_VERSION: u32 = 6;
    pub const REMEDIATION_PROOF_VERSION: u32 = 7;
    pub const PAYROLL_SCHEMA_VERSION: u32 = 1;
    pub const EXCEPTION_SCHEMA_VERSION: u32 = 2;
    const MAX_VALIDITY_WINDOW: u64 = 3600;
    const CLAIM_PROVED: u8 = 1;
    const CLAIM_PAYMENT_INVOKED: u8 = 2;
    const ATTEMPT_AUTHORIZED: u8 = 1;
    const ATTEMPT_INVOKED: u8 = 2;
    const ATTEMPT_EXPIRED: u8 = 3;
    const AUTHORIZED: u8 = 1;
    const CONSUMED: u8 = 2;
    const AUTH_EXPIRED: u8 = 3;
    const PAYROLL_PROOFS_COLLECTING: u8 = 1;
    const PAYROLL_PROOFS_AUTHORIZED: u8 = 2;
    const ALL_PAYROLL_PROOFS_VERIFIED: u8 = 7;
    const EMPLOYER_STATEMENT_SOURCE: u8 = 2;

    mod errors {
        pub const ZERO_ADDRESS: felt252 = 'PAYO_ZERO_ADDRESS';
        pub const BAD_POOL: felt252 = 'PAYO_BAD_POOL';
        pub const BAD_MODE: felt252 = 'PAYO_BAD_MODE';
        pub const BAD_VERSION: felt252 = 'PAYO_BAD_VERSION';
        pub const BAD_WINDOW: felt252 = 'PAYO_BAD_WINDOW';
        pub const BAD_STATE: felt252 = 'PAYO_BAD_STATE';
        pub const BAD_ROOT: felt252 = 'PAYO_BAD_ROOT';
        pub const BAD_OWNER: felt252 = 'PAYO_BAD_OWNER';
        pub const BAD_PARENT: felt252 = 'PAYO_BAD_PARENT';
        pub const REPLAY: felt252 = 'PAYO_REPLAY';
        pub const PROOF_FAILED: felt252 = 'PAYO_PROOF_FAILED';
        pub const PUBLIC_INPUTS: felt252 = 'PAYO_PUBLIC_INPUTS';
        pub const ROOT_INACTIVE: felt252 = 'PAYO_ROOT_INACTIVE';
        pub const VERIFIER_INACTIVE: felt252 = 'PAYO_VER_INACTIVE';
        pub const ACTION_EXPIRED: felt252 = 'PAYO_ACTION_EXPIRED';
        pub const ACTIVE_ATTEMPT: felt252 = 'PAYO_ACTIVE_ATTEMPT';
    }

    #[storage]
    struct Storage {
        pool: ContractAddress,
        catalog_registry: ContractAddress,
        obligation_registry: ContractAddress,
        chain_id: felt252,
        snapshots: Map<(u128, u128), ObligationSnapshotRecord>,
        statements: Map<(u128, u128), PayrollStatementRecord>,
        run_has_statement: Map<(u128, u128), bool>,
        run_anchors: Map<(u128, u128), RunAnchorRecord>,
        pending_payroll_authorizations: Map<(u128, u128), PendingPayrollAuthorization>,
        claims: Map<(u128, u128), AcceptedClaimRecord>,
        attempts: Map<(u128, u128), RemediationAttemptRecord>,
        authorizations: Map<(u8, u128, u128), ActionAuthorization>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ObligationSnapshotRegistered: ObligationSnapshotRegistered,
        EmployerStatementRegistered: EmployerStatementRegistered,
        PayrollAuthorizationBegun: PayrollAuthorizationBegun,
        PayrollAuthorizationProofVerified: PayrollAuthorizationProofVerified,
        PayrollAuthorized: PayrollAuthorized,
        PrivateActionInvoked: PrivateActionInvoked,
        ClaimAccepted: ClaimAccepted,
        RemediationAuthorized: RemediationAuthorized,
        RemediationExpired: RemediationExpired,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ObligationSnapshotRegistered {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        #[key]
        pub owner: ContractAddress,
        pub snapshot_fact_high: u128,
        pub snapshot_fact_low: u128,
        pub due_at: u64,
        pub grace_ends_at: u64,
        pub claim_ends_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct EmployerStatementRegistered {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        pub statement_fact_high: u128,
        pub statement_fact_low: u128,
        pub observed_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PayrollAuthorized {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        pub manifest_root_high: u128,
        pub manifest_root_low: u128,
        pub expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PayrollAuthorizationBegun {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        pub payroll_shard_0_hash: felt252,
        pub payroll_shard_1_hash: felt252,
        pub snapshot_proof_hash: felt252,
        pub expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PayrollAuthorizationProofVerified {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        pub proof_kind: u8,
        pub verified_mask: u8,
        pub authorized: bool,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PrivateActionInvoked {
        #[key]
        pub mode: u8,
        #[key]
        pub subject_high: u128,
        #[key]
        pub subject_low: u128,
        pub fact_high: u128,
        pub fact_low: u128,
        pub action_high: u128,
        pub action_low: u128,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ClaimAccepted {
        #[key]
        pub subject_high: u128,
        #[key]
        pub subject_low: u128,
        pub run_nullifier_high: u128,
        pub run_nullifier_low: u128,
        pub fact_high: u128,
        pub fact_low: u128,
        pub parent_fact_high: u128,
        pub parent_fact_low: u128,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RemediationAuthorized {
        #[key]
        pub subject_high: u128,
        #[key]
        pub subject_low: u128,
        pub claim_subject_high: u128,
        pub claim_subject_low: u128,
        pub action_high: u128,
        pub action_low: u128,
        pub expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RemediationExpired {
        #[key]
        pub subject_high: u128,
        #[key]
        pub subject_low: u128,
        pub claim_subject_high: u128,
        pub claim_subject_low: u128,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        pool: ContractAddress,
        catalog_registry: ContractAddress,
        obligation_registry: ContractAddress,
        chain_id: felt252,
    ) {
        assert(!pool.is_zero(), errors::ZERO_ADDRESS);
        assert(!catalog_registry.is_zero(), errors::ZERO_ADDRESS);
        assert(!obligation_registry.is_zero(), errors::ZERO_ADDRESS);
        assert(chain_id != 0, errors::ZERO_ADDRESS);
        self.pool.write(pool);
        self.catalog_registry.write(catalog_registry);
        self.obligation_registry.write(obligation_registry);
        self.chain_id.write(chain_id);
    }

    fn now() -> u64 {
        get_block_info().unbox().block_timestamp
    }

    fn as_u256<T, +Into<T, u256>>(value: T) -> u256 {
        value.into()
    }

    fn limbs(high: u128, low: u128) -> u256 {
        u256 { high, low }
    }

    fn nonzero(high: u128, low: u128) -> bool {
        high != 0 || low != 0
    }

    fn assert_bounded_window(validity_start: u64, validity_expiry: u64) {
        assert(validity_expiry >= validity_start, errors::BAD_WINDOW);
        assert(validity_expiry - validity_start <= MAX_VALIDITY_WINDOW, errors::BAD_WINDOW);
    }

    fn assert_window(validity_start: u64, validity_expiry: u64) {
        assert_bounded_window(validity_start, validity_expiry);
        let timestamp = now();
        assert(validity_start <= timestamp && timestamp <= validity_expiry, errors::BAD_WINDOW);
    }

    fn catalog(self: @ContractState) -> IExceptionCatalogRegistryDispatcher {
        IExceptionCatalogRegistryDispatcher { contract_address: self.catalog_registry.read() }
    }

    fn obligations(self: @ContractState) -> IExceptionObligationRegistryDispatcher {
        IExceptionObligationRegistryDispatcher { contract_address: self.obligation_registry.read() }
    }

    fn verifier_for(
        self: @ContractState, mode: u8, version: u32,
    ) -> IExceptionIntegrityVerifierDispatcher {
        let registry = catalog(self);
        assert(registry.is_verifier_valid(mode, version), errors::VERIFIER_INACTIVE);
        IExceptionIntegrityVerifierDispatcher {
            contract_address: registry.get_verifier(mode, version),
        }
    }

    fn garaga_verifier_for(
        self: @ContractState, mode: u8, version: u32,
    ) -> IExceptionGaragaVerifierDispatcher {
        let registry = catalog(self);
        assert(registry.is_verifier_valid(mode, version), errors::VERIFIER_INACTIVE);
        IExceptionGaragaVerifierDispatcher {
            contract_address: registry.get_verifier(mode, version),
        }
    }

    fn assert_public_input(inputs: Span<u256>, index: usize, expected: u256) {
        assert(inputs.len() > index, errors::PUBLIC_INPUTS);
        assert(*inputs.at(index) == expected, errors::PUBLIC_INPUTS);
    }

    fn assert_payroll_inputs(
        self: @ContractState,
        inputs: Span<u256>,
        proof: PayrollProofStateV2,
        shard_index: u8,
    ) {
        assert(inputs.len() == 17, errors::PUBLIC_INPUTS);
        let seal: felt252 = get_contract_address().into();
        assert_public_input(inputs, 0, as_u256(self.chain_id.read()));
        assert_public_input(inputs, 1, as_u256(seal));
        assert_public_input(inputs, 2, as_u256(proof.proof_version));
        assert_public_input(inputs, 3, as_u256(proof.schema_version));
        assert_public_input(inputs, 4, as_u256(proof.agreement_root_high));
        assert_public_input(inputs, 5, as_u256(proof.agreement_root_low));
        assert_public_input(inputs, 6, as_u256(proof.manifest_root_high));
        assert_public_input(inputs, 7, as_u256(proof.manifest_root_low));
        assert_public_input(inputs, 8, as_u256(proof.policy_root_high));
        assert_public_input(inputs, 9, as_u256(proof.policy_root_low));
        assert_public_input(inputs, 10, as_u256(proof.fx_root_high));
        assert_public_input(inputs, 11, as_u256(proof.fx_root_low));
        assert_public_input(inputs, 12, as_u256(proof.run_nullifier_high));
        assert_public_input(inputs, 13, as_u256(proof.run_nullifier_low));
        assert_public_input(inputs, 14, as_u256(proof.validity_start));
        assert_public_input(inputs, 15, as_u256(proof.validity_expiry));
        assert_public_input(inputs, 16, as_u256(shard_index));
    }

    fn assert_exception_inputs(
        self: @ContractState, inputs: Span<u256>, proof: ExceptionProofStateV2,
    ) {
        assert(inputs.len() == 23, errors::PUBLIC_INPUTS);
        let seal: felt252 = get_contract_address().into();
        assert_public_input(inputs, 0, as_u256(self.chain_id.read()));
        assert_public_input(inputs, 1, as_u256(seal));
        assert_public_input(inputs, 2, as_u256(proof.proof_version));
        assert_public_input(inputs, 3, as_u256(proof.schema_version));
        assert_public_input(inputs, 4, as_u256(proof.agreement_root_high));
        assert_public_input(inputs, 5, as_u256(proof.agreement_root_low));
        assert_public_input(inputs, 6, as_u256(proof.manifest_root_high));
        assert_public_input(inputs, 7, as_u256(proof.manifest_root_low));
        assert_public_input(inputs, 8, as_u256(proof.policy_root_high));
        assert_public_input(inputs, 9, as_u256(proof.policy_root_low));
        assert_public_input(inputs, 10, as_u256(proof.fx_root_high));
        assert_public_input(inputs, 11, as_u256(proof.fx_root_low));
        assert_public_input(inputs, 12, as_u256(proof.subject_nullifier_high));
        assert_public_input(inputs, 13, as_u256(proof.subject_nullifier_low));
        assert_public_input(inputs, 14, as_u256(proof.parent_nullifier_high));
        assert_public_input(inputs, 15, as_u256(proof.parent_nullifier_low));
        assert_public_input(inputs, 16, as_u256(proof.fact_commitment_high));
        assert_public_input(inputs, 17, as_u256(proof.fact_commitment_low));
        assert_public_input(inputs, 18, as_u256(proof.parent_fact_commitment_high));
        assert_public_input(inputs, 19, as_u256(proof.parent_fact_commitment_low));
        assert_public_input(inputs, 20, as_u256(proof.validity_start));
        assert_public_input(inputs, 21, as_u256(proof.validity_expiry));
        assert_public_input(inputs, 22, as_u256(proof.shard_index));
    }

    fn verify_exception(
        self: @ContractState,
        mode: u8,
        proof: ExceptionProofStateV2,
        calldata: Span<felt252>,
    ) {
        let public_inputs = garaga_verifier_for(self, mode, proof.proof_version)
            .verify_ultra_keccak_zk_honk_proof(calldata)
            .expect(errors::PROOF_FAILED);
        assert_exception_inputs(self, public_inputs, proof);
    }

    fn assert_payroll_authorization_bindings(
        self: @ContractState,
        payroll: PayrollProofStateV2,
        snapshot: ExceptionProofStateV2,
    ) -> ObligationSnapshotRecord {
        assert(payroll.proof_version == PAYROLL_PROOF_VERSION, errors::BAD_VERSION);
        assert(payroll.schema_version == PAYROLL_SCHEMA_VERSION, errors::BAD_VERSION);
        assert(snapshot.proof_version == SNAPSHOT_PROOF_VERSION, errors::BAD_VERSION);
        assert(snapshot.schema_version == EXCEPTION_SCHEMA_VERSION, errors::BAD_VERSION);
        assert(snapshot.shard_index == 0, errors::PUBLIC_INPUTS);
        assert_bounded_window(payroll.validity_start, payroll.validity_expiry);
        assert_bounded_window(snapshot.validity_start, snapshot.validity_expiry);
        let run_key = (payroll.run_nullifier_high, payroll.run_nullifier_low);
        let registered = self.snapshots.read(run_key);
        assert(registered.exists, errors::BAD_PARENT);
        assert(registered.claim_count == 0, errors::BAD_STATE);
        assert(
            payroll.agreement_root_high == registered.base_agreement_root_high
                && payroll.agreement_root_low == registered.base_agreement_root_low,
            errors::BAD_ROOT,
        );
        assert(
            payroll.policy_root_high == registered.policy_root_high
                && payroll.policy_root_low == registered.policy_root_low,
            errors::BAD_ROOT,
        );
        assert(
            snapshot.agreement_root_high == registered.base_agreement_root_high
                && snapshot.agreement_root_low == registered.base_agreement_root_low,
            errors::BAD_ROOT,
        );
        assert(
            snapshot.manifest_root_high == registered.claim_root_high
                && snapshot.manifest_root_low == registered.claim_root_low,
            errors::BAD_ROOT,
        );
        assert(
            snapshot.policy_root_high == registered.policy_root_high
                && snapshot.policy_root_low == registered.policy_root_low,
            errors::BAD_ROOT,
        );
        assert(snapshot.fx_root_high == 0 && snapshot.fx_root_low == 0, errors::BAD_ROOT);
        assert(
            snapshot.subject_nullifier_high == payroll.run_nullifier_high
                && snapshot.subject_nullifier_low == payroll.run_nullifier_low,
            errors::BAD_PARENT,
        );
        assert(
            snapshot.parent_nullifier_high == 0 && snapshot.parent_nullifier_low == 0,
            errors::BAD_PARENT,
        );
        assert(
            snapshot.fact_commitment_high == registered.snapshot_fact_high
                && snapshot.fact_commitment_low == registered.snapshot_fact_low,
            errors::BAD_PARENT,
        );
        assert(
            snapshot.parent_fact_commitment_high == 0
                && snapshot.parent_fact_commitment_low == 0,
            errors::BAD_PARENT,
        );
        let registry = catalog(self);
        assert(
            registry.is_policy_root_valid(payroll.policy_root_high, payroll.policy_root_low),
            errors::ROOT_INACTIVE,
        );
        assert(
            registry.is_fx_root_valid(payroll.fx_root_high, payroll.fx_root_low),
            errors::ROOT_INACTIVE,
        );
        registered
    }

    fn commit_payroll_authorization(
        ref self: ContractState,
        payroll: PayrollProofStateV2,
        registered: ObligationSnapshotRecord,
    ) {
        let run_key = (payroll.run_nullifier_high, payroll.run_nullifier_low);
        let previous = self.run_anchors.read(run_key);
        if previous.exists {
            assert(!previous.invoked, errors::REPLAY);
            assert(
                previous.agreement_root_high == payroll.agreement_root_high
                    && previous.agreement_root_low == payroll.agreement_root_low
                    && previous.manifest_root_high == payroll.manifest_root_high
                    && previous.manifest_root_low == payroll.manifest_root_low
                    && previous.policy_root_high == payroll.policy_root_high
                    && previous.policy_root_low == payroll.policy_root_low
                    && previous.fx_root_high == payroll.fx_root_high
                    && previous.fx_root_low == payroll.fx_root_low,
                errors::BAD_STATE,
            );
        }
        let timestamp = now();
        self.run_anchors.write(
            run_key,
            RunAnchorRecord {
                exists: true,
                invoked: false,
                agreement_root_high: payroll.agreement_root_high,
                agreement_root_low: payroll.agreement_root_low,
                manifest_root_high: payroll.manifest_root_high,
                manifest_root_low: payroll.manifest_root_low,
                policy_root_high: payroll.policy_root_high,
                policy_root_low: payroll.policy_root_low,
                fx_root_high: payroll.fx_root_high,
                fx_root_low: payroll.fx_root_low,
                snapshot_fact_high: registered.snapshot_fact_high,
                snapshot_fact_low: registered.snapshot_fact_low,
                authorized_at: timestamp,
                invoked_at: 0,
            },
        );
        write_authorization(
            ref self,
            MODE_PAYROLL,
            payroll.run_nullifier_high,
            payroll.run_nullifier_low,
            registered.snapshot_fact_high,
            registered.snapshot_fact_low,
            payroll.manifest_root_high,
            payroll.manifest_root_low,
            payroll.validity_expiry,
        );
        self.emit(
            PayrollAuthorized {
                run_nullifier_high: payroll.run_nullifier_high,
                run_nullifier_low: payroll.run_nullifier_low,
                manifest_root_high: payroll.manifest_root_high,
                manifest_root_low: payroll.manifest_root_low,
                expires_at: payroll.validity_expiry,
            },
        );
    }

    fn write_authorization(
        ref self: ContractState,
        mode: u8,
        subject_high: u128,
        subject_low: u128,
        fact_high: u128,
        fact_low: u128,
        action_high: u128,
        action_low: u128,
        expires_at: u64,
    ) {
        let key = (mode, subject_high, subject_low);
        let previous = self.authorizations.read(key);
        assert(!previous.exists || previous.status != CONSUMED, errors::REPLAY);
        self.authorizations.write(
            key,
            ActionAuthorization {
                exists: true,
                status: AUTHORIZED,
                fact_commitment_high: fact_high,
                fact_commitment_low: fact_low,
                action_commitment_high: action_high,
                action_commitment_low: action_low,
                expires_at,
            },
        );
    }

    #[abi(embed_v0)]
    impl ExceptionSealImpl of super::IPayoPayrollExceptionSeal<ContractState> {
        fn register_obligation_snapshot(
            ref self: ContractState,
            run_nullifier_high: u128,
            run_nullifier_low: u128,
            base_agreement_root_high: u128,
            base_agreement_root_low: u128,
            claim_root_high: u128,
            claim_root_low: u128,
            policy_root_high: u128,
            policy_root_low: u128,
            due_at: u64,
            grace_ends_at: u64,
            claim_ends_at: u64,
            snapshot_fact_high: u128,
            snapshot_fact_low: u128,
        ) {
            assert(nonzero(run_nullifier_high, run_nullifier_low), errors::BAD_ROOT);
            assert(nonzero(base_agreement_root_high, base_agreement_root_low), errors::BAD_ROOT);
            assert(nonzero(claim_root_high, claim_root_low), errors::BAD_ROOT);
            assert(nonzero(policy_root_high, policy_root_low), errors::BAD_ROOT);
            assert(nonzero(snapshot_fact_high, snapshot_fact_low), errors::BAD_ROOT);
            let timestamp = now();
            assert(timestamp <= due_at, errors::BAD_WINDOW);
            assert(due_at <= grace_ends_at && grace_ends_at < claim_ends_at, errors::BAD_WINDOW);
            let key = (run_nullifier_high, run_nullifier_low);
            assert(!self.snapshots.read(key).exists, errors::REPLAY);
            let owner = get_caller_address();
            let registry = obligations(@self);
            assert(
                registry.is_obligation_root_valid(
                    base_agreement_root_high, base_agreement_root_low,
                ),
                errors::ROOT_INACTIVE,
            );
            assert(
                registry.get_obligation_root_owner(
                    base_agreement_root_high, base_agreement_root_low,
                ) == owner,
                errors::BAD_OWNER,
            );
            assert(
                catalog(@self).is_policy_root_valid(policy_root_high, policy_root_low),
                errors::ROOT_INACTIVE,
            );
            let owner_felt: felt252 = owner.into();
            let expected = obligation_snapshot_commitment_v2(
                EXCEPTION_SCHEMA_VERSION.try_into().unwrap(),
                limbs(run_nullifier_high, run_nullifier_low),
                limbs(base_agreement_root_high, base_agreement_root_low),
                limbs(claim_root_high, claim_root_low),
                limbs(policy_root_high, policy_root_low),
                owner_felt.into(),
                due_at,
                grace_ends_at,
                claim_ends_at,
                limbs(claim_root_high, claim_root_low),
            );
            assert(expected == limbs(snapshot_fact_high, snapshot_fact_low), errors::PUBLIC_INPUTS);
            self.snapshots.write(
                key,
                ObligationSnapshotRecord {
                    exists: true,
                    owner,
                    base_agreement_root_high,
                    base_agreement_root_low,
                    claim_root_high,
                    claim_root_low,
                    policy_root_high,
                    policy_root_low,
                    snapshot_fact_high,
                    snapshot_fact_low,
                    due_at,
                    grace_ends_at,
                    claim_ends_at,
                    registered_at: timestamp,
                    claim_count: 0,
                },
            );
            self.emit(
                ObligationSnapshotRegistered {
                    run_nullifier_high,
                    run_nullifier_low,
                    owner,
                    snapshot_fact_high,
                    snapshot_fact_low,
                    due_at,
                    grace_ends_at,
                    claim_ends_at,
                },
            );
        }

        fn register_employer_statement(
            ref self: ContractState,
            run_nullifier_high: u128,
            run_nullifier_low: u128,
            manifest_root_high: u128,
            manifest_root_low: u128,
            fx_root_high: u128,
            fx_root_low: u128,
            availability_high: u128,
            availability_low: u128,
            observed_at: u64,
            statement_fact_high: u128,
            statement_fact_low: u128,
        ) {
            let run_key = (run_nullifier_high, run_nullifier_low);
            let snapshot = self.snapshots.read(run_key);
            assert(snapshot.exists, errors::BAD_PARENT);
            assert(snapshot.owner == get_caller_address(), errors::BAD_OWNER);
            assert(nonzero(manifest_root_high, manifest_root_low), errors::BAD_ROOT);
            assert(nonzero(availability_high, availability_low), errors::BAD_ROOT);
            assert(nonzero(statement_fact_high, statement_fact_low), errors::BAD_ROOT);
            let timestamp = now();
            assert(snapshot.due_at <= observed_at && observed_at <= timestamp, errors::BAD_WINDOW);
            if nonzero(fx_root_high, fx_root_low) {
                assert(
                    catalog(@self).is_fx_root_valid(fx_root_high, fx_root_low),
                    errors::ROOT_INACTIVE,
                );
            }
            let expected = payroll_statement_commitment_v2(
                EXCEPTION_SCHEMA_VERSION.try_into().unwrap(),
                limbs(run_nullifier_high, run_nullifier_low),
                limbs(snapshot.snapshot_fact_high, snapshot.snapshot_fact_low),
                limbs(manifest_root_high, manifest_root_low),
                limbs(fx_root_high, fx_root_low),
                limbs(availability_high, availability_low),
                observed_at,
                EMPLOYER_STATEMENT_SOURCE,
            );
            assert(expected == limbs(statement_fact_high, statement_fact_low), errors::PUBLIC_INPUTS);
            let statement_key = (statement_fact_high, statement_fact_low);
            assert(!self.statements.read(statement_key).exists, errors::REPLAY);
            self.statements.write(
                statement_key,
                PayrollStatementRecord {
                    exists: true,
                    owner: snapshot.owner,
                    run_nullifier_high,
                    run_nullifier_low,
                    snapshot_fact_high: snapshot.snapshot_fact_high,
                    snapshot_fact_low: snapshot.snapshot_fact_low,
                    manifest_root_high,
                    manifest_root_low,
                    fx_root_high,
                    fx_root_low,
                    availability_high,
                    availability_low,
                    observed_at,
                    source: EMPLOYER_STATEMENT_SOURCE,
                },
            );
            self.run_has_statement.write(run_key, true);
            self.emit(
                EmployerStatementRegistered {
                    run_nullifier_high,
                    run_nullifier_low,
                    statement_fact_high,
                    statement_fact_low,
                    observed_at,
                },
            );
        }

        fn authorize_payroll(
            ref self: ContractState,
            payroll: PayrollProofStateV2,
            snapshot: ExceptionProofStateV2,
            payroll_shard_0: Span<felt252>,
            payroll_shard_1: Span<felt252>,
            snapshot_proof: Span<felt252>,
        ) {
            let registered = assert_payroll_authorization_bindings(@self, payroll, snapshot);
            // Compatibility path: all three proofs arrive in one call, so both
            // validity windows must overlap. Production uses the staged path below.
            assert_window(payroll.validity_start, payroll.validity_expiry);
            assert_window(snapshot.validity_start, snapshot.validity_expiry);
            let payroll_inputs = verifier_for(@self, MODE_PAYROLL, PAYROLL_PROOF_VERSION)
                .verify_payroll_integrity_bundle(payroll_shard_0, payroll_shard_1)
                .expect(errors::PROOF_FAILED);
            assert(payroll_inputs.len() == 34, errors::PUBLIC_INPUTS);
            assert_payroll_inputs(@self, payroll_inputs.slice(0, 17), payroll, 0);
            assert_payroll_inputs(@self, payroll_inputs.slice(17, 17), payroll, 1);
            verify_exception(@self, MODE_PAYROLL, snapshot, snapshot_proof);
            commit_payroll_authorization(ref self, payroll, registered);
        }

        fn begin_payroll_authorization(
            ref self: ContractState,
            payroll: PayrollProofStateV2,
            snapshot: ExceptionProofStateV2,
            payroll_shard_0_hash: felt252,
            payroll_shard_1_hash: felt252,
            snapshot_proof_hash: felt252,
        ) {
            assert(payroll_shard_0_hash != 0, errors::BAD_ROOT);
            assert(payroll_shard_1_hash != 0, errors::BAD_ROOT);
            assert(snapshot_proof_hash != 0, errors::BAD_ROOT);
            assert_payroll_authorization_bindings(@self, payroll, snapshot);
            // The snapshot is proved before payday. Payroll shards may intentionally
            // have a later, non-overlapping validity window.
            assert_window(snapshot.validity_start, snapshot.validity_expiry);
            assert(now() <= payroll.validity_expiry, errors::BAD_WINDOW);
            let run_key = (payroll.run_nullifier_high, payroll.run_nullifier_low);
            let previous = self.pending_payroll_authorizations.read(run_key);
            if previous.exists {
                let timestamp = now();
                let snapshot_is_missing = previous.verified_mask & 4 == 0;
                assert(
                    previous.status == PAYROLL_PROOFS_COLLECTING
                        && (timestamp > previous.payroll.validity_expiry
                            || (snapshot_is_missing
                                && timestamp > previous.snapshot.validity_expiry)),
                    errors::REPLAY,
                );
            }
            assert(!self.run_anchors.read(run_key).exists, errors::REPLAY);
            let timestamp = now();
            self.pending_payroll_authorizations.write(
                run_key,
                PendingPayrollAuthorization {
                    exists: true,
                    status: PAYROLL_PROOFS_COLLECTING,
                    payroll,
                    snapshot,
                    payroll_shard_0_hash,
                    payroll_shard_1_hash,
                    snapshot_proof_hash,
                    verified_mask: 0,
                    created_at: timestamp,
                    updated_at: timestamp,
                },
            );
            self.emit(
                PayrollAuthorizationBegun {
                    run_nullifier_high: payroll.run_nullifier_high,
                    run_nullifier_low: payroll.run_nullifier_low,
                    payroll_shard_0_hash,
                    payroll_shard_1_hash,
                    snapshot_proof_hash,
                    expires_at: payroll.validity_expiry,
                },
            );
        }

        fn verify_payroll_authorization_proof(
            ref self: ContractState,
            run_nullifier_high: u128,
            run_nullifier_low: u128,
            proof_kind: u8,
            proof_calldata: Span<felt252>,
        ) {
            assert(proof_kind <= 2, errors::BAD_MODE);
            assert(!proof_calldata.is_empty(), errors::PROOF_FAILED);
            let run_key = (run_nullifier_high, run_nullifier_low);
            let mut pending = self.pending_payroll_authorizations.read(run_key);
            assert(
                pending.exists && pending.status == PAYROLL_PROOFS_COLLECTING,
                errors::BAD_STATE,
            );
            let proof_bit: u8 = if proof_kind == 0 { 1 } else if proof_kind == 1 { 2 } else { 4 };
            assert(pending.verified_mask & proof_bit == 0, errors::REPLAY);
            let expected_hash = if proof_kind == 0 {
                pending.payroll_shard_0_hash
            } else if proof_kind == 1 {
                pending.payroll_shard_1_hash
            } else {
                pending.snapshot_proof_hash
            };
            assert(poseidon_hash_span(proof_calldata) == expected_hash, errors::BAD_ROOT);
            if proof_kind <= 1 {
                // Snapshot correctness must already be durable before payday proofs.
                assert(pending.verified_mask & 4 == 4, errors::BAD_STATE);
                assert_window(pending.payroll.validity_start, pending.payroll.validity_expiry);
                let inputs = verifier_for(@self, MODE_PAYROLL, PAYROLL_PROOF_VERSION)
                    .verify_payroll_integrity_shard(proof_calldata)
                    .expect(errors::PROOF_FAILED);
                assert_payroll_inputs(@self, inputs, pending.payroll, proof_kind);
            } else {
                assert(pending.verified_mask == 0, errors::BAD_STATE);
                assert_window(pending.snapshot.validity_start, pending.snapshot.validity_expiry);
                verify_exception(@self, MODE_PAYROLL, pending.snapshot, proof_calldata);
            }
            pending.verified_mask = pending.verified_mask | proof_bit;
            pending.updated_at = now();
            if pending.verified_mask == ALL_PAYROLL_PROOFS_VERIFIED {
                // The final proof is necessarily a payroll shard. The snapshot proof
                // can be outside its former window because its verified state is stored.
                assert_window(pending.payroll.validity_start, pending.payroll.validity_expiry);
                let registered = assert_payroll_authorization_bindings(
                    @self, pending.payroll, pending.snapshot,
                );
                commit_payroll_authorization(ref self, pending.payroll, registered);
                pending.status = PAYROLL_PROOFS_AUTHORIZED;
            }
            self.pending_payroll_authorizations.write(run_key, pending);
            self.emit(
                PayrollAuthorizationProofVerified {
                    run_nullifier_high,
                    run_nullifier_low,
                    proof_kind,
                    verified_mask: pending.verified_mask,
                    authorized: pending.status == PAYROLL_PROOFS_AUTHORIZED,
                },
            );
        }

        fn authorize_claim(
            ref self: ContractState,
            claim: ExceptionProofStateV2,
            claim_proof: Span<felt252>,
        ) {
            assert(claim.proof_version == CLAIM_PROOF_VERSION, errors::BAD_VERSION);
            assert(claim.schema_version == EXCEPTION_SCHEMA_VERSION, errors::BAD_VERSION);
            assert(claim.shard_index == 0, errors::PUBLIC_INPUTS);
            assert_window(claim.validity_start, claim.validity_expiry);
            let run_key = (claim.parent_nullifier_high, claim.parent_nullifier_low);
            let snapshot = self.snapshots.read(run_key);
            assert(snapshot.exists, errors::BAD_PARENT);
            let timestamp = now();
            assert(
                snapshot.grace_ends_at <= timestamp && timestamp <= snapshot.claim_ends_at,
                errors::BAD_WINDOW,
            );
            assert(
                claim.agreement_root_high == snapshot.base_agreement_root_high
                    && claim.agreement_root_low == snapshot.base_agreement_root_low,
                errors::BAD_ROOT,
            );
            assert(
                claim.policy_root_high == snapshot.policy_root_high
                    && claim.policy_root_low == snapshot.policy_root_low,
                errors::BAD_ROOT,
            );
            let parent_is_snapshot = claim.parent_fact_commitment_high
                == snapshot.snapshot_fact_high
                && claim.parent_fact_commitment_low == snapshot.snapshot_fact_low;
            if parent_is_snapshot {
                assert(!self.run_anchors.read(run_key).exists, errors::BAD_STATE);
                assert(!self.run_has_statement.read(run_key), errors::BAD_STATE);
            } else {
                let statement = self
                    .statements
                    .read((claim.parent_fact_commitment_high, claim.parent_fact_commitment_low));
                assert(statement.exists, errors::BAD_PARENT);
                assert(
                    statement.run_nullifier_high == claim.parent_nullifier_high
                        && statement.run_nullifier_low == claim.parent_nullifier_low,
                    errors::BAD_PARENT,
                );
                assert(
                    statement.snapshot_fact_high == snapshot.snapshot_fact_high
                        && statement.snapshot_fact_low == snapshot.snapshot_fact_low,
                    errors::BAD_PARENT,
                );
                assert(
                    statement.manifest_root_high == claim.manifest_root_high
                        && statement.manifest_root_low == claim.manifest_root_low
                        && statement.fx_root_high == claim.fx_root_high
                        && statement.fx_root_low == claim.fx_root_low,
                    errors::BAD_ROOT,
                );
            }
            let claim_key = (claim.subject_nullifier_high, claim.subject_nullifier_low);
            assert(nonzero(claim.subject_nullifier_high, claim.subject_nullifier_low), errors::BAD_ROOT);
            assert(!self.claims.read(claim_key).exists, errors::REPLAY);
            verify_exception(@self, MODE_CLAIM, claim, claim_proof);
            self.claims.write(
                claim_key,
                AcceptedClaimRecord {
                    exists: true,
                    status: CLAIM_PROVED,
                    run_nullifier_high: claim.parent_nullifier_high,
                    run_nullifier_low: claim.parent_nullifier_low,
                    agreement_root_high: claim.agreement_root_high,
                    agreement_root_low: claim.agreement_root_low,
                    policy_root_high: claim.policy_root_high,
                    policy_root_low: claim.policy_root_low,
                    fact_commitment_high: claim.fact_commitment_high,
                    fact_commitment_low: claim.fact_commitment_low,
                    accepted_at: timestamp,
                    has_active_attempt: false,
                    active_attempt_high: 0,
                    active_attempt_low: 0,
                },
            );
            let mut updated_snapshot = snapshot;
            updated_snapshot.claim_count += 1;
            self.snapshots.write(run_key, updated_snapshot);
            self.emit(
                ClaimAccepted {
                    subject_high: claim.subject_nullifier_high,
                    subject_low: claim.subject_nullifier_low,
                    run_nullifier_high: claim.parent_nullifier_high,
                    run_nullifier_low: claim.parent_nullifier_low,
                    fact_high: claim.fact_commitment_high,
                    fact_low: claim.fact_commitment_low,
                    parent_fact_high: claim.parent_fact_commitment_high,
                    parent_fact_low: claim.parent_fact_commitment_low,
                },
            );
        }

        fn authorize_remediation(
            ref self: ContractState,
            remediation: ExceptionProofStateV2,
            remediation_proof: Span<felt252>,
        ) {
            assert(remediation.proof_version == REMEDIATION_PROOF_VERSION, errors::BAD_VERSION);
            assert(remediation.schema_version == EXCEPTION_SCHEMA_VERSION, errors::BAD_VERSION);
            assert(remediation.shard_index == 0, errors::PUBLIC_INPUTS);
            assert_window(remediation.validity_start, remediation.validity_expiry);
            let claim_key = (
                remediation.parent_nullifier_high, remediation.parent_nullifier_low,
            );
            let mut claim = self.claims.read(claim_key);
            assert(claim.exists && claim.status == CLAIM_PROVED, errors::BAD_PARENT);
            assert(
                remediation.parent_fact_commitment_high == claim.fact_commitment_high
                    && remediation.parent_fact_commitment_low == claim.fact_commitment_low,
                errors::BAD_PARENT,
            );
            assert(
                remediation.agreement_root_high == claim.agreement_root_high
                    && remediation.agreement_root_low == claim.agreement_root_low
                    && remediation.policy_root_high == claim.policy_root_high
                    && remediation.policy_root_low == claim.policy_root_low,
                errors::BAD_ROOT,
            );
            if nonzero(remediation.fx_root_high, remediation.fx_root_low) {
                assert(
                    catalog(@self)
                        .is_fx_root_valid(remediation.fx_root_high, remediation.fx_root_low),
                    errors::ROOT_INACTIVE,
                );
            }
            if claim.has_active_attempt {
                let active_key = (claim.active_attempt_high, claim.active_attempt_low);
                let mut active = self.attempts.read(active_key);
                if active.status == ATTEMPT_AUTHORIZED && now() > active.expires_at {
                    active.status = ATTEMPT_EXPIRED;
                    self.attempts.write(active_key, active);
                    claim.has_active_attempt = false;
                } else {
                    assert(false, errors::ACTIVE_ATTEMPT);
                }
            }
            let attempt_key = (
                remediation.subject_nullifier_high, remediation.subject_nullifier_low,
            );
            assert(nonzero(remediation.subject_nullifier_high, remediation.subject_nullifier_low), errors::BAD_ROOT);
            assert(!self.attempts.read(attempt_key).exists, errors::REPLAY);
            verify_exception(@self, MODE_REMEDIATE, remediation, remediation_proof);
            let timestamp = now();
            self.attempts.write(
                attempt_key,
                RemediationAttemptRecord {
                    exists: true,
                    status: ATTEMPT_AUTHORIZED,
                    claim_subject_high: remediation.parent_nullifier_high,
                    claim_subject_low: remediation.parent_nullifier_low,
                    fact_commitment_high: remediation.fact_commitment_high,
                    fact_commitment_low: remediation.fact_commitment_low,
                    action_commitment_high: remediation.manifest_root_high,
                    action_commitment_low: remediation.manifest_root_low,
                    expires_at: remediation.validity_expiry,
                    authorized_at: timestamp,
                    invoked_at: 0,
                },
            );
            claim.has_active_attempt = true;
            claim.active_attempt_high = remediation.subject_nullifier_high;
            claim.active_attempt_low = remediation.subject_nullifier_low;
            self.claims.write(claim_key, claim);
            write_authorization(
                ref self,
                MODE_REMEDIATE,
                remediation.subject_nullifier_high,
                remediation.subject_nullifier_low,
                remediation.fact_commitment_high,
                remediation.fact_commitment_low,
                remediation.manifest_root_high,
                remediation.manifest_root_low,
                remediation.validity_expiry,
            );
            self.emit(
                RemediationAuthorized {
                    subject_high: remediation.subject_nullifier_high,
                    subject_low: remediation.subject_nullifier_low,
                    claim_subject_high: remediation.parent_nullifier_high,
                    claim_subject_low: remediation.parent_nullifier_low,
                    action_high: remediation.manifest_root_high,
                    action_low: remediation.manifest_root_low,
                    expires_at: remediation.validity_expiry,
                },
            );
        }

        fn expire_remediation_attempt(
            ref self: ContractState, subject_high: u128, subject_low: u128,
        ) {
            let attempt_key = (subject_high, subject_low);
            let mut attempt = self.attempts.read(attempt_key);
            assert(attempt.exists && attempt.status == ATTEMPT_AUTHORIZED, errors::BAD_STATE);
            assert(now() > attempt.expires_at, errors::BAD_WINDOW);
            attempt.status = ATTEMPT_EXPIRED;
            self.attempts.write(attempt_key, attempt);
            let claim_key = (attempt.claim_subject_high, attempt.claim_subject_low);
            let mut claim = self.claims.read(claim_key);
            if claim.has_active_attempt
                && claim.active_attempt_high == subject_high
                && claim.active_attempt_low == subject_low {
                claim.has_active_attempt = false;
                self.claims.write(claim_key, claim);
            }
            let auth_key = (MODE_REMEDIATE, subject_high, subject_low);
            let mut authorization = self.authorizations.read(auth_key);
            if authorization.exists && authorization.status == AUTHORIZED {
                authorization.status = AUTH_EXPIRED;
                self.authorizations.write(auth_key, authorization);
            }
            self.emit(
                RemediationExpired {
                    subject_high,
                    subject_low,
                    claim_subject_high: attempt.claim_subject_high,
                    claim_subject_low: attempt.claim_subject_low,
                },
            );
        }

        fn privacy_invoke(
            ref self: ContractState,
            mode: u8,
            subject_high: u128,
            subject_low: u128,
            fact_high: u128,
            fact_low: u128,
            action_high: u128,
            action_low: u128,
        ) -> Span<ExceptionOpenNoteDeposit> {
            assert(get_caller_address() == self.pool.read(), errors::BAD_POOL);
            assert(mode == MODE_PAYROLL || mode == MODE_REMEDIATE, errors::BAD_MODE);
            let auth_key = (mode, subject_high, subject_low);
            let mut authorization = self.authorizations.read(auth_key);
            assert(authorization.exists && authorization.status == AUTHORIZED, errors::BAD_STATE);
            assert(now() <= authorization.expires_at, errors::ACTION_EXPIRED);
            assert(
                authorization.fact_commitment_high == fact_high
                    && authorization.fact_commitment_low == fact_low
                    && authorization.action_commitment_high == action_high
                    && authorization.action_commitment_low == action_low,
                errors::PUBLIC_INPUTS,
            );
            // Consume before all later writes; a revert rolls the entire call back.
            authorization.status = CONSUMED;
            self.authorizations.write(auth_key, authorization);
            let timestamp = now();
            if mode == MODE_PAYROLL {
                let run_key = (subject_high, subject_low);
                let mut anchor = self.run_anchors.read(run_key);
                assert(anchor.exists && !anchor.invoked, errors::BAD_STATE);
                anchor.invoked = true;
                anchor.invoked_at = timestamp;
                self.run_anchors.write(run_key, anchor);
            } else {
                let attempt_key = (subject_high, subject_low);
                let mut attempt = self.attempts.read(attempt_key);
                assert(attempt.exists && attempt.status == ATTEMPT_AUTHORIZED, errors::BAD_STATE);
                attempt.status = ATTEMPT_INVOKED;
                attempt.invoked_at = timestamp;
                self.attempts.write(attempt_key, attempt);
                let claim_key = (attempt.claim_subject_high, attempt.claim_subject_low);
                let mut claim = self.claims.read(claim_key);
                assert(claim.exists && claim.status == CLAIM_PROVED, errors::BAD_STATE);
                claim.status = CLAIM_PAYMENT_INVOKED;
                claim.has_active_attempt = false;
                self.claims.write(claim_key, claim);
            }
            self.emit(
                PrivateActionInvoked {
                    mode,
                    subject_high,
                    subject_low,
                    fact_high,
                    fact_low,
                    action_high,
                    action_low,
                },
            );
            array![].span()
        }

        fn get_snapshot(
            self: @ContractState, run_high: u128, run_low: u128,
        ) -> ObligationSnapshotRecord {
            self.snapshots.read((run_high, run_low))
        }

        fn get_statement(
            self: @ContractState, fact_high: u128, fact_low: u128,
        ) -> PayrollStatementRecord {
            self.statements.read((fact_high, fact_low))
        }

        fn get_run_anchor(
            self: @ContractState, run_high: u128, run_low: u128,
        ) -> RunAnchorRecord {
            self.run_anchors.read((run_high, run_low))
        }

        fn get_pending_payroll_authorization(
            self: @ContractState, run_high: u128, run_low: u128,
        ) -> PendingPayrollAuthorization {
            self.pending_payroll_authorizations.read((run_high, run_low))
        }

        fn get_claim(
            self: @ContractState, subject_high: u128, subject_low: u128,
        ) -> AcceptedClaimRecord {
            self.claims.read((subject_high, subject_low))
        }

        fn get_remediation_attempt(
            self: @ContractState, subject_high: u128, subject_low: u128,
        ) -> RemediationAttemptRecord {
            self.attempts.read((subject_high, subject_low))
        }
    }
}
