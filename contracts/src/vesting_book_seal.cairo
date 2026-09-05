use starknet::ContractAddress;
use crate::payroll_exception_seal::{
    AcceptedClaimRecord, ObligationSnapshotRecord, RemediationAttemptRecord,
};

// Positionally compatible with privacy::objects::OpenNoteDeposit. PAYO does
// not create or custody notes, so successful callbacks return an empty span.
#[derive(Serde, Copy, Drop, PartialEq, Debug)]
pub struct VestingOpenNoteDeposit {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u128,
}

#[derive(Serde, Copy, Drop, PartialEq, starknet::Store)]
pub struct VestingPayrollProofState {
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
pub struct VestingTransitionProofState {
    pub proof_version: u32,
    pub schema_version: u32,
    // 0 = ordinary, 1 = vesting, 2 = bounded-agent payroll.
    pub entry_kind: u8,
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
    pub subject_nullifier_high: u128,
    pub subject_nullifier_low: u128,
    pub parent_fact_high: u128,
    pub parent_fact_low: u128,
    pub fact_high: u128,
    pub fact_low: u128,
    pub owner: ContractAddress,
    pub source_seal: ContractAddress,
    pub source_proof_version: u32,
    pub attestation_root_high: u128,
    pub attestation_root_low: u128,
    pub shard_0_contributor_count: u32,
    pub shard_1_contributor_count: u32,
    pub totals_disclosed: u8,
    pub totals_commitment_high: u128,
    pub totals_commitment_low: u128,
    pub shard_0_strk_gross: u128,
    pub shard_0_strk_deductions: u128,
    pub shard_0_strk_net: u128,
    pub shard_0_usdc_gross: u128,
    pub shard_0_usdc_deductions: u128,
    pub shard_0_usdc_net: u128,
    pub shard_1_strk_gross: u128,
    pub shard_1_strk_deductions: u128,
    pub shard_1_strk_net: u128,
    pub shard_1_usdc_gross: u128,
    pub shard_1_usdc_deductions: u128,
    pub shard_1_usdc_net: u128,
    pub schedule_id_high: u128,
    pub schedule_id_low: u128,
    pub previous_state_high: u128,
    pub previous_state_low: u128,
    pub next_state_high: u128,
    pub next_state_low: u128,
    pub release_nullifier_high: u128,
    pub release_nullifier_low: u128,
    pub book_entry_high: u128,
    pub book_entry_low: u128,
    pub period_start: u64,
    pub period_end: u64,
    pub validity_start: u64,
    pub validity_expiry: u64,
}

#[derive(Serde, Copy, Drop, PartialEq, starknet::Store)]
pub struct VestingStateRecord {
    pub exists: bool,
    pub owner: ContractAddress,
    pub state_high: u128,
    pub state_low: u128,
    pub updated_at: u64,
}

#[derive(Serde, Copy, Drop, PartialEq, starknet::Store)]
pub struct PayrollBookRecord {
    pub exists: bool,
    pub entry_count: u32,
    pub contributor_count: u64,
    pub disclosed_entry_count: u32,
    pub undisclosed_entry_count: u32,
    pub ordinary_entry_count: u32,
    pub vesting_entry_count: u32,
    pub agent_entry_count: u32,
    pub claim_entry_count: u32,
    pub remediation_entry_count: u32,
    pub strk_gross: u256,
    pub strk_deductions: u256,
    pub strk_net: u256,
    pub usdc_gross: u256,
    pub usdc_deductions: u256,
    pub usdc_net: u256,
    pub accumulator_root: felt252,
    pub updated_at: u64,
}

#[derive(Serde, Copy, Drop, starknet::Store)]
pub struct PendingVestingAuthorization {
    pub exists: bool,
    // 1 = collecting four proof shards, 2 = authorized, 3 = invoked.
    pub status: u8,
    pub payroll: VestingPayrollProofState,
    pub transition: VestingTransitionProofState,
    pub payroll_shard_0_hash: felt252,
    pub payroll_shard_1_hash: felt252,
    pub transition_shard_0_hash: felt252,
    pub transition_shard_1_hash: felt252,
    pub verified_mask: u8,
    pub created_at: u64,
    pub updated_at: u64,
}

#[starknet::interface]
pub trait IVestingIntegrityVerifier<TContractState> {
    fn verify_payroll_integrity_shard(
        self: @TContractState, proof: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
}

#[starknet::interface]
pub trait IVestingCatalogRegistry<TContractState> {
    fn is_policy_root_valid(self: @TContractState, root_high: u128, root_low: u128) -> bool;
    fn is_fx_root_valid(self: @TContractState, root_high: u128, root_low: u128) -> bool;
    fn is_verifier_valid(self: @TContractState, mode: u8, proof_version: u32) -> bool;
    fn get_verifier(
        self: @TContractState, mode: u8, proof_version: u32,
    ) -> ContractAddress;
}

#[starknet::interface]
pub trait IVestingObligationRegistry<TContractState> {
    fn is_obligation_root_valid(
        self: @TContractState, root_high: u128, root_low: u128,
    ) -> bool;
    fn get_obligation_root_owner(
        self: @TContractState, root_high: u128, root_low: u128,
    ) -> ContractAddress;
}

#[starknet::interface]
pub trait IVestingExceptionSource<TContractState> {
    fn get_snapshot(
        self: @TContractState, run_high: u128, run_low: u128,
    ) -> ObligationSnapshotRecord;
    fn get_claim(
        self: @TContractState, subject_high: u128, subject_low: u128,
    ) -> AcceptedClaimRecord;
    fn get_remediation_attempt(
        self: @TContractState, subject_high: u128, subject_low: u128,
    ) -> RemediationAttemptRecord;
}

#[starknet::interface]
pub trait IPayoVestingBookSeal<TContractState> {
    fn begin_exception_book_authorization(
        ref self: TContractState,
        transition: VestingTransitionProofState,
        transition_shard_0_hash: felt252,
        transition_shard_1_hash: felt252,
    );
    fn begin_vesting_authorization(
        ref self: TContractState,
        payroll: VestingPayrollProofState,
        transition: VestingTransitionProofState,
        payroll_shard_0_hash: felt252,
        payroll_shard_1_hash: felt252,
        transition_shard_0_hash: felt252,
        transition_shard_1_hash: felt252,
    );
    fn verify_vesting_authorization_proof(
        ref self: TContractState,
        run_nullifier_high: u128,
        run_nullifier_low: u128,
        proof_kind: u8,
        proof_calldata: Span<felt252>,
    );
    fn finalize_claim_book_entry(
        ref self: TContractState, subject_high: u128, subject_low: u128,
        book_entry_high: u128, book_entry_low: u128,
    );
    fn privacy_invoke(
        ref self: TContractState,
        run_nullifier_high: u128,
        run_nullifier_low: u128,
        release_nullifier_high: u128,
        release_nullifier_low: u128,
        book_entry_high: u128,
        book_entry_low: u128,
    ) -> Span<VestingOpenNoteDeposit>;
    fn get_pending_authorization(
        self: @TContractState, run_high: u128, run_low: u128,
    ) -> PendingVestingAuthorization;
    fn get_authorized_source_seal(
        self: @TContractState, run_high: u128, run_low: u128,
    ) -> ContractAddress;
    fn get_vesting_state(
        self: @TContractState, schedule_high: u128, schedule_low: u128,
    ) -> VestingStateRecord;
    fn is_release_consumed(
        self: @TContractState, release_high: u128, release_low: u128,
    ) -> bool;
    fn get_payroll_book(
        self: @TContractState, owner: ContractAddress, period_start: u64, period_end: u64,
    ) -> PayrollBookRecord;
    fn get_payroll_book_entry(
        self: @TContractState,
        owner: ContractAddress,
        period_start: u64,
        period_end: u64,
        index: u32,
    ) -> u256;
    fn get_pool(self: @TContractState) -> ContractAddress;
    fn get_catalog_registry(self: @TContractState) -> ContractAddress;
    fn get_obligation_registry(self: @TContractState) -> ContractAddress;
    fn get_exception_seal(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PayoVestingBookSeal {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_info, get_caller_address, get_contract_address};
    use super::{
        IVestingCatalogRegistryDispatcher, IVestingCatalogRegistryDispatcherTrait,
        IVestingIntegrityVerifierDispatcher, IVestingIntegrityVerifierDispatcherTrait,
        IVestingObligationRegistryDispatcher, IVestingObligationRegistryDispatcherTrait,
        IVestingExceptionSourceDispatcher, IVestingExceptionSourceDispatcherTrait,
        PayrollBookRecord, PendingVestingAuthorization, VestingOpenNoteDeposit,
        VestingPayrollProofState, VestingStateRecord, VestingTransitionProofState,
    };

    pub const MODE_PAYROLL: u8 = 0;
    pub const PAYROLL_PROOF_VERSION: u32 = 2;
    pub const VESTING_PROOF_VERSION: u32 = 3;
    pub const SCHEMA_VERSION: u32 = 1;
    const MAX_VALIDITY_WINDOW: u64 = 3600;
    const COLLECTING: u8 = 1;
    const AUTHORIZED: u8 = 2;
    const INVOKED: u8 = 3;
    const ALL_PROOFS_VERIFIED: u8 = 15;

    mod errors {
        pub const ZERO_ADDRESS: felt252 = 'PAYO_ZERO_ADDRESS';
        pub const BAD_POOL: felt252 = 'PAYO_BAD_POOL';
        pub const BAD_VERSION: felt252 = 'PAYO_BAD_VERSION';
        pub const BAD_WINDOW: felt252 = 'PAYO_BAD_WINDOW';
        pub const BAD_STATE: felt252 = 'PAYO_BAD_STATE';
        pub const BAD_ROOT: felt252 = 'PAYO_BAD_ROOT';
        pub const BAD_OWNER: felt252 = 'PAYO_BAD_OWNER';
        pub const BAD_PROOF: felt252 = 'PAYO_BAD_PROOF';
        pub const BAD_PROOF_HASH: felt252 = 'PAYO_BAD_PROOF_HASH';
        pub const PUBLIC_INPUTS: felt252 = 'PAYO_PUBLIC_INPUTS';
        pub const ROOT_INACTIVE: felt252 = 'PAYO_ROOT_INACTIVE';
        pub const VERIFIER_INACTIVE: felt252 = 'PAYO_VER_INACTIVE';
        pub const REPLAY: felt252 = 'PAYO_REPLAY';
        pub const STALE_STATE: felt252 = 'PAYO_STALE_STATE';
    }

    #[storage]
    struct Storage {
        pool: ContractAddress,
        catalog_registry: ContractAddress,
        obligation_registry: ContractAddress,
        exception_seal: ContractAddress,
        chain_id: felt252,
        pending: Map<(u128, u128), PendingVestingAuthorization>,
        run_consumed: Map<(u128, u128), bool>,
        vesting_states: Map<(u128, u128), VestingStateRecord>,
        release_consumed: Map<(u128, u128), bool>,
        payroll_books: Map<(ContractAddress, u64, u64), PayrollBookRecord>,
        payroll_book_entries: Map<(ContractAddress, u64, u64, u32), u256>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        VestingAuthorizationBegun: VestingAuthorizationBegun,
        VestingProofVerified: VestingProofVerified,
        VestingAuthorized: VestingAuthorized,
        VestingReleased: VestingReleased,
        PayrollBookEntryAppended: PayrollBookEntryAppended,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VestingAuthorizationBegun {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        #[key]
        pub schedule_id_high: u128,
        pub schedule_id_low: u128,
        pub expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VestingProofVerified {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        #[key]
        pub proof_kind: u8,
        pub verified_mask: u8,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VestingAuthorized {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        pub release_nullifier_high: u128,
        pub release_nullifier_low: u128,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VestingReleased {
        #[key]
        pub schedule_id_high: u128,
        #[key]
        pub schedule_id_low: u128,
        #[key]
        pub release_nullifier_high: u128,
        pub release_nullifier_low: u128,
        pub state_high: u128,
        pub state_low: u128,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PayrollBookEntryAppended {
        #[key]
        pub owner: ContractAddress,
        #[key]
        pub period_start: u64,
        #[key]
        pub period_end: u64,
        pub index: u32,
        pub entry_high: u128,
        pub entry_low: u128,
        pub accumulator_root: felt252,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        pool: ContractAddress,
        catalog_registry: ContractAddress,
        obligation_registry: ContractAddress,
        exception_seal: ContractAddress,
        chain_id: felt252,
    ) {
        assert(!pool.is_zero(), errors::ZERO_ADDRESS);
        assert(!catalog_registry.is_zero(), errors::ZERO_ADDRESS);
        assert(!obligation_registry.is_zero(), errors::ZERO_ADDRESS);
        assert(!exception_seal.is_zero(), errors::ZERO_ADDRESS);
        assert(chain_id != 0, errors::ZERO_ADDRESS);
        self.pool.write(pool);
        self.catalog_registry.write(catalog_registry);
        self.obligation_registry.write(obligation_registry);
        self.exception_seal.write(exception_seal);
        self.chain_id.write(chain_id);
    }

    fn now() -> u64 { get_block_info().unbox().block_timestamp }

    fn catalog(self: @ContractState) -> IVestingCatalogRegistryDispatcher {
        IVestingCatalogRegistryDispatcher { contract_address: self.catalog_registry.read() }
    }

    fn exception_source(self: @ContractState) -> IVestingExceptionSourceDispatcher {
        IVestingExceptionSourceDispatcher { contract_address: self.exception_seal.read() }
    }

    fn obligations(self: @ContractState) -> IVestingObligationRegistryDispatcher {
        IVestingObligationRegistryDispatcher { contract_address: self.obligation_registry.read() }
    }

    fn verifier(
        self: @ContractState, proof_version: u32,
    ) -> IVestingIntegrityVerifierDispatcher {
        IVestingIntegrityVerifierDispatcher {
            contract_address: catalog(self).get_verifier(MODE_PAYROLL, proof_version),
        }
    }

    fn as_u256<T, +Into<T, u256>>(value: T) -> u256 { value.into() }

    fn assert_input(inputs: Span<u256>, index: usize, expected: u256) {
        assert(inputs.len() > index, errors::PUBLIC_INPUTS);
        assert(*inputs.at(index) == expected, errors::PUBLIC_INPUTS);
    }

    fn assert_bounded_window(start: u64, expiry: u64) {
        assert(expiry >= start, errors::BAD_WINDOW);
        assert(expiry - start <= MAX_VALIDITY_WINDOW, errors::BAD_WINDOW);
    }

    fn assert_live_window(start: u64, expiry: u64) {
        assert_bounded_window(start, expiry);
        let timestamp = now();
        assert(timestamp >= start && timestamp <= expiry, errors::BAD_WINDOW);
    }

    fn assert_payroll_inputs(
        self: @ContractState,
        inputs: Span<u256>,
        state: VestingPayrollProofState,
        source_seal: ContractAddress,
        shard_index: u8,
    ) {
        assert(inputs.len() == 17, errors::PUBLIC_INPUTS);
        let seal: felt252 = source_seal.into();
        assert_input(inputs, 0, as_u256(self.chain_id.read()));
        assert_input(inputs, 1, as_u256(seal));
        assert_input(inputs, 2, as_u256(state.proof_version));
        assert_input(inputs, 3, as_u256(state.schema_version));
        assert_input(inputs, 4, as_u256(state.agreement_root_high));
        assert_input(inputs, 5, as_u256(state.agreement_root_low));
        assert_input(inputs, 6, as_u256(state.manifest_root_high));
        assert_input(inputs, 7, as_u256(state.manifest_root_low));
        assert_input(inputs, 8, as_u256(state.policy_root_high));
        assert_input(inputs, 9, as_u256(state.policy_root_low));
        assert_input(inputs, 10, as_u256(state.fx_root_high));
        assert_input(inputs, 11, as_u256(state.fx_root_low));
        assert_input(inputs, 12, as_u256(state.run_nullifier_high));
        assert_input(inputs, 13, as_u256(state.run_nullifier_low));
        assert_input(inputs, 14, as_u256(state.validity_start));
        assert_input(inputs, 15, as_u256(state.validity_expiry));
        assert_input(inputs, 16, as_u256(shard_index));
    }

    fn assert_transition_inputs(
        self: @ContractState,
        inputs: Span<u256>,
        state: VestingTransitionProofState,
        shard_index: u8,
    ) {
        assert(inputs.len() == 58, errors::PUBLIC_INPUTS);
        let seal: felt252 = get_contract_address().into();
        let owner: felt252 = state.owner.into();
        let source_seal: felt252 = state.source_seal.into();
        assert_input(inputs, 0, as_u256(self.chain_id.read()));
        assert_input(inputs, 1, as_u256(seal));
        assert_input(inputs, 2, as_u256(state.proof_version));
        assert_input(inputs, 3, as_u256(state.schema_version));
        assert_input(inputs, 4, as_u256(state.entry_kind));
        assert_input(inputs, 5, as_u256(state.agreement_root_high));
        assert_input(inputs, 6, as_u256(state.agreement_root_low));
        assert_input(inputs, 7, as_u256(state.manifest_root_high));
        assert_input(inputs, 8, as_u256(state.manifest_root_low));
        assert_input(inputs, 9, as_u256(state.policy_root_high));
        assert_input(inputs, 10, as_u256(state.policy_root_low));
        assert_input(inputs, 11, as_u256(state.fx_root_high));
        assert_input(inputs, 12, as_u256(state.fx_root_low));
        assert_input(inputs, 13, as_u256(state.run_nullifier_high));
        assert_input(inputs, 14, as_u256(state.run_nullifier_low));
        assert_input(inputs, 15, as_u256(state.subject_nullifier_high));
        assert_input(inputs, 16, as_u256(state.subject_nullifier_low));
        assert_input(inputs, 17, as_u256(state.parent_fact_high));
        assert_input(inputs, 18, as_u256(state.parent_fact_low));
        assert_input(inputs, 19, as_u256(state.fact_high));
        assert_input(inputs, 20, as_u256(state.fact_low));
        assert_input(inputs, 21, as_u256(owner));
        assert_input(inputs, 22, as_u256(source_seal));
        assert_input(inputs, 23, as_u256(state.source_proof_version));
        assert_input(inputs, 24, as_u256(state.attestation_root_high));
        assert_input(inputs, 25, as_u256(state.attestation_root_low));
        assert_input(inputs, 26, as_u256(state.shard_0_contributor_count));
        assert_input(inputs, 27, as_u256(state.shard_1_contributor_count));
        assert_input(inputs, 28, as_u256(state.totals_disclosed));
        assert_input(inputs, 29, as_u256(state.totals_commitment_high));
        assert_input(inputs, 30, as_u256(state.totals_commitment_low));
        assert_input(inputs, 31, as_u256(state.shard_0_strk_gross));
        assert_input(inputs, 32, as_u256(state.shard_0_strk_deductions));
        assert_input(inputs, 33, as_u256(state.shard_0_strk_net));
        assert_input(inputs, 34, as_u256(state.shard_0_usdc_gross));
        assert_input(inputs, 35, as_u256(state.shard_0_usdc_deductions));
        assert_input(inputs, 36, as_u256(state.shard_0_usdc_net));
        assert_input(inputs, 37, as_u256(state.shard_1_strk_gross));
        assert_input(inputs, 38, as_u256(state.shard_1_strk_deductions));
        assert_input(inputs, 39, as_u256(state.shard_1_strk_net));
        assert_input(inputs, 40, as_u256(state.shard_1_usdc_gross));
        assert_input(inputs, 41, as_u256(state.shard_1_usdc_deductions));
        assert_input(inputs, 42, as_u256(state.shard_1_usdc_net));
        assert_input(inputs, 43, as_u256(state.schedule_id_high));
        assert_input(inputs, 44, as_u256(state.schedule_id_low));
        assert_input(inputs, 45, as_u256(state.previous_state_high));
        assert_input(inputs, 46, as_u256(state.previous_state_low));
        assert_input(inputs, 47, as_u256(state.next_state_high));
        assert_input(inputs, 48, as_u256(state.next_state_low));
        assert_input(inputs, 49, as_u256(state.release_nullifier_high));
        assert_input(inputs, 50, as_u256(state.release_nullifier_low));
        assert_input(inputs, 51, as_u256(state.book_entry_high));
        assert_input(inputs, 52, as_u256(state.book_entry_low));
        assert_input(inputs, 53, as_u256(state.period_start));
        assert_input(inputs, 54, as_u256(state.period_end));
        assert_input(inputs, 55, as_u256(state.validity_start));
        assert_input(inputs, 56, as_u256(state.validity_expiry));
        assert_input(inputs, 57, as_u256(shard_index));
    }

    fn assert_token_totals(gross: u128, deductions: u128, net: u128) {
        assert(gross >= deductions, errors::PUBLIC_INPUTS);
        assert(gross - deductions == net, errors::PUBLIC_INPUTS);
    }

    fn assert_book_totals(state: VestingTransitionProofState) {
        assert(
            state.shard_0_contributor_count <= 25
                && state.shard_1_contributor_count <= 25
                && state.shard_0_contributor_count + state.shard_1_contributor_count > 0,
            errors::PUBLIC_INPUTS,
        );
        assert(state.totals_disclosed <= 1, errors::PUBLIC_INPUTS);
        assert(
            state.totals_commitment_high != 0 || state.totals_commitment_low != 0,
            errors::PUBLIC_INPUTS,
        );
        if state.totals_disclosed == 0 {
            assert(
                state.shard_0_strk_gross == 0
                    && state.shard_0_strk_deductions == 0
                    && state.shard_0_strk_net == 0
                    && state.shard_0_usdc_gross == 0
                    && state.shard_0_usdc_deductions == 0
                    && state.shard_0_usdc_net == 0
                    && state.shard_1_strk_gross == 0
                    && state.shard_1_strk_deductions == 0
                    && state.shard_1_strk_net == 0
                    && state.shard_1_usdc_gross == 0
                    && state.shard_1_usdc_deductions == 0
                    && state.shard_1_usdc_net == 0,
                errors::PUBLIC_INPUTS,
            );
        } else {
            assert_token_totals(
                state.shard_0_strk_gross,
                state.shard_0_strk_deductions,
                state.shard_0_strk_net,
            );
            assert_token_totals(
                state.shard_0_usdc_gross,
                state.shard_0_usdc_deductions,
                state.shard_0_usdc_net,
            );
            assert_token_totals(
                state.shard_1_strk_gross,
                state.shard_1_strk_deductions,
                state.shard_1_strk_net,
            );
            assert_token_totals(
                state.shard_1_usdc_gross,
                state.shard_1_usdc_deductions,
                state.shard_1_usdc_net,
            );
            assert(
                state.shard_0_strk_net != 0
                    || state.shard_0_usdc_net != 0
                    || state.shard_1_strk_net != 0
                    || state.shard_1_usdc_net != 0,
                errors::PUBLIC_INPUTS,
            );
        }
    }

    fn assert_exception_source(
        self: @ContractState,
        transition: VestingTransitionProofState,
        require_invoked: bool,
    ) {
        assert(transition.source_seal == self.exception_seal.read(), errors::BAD_ROOT);
        let source = exception_source(self);
        if transition.entry_kind == 3 {
            let claim = source.get_claim(
                transition.subject_nullifier_high, transition.subject_nullifier_low,
            );
            assert(claim.exists && claim.status >= 1, errors::BAD_STATE);
            assert(
                claim.run_nullifier_high == transition.run_nullifier_high
                    && claim.run_nullifier_low == transition.run_nullifier_low
                    && claim.agreement_root_high == transition.agreement_root_high
                    && claim.agreement_root_low == transition.agreement_root_low
                    && claim.policy_root_high == transition.policy_root_high
                    && claim.policy_root_low == transition.policy_root_low
                    && claim.fact_commitment_high == transition.fact_high
                    && claim.fact_commitment_low == transition.fact_low,
                errors::BAD_ROOT,
            );
            let snapshot = source.get_snapshot(
                transition.run_nullifier_high, transition.run_nullifier_low,
            );
            assert(
                snapshot.exists
                    && snapshot.owner == transition.owner
                    && snapshot.base_agreement_root_high == transition.agreement_root_high
                    && snapshot.base_agreement_root_low == transition.agreement_root_low
                    && snapshot.policy_root_high == transition.policy_root_high
                    && snapshot.policy_root_low == transition.policy_root_low,
                errors::BAD_OWNER,
            );
        } else {
            let attempt = source.get_remediation_attempt(
                transition.subject_nullifier_high, transition.subject_nullifier_low,
            );
            assert(attempt.exists, errors::BAD_STATE);
            if require_invoked {
                assert(attempt.status == 2, errors::BAD_STATE);
            } else {
                assert(attempt.status == 1 || attempt.status == 2, errors::BAD_STATE);
            }
            assert(
                attempt.fact_commitment_high == transition.fact_high
                    && attempt.fact_commitment_low == transition.fact_low
                    && attempt.action_commitment_high == transition.manifest_root_high
                    && attempt.action_commitment_low == transition.manifest_root_low,
                errors::BAD_ROOT,
            );
            let claim = source.get_claim(
                attempt.claim_subject_high, attempt.claim_subject_low,
            );
            assert(claim.exists && claim.status >= 1, errors::BAD_STATE);
            assert(
                claim.run_nullifier_high == transition.run_nullifier_high
                    && claim.run_nullifier_low == transition.run_nullifier_low
                    && claim.agreement_root_high == transition.agreement_root_high
                    && claim.agreement_root_low == transition.agreement_root_low
                    && claim.policy_root_high == transition.policy_root_high
                    && claim.policy_root_low == transition.policy_root_low
                    && claim.fact_commitment_high == transition.parent_fact_high
                    && claim.fact_commitment_low == transition.parent_fact_low,
                errors::BAD_ROOT,
            );
            let snapshot = source.get_snapshot(
                claim.run_nullifier_high, claim.run_nullifier_low,
            );
            assert(snapshot.exists && snapshot.owner == transition.owner, errors::BAD_OWNER);
        }
    }

    fn assert_bindings(
        self: @ContractState,
        payroll: VestingPayrollProofState,
        transition: VestingTransitionProofState,
    ) {
        assert(transition.proof_version == VESTING_PROOF_VERSION, errors::BAD_VERSION);
        assert(transition.schema_version == SCHEMA_VERSION, errors::BAD_VERSION);
        assert(transition.entry_kind <= 4, errors::BAD_VERSION);
        assert_bounded_window(transition.validity_start, transition.validity_expiry);
        assert(transition.period_end > transition.period_start, errors::BAD_WINDOW);
        assert(
            transition.validity_start >= transition.period_start
                && transition.validity_start < transition.period_end,
            errors::BAD_WINDOW,
        );
        assert_book_totals(transition);
        assert(
            transition.book_entry_high != 0 || transition.book_entry_low != 0,
            errors::BAD_ROOT,
        );
        let policy_registry = catalog(self);
        assert(
            policy_registry.is_policy_root_valid(
                transition.policy_root_high, transition.policy_root_low,
            ),
            errors::ROOT_INACTIVE,
        );
        if transition.fx_root_high != 0 || transition.fx_root_low != 0 {
            assert(
                policy_registry.is_fx_root_valid(
                    transition.fx_root_high, transition.fx_root_low,
                ),
                errors::ROOT_INACTIVE,
            );
        }
        if transition.attestation_root_high != 0 || transition.attestation_root_low != 0 {
            assert(
                policy_registry.is_policy_root_valid(
                    transition.attestation_root_high, transition.attestation_root_low,
                ),
                errors::ROOT_INACTIVE,
            );
        }
        assert(
            policy_registry.is_verifier_valid(MODE_PAYROLL, VESTING_PROOF_VERSION),
            errors::VERIFIER_INACTIVE,
        );

        let payroll_entry = transition.entry_kind <= 2;
        if payroll_entry {
            assert(payroll.proof_version == PAYROLL_PROOF_VERSION, errors::BAD_VERSION);
            assert(payroll.schema_version == SCHEMA_VERSION, errors::BAD_VERSION);
            assert(transition.source_proof_version == PAYROLL_PROOF_VERSION, errors::BAD_VERSION);
            assert_bounded_window(payroll.validity_start, payroll.validity_expiry);
            let seal = get_contract_address();
            if transition.entry_kind == 2 {
                assert(!transition.source_seal.is_zero(), errors::BAD_ROOT);
            } else {
                assert(transition.source_seal == seal, errors::BAD_ROOT);
            }
            assert(
                payroll.agreement_root_high == transition.agreement_root_high
                    && payroll.agreement_root_low == transition.agreement_root_low
                    && payroll.manifest_root_high == transition.manifest_root_high
                    && payroll.manifest_root_low == transition.manifest_root_low
                    && payroll.policy_root_high == transition.policy_root_high
                    && payroll.policy_root_low == transition.policy_root_low
                    && payroll.fx_root_high == transition.fx_root_high
                    && payroll.fx_root_low == transition.fx_root_low
                    && payroll.run_nullifier_high == transition.run_nullifier_high
                    && payroll.run_nullifier_low == transition.run_nullifier_low
                    && transition.subject_nullifier_high == transition.run_nullifier_high
                    && transition.subject_nullifier_low == transition.run_nullifier_low
                    && transition.parent_fact_high == 0
                    && transition.parent_fact_low == 0
                    && transition.fact_high == 0
                    && transition.fact_low == 0
                    && payroll.validity_start == transition.validity_start
                    && payroll.validity_expiry == transition.validity_expiry,
                errors::BAD_ROOT,
            );
            assert(
                policy_registry.is_fx_root_valid(payroll.fx_root_high, payroll.fx_root_low),
                errors::ROOT_INACTIVE,
            );
            assert(
                policy_registry.is_verifier_valid(MODE_PAYROLL, PAYROLL_PROOF_VERSION),
                errors::VERIFIER_INACTIVE,
            );
            let registry = obligations(self);
            assert(
                registry.is_obligation_root_valid(
                    payroll.agreement_root_high, payroll.agreement_root_low,
                ),
                errors::ROOT_INACTIVE,
            );
            assert(
                registry.get_obligation_root_owner(
                    payroll.agreement_root_high, payroll.agreement_root_low,
                ) == transition.owner,
                errors::BAD_OWNER,
            );
        } else {
            assert(
                (transition.entry_kind == 3 && transition.source_proof_version == 6)
                    || (transition.entry_kind == 4 && transition.source_proof_version == 7),
                errors::BAD_VERSION,
            );
            assert(
                transition.attestation_root_high == 0
                    && transition.attestation_root_low == 0
                    && transition.schedule_id_high == 0
                    && transition.schedule_id_low == 0
                    && transition.previous_state_high == 0
                    && transition.previous_state_low == 0
                    && transition.next_state_high == 0
                    && transition.next_state_low == 0
                    && transition.release_nullifier_high == 0
                    && transition.release_nullifier_low == 0,
                errors::BAD_ROOT,
            );
            assert(
                transition.shard_0_contributor_count == 1
                    && transition.shard_1_contributor_count == 0,
                errors::PUBLIC_INPUTS,
            );
            if transition.entry_kind == 3 {
                assert(transition.totals_disclosed == 0, errors::PUBLIC_INPUTS);
            }
            assert_exception_source(self, transition, false);
        }

        if transition.entry_kind == 1 {
            assert(
                transition.schedule_id_high != 0 || transition.schedule_id_low != 0,
                errors::BAD_ROOT,
            );
            assert(
                transition.next_state_high != 0 || transition.next_state_low != 0,
                errors::BAD_ROOT,
            );
            assert(
                transition.release_nullifier_high != 0
                    || transition.release_nullifier_low != 0,
                errors::BAD_ROOT,
            );
            let state = self.vesting_states.read((
                transition.schedule_id_high, transition.schedule_id_low,
            ));
            if state.exists {
                assert(state.owner == transition.owner, errors::BAD_OWNER);
                assert(
                    state.state_high == transition.previous_state_high
                        && state.state_low == transition.previous_state_low,
                    errors::STALE_STATE,
                );
            } else {
                assert(
                    transition.previous_state_high == 0 && transition.previous_state_low == 0,
                    errors::STALE_STATE,
                );
            }
            assert(
                !self.release_consumed.read((
                    transition.release_nullifier_high, transition.release_nullifier_low,
                )),
                errors::REPLAY,
            );
        } else if transition.entry_kind <= 2 {
            assert(
                transition.schedule_id_high == 0 && transition.schedule_id_low == 0
                    && transition.previous_state_high == 0
                    && transition.previous_state_low == 0
                    && transition.next_state_high == 0
                    && transition.next_state_low == 0
                    && transition.release_nullifier_high == 0
                    && transition.release_nullifier_low == 0,
                errors::BAD_ROOT,
            );
        }
        assert(
            !self.run_consumed.read((
                transition.subject_nullifier_high, transition.subject_nullifier_low,
            )),
            errors::REPLAY,
        );
    }

    fn initial_book_root(
        self: @ContractState, owner: ContractAddress, period_start: u64, period_end: u64,
    ) -> felt252 {
        let owner_felt: felt252 = owner.into();
        let seal: felt252 = get_contract_address().into();
        poseidon_hash_span(
            array![
                'PAYO_BOOK_V1', self.chain_id.read(), seal, owner_felt,
                period_start.into(), period_end.into(),
            ].span(),
        )
    }

    fn add_u128_pair(current: u256, first: u128, second: u128) -> u256 {
        current + u256 { high: 0, low: first } + u256 { high: 0, low: second }
    }

    fn append_book_entry(
        ref self: ContractState,
        state: VestingTransitionProofState,
    ) -> (u32, felt252) {
        let key = (state.owner, state.period_start, state.period_end);
        let mut book = self.payroll_books.read(key);
        let previous_root = if book.exists {
            book.accumulator_root
        } else {
            initial_book_root(@self, state.owner, state.period_start, state.period_end)
        };
        let index = book.entry_count;
        let next_root = poseidon_hash_span(
            array![
                'PAYO_BOOK_ADD_V1', previous_root, state.book_entry_high.into(),
                state.book_entry_low.into(), index.into(),
            ].span(),
        );
        self.payroll_book_entries.write(
            (state.owner, state.period_start, state.period_end, index),
            u256 { high: state.book_entry_high, low: state.book_entry_low },
        );
        let added_contributors: u64 = (
            state.shard_0_contributor_count + state.shard_1_contributor_count
        ).into();
        book.exists = true;
        book.entry_count = index + 1;
        book.contributor_count = book.contributor_count + added_contributors;
        if state.totals_disclosed == 1 {
            book.disclosed_entry_count = book.disclosed_entry_count + 1;
            book.strk_gross = add_u128_pair(
                book.strk_gross, state.shard_0_strk_gross, state.shard_1_strk_gross,
            );
            book.strk_deductions = add_u128_pair(
                book.strk_deductions,
                state.shard_0_strk_deductions,
                state.shard_1_strk_deductions,
            );
            book.strk_net = add_u128_pair(
                book.strk_net, state.shard_0_strk_net, state.shard_1_strk_net,
            );
            book.usdc_gross = add_u128_pair(
                book.usdc_gross, state.shard_0_usdc_gross, state.shard_1_usdc_gross,
            );
            book.usdc_deductions = add_u128_pair(
                book.usdc_deductions,
                state.shard_0_usdc_deductions,
                state.shard_1_usdc_deductions,
            );
            book.usdc_net = add_u128_pair(
                book.usdc_net, state.shard_0_usdc_net, state.shard_1_usdc_net,
            );
        } else {
            book.undisclosed_entry_count = book.undisclosed_entry_count + 1;
        }
        if state.entry_kind == 0 {
            book.ordinary_entry_count = book.ordinary_entry_count + 1;
        } else if state.entry_kind == 1 {
            book.vesting_entry_count = book.vesting_entry_count + 1;
        } else if state.entry_kind == 2 {
            book.agent_entry_count = book.agent_entry_count + 1;
        } else if state.entry_kind == 3 {
            book.claim_entry_count = book.claim_entry_count + 1;
        } else {
            book.remediation_entry_count = book.remediation_entry_count + 1;
        }
        book.accumulator_root = next_root;
        book.updated_at = now();
        self.payroll_books.write(key, book);
        (index, next_root)
    }

    #[abi(embed_v0)]
    impl VestingBookSealImpl of super::IPayoVestingBookSeal<ContractState> {
        fn begin_exception_book_authorization(
            ref self: ContractState,
            transition: VestingTransitionProofState,
            transition_shard_0_hash: felt252,
            transition_shard_1_hash: felt252,
        ) {
            assert(transition.entry_kind == 3 || transition.entry_kind == 4, errors::BAD_VERSION);
            assert(transition_shard_0_hash != 0, errors::BAD_PROOF_HASH);
            assert(transition_shard_1_hash != 0, errors::BAD_PROOF_HASH);
            // Exception entries have no payroll-v2 source proof. The pending
            // struct remains ABI-compatible while its clock is taken from v3.
            let payroll = VestingPayrollProofState {
                proof_version: 0,
                schema_version: 0,
                agreement_root_high: 0,
                agreement_root_low: 0,
                manifest_root_high: 0,
                manifest_root_low: 0,
                policy_root_high: 0,
                policy_root_low: 0,
                fx_root_high: 0,
                fx_root_low: 0,
                run_nullifier_high: 0,
                run_nullifier_low: 0,
                validity_start: transition.validity_start,
                validity_expiry: transition.validity_expiry,
            };
            assert_bindings(@self, payroll, transition);
            assert(now() <= transition.validity_expiry, errors::BAD_WINDOW);
            let key = (
                transition.subject_nullifier_high, transition.subject_nullifier_low,
            );
            let previous = self.pending.read(key);
            if previous.exists {
                assert(
                    previous.status != INVOKED
                        && now() > previous.transition.validity_expiry,
                    errors::REPLAY,
                );
            }
            let timestamp = now();
            self.pending.write(
                key,
                PendingVestingAuthorization {
                    exists: true,
                    status: COLLECTING,
                    payroll,
                    transition,
                    payroll_shard_0_hash: 0,
                    payroll_shard_1_hash: 0,
                    transition_shard_0_hash,
                    transition_shard_1_hash,
                    verified_mask: 0,
                    created_at: timestamp,
                    updated_at: timestamp,
                },
            );
            self.emit(
                VestingAuthorizationBegun {
                    run_nullifier_high: transition.subject_nullifier_high,
                    run_nullifier_low: transition.subject_nullifier_low,
                    schedule_id_high: 0,
                    schedule_id_low: 0,
                    expires_at: transition.validity_expiry,
                },
            );
        }

        fn begin_vesting_authorization(
            ref self: ContractState,
            payroll: VestingPayrollProofState,
            transition: VestingTransitionProofState,
            payroll_shard_0_hash: felt252,
            payroll_shard_1_hash: felt252,
            transition_shard_0_hash: felt252,
            transition_shard_1_hash: felt252,
        ) {
            assert(transition.entry_kind <= 2, errors::BAD_VERSION);
            assert(payroll_shard_0_hash != 0, errors::BAD_PROOF_HASH);
            assert(payroll_shard_1_hash != 0, errors::BAD_PROOF_HASH);
            assert(transition_shard_0_hash != 0, errors::BAD_PROOF_HASH);
            assert(transition_shard_1_hash != 0, errors::BAD_PROOF_HASH);
            assert_bindings(@self, payroll, transition);
            assert(now() <= payroll.validity_expiry, errors::BAD_WINDOW);
            let key = (
                transition.subject_nullifier_high, transition.subject_nullifier_low,
            );
            let previous = self.pending.read(key);
            if previous.exists {
                assert(
                    previous.status != INVOKED && now() > previous.transition.validity_expiry,
                    errors::REPLAY,
                );
            }
            let timestamp = now();
            self.pending.write(
                key,
                PendingVestingAuthorization {
                    exists: true,
                    status: COLLECTING,
                    payroll,
                    transition,
                    payroll_shard_0_hash,
                    payroll_shard_1_hash,
                    transition_shard_0_hash,
                    transition_shard_1_hash,
                    verified_mask: 0,
                    created_at: timestamp,
                    updated_at: timestamp,
                },
            );
            self.emit(
                VestingAuthorizationBegun {
                    run_nullifier_high: payroll.run_nullifier_high,
                    run_nullifier_low: payroll.run_nullifier_low,
                    schedule_id_high: transition.schedule_id_high,
                    schedule_id_low: transition.schedule_id_low,
                    expires_at: payroll.validity_expiry,
                },
            );
        }

        fn verify_vesting_authorization_proof(
            ref self: ContractState,
            run_nullifier_high: u128,
            run_nullifier_low: u128,
            proof_kind: u8,
            proof_calldata: Span<felt252>,
        ) {
            assert(proof_kind <= 3, errors::BAD_PROOF);
            assert(!proof_calldata.is_empty(), errors::BAD_PROOF);
            let key = (run_nullifier_high, run_nullifier_low);
            let mut pending = self.pending.read(key);
            assert(pending.exists && pending.status == COLLECTING, errors::BAD_STATE);
            assert_live_window(
                pending.transition.validity_start, pending.transition.validity_expiry,
            );
            assert_bindings(@self, pending.payroll, pending.transition);
            let exception_entry = pending.transition.entry_kind >= 3;
            assert(!exception_entry || proof_kind >= 2, errors::BAD_PROOF);
            let proof_bit: u8 = if proof_kind == 0 {
                1
            } else if proof_kind == 1 {
                2
            } else if proof_kind == 2 {
                4
            } else {
                8
            };
            assert(pending.verified_mask & proof_bit == 0, errors::REPLAY);
            let expected_hash = if proof_kind == 0 {
                pending.payroll_shard_0_hash
            } else if proof_kind == 1 {
                pending.payroll_shard_1_hash
            } else if proof_kind == 2 {
                pending.transition_shard_0_hash
            } else {
                pending.transition_shard_1_hash
            };
            assert(poseidon_hash_span(proof_calldata) == expected_hash, errors::BAD_PROOF_HASH);
            if proof_kind <= 1 {
                let inputs = verifier(@self, PAYROLL_PROOF_VERSION)
                    .verify_payroll_integrity_shard(proof_calldata)
                    .expect(errors::BAD_PROOF);
                assert_payroll_inputs(
                    @self, inputs, pending.payroll, pending.transition.source_seal, proof_kind,
                );
            } else {
                let shard_index = proof_kind - 2;
                let inputs = verifier(@self, VESTING_PROOF_VERSION)
                    .verify_payroll_integrity_shard(proof_calldata)
                    .expect(errors::BAD_PROOF);
                assert_transition_inputs(@self, inputs, pending.transition, shard_index);
            }
            pending.verified_mask = pending.verified_mask | proof_bit;
            pending.updated_at = now();
            let required_mask: u8 = if exception_entry { 12 } else { ALL_PROOFS_VERIFIED };
            if pending.verified_mask == required_mask {
                assert_bindings(@self, pending.payroll, pending.transition);
                pending.status = AUTHORIZED;
                self.emit(
                    VestingAuthorized {
                        run_nullifier_high,
                        run_nullifier_low,
                        release_nullifier_high: pending.transition.release_nullifier_high,
                        release_nullifier_low: pending.transition.release_nullifier_low,
                    },
                );
            }
            self.pending.write(key, pending);
            self.emit(
                VestingProofVerified {
                    run_nullifier_high,
                    run_nullifier_low,
                    proof_kind,
                    verified_mask: pending.verified_mask,
                },
            );
        }

        fn finalize_claim_book_entry(
            ref self: ContractState,
            subject_high: u128,
            subject_low: u128,
            book_entry_high: u128,
            book_entry_low: u128,
        ) {
            let key = (subject_high, subject_low);
            let mut pending = self.pending.read(key);
            assert(
                pending.exists && pending.status == AUTHORIZED
                    && pending.transition.entry_kind == 3,
                errors::BAD_STATE,
            );
            assert_live_window(
                pending.transition.validity_start, pending.transition.validity_expiry,
            );
            assert_bindings(@self, pending.payroll, pending.transition);
            assert_exception_source(@self, pending.transition, false);
            assert(
                pending.transition.subject_nullifier_high == subject_high
                    && pending.transition.subject_nullifier_low == subject_low
                    && pending.transition.book_entry_high == book_entry_high
                    && pending.transition.book_entry_low == book_entry_low,
                errors::PUBLIC_INPUTS,
            );

            pending.status = INVOKED;
            pending.updated_at = now();
            self.pending.write(key, pending);
            self.run_consumed.write(key, true);
            let (index, root) = append_book_entry(ref self, pending.transition);
            self.emit(
                PayrollBookEntryAppended {
                    owner: pending.transition.owner,
                    period_start: pending.transition.period_start,
                    period_end: pending.transition.period_end,
                    index,
                    entry_high: book_entry_high,
                    entry_low: book_entry_low,
                    accumulator_root: root,
                },
            );
        }

        fn privacy_invoke(
            ref self: ContractState,
            run_nullifier_high: u128,
            run_nullifier_low: u128,
            release_nullifier_high: u128,
            release_nullifier_low: u128,
            book_entry_high: u128,
            book_entry_low: u128,
        ) -> Span<VestingOpenNoteDeposit> {
            assert(get_caller_address() == self.pool.read(), errors::BAD_POOL);
            let key = (run_nullifier_high, run_nullifier_low);
            let mut pending = self.pending.read(key);
            assert(pending.exists && pending.status == AUTHORIZED, errors::BAD_STATE);
            assert(pending.transition.entry_kind != 3, errors::BAD_STATE);
            assert_live_window(
                pending.transition.validity_start, pending.transition.validity_expiry,
            );
            assert_bindings(@self, pending.payroll, pending.transition);
            if pending.transition.entry_kind == 4 {
                // The exception seal must consume the exact remediation action
                // earlier in the same STRK20 multicall. A later revert rolls
                // back both contracts, making payment and book append atomic.
                assert_exception_source(@self, pending.transition, true);
            }
            assert(
                pending.transition.subject_nullifier_high == run_nullifier_high
                    && pending.transition.subject_nullifier_low == run_nullifier_low
                    && pending.transition.release_nullifier_high == release_nullifier_high
                    && pending.transition.release_nullifier_low == release_nullifier_low
                    && pending.transition.book_entry_high == book_entry_high
                    && pending.transition.book_entry_low == book_entry_low,
                errors::PUBLIC_INPUTS,
            );

            // Consume every replay key before later writes. A downstream revert
            // reverts the whole Starknet transaction, including these writes.
            pending.status = INVOKED;
            pending.updated_at = now();
            self.pending.write(key, pending);
            self.run_consumed.write(key, true);
            if pending.transition.entry_kind == 1 {
                self.release_consumed.write(
                    (release_nullifier_high, release_nullifier_low), true,
                );
                let timestamp = now();
                self.vesting_states.write(
                    (pending.transition.schedule_id_high, pending.transition.schedule_id_low),
                    VestingStateRecord {
                        exists: true,
                        owner: pending.transition.owner,
                        state_high: pending.transition.next_state_high,
                        state_low: pending.transition.next_state_low,
                        updated_at: timestamp,
                    },
                );
            }
            let (index, root) = append_book_entry(ref self, pending.transition);
            if pending.transition.entry_kind == 1 {
                self.emit(
                    VestingReleased {
                        schedule_id_high: pending.transition.schedule_id_high,
                        schedule_id_low: pending.transition.schedule_id_low,
                        release_nullifier_high,
                        release_nullifier_low,
                        state_high: pending.transition.next_state_high,
                        state_low: pending.transition.next_state_low,
                    },
                );
            }
            self.emit(
                PayrollBookEntryAppended {
                    owner: pending.transition.owner,
                    period_start: pending.transition.period_start,
                    period_end: pending.transition.period_end,
                    index,
                    entry_high: book_entry_high,
                    entry_low: book_entry_low,
                    accumulator_root: root,
                },
            );
            array![].span()
        }

        fn get_pending_authorization(
            self: @ContractState, run_high: u128, run_low: u128,
        ) -> PendingVestingAuthorization {
            self.pending.read((run_high, run_low))
        }

        fn get_authorized_source_seal(
            self: @ContractState, run_high: u128, run_low: u128,
        ) -> ContractAddress {
            let pending = self.pending.read((run_high, run_low));
            assert(
                pending.exists && pending.status == AUTHORIZED
                    && pending.transition.entry_kind == 2,
                errors::BAD_STATE,
            );
            pending.transition.source_seal
        }

        fn get_vesting_state(
            self: @ContractState, schedule_high: u128, schedule_low: u128,
        ) -> VestingStateRecord {
            self.vesting_states.read((schedule_high, schedule_low))
        }

        fn is_release_consumed(
            self: @ContractState, release_high: u128, release_low: u128,
        ) -> bool {
            self.release_consumed.read((release_high, release_low))
        }

        fn get_payroll_book(
            self: @ContractState, owner: ContractAddress, period_start: u64, period_end: u64,
        ) -> PayrollBookRecord {
            self.payroll_books.read((owner, period_start, period_end))
        }

        fn get_payroll_book_entry(
            self: @ContractState,
            owner: ContractAddress,
            period_start: u64,
            period_end: u64,
            index: u32,
        ) -> u256 {
            self.payroll_book_entries.read((owner, period_start, period_end, index))
        }

        fn get_pool(self: @ContractState) -> ContractAddress { self.pool.read() }

        fn get_catalog_registry(self: @ContractState) -> ContractAddress {
            self.catalog_registry.read()
        }

        fn get_obligation_registry(self: @ContractState) -> ContractAddress {
            self.obligation_registry.read()
        }

        fn get_exception_seal(self: @ContractState) -> ContractAddress {
            self.exception_seal.read()
        }
    }
}
