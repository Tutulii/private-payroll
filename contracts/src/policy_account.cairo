use starknet::ContractAddress;

/// Owner-authorized, privacy-preserving limits for one agent session.  Exact
/// payroll values and recipients remain inside the payroll manifest; their
/// pre-authorized manifest/nullifier pairs are committed by `authorized_runs_root`.
#[derive(Copy, Drop, Serde)]
pub struct PolicyConfig {
    pub session_public_key: felt252,
    pub pool: ContractAddress,
    pub seal: ContractAddress,
    pub book_seal: ContractAddress,
    pub seal_mode: u8,
    pub proof_version: u32,
    pub schema_version: u32,
    pub payroll_policy_root_high: u128,
    pub payroll_policy_root_low: u128,
    pub token_set_commitment: felt252,
    pub recipient_set_commitment: felt252,
    pub purpose_commitment: felt252,
    pub amount_limit_commitment: felt252,
    pub authorized_runs_root: felt252,
    pub valid_after: u64,
    pub valid_before: u64,
    pub period_seconds: u64,
    pub max_calls_per_period: u32,
    pub max_call_count: u32,
}

#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PolicyState {
    pub configured: bool,
    pub revoked: bool,
    pub session_public_key: felt252,
    pub pool: ContractAddress,
    pub seal: ContractAddress,
    pub book_seal: ContractAddress,
    pub seal_mode: u8,
    pub proof_version: u32,
    pub schema_version: u32,
    pub payroll_policy_root_high: u128,
    pub payroll_policy_root_low: u128,
    pub token_set_commitment: felt252,
    pub recipient_set_commitment: felt252,
    pub purpose_commitment: felt252,
    pub amount_limit_commitment: felt252,
    pub authorized_runs_root: felt252,
    pub valid_after: u64,
    pub valid_before: u64,
    pub period_seconds: u64,
    pub max_calls_per_period: u32,
    pub max_call_count: u32,
    pub period_started_at: u64,
    pub period_call_count: u32,
    pub used_call_count: u32,
}

/// Onchain evidence derived by the account from the exact STRK20
/// apply-actions calldata that it executed. No caller supplies these hashes.
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct SettlementReceipt {
    pub exists: bool,
    pub policy_id: felt252,
    pub manifest_root_high: u128,
    pub manifest_root_low: u128,
    pub transaction_reference_high: u128,
    pub transaction_reference_low: u128,
    pub settlement_root_high: u128,
    pub settlement_root_low: u128,
    pub emitted_note_count: u32,
    pub created_at: u64,
}

#[starknet::interface]
pub trait IPayoPolicyAccount<TContractState> {
    fn configure_policy(ref self: TContractState, policy_id: felt252, config: PolicyConfig);
    fn revoke_policy(ref self: TContractState, policy_id: felt252);
    fn rotate_session_key(
        ref self: TContractState, policy_id: felt252, new_session_public_key: felt252,
    );
    fn set_policy_account_paused(ref self: TContractState, paused: bool);
    fn execute_policy_intent(
        ref self: TContractState,
        policy_id: felt252,
        agreement_root_high: u128,
        agreement_root_low: u128,
        manifest_root_high: u128,
        manifest_root_low: u128,
        run_nullifier_high: u128,
        run_nullifier_low: u128,
        run_path_bits: u16,
        run_siblings: Span<felt252>,
        pool_calldata: Span<felt252>,
        settlement_proof_calldata: Span<felt252>,
    );
    fn get_policy(self: @TContractState, policy_id: felt252) -> PolicyState;
    fn is_policy_active(self: @TContractState, policy_id: felt252) -> bool;
    fn is_run_available(
        self: @TContractState, mode: u8, run_nullifier_high: u128, run_nullifier_low: u128,
    ) -> bool;
    fn get_settlement_receipt(
        self: @TContractState, run_nullifier_high: u128, run_nullifier_low: u128,
    ) -> SettlementReceipt;
    fn is_policy_account_paused(self: @TContractState) -> bool;
}

/// A native Starknet account for bounded AI-agent execution. The owner keeps
/// normal SNIP-6 control. Session keys can only use SNIP-9 V2 to call the
/// account's single policy gateway; they can never submit arbitrary calls.
#[starknet::interface]
trait IPayoAuthorizedBookSource<TContractState> {
    fn get_authorized_source_seal(
        self: @TContractState, run_high: u128, run_low: u128,
    ) -> ContractAddress;
}

#[starknet::contract(account)]
pub mod PayoPolicyAccount {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use openzeppelin_account::AccountComponent;
    use openzeppelin_account::extensions::SRC9Component::SNIP12MetadataImpl;
    use openzeppelin_account::extensions::src9::snip12_utils::OutsideExecutionStructHash;
    use openzeppelin_account::utils::is_valid_stark_signature;
    use openzeppelin_interfaces::src9::{ISRC9_V2, ISRC9_V2_ID, OutsideExecution};
    use openzeppelin_introspection::src5::SRC5Component;
    use openzeppelin_introspection::src5::SRC5Component::InternalTrait as SRC5InternalTrait;
    use openzeppelin_utils::cryptography::snip12::OffchainMessageHash;
    use openzeppelin_utils::execution::execute_single_call;
    use payo_contracts::settlement_commitments::{
        SettlementNote, build_settlement_root_v1, settlement_transaction_reference_v1,
    };
    use privacy::actions::ServerAction;
    use privacy::snip12::ScreeningAttestation;
    use starknet::account::Call;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{
        get_block_info, get_caller_address, get_contract_address, get_execution_info,
    };
    use super::{
        IPayoAuthorizedBookSourceDispatcher, IPayoAuthorizedBookSourceDispatcherTrait,
        IPayoPolicyAccount, PolicyConfig, PolicyState, SettlementReceipt,
    };

    component!(path: AccountComponent, storage: account, event: AccountEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    #[abi(embed_v0)]
    pub(crate) impl AccountMixinImpl = AccountComponent::AccountMixinImpl<ContractState>;
    impl AccountInternalImpl = AccountComponent::InternalImpl<ContractState>;
    impl SRC5InternalImpl = SRC5Component::InternalImpl<ContractState>;

    const RUN_TREE_DEPTH: usize = 8;
    const RUN_PATH_LIMIT: u16 = 256;
    const MAX_SETTLEMENT_PROOF_FELTS: usize = 4_992;
    const MAX_POLICY_LIFETIME: u64 = 366 * 24 * 60 * 60;
    const MAX_PERIOD_SECONDS: u64 = 366 * 24 * 60 * 60;
    const MODE_PRECOMMIT: u8 = 0;
    const MODE_FINALIZE: u8 = 1;
    const MODE_UNIVERSAL_BOOK: u8 = 2;
    const RUN_LEAF_DOMAIN: felt252 = 'PAYO_AGENT_RUN_V1';

    mod errors {
        pub const PAUSED: felt252 = 'PAYO_ACCOUNT_PAUSED';
        pub const BAD_CALL: felt252 = 'PAYO_POLICY_BAD_CALL';
        pub const BAD_CALLER: felt252 = 'PAYO_POLICY_BAD_CALLER';
        pub const BAD_CONFIG: felt252 = 'PAYO_POLICY_BAD_CONFIG';
        pub const BAD_POLICY: felt252 = 'PAYO_POLICY_BAD_POLICY';
        pub const POLICY_EXISTS: felt252 = 'PAYO_POLICY_EXISTS';
        pub const POLICY_REVOKED: felt252 = 'PAYO_POLICY_REVOKED';
        pub const POLICY_EXPIRED: felt252 = 'PAYO_POLICY_EXPIRED';
        pub const BAD_SIGNATURE: felt252 = 'PAYO_POLICY_BAD_SIG';
        pub const BAD_NONCE: felt252 = 'PAYO_POLICY_BAD_NONCE';
        pub const BAD_WINDOW: felt252 = 'PAYO_POLICY_BAD_WINDOW';
        pub const BAD_RUN: felt252 = 'PAYO_POLICY_BAD_RUN';
        pub const RUN_REPLAY: felt252 = 'PAYO_POLICY_RUN_REPLAY';
        pub const CALL_LIMIT: felt252 = 'PAYO_POLICY_CALL_LIMIT';
        pub const PERIOD_LIMIT: felt252 = 'PAYO_POLICY_PERIOD_LIMIT';
        pub const BAD_POOL_ACTION: felt252 = 'PAYO_POLICY_POOL_ACTION';
        pub const BAD_SETTLEMENT_PROOF: felt252 = 'PAYO_POLICY_SETTLEMENT';
        pub const REENTRANCY: felt252 = 'PAYO_POLICY_REENTRANCY';
    }

    #[storage]
    pub struct Storage {
        #[substorage(v0)]
        pub account: AccountComponent::Storage,
        #[substorage(v0)]
        pub src5: SRC5Component::Storage,
        pub policies: Map<felt252, PolicyState>,
        pub outside_nonces: Map<felt252, bool>,
        pub consumed_runs: Map<(u8, u128, u128), bool>,
        pub settlement_receipts: Map<(u128, u128), SettlementReceipt>,
        pub paused: bool,
        pub executing: bool,
        pub active_policy_id: felt252,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        AccountEvent: AccountComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
        PolicyConfigured: PolicyConfigured,
        PolicyRevoked: PolicyRevoked,
        SessionKeyRotated: SessionKeyRotated,
        PolicyAccountPauseChanged: PolicyAccountPauseChanged,
        PolicyRunExecuted: PolicyRunExecuted,
        SettlementRecorded: SettlementRecorded,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PolicyConfigured {
        #[key]
        pub policy_id: felt252,
        pub authorized_runs_root: felt252,
        pub valid_after: u64,
        pub valid_before: u64,
        pub max_call_count: u32,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PolicyRevoked {
        #[key]
        pub policy_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct SessionKeyRotated {
        #[key]
        pub policy_id: felt252,
        pub new_session_public_key: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PolicyAccountPauseChanged {
        pub paused: bool,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PolicyRunExecuted {
        #[key]
        pub policy_id: felt252,
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        pub mode: u8,
        pub manifest_root_high: u128,
        pub manifest_root_low: u128,
        pub used_call_count: u32,
    }

    #[derive(Drop, starknet::Event)]
    pub struct SettlementRecorded {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        pub policy_id: felt252,
        pub manifest_root_high: u128,
        pub manifest_root_low: u128,
        pub transaction_reference_high: u128,
        pub transaction_reference_low: u128,
        pub settlement_root_high: u128,
        pub settlement_root_low: u128,
        pub emitted_note_count: u32,
    }

    #[constructor]
    pub fn constructor(ref self: ContractState, public_key: felt252) {
        assert(public_key.is_non_zero(), errors::BAD_CONFIG);
        self.account.initializer(public_key);
        self.src5.register_interface(ISRC9_V2_ID);
    }

    fn assert_self(self: @ContractState) {
        assert(get_caller_address() == get_contract_address(), errors::BAD_CALLER);
    }

    fn policy_window_is_active(policy: PolicyState, now: u64) -> bool {
        policy.configured
            && !policy.revoked
            && policy.valid_after < now
            && now < policy.valid_before
    }

    fn policy_is_active(policy: PolicyState, now: u64) -> bool {
        policy_window_is_active(policy, now) && policy.used_call_count < policy.max_call_count
    }

    pub fn run_leaf(
        policy_id: felt252,
        policy: PolicyState,
        agreement_root_high: u128,
        agreement_root_low: u128,
        manifest_root_high: u128,
        manifest_root_low: u128,
        run_nullifier_high: u128,
        run_nullifier_low: u128,
    ) -> felt252 {
        poseidon_hash_span(
            array![
                RUN_LEAF_DOMAIN,
                policy_id,
                policy.seal_mode.into(),
                policy.proof_version.into(),
                policy.schema_version.into(),
                policy.payroll_policy_root_high.into(),
                policy.payroll_policy_root_low.into(),
                policy.token_set_commitment,
                policy.recipient_set_commitment,
                policy.purpose_commitment,
                policy.amount_limit_commitment,
                agreement_root_high.into(),
                agreement_root_low.into(),
                manifest_root_high.into(),
                manifest_root_low.into(),
                run_nullifier_high.into(),
                run_nullifier_low.into(),
            ]
                .span(),
        )
    }

    pub fn assert_run_membership(
        root: felt252, leaf: felt252, path_bits: u16, siblings: Span<felt252>,
    ) {
        assert(siblings.len() == RUN_TREE_DEPTH, errors::BAD_RUN);
        assert(path_bits < RUN_PATH_LIMIT, errors::BAD_RUN);
        let mut current = leaf;
        let mut remaining_path = path_bits;
        let mut level: usize = 0;
        loop {
            if level == RUN_TREE_DEPTH {
                break;
            }
            let sibling = *siblings.at(level);
            let bit = remaining_path % 2;
            remaining_path /= 2;
            current = if bit == 0 {
                poseidon_hash_span(array![current, sibling].span())
            } else {
                poseidon_hash_span(array![sibling, current].span())
            };
            level += 1;
        };
        assert(current == root, errors::BAD_RUN);
    }

    fn assert_private_payroll_actions(
        self: @ContractState,
        policy: PolicyState,
        run_nullifier_high: u128,
        run_nullifier_low: u128,
        pool_calldata: Span<felt252>,
    ) -> (u256, u32) {
        let mut serialized = pool_calldata;
        let actions = Serde::<Span<ServerAction>>::deserialize(ref serialized)
            .expect(errors::BAD_POOL_ACTION);
        let screening = Serde::<Option<ScreeningAttestation>>::deserialize(ref serialized)
            .expect(errors::BAD_POOL_ACTION);
        assert(serialized.is_empty(), errors::BAD_POOL_ACTION);
        assert(screening.is_none(), errors::BAD_POOL_ACTION);

        let mut emitted_notes: Array<SettlementNote> = ArrayTrait::new();
        let mut book_invoke_count: u8 = 0;
        for action in actions {
            match action {
                // Private-note storage and events are allowed. Public deposits,
                // withdrawals, open notes, and viewing-key registration are not.
                ServerAction::WriteOnce(_) => {},
                ServerAction::Append(_) => {},
                ServerAction::EmitEncNoteCreated(input) => {
                    emitted_notes.append(
                        SettlementNote {
                            note_id: *input.note_id,
                            packed_value: *input.packed_value,
                        },
                    );
                },
                ServerAction::EmitNoteUsed(_) => {},
                // Universal mode permits one exact, owner-pinned callback to
                // append this run to the v3 book inside the STRK20 payment.
                ServerAction::Invoke(input) => {
                    assert(policy.seal_mode == MODE_UNIVERSAL_BOOK, errors::BAD_POOL_ACTION);
                    assert(*input.contract_address == policy.book_seal, errors::BAD_POOL_ACTION);
                    assert(input.calldata.len() == 6, errors::BAD_POOL_ACTION);
                    assert(*input.calldata.at(0) == run_nullifier_high.into(), errors::BAD_POOL_ACTION);
                    assert(*input.calldata.at(1) == run_nullifier_low.into(), errors::BAD_POOL_ACTION);
                    assert(*input.calldata.at(2) == 0, errors::BAD_POOL_ACTION);
                    assert(*input.calldata.at(3) == 0, errors::BAD_POOL_ACTION);
                    assert(
                        *input.calldata.at(4) != 0 || *input.calldata.at(5) != 0,
                        errors::BAD_POOL_ACTION,
                    );
                    book_invoke_count += 1;
                },
                ServerAction::InvokeWithComputation(_) => {
                    assert(false, errors::BAD_POOL_ACTION);
                },
                _ => { assert(false, errors::BAD_POOL_ACTION); },
            }
        };
        let emitted_note_count: u32 = emitted_notes.len().try_into().unwrap();
        assert(emitted_note_count > 0, errors::BAD_POOL_ACTION);
        if policy.seal_mode == MODE_UNIVERSAL_BOOK {
            assert(book_invoke_count == 1, errors::BAD_POOL_ACTION);
            let source = IPayoAuthorizedBookSourceDispatcher {
                contract_address: policy.book_seal,
            }.get_authorized_source_seal(run_nullifier_high, run_nullifier_low);
            assert(source == policy.seal, errors::BAD_POOL_ACTION);
        } else {
            assert(book_invoke_count == 0, errors::BAD_POOL_ACTION);
        }
        (build_settlement_root_v1(emitted_notes.span()), emitted_note_count)
    }

    #[abi(embed_v0)]
    pub impl PolicyImpl of IPayoPolicyAccount<ContractState> {
        fn configure_policy(
            ref self: ContractState, policy_id: felt252, config: PolicyConfig,
        ) {
            assert_self(@self);
            assert(policy_id.is_non_zero(), errors::BAD_CONFIG);
            assert(!self.policies.read(policy_id).configured, errors::POLICY_EXISTS);
            assert(config.session_public_key.is_non_zero(), errors::BAD_CONFIG);
            assert(!config.pool.is_zero() && !config.seal.is_zero(), errors::BAD_CONFIG);
            assert(
                config.seal_mode == MODE_PRECOMMIT
                    || config.seal_mode == MODE_FINALIZE
                    || config.seal_mode == MODE_UNIVERSAL_BOOK,
                errors::BAD_CONFIG,
            );
            if config.seal_mode == MODE_UNIVERSAL_BOOK {
                assert(!config.book_seal.is_zero(), errors::BAD_CONFIG);
            } else {
                assert(config.book_seal.is_zero(), errors::BAD_CONFIG);
            }
            assert(config.proof_version > 0 && config.schema_version > 0, errors::BAD_CONFIG);
            assert(
                config.payroll_policy_root_high != 0 || config.payroll_policy_root_low != 0,
                errors::BAD_CONFIG,
            );
            assert(config.token_set_commitment.is_non_zero(), errors::BAD_CONFIG);
            assert(config.recipient_set_commitment.is_non_zero(), errors::BAD_CONFIG);
            assert(config.purpose_commitment.is_non_zero(), errors::BAD_CONFIG);
            assert(config.amount_limit_commitment.is_non_zero(), errors::BAD_CONFIG);
            assert(config.authorized_runs_root.is_non_zero(), errors::BAD_CONFIG);
            assert(config.valid_before > config.valid_after, errors::BAD_CONFIG);
            assert(
                config.valid_before - config.valid_after <= MAX_POLICY_LIFETIME,
                errors::BAD_CONFIG,
            );
            assert(
                config.period_seconds > 0 && config.period_seconds <= MAX_PERIOD_SECONDS,
                errors::BAD_CONFIG,
            );
            assert(config.max_calls_per_period > 0, errors::BAD_CONFIG);
            assert(config.max_call_count > 0, errors::BAD_CONFIG);
            assert(
                config.max_calls_per_period <= config.max_call_count,
                errors::BAD_CONFIG,
            );
            let policy = PolicyState {
                configured: true,
                revoked: false,
                session_public_key: config.session_public_key,
                pool: config.pool,
                seal: config.seal,
                book_seal: config.book_seal,
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
            };
            self.policies.write(policy_id, policy);
            self.emit(
                PolicyConfigured {
                    policy_id,
                    authorized_runs_root: config.authorized_runs_root,
                    valid_after: config.valid_after,
                    valid_before: config.valid_before,
                    max_call_count: config.max_call_count,
                },
            );
        }

        fn revoke_policy(ref self: ContractState, policy_id: felt252) {
            assert_self(@self);
            let mut policy = self.policies.read(policy_id);
            assert(policy.configured, errors::BAD_POLICY);
            assert(!policy.revoked, errors::POLICY_REVOKED);
            policy.revoked = true;
            self.policies.write(policy_id, policy);
            self.emit(PolicyRevoked { policy_id });
        }

        fn rotate_session_key(
            ref self: ContractState, policy_id: felt252, new_session_public_key: felt252,
        ) {
            assert_self(@self);
            assert(new_session_public_key.is_non_zero(), errors::BAD_CONFIG);
            let mut policy = self.policies.read(policy_id);
            assert(policy.configured, errors::BAD_POLICY);
            assert(!policy.revoked, errors::POLICY_REVOKED);
            policy.session_public_key = new_session_public_key;
            self.policies.write(policy_id, policy);
            self.emit(SessionKeyRotated { policy_id, new_session_public_key });
        }

        fn set_policy_account_paused(ref self: ContractState, paused: bool) {
            assert_self(@self);
            self.paused.write(paused);
            self.emit(PolicyAccountPauseChanged { paused });
        }

        fn execute_policy_intent(
            ref self: ContractState,
            policy_id: felt252,
            agreement_root_high: u128,
            agreement_root_low: u128,
            manifest_root_high: u128,
            manifest_root_low: u128,
            run_nullifier_high: u128,
            run_nullifier_low: u128,
            run_path_bits: u16,
            run_siblings: Span<felt252>,
            pool_calldata: Span<felt252>,
            settlement_proof_calldata: Span<felt252>,
        ) {
            assert_self(@self);
            assert(self.executing.read(), errors::BAD_CALLER);
            assert(self.active_policy_id.read() == policy_id, errors::BAD_POLICY);
            assert(!self.paused.read(), errors::PAUSED);
            assert(
                agreement_root_high != 0 || agreement_root_low != 0,
                errors::BAD_RUN,
            );
            assert(manifest_root_high != 0 || manifest_root_low != 0, errors::BAD_RUN);
            assert(run_nullifier_high != 0 || run_nullifier_low != 0, errors::BAD_RUN);
            let mut policy = self.policies.read(policy_id);
            let now = get_block_info().unbox().block_timestamp;
            assert(policy_window_is_active(policy, now), errors::POLICY_EXPIRED);
            assert(policy.used_call_count < policy.max_call_count, errors::CALL_LIMIT);
            if now - policy.period_started_at >= policy.period_seconds {
                policy.period_started_at = now;
                policy.period_call_count = 0;
            }
            assert(
                policy.period_call_count < policy.max_calls_per_period,
                errors::PERIOD_LIMIT,
            );
            // Garaga proof calldata is ~3.2k felts and Starknet caps an invoke
            // at 5k felts. Autonomous runs therefore prove one canonical
            // SettlementMatch chunk (up to three payroll lines) atomically.
            // Larger payrolls use separate owner-authorized runs or Ready.
            assert(
                !settlement_proof_calldata.is_empty()
                    && settlement_proof_calldata.len() <= MAX_SETTLEMENT_PROOF_FELTS,
                errors::BAD_SETTLEMENT_PROOF,
            );
            assert(
                !self.consumed_runs.read((policy.seal_mode, run_nullifier_high, run_nullifier_low)),
                errors::RUN_REPLAY,
            );
            let leaf = run_leaf(
                policy_id,
                policy,
                agreement_root_high,
                agreement_root_low,
                manifest_root_high,
                manifest_root_low,
                run_nullifier_high,
                run_nullifier_low,
            );
            assert_run_membership(policy.authorized_runs_root, leaf, run_path_bits, run_siblings);
            let (settlement_root, emitted_note_count) = assert_private_payroll_actions(
                @self, policy, run_nullifier_high, run_nullifier_low, pool_calldata,
            );
            let chain_id = get_execution_info().unbox().tx_info.chain_id;
            let transaction_reference = settlement_transaction_reference_v1(
                chain_id, get_contract_address(), policy.pool, pool_calldata,
            );

            policy.period_call_count += 1;
            policy.used_call_count += 1;
            self.policies.write(policy_id, policy);
            self.consumed_runs
                .write((policy.seal_mode, run_nullifier_high, run_nullifier_low), true);

            let call = Call {
                to: policy.pool,
                selector: selector!("apply_actions"),
                calldata: pool_calldata,
            };
            execute_single_call(@call);
            let receipt = SettlementReceipt {
                exists: true,
                policy_id,
                manifest_root_high,
                manifest_root_low,
                transaction_reference_high: transaction_reference.high,
                transaction_reference_low: transaction_reference.low,
                settlement_root_high: settlement_root.high,
                settlement_root_low: settlement_root.low,
                emitted_note_count,
                created_at: now,
            };
            self
                .settlement_receipts
                .write((run_nullifier_high, run_nullifier_low), receipt);
            let registration_calldata = array![
                run_nullifier_high.into(), run_nullifier_low.into(),
            ];
            let registration_call = Call {
                to: policy.seal,
                selector: selector!("register_direct_settlement_source"),
                calldata: registration_calldata.span(),
            };
            execute_single_call(@registration_call);
            let mut finalization_calldata = array![
                8,
                run_nullifier_high.into(),
                run_nullifier_low.into(),
                0,
                1,
            ];
            settlement_proof_calldata.serialize(ref finalization_calldata);
            let finalization_call = Call {
                to: policy.seal,
                selector: selector!("finalize_settlement"),
                calldata: finalization_calldata.span(),
            };
            // The pool transfer, receipt registration and SettlementMatch v8
            // verification share one transaction. Any mismatch reverts all
            // state and emitted private notes.
            execute_single_call(@finalization_call);
            self.emit(
                PolicyRunExecuted {
                    policy_id,
                    run_nullifier_high,
                    run_nullifier_low,
                    mode: policy.seal_mode,
                    manifest_root_high,
                    manifest_root_low,
                    used_call_count: policy.used_call_count,
                },
            );
            self.emit(
                SettlementRecorded {
                    run_nullifier_high,
                    run_nullifier_low,
                    policy_id,
                    manifest_root_high,
                    manifest_root_low,
                    transaction_reference_high: transaction_reference.high,
                    transaction_reference_low: transaction_reference.low,
                    settlement_root_high: settlement_root.high,
                    settlement_root_low: settlement_root.low,
                    emitted_note_count,
                },
            );
        }

        fn get_policy(self: @ContractState, policy_id: felt252) -> PolicyState {
            self.policies.read(policy_id)
        }

        fn is_policy_active(self: @ContractState, policy_id: felt252) -> bool {
            policy_is_active(self.policies.read(policy_id), get_block_info().unbox().block_timestamp)
        }

        fn is_run_available(
            self: @ContractState,
            mode: u8,
            run_nullifier_high: u128,
            run_nullifier_low: u128,
        ) -> bool {
            !self.consumed_runs.read((mode, run_nullifier_high, run_nullifier_low))
        }

        fn get_settlement_receipt(
            self: @ContractState, run_nullifier_high: u128, run_nullifier_low: u128,
        ) -> SettlementReceipt {
            self.settlement_receipts.read((run_nullifier_high, run_nullifier_low))
        }

        fn is_policy_account_paused(self: @ContractState) -> bool {
            self.paused.read()
        }
    }

    #[abi(embed_v0)]
    pub impl OutsideExecutionV2Impl of ISRC9_V2<ContractState> {
        fn execute_from_outside_v2(
            ref self: ContractState,
            outside_execution: OutsideExecution,
            signature: Span<felt252>,
        ) -> Array<Span<felt252>> {
            assert(!self.paused.read(), errors::PAUSED);
            assert(!self.executing.read(), errors::REENTRANCY);
            if outside_execution.caller.into() != 'ANY_CALLER' {
                assert(get_caller_address() == outside_execution.caller, errors::BAD_CALLER);
            }
            let now = get_block_info().unbox().block_timestamp;
            assert(outside_execution.execute_after < now, errors::BAD_WINDOW);
            assert(now < outside_execution.execute_before, errors::BAD_WINDOW);
            assert(
                !self.outside_nonces.read(outside_execution.nonce),
                errors::BAD_NONCE,
            );
            assert(outside_execution.calls.len() == 1, errors::BAD_CALL);
            let call = *outside_execution.calls.at(0);
            assert(call.to == get_contract_address(), errors::BAD_CALL);
            assert(call.selector == selector!("execute_policy_intent"), errors::BAD_CALL);
            assert(!call.calldata.is_empty(), errors::BAD_CALL);
            let policy_id = *call.calldata.at(0);
            let policy = self.policies.read(policy_id);
            assert(policy.configured, errors::BAD_POLICY);
            assert(!policy.revoked, errors::POLICY_REVOKED);
            assert(policy_window_is_active(policy, now), errors::POLICY_EXPIRED);
            assert(policy.used_call_count < policy.max_call_count, errors::CALL_LIMIT);

            let message_hash = outside_execution.get_message_hash(get_contract_address());
            assert(
                is_valid_stark_signature(message_hash, policy.session_public_key, signature),
                errors::BAD_SIGNATURE,
            );

            self.outside_nonces.write(outside_execution.nonce, true);
            self.executing.write(true);
            self.active_policy_id.write(policy_id);
            let result = execute_single_call(@call);
            self.active_policy_id.write(0);
            self.executing.write(false);
            let mut results = array![];
            results.append(result);
            results
        }

        fn is_valid_outside_execution_nonce(
            self: @ContractState, nonce: felt252,
        ) -> bool {
            !self.outside_nonces.read(nonce)
        }
    }
}
