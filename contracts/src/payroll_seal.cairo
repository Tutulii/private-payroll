use starknet::ContractAddress;
use payo_contracts::policy_account::SettlementReceipt;

// Must remain positionally compatible with privacy::objects::OpenNoteDeposit.
#[derive(Serde, Copy, Drop, PartialEq, Debug)]
pub struct OpenNoteDeposit {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u128,
}

#[derive(Serde, Copy, Drop, starknet::Store)]
pub struct SealedProofState {
    pub mode: u8,
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
    pub shard_0_hash: felt252,
    pub shard_1_hash: felt252,
    pub previous_status: u8,
}

#[starknet::interface]
pub trait IIntegrityVerifier<TContractState> {
    fn verify_payroll_integrity_bundle(
        self: @TContractState, shard_0_proof: Span<felt252>, shard_1_proof: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
    fn verify_payroll_integrity_shard(
        self: @TContractState, shard_proof: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
}

#[starknet::interface]
pub trait ISettlementVerifier<TContractState> {
    fn verify_ultra_keccak_zk_honk_proof(
        self: @TContractState, proof_calldata: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
}

#[starknet::interface]
pub trait ISettlementReceiptSource<TContractState> {
    fn get_settlement_receipt(
        self: @TContractState, run_nullifier_high: u128, run_nullifier_low: u128,
    ) -> SettlementReceipt;
}

#[starknet::interface]
pub trait ICatalogRegistry<TContractState> {
    fn is_policy_root_valid(self: @TContractState, root_high: u128, root_low: u128) -> bool;
    fn is_fx_root_valid(self: @TContractState, root_high: u128, root_low: u128) -> bool;
    fn is_verifier_valid(self: @TContractState, mode: u8, proof_version: u32) -> bool;
    fn get_verifier(
        self: @TContractState, mode: u8, proof_version: u32,
    ) -> ContractAddress;
}

#[starknet::interface]
pub trait IObligationRootRegistry<TContractState> {
    fn is_obligation_root_valid(
        self: @TContractState, root_high: u128, root_low: u128,
    ) -> bool;
}

#[starknet::interface]
pub trait IPayoPayrollSeal<TContractState> {
    /// Called only by the configured STRK20 pool through its INVOKE action. A
    /// caller supplies either both proof shards for direct verification, or two
    /// non-zero Poseidon hashes and empty proof spans for the split fallback.
    fn privacy_invoke(
        ref self: TContractState,
        mode: u8,
        proof_version: u32,
        schema_version: u32,
        agreement_root_high: u128,
        agreement_root_low: u128,
        manifest_root_high: u128,
        manifest_root_low: u128,
        policy_root_high: u128,
        policy_root_low: u128,
        fx_root_high: u128,
        fx_root_low: u128,
        run_nullifier_high: u128,
        run_nullifier_low: u128,
        validity_start: u64,
        validity_expiry: u64,
        shard_0_hash: felt252,
        shard_1_hash: felt252,
        shard_0_proof_calldata: Span<felt252>,
        shard_1_proof_calldata: Span<felt252>,
    ) -> Span<OpenNoteDeposit>;

    /// Permissionlessly stages the exact PayrollIntegrity commitment for a
    /// direct policy-account run. This moves no funds. Both hash-bound shards
    /// must reach the configured verifier before a private payment can use the
    /// run as its atomic SettlementMatch source.
    fn precommit_direct(
        ref self: TContractState,
        proof_version: u32,
        schema_version: u32,
        agreement_root_high: u128,
        agreement_root_low: u128,
        manifest_root_high: u128,
        manifest_root_low: u128,
        policy_root_high: u128,
        policy_root_low: u128,
        fx_root_high: u128,
        fx_root_low: u128,
        run_nullifier_high: u128,
        run_nullifier_low: u128,
        validity_start: u64,
        validity_expiry: u64,
        shard_0_hash: felt252,
        shard_1_hash: felt252,
    );

    /// Anyone may finish a pool-created sealed run one shard at a time. Each
    /// proof is hash-bound, registry/version checked, and public-input checked.
    fn verify_sealed_shard(
        ref self: TContractState,
        run_nullifier_high: u128,
        run_nullifier_low: u128,
        shard_index: u8,
        proof_calldata: Span<felt252>,
    );

    /// Called atomically by the policy account after the pool has accepted the
    /// PayrollIntegrity PRECOMMIT and the account has stored its derived receipt.
    fn register_direct_settlement_source(
        ref self: TContractState, run_nullifier_high: u128, run_nullifier_low: u128,
    );

    /// Verifies one SettlementMatch v8 chunk. The run becomes FINALIZED only
    /// after every unique chunk has been checked against the policy receipt.
    fn finalize_settlement(
        ref self: TContractState,
        proof_version: u32,
        run_nullifier_high: u128,
        run_nullifier_low: u128,
        chunk_index: u8,
        chunk_count: u8,
        proof_calldata: Span<felt252>,
    );

    fn get_run_status(
        self: @TContractState, run_nullifier_high: u128, run_nullifier_low: u128,
    ) -> u8;
    fn is_sealed_shard_verified(
        self: @TContractState,
        run_nullifier_high: u128,
        run_nullifier_low: u128,
        shard_index: u8,
    ) -> bool;
    fn get_settlement_source(
        self: @TContractState, run_nullifier_high: u128, run_nullifier_low: u128,
    ) -> ContractAddress;
    fn get_settlement_progress(
        self: @TContractState, run_nullifier_high: u128, run_nullifier_low: u128,
    ) -> (u8, u8);
    fn is_settlement_chunk_verified(
        self: @TContractState,
        run_nullifier_high: u128,
        run_nullifier_low: u128,
        chunk_index: u8,
    ) -> bool;
    fn get_pool(self: @TContractState) -> ContractAddress;
    fn get_catalog_registry(self: @TContractState) -> ContractAddress;
    fn get_obligation_registry(self: @TContractState) -> ContractAddress;
    fn get_verifier(
        self: @TContractState, mode: u8, proof_version: u32,
    ) -> ContractAddress;
}

#[starknet::contract]
pub mod PayoPayrollSeal {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_info, get_caller_address, get_contract_address};
    use super::{
        ICatalogRegistryDispatcher, ICatalogRegistryDispatcherTrait, IIntegrityVerifierDispatcher,
        IIntegrityVerifierDispatcherTrait, IObligationRootRegistryDispatcher,
        IObligationRootRegistryDispatcherTrait, ISettlementReceiptSourceDispatcher,
        ISettlementReceiptSourceDispatcherTrait, ISettlementVerifierDispatcher,
        ISettlementVerifierDispatcherTrait, OpenNoteDeposit, SealedProofState,
        SettlementReceipt,
    };

    mod errors {
        pub const BAD_POOL: felt252 = 'PAYO_BAD_POOL';
        pub const BAD_MODE: felt252 = 'PAYO_BAD_MODE';
        pub const BAD_VERSION: felt252 = 'PAYO_BAD_VERSION';
        pub const BAD_WINDOW: felt252 = 'PAYO_BAD_WINDOW';
        pub const BAD_STATE: felt252 = 'PAYO_BAD_STATE';
        pub const REPLAY: felt252 = 'PAYO_REPLAY';
        pub const PROOF_FAILED: felt252 = 'PAYO_PROOF_FAILED';
        pub const PUBLIC_INPUTS: felt252 = 'PAYO_PUBLIC_INPUTS';
        pub const ZERO_ADDRESS: felt252 = 'PAYO_ZERO_ADDRESS';
        pub const ROOT_INACTIVE: felt252 = 'PAYO_ROOT_INACTIVE';
        pub const VERIFIER_INACTIVE: felt252 = 'PAYO_VER_INACTIVE';
        pub const BAD_PROOF_FORM: felt252 = 'PAYO_BAD_PROOF_FORM';
        pub const BAD_PROOF_HASH: felt252 = 'PAYO_BAD_PROOF_HASH';
        pub const SHARD_REPLAY: felt252 = 'PAYO_SHARD_REPLAY';
        pub const BAD_SETTLEMENT: felt252 = 'PAYO_BAD_SETTLEMENT';
        pub const BAD_SETTLEMENT_SOURCE: felt252 = 'PAYO_BAD_SETTLE_SRC';
        pub const SETTLEMENT_REPLAY: felt252 = 'PAYO_SETTLE_REPLAY';
    }

    pub const MODE_PRECOMMIT: u8 = 0;
    pub const MODE_FINALIZE: u8 = 1;
    pub const MODE_CLAIM: u8 = 2;
    pub const MODE_REMEDIATE: u8 = 3;
    pub const STATUS_NONE: u8 = 0;
    pub const STATUS_SEALED: u8 = 1;
    pub const STATUS_PROVEN: u8 = 2;
    pub const STATUS_FINALIZED: u8 = 3;
    pub const STATUS_CLAIMED: u8 = 4;
    pub const STATUS_REMEDIATED: u8 = 5;
    const MAX_VALIDITY_WINDOW: u64 = 3600;
    const SETTLEMENT_PROOF_VERSION: u32 = 8;
    const MAX_SETTLEMENT_CHUNKS: u8 = 17;

    #[storage]
    struct Storage {
        pool: ContractAddress,
        catalog_registry: ContractAddress,
        obligation_registry: ContractAddress,
        chain_id: felt252,
        run_status: Map<(u128, u128), u8>,
        sealed_proofs: Map<(u128, u128), SealedProofState>,
        shard_verified: Map<(u128, u128, u8), bool>,
        settlement_sources: Map<(u128, u128), ContractAddress>,
        settlement_chunk_count: Map<(u128, u128), u8>,
        settlement_verified_count: Map<(u128, u128), u8>,
        settlement_chunk_verified: Map<(u128, u128, u8), bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        PayrollSealed: PayrollSealed,
        SealedShardVerified: SealedShardVerified,
        PayrollStateChanged: PayrollStateChanged,
        DirectSettlementSourceRegistered: DirectSettlementSourceRegistered,
        SettlementChunkVerified: SettlementChunkVerified,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PayrollSealed {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        pub mode: u8,
        pub shard_0_hash: felt252,
        pub shard_1_hash: felt252,
        pub proof_version: u32,
    }

    #[derive(Drop, starknet::Event)]
    pub struct SealedShardVerified {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        #[key]
        pub shard_index: u8,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PayrollStateChanged {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        pub mode: u8,
        pub previous_status: u8,
        pub new_status: u8,
        pub manifest_root_high: u128,
        pub manifest_root_low: u128,
        pub proof_version: u32,
    }

    #[derive(Drop, starknet::Event)]
    pub struct DirectSettlementSourceRegistered {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        #[key]
        pub source: ContractAddress,
        pub settlement_root_high: u128,
        pub settlement_root_low: u128,
        pub transaction_reference_high: u128,
        pub transaction_reference_low: u128,
        pub emitted_note_count: u32,
    }

    #[derive(Drop, starknet::Event)]
    pub struct SettlementChunkVerified {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        #[key]
        pub chunk_index: u8,
        pub chunk_count: u8,
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

    fn assert_public_input(inputs: Span<u256>, index: usize, expected: u256) {
        assert(inputs.len() > index, errors::PUBLIC_INPUTS);
        assert(*inputs.at(index) == expected, errors::PUBLIC_INPUTS);
    }

    fn assert_settlement_receipt(
        proof: SealedProofState, receipt: SettlementReceipt,
    ) {
        assert(receipt.exists, errors::BAD_SETTLEMENT);
        assert(receipt.policy_id != 0, errors::BAD_SETTLEMENT);
        assert(
            receipt.manifest_root_high == proof.manifest_root_high
                && receipt.manifest_root_low == proof.manifest_root_low,
            errors::BAD_SETTLEMENT,
        );
        assert(
            receipt.transaction_reference_high != 0
                || receipt.transaction_reference_low != 0,
            errors::BAD_SETTLEMENT,
        );
        assert(
            receipt.settlement_root_high != 0 || receipt.settlement_root_low != 0,
            errors::BAD_SETTLEMENT,
        );
        assert(
            receipt.emitted_note_count > 0 && receipt.emitted_note_count <= 64,
            errors::BAD_SETTLEMENT,
        );
    }

    fn as_u256<T, +Into<T, u256>>(value: T) -> u256 {
        value.into()
    }

    fn assert_mode_state(mode: u8, status: u8) {
        assert(mode <= MODE_REMEDIATE, errors::BAD_MODE);
        if mode == MODE_PRECOMMIT || mode == MODE_CLAIM {
            assert(status == STATUS_NONE, errors::REPLAY);
        } else if mode == MODE_FINALIZE {
            assert(status == STATUS_PROVEN, errors::BAD_STATE);
        } else {
            assert(status == STATUS_CLAIMED, errors::BAD_STATE);
        }
    }

    fn target_status(mode: u8) -> u8 {
        assert(mode <= MODE_REMEDIATE, errors::BAD_MODE);
        if mode == MODE_PRECOMMIT {
            STATUS_PROVEN
        } else if mode == MODE_FINALIZE {
            STATUS_FINALIZED
        } else if mode == MODE_CLAIM {
            STATUS_CLAIMED
        } else {
            STATUS_REMEDIATED
        }
    }

    fn assert_window(validity_start: u64, validity_expiry: u64) {
        let now = get_block_info().unbox().block_timestamp;
        assert(validity_expiry >= validity_start, errors::BAD_WINDOW);
        assert(validity_expiry - validity_start <= MAX_VALIDITY_WINDOW, errors::BAD_WINDOW);
        assert(validity_start <= now && now <= validity_expiry, errors::BAD_WINDOW);
    }

    fn assert_active_configuration(self: @ContractState, proof: SealedProofState) {
        let catalog = ICatalogRegistryDispatcher {
            contract_address: self.catalog_registry.read(),
        };
        let obligations = IObligationRootRegistryDispatcher {
            contract_address: self.obligation_registry.read(),
        };
        assert(
            catalog.is_policy_root_valid(proof.policy_root_high, proof.policy_root_low),
            errors::ROOT_INACTIVE,
        );
        assert(
            catalog.is_fx_root_valid(proof.fx_root_high, proof.fx_root_low),
            errors::ROOT_INACTIVE,
        );
        assert(
            obligations
                .is_obligation_root_valid(
                    proof.agreement_root_high, proof.agreement_root_low,
                ),
            errors::ROOT_INACTIVE,
        );
        assert(
            catalog.is_verifier_valid(proof.mode, proof.proof_version),
            errors::VERIFIER_INACTIVE,
        );
    }

    fn verifier_for(self: @ContractState, mode: u8, proof_version: u32) -> ContractAddress {
        let catalog = ICatalogRegistryDispatcher {
            contract_address: self.catalog_registry.read(),
        };
        catalog.get_verifier(mode, proof_version)
    }

    fn assert_shard_public_inputs(
        self: @ContractState,
        inputs: Span<u256>,
        proof: SealedProofState,
        shard_index: u8,
    ) {
        assert(inputs.len() == 17, errors::PUBLIC_INPUTS);
        let seal_address: felt252 = get_contract_address().into();
        assert_public_input(inputs, 0, as_u256(self.chain_id.read()));
        assert_public_input(inputs, 1, as_u256(seal_address));
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

    fn emit_state_change(ref self: ContractState, proof: SealedProofState, new_status: u8) {
        self.emit(
            PayrollStateChanged {
                run_nullifier_high: proof.run_nullifier_high,
                run_nullifier_low: proof.run_nullifier_low,
                mode: proof.mode,
                previous_status: proof.previous_status,
                new_status,
                manifest_root_high: proof.manifest_root_high,
                manifest_root_low: proof.manifest_root_low,
                proof_version: proof.proof_version,
            },
        );
    }

    #[abi(embed_v0)]
    impl PayrollSealImpl of super::IPayoPayrollSeal<ContractState> {
        fn precommit_direct(
            ref self: ContractState,
            proof_version: u32,
            schema_version: u32,
            agreement_root_high: u128,
            agreement_root_low: u128,
            manifest_root_high: u128,
            manifest_root_low: u128,
            policy_root_high: u128,
            policy_root_low: u128,
            fx_root_high: u128,
            fx_root_low: u128,
            run_nullifier_high: u128,
            run_nullifier_low: u128,
            validity_start: u64,
            validity_expiry: u64,
            shard_0_hash: felt252,
            shard_1_hash: felt252,
        ) {
            assert(proof_version > 0, errors::BAD_VERSION);
            assert(schema_version == 1, errors::BAD_VERSION);
            assert_window(validity_start, validity_expiry);
            assert(shard_0_hash != 0 && shard_1_hash != 0, errors::BAD_PROOF_HASH);
            let nullifier = (run_nullifier_high, run_nullifier_low);
            let previous_status = self.run_status.read(nullifier);
            assert_mode_state(MODE_PRECOMMIT, previous_status);
            let proof = SealedProofState {
                mode: MODE_PRECOMMIT,
                proof_version,
                schema_version,
                agreement_root_high,
                agreement_root_low,
                manifest_root_high,
                manifest_root_low,
                policy_root_high,
                policy_root_low,
                fx_root_high,
                fx_root_low,
                run_nullifier_high,
                run_nullifier_low,
                validity_start,
                validity_expiry,
                shard_0_hash,
                shard_1_hash,
                previous_status,
            };
            assert_active_configuration(@self, proof);
            self.sealed_proofs.write(nullifier, proof);
            self.shard_verified.write((run_nullifier_high, run_nullifier_low, 0), false);
            self.shard_verified.write((run_nullifier_high, run_nullifier_low, 1), false);
            self.run_status.write(nullifier, STATUS_SEALED);
            self.emit(
                PayrollSealed {
                    run_nullifier_high,
                    run_nullifier_low,
                    mode: MODE_PRECOMMIT,
                    shard_0_hash,
                    shard_1_hash,
                    proof_version,
                },
            );
        }

        fn privacy_invoke(
            ref self: ContractState,
            mode: u8,
            proof_version: u32,
            schema_version: u32,
            agreement_root_high: u128,
            agreement_root_low: u128,
            manifest_root_high: u128,
            manifest_root_low: u128,
            policy_root_high: u128,
            policy_root_low: u128,
            fx_root_high: u128,
            fx_root_low: u128,
            run_nullifier_high: u128,
            run_nullifier_low: u128,
            validity_start: u64,
            validity_expiry: u64,
            shard_0_hash: felt252,
            shard_1_hash: felt252,
            shard_0_proof_calldata: Span<felt252>,
            shard_1_proof_calldata: Span<felt252>,
        ) -> Span<OpenNoteDeposit> {
            assert(get_caller_address() == self.pool.read(), errors::BAD_POOL);
            assert(mode <= MODE_REMEDIATE, errors::BAD_MODE);
            assert(mode != MODE_FINALIZE, errors::BAD_MODE);
            assert(proof_version > 0, errors::BAD_VERSION);
            assert(schema_version == 1, errors::BAD_VERSION);
            assert_window(validity_start, validity_expiry);

            let nullifier = (run_nullifier_high, run_nullifier_low);
            let previous_status = self.run_status.read(nullifier);
            assert_mode_state(mode, previous_status);
            let proof = SealedProofState {
                mode,
                proof_version,
                schema_version,
                agreement_root_high,
                agreement_root_low,
                manifest_root_high,
                manifest_root_low,
                policy_root_high,
                policy_root_low,
                fx_root_high,
                fx_root_low,
                run_nullifier_high,
                run_nullifier_low,
                validity_start,
                validity_expiry,
                shard_0_hash,
                shard_1_hash,
                previous_status,
            };
            assert_active_configuration(@self, proof);
            self.sealed_proofs.write(nullifier, proof);

            let direct = !shard_0_proof_calldata.is_empty()
                && !shard_1_proof_calldata.is_empty();
            let sealed = shard_0_proof_calldata.is_empty()
                && shard_1_proof_calldata.is_empty();
            assert(direct || sealed, errors::BAD_PROOF_FORM);
            if sealed {
                assert(shard_0_hash != 0 && shard_1_hash != 0, errors::BAD_PROOF_HASH);
                // CLAIM and REMEDIATE intentionally share the claim nullifier.
                // Reset the per-shard cursor when the accepted claim advances
                // into a fresh remediation proof; otherwise the claim's true
                // bits would make remediation replay or skip verification.
                self.shard_verified.write((run_nullifier_high, run_nullifier_low, 0), false);
                self.shard_verified.write((run_nullifier_high, run_nullifier_low, 1), false);
                self.run_status.write(nullifier, STATUS_SEALED);
                self.emit(
                    PayrollSealed {
                        run_nullifier_high,
                        run_nullifier_low,
                        mode,
                        shard_0_hash,
                        shard_1_hash,
                        proof_version,
                    },
                );
            } else {
                let verifier = IIntegrityVerifierDispatcher {
                    contract_address: verifier_for(@self, mode, proof_version),
                };
                let public_inputs = verifier
                    .verify_payroll_integrity_bundle(
                        shard_0_proof_calldata, shard_1_proof_calldata,
                    )
                    .expect(errors::PROOF_FAILED);
                assert(public_inputs.len() == 34, errors::PUBLIC_INPUTS);
                assert_shard_public_inputs(@self, public_inputs.slice(0, 17), proof, 0);
                assert_shard_public_inputs(@self, public_inputs.slice(17, 17), proof, 1);
                let new_status = target_status(mode);
                self.run_status.write(nullifier, new_status);
                emit_state_change(ref self, proof, new_status);
            }

            // The seal never receives or custodies payroll tokens.
            array![].span()
        }

        fn verify_sealed_shard(
            ref self: ContractState,
            run_nullifier_high: u128,
            run_nullifier_low: u128,
            shard_index: u8,
            proof_calldata: Span<felt252>,
        ) {
            assert(shard_index <= 1, errors::BAD_MODE);
            let nullifier = (run_nullifier_high, run_nullifier_low);
            assert(self.run_status.read(nullifier) == STATUS_SEALED, errors::BAD_STATE);
            let proof = self.sealed_proofs.read(nullifier);
            assert_window(proof.validity_start, proof.validity_expiry);
            assert_active_configuration(@self, proof);
            assert(
                !self.shard_verified.read((run_nullifier_high, run_nullifier_low, shard_index)),
                errors::SHARD_REPLAY,
            );
            let expected_hash = if shard_index == 0 {
                proof.shard_0_hash
            } else {
                proof.shard_1_hash
            };
            assert(poseidon_hash_span(proof_calldata) == expected_hash, errors::BAD_PROOF_HASH);
            let verifier = IIntegrityVerifierDispatcher {
                contract_address: verifier_for(@self, proof.mode, proof.proof_version),
            };
            let public_inputs = verifier
                .verify_payroll_integrity_shard(proof_calldata)
                .expect(errors::PROOF_FAILED);
            assert_shard_public_inputs(@self, public_inputs, proof, shard_index);
            self
                .shard_verified
                .write((run_nullifier_high, run_nullifier_low, shard_index), true);
            self.emit(
                SealedShardVerified { run_nullifier_high, run_nullifier_low, shard_index },
            );

            if self.shard_verified.read((run_nullifier_high, run_nullifier_low, 0))
                && self.shard_verified.read((run_nullifier_high, run_nullifier_low, 1)) {
                let new_status = target_status(proof.mode);
                self.run_status.write(nullifier, new_status);
                emit_state_change(ref self, proof, new_status);
            }
        }

        fn register_direct_settlement_source(
            ref self: ContractState,
            run_nullifier_high: u128,
            run_nullifier_low: u128,
        ) {
            let nullifier = (run_nullifier_high, run_nullifier_low);
            assert(self.run_status.read(nullifier) == STATUS_PROVEN, errors::BAD_STATE);
            assert(
                self.settlement_sources.read(nullifier).is_zero(),
                errors::BAD_SETTLEMENT_SOURCE,
            );
            let proof = self.sealed_proofs.read(nullifier);
            assert(proof.mode == MODE_PRECOMMIT, errors::BAD_STATE);
            let source = get_caller_address();
            assert(!source.is_zero() && source != self.pool.read(), errors::BAD_SETTLEMENT_SOURCE);
            let receipt = ISettlementReceiptSourceDispatcher { contract_address: source }
                .get_settlement_receipt(run_nullifier_high, run_nullifier_low);
            assert_settlement_receipt(proof, receipt);
            self.settlement_sources.write(nullifier, source);
            self.emit(
                DirectSettlementSourceRegistered {
                    run_nullifier_high,
                    run_nullifier_low,
                    source,
                    settlement_root_high: receipt.settlement_root_high,
                    settlement_root_low: receipt.settlement_root_low,
                    transaction_reference_high: receipt.transaction_reference_high,
                    transaction_reference_low: receipt.transaction_reference_low,
                    emitted_note_count: receipt.emitted_note_count,
                },
            );
        }

        fn finalize_settlement(
            ref self: ContractState,
            proof_version: u32,
            run_nullifier_high: u128,
            run_nullifier_low: u128,
            chunk_index: u8,
            chunk_count: u8,
            proof_calldata: Span<felt252>,
        ) {
            let nullifier = (run_nullifier_high, run_nullifier_low);
            assert(self.run_status.read(nullifier) == STATUS_PROVEN, errors::BAD_STATE);
            assert(proof_version == SETTLEMENT_PROOF_VERSION, errors::BAD_VERSION);
            assert(
                chunk_count > 0
                    && chunk_count <= MAX_SETTLEMENT_CHUNKS
                    && chunk_index < chunk_count,
                errors::BAD_SETTLEMENT,
            );
            assert(
                !self
                    .settlement_chunk_verified
                    .read((run_nullifier_high, run_nullifier_low, chunk_index)),
                errors::SETTLEMENT_REPLAY,
            );
            let source = self.settlement_sources.read(nullifier);
            assert(!source.is_zero(), errors::BAD_SETTLEMENT_SOURCE);
            let proof = self.sealed_proofs.read(nullifier);
            let receipt = ISettlementReceiptSourceDispatcher { contract_address: source }
                .get_settlement_receipt(run_nullifier_high, run_nullifier_low);
            assert_settlement_receipt(proof, receipt);

            let expected_chunk_count = self.settlement_chunk_count.read(nullifier);
            if expected_chunk_count == 0 {
                self.settlement_chunk_count.write(nullifier, chunk_count);
            } else {
                assert(expected_chunk_count == chunk_count, errors::BAD_SETTLEMENT);
            }

            let catalog = ICatalogRegistryDispatcher {
                contract_address: self.catalog_registry.read(),
            };
            assert(
                catalog.is_verifier_valid(MODE_FINALIZE, proof_version),
                errors::VERIFIER_INACTIVE,
            );
            let verifier = ISettlementVerifierDispatcher {
                contract_address: catalog.get_verifier(MODE_FINALIZE, proof_version),
            };
            let public_inputs = verifier
                .verify_ultra_keccak_zk_honk_proof(proof_calldata)
                .expect(errors::PROOF_FAILED);
            assert(public_inputs.len() == 11, errors::PUBLIC_INPUTS);
            assert_public_input(public_inputs, 0, as_u256(proof_version));
            assert_public_input(public_inputs, 1, as_u256(proof.manifest_root_high));
            assert_public_input(public_inputs, 2, as_u256(proof.manifest_root_low));
            assert_public_input(public_inputs, 3, as_u256(run_nullifier_high));
            assert_public_input(public_inputs, 4, as_u256(run_nullifier_low));
            assert_public_input(
                public_inputs, 5, as_u256(receipt.transaction_reference_high),
            );
            assert_public_input(
                public_inputs, 6, as_u256(receipt.transaction_reference_low),
            );
            assert_public_input(public_inputs, 7, as_u256(receipt.settlement_root_high));
            assert_public_input(public_inputs, 8, as_u256(receipt.settlement_root_low));
            assert_public_input(public_inputs, 9, as_u256(chunk_index));
            assert_public_input(public_inputs, 10, as_u256(chunk_count));

            self
                .settlement_chunk_verified
                .write((run_nullifier_high, run_nullifier_low, chunk_index), true);
            let verified_count = self.settlement_verified_count.read(nullifier) + 1;
            self.settlement_verified_count.write(nullifier, verified_count);
            self.emit(
                SettlementChunkVerified {
                    run_nullifier_high, run_nullifier_low, chunk_index, chunk_count,
                },
            );
            if verified_count == chunk_count {
                self.run_status.write(nullifier, STATUS_FINALIZED);
                let mut final_proof = proof;
                final_proof.mode = MODE_FINALIZE;
                final_proof.proof_version = proof_version;
                final_proof.previous_status = STATUS_PROVEN;
                emit_state_change(ref self, final_proof, STATUS_FINALIZED);
            }
        }

        fn get_run_status(
            self: @ContractState, run_nullifier_high: u128, run_nullifier_low: u128,
        ) -> u8 {
            self.run_status.read((run_nullifier_high, run_nullifier_low))
        }

        fn is_sealed_shard_verified(
            self: @ContractState,
            run_nullifier_high: u128,
            run_nullifier_low: u128,
            shard_index: u8,
        ) -> bool {
            self.shard_verified.read((run_nullifier_high, run_nullifier_low, shard_index))
        }

        fn get_settlement_source(
            self: @ContractState, run_nullifier_high: u128, run_nullifier_low: u128,
        ) -> ContractAddress {
            self.settlement_sources.read((run_nullifier_high, run_nullifier_low))
        }

        fn get_settlement_progress(
            self: @ContractState, run_nullifier_high: u128, run_nullifier_low: u128,
        ) -> (u8, u8) {
            let nullifier = (run_nullifier_high, run_nullifier_low);
            (
                self.settlement_verified_count.read(nullifier),
                self.settlement_chunk_count.read(nullifier),
            )
        }

        fn is_settlement_chunk_verified(
            self: @ContractState,
            run_nullifier_high: u128,
            run_nullifier_low: u128,
            chunk_index: u8,
        ) -> bool {
            self
                .settlement_chunk_verified
                .read((run_nullifier_high, run_nullifier_low, chunk_index))
        }

        fn get_pool(self: @ContractState) -> ContractAddress {
            self.pool.read()
        }

        fn get_catalog_registry(self: @ContractState) -> ContractAddress {
            self.catalog_registry.read()
        }

        fn get_obligation_registry(self: @ContractState) -> ContractAddress {
            self.obligation_registry.read()
        }

        fn get_verifier(
            self: @ContractState, mode: u8, proof_version: u32,
        ) -> ContractAddress {
            verifier_for(self, mode, proof_version)
        }
    }
}
