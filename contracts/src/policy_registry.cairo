use starknet::ContractAddress;

#[derive(Drop, Serde, starknet::Store)]
pub struct CatalogRootState {
    pub valid_after: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

#[derive(Drop, Serde, starknet::Store)]
pub struct VerifierState {
    pub verifier: ContractAddress,
    pub valid_after: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

#[starknet::interface]
pub trait IPayoPolicyRegistry<TContractState> {
    fn schedule_policy_root(
        ref self: TContractState,
        root_high: u128,
        root_low: u128,
        _valid_after: u64,
        expires_at: u64,
    );
    fn schedule_fx_root(
        ref self: TContractState,
        root_high: u128,
        root_low: u128,
        _valid_after: u64,
        expires_at: u64,
    );
    fn publish_fx_root(
        ref self: TContractState,
        root_high: u128,
        root_low: u128,
        observed_at: u64,
        maximum_age_seconds: u64,
    );
    fn schedule_fx_publisher(
        ref self: TContractState, new_publisher: ContractAddress, _valid_after: u64,
    );
    fn activate_fx_publisher(ref self: TContractState);
    fn schedule_verifier(
        ref self: TContractState,
        mode: u8,
        proof_version: u32,
        verifier: ContractAddress,
        _valid_after: u64,
        expires_at: u64,
    );
    fn revoke_policy_root(ref self: TContractState, root_high: u128, root_low: u128);
    fn revoke_fx_root(ref self: TContractState, root_high: u128, root_low: u128);
    fn revoke_verifier(ref self: TContractState, mode: u8, proof_version: u32);
    fn is_policy_root_valid(self: @TContractState, root_high: u128, root_low: u128) -> bool;
    fn is_fx_root_valid(self: @TContractState, root_high: u128, root_low: u128) -> bool;
    fn is_verifier_valid(self: @TContractState, mode: u8, proof_version: u32) -> bool;
    fn get_verifier(
        self: @TContractState, mode: u8, proof_version: u32,
    ) -> ContractAddress;
    fn get_fx_publisher(self: @TContractState) -> ContractAddress;
    fn transfer_admin(ref self: TContractState, new_admin: ContractAddress);
    fn get_admin(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PayoPolicyRegistry {
    use core::num::traits::Zero;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_info, get_caller_address};
    use super::{CatalogRootState, VerifierState};

    mod errors {
        pub const NOT_ADMIN: felt252 = 'PAYO_NOT_ADMIN';
        pub const BAD_WINDOW: felt252 = 'PAYO_BAD_WINDOW';
        pub const ZERO_ADDRESS: felt252 = 'PAYO_ZERO_ADDRESS';
        pub const BAD_MODE: felt252 = 'PAYO_BAD_MODE';
        pub const VERIFIER_INACTIVE: felt252 = 'PAYO_VER_INACTIVE';
        pub const NOT_FX_PUBLISHER: felt252 = 'PAYO_NOT_FX_PUBLISHER';
        pub const BAD_FX_AGE: felt252 = 'PAYO_BAD_FX_AGE';
        pub const FX_PUBLISHER_EARLY: felt252 = 'PAYO_FX_PUB_EARLY';
        pub const NO_PENDING_PUBLISHER: felt252 = 'PAYO_NO_FX_PUBLISHER';
    }

    pub const MAX_FX_ROOT_AGE: u64 = 3600;
    const MAX_MODE: u8 = 3;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        policy_roots: Map<(u128, u128), CatalogRootState>,
        fx_roots: Map<(u128, u128), CatalogRootState>,
        verifiers: Map<(u8, u32), VerifierState>,
        fx_publisher: ContractAddress,
        pending_fx_publisher: ContractAddress,
        pending_fx_publisher_valid_after: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        CatalogRootScheduled: CatalogRootScheduled,
        CatalogRootRevoked: CatalogRootRevoked,
        VerifierScheduled: VerifierScheduled,
        VerifierRevoked: VerifierRevoked,
        FxPublisherScheduled: FxPublisherScheduled,
        FxPublisherActivated: FxPublisherActivated,
        AdminTransferred: AdminTransferred,
    }

    #[derive(Drop, starknet::Event)]
    pub struct CatalogRootScheduled {
        #[key]
        pub catalog_kind: u8,
        #[key]
        pub root_high: u128,
        #[key]
        pub root_low: u128,
        pub valid_after: u64,
        pub expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct CatalogRootRevoked {
        #[key]
        pub catalog_kind: u8,
        #[key]
        pub root_high: u128,
        #[key]
        pub root_low: u128,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VerifierScheduled {
        #[key]
        pub mode: u8,
        #[key]
        pub proof_version: u32,
        pub verifier: ContractAddress,
        pub valid_after: u64,
        pub expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VerifierRevoked {
        #[key]
        pub mode: u8,
        #[key]
        pub proof_version: u32,
    }

    #[derive(Drop, starknet::Event)]
    pub struct FxPublisherScheduled {
        pub new_publisher: ContractAddress,
        pub valid_after: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct FxPublisherActivated {
        pub previous_publisher: ContractAddress,
        pub new_publisher: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct AdminTransferred {
        pub previous_admin: ContractAddress,
        pub new_admin: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        assert(!admin.is_zero(), errors::ZERO_ADDRESS);
        self.admin.write(admin);
        self.fx_publisher.write(admin);
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), errors::NOT_ADMIN);
    }

    fn immediate_window(expires_at: u64) -> u64 {
        let now = get_block_info().unbox().block_timestamp;
        assert(expires_at > now, errors::BAD_WINDOW);
        now
    }

    fn root_is_valid(root: CatalogRootState, now: u64) -> bool {
        !root.revoked && root.valid_after <= now && now <= root.expires_at
    }

    fn verifier_is_valid(verifier: VerifierState, now: u64) -> bool {
        !verifier.verifier.is_zero()
            && !verifier.revoked
            && verifier.valid_after <= now
            && now <= verifier.expires_at
    }

    #[abi(embed_v0)]
    impl RegistryImpl of super::IPayoPolicyRegistry<ContractState> {
        fn schedule_policy_root(
            ref self: ContractState,
            root_high: u128,
            root_low: u128,
            _valid_after: u64,
            expires_at: u64,
        ) {
            assert_admin(@self);
            // Keep the legacy positional ABI while making the hackathon profile immediate.
            let valid_after = immediate_window(expires_at);
            self.policy_roots.write(
                (root_high, root_low), CatalogRootState { valid_after, expires_at, revoked: false },
            );
            self.emit(
                CatalogRootScheduled {
                    catalog_kind: 0, root_high, root_low, valid_after, expires_at,
                },
            );
        }

        fn schedule_fx_root(
            ref self: ContractState,
            root_high: u128,
            root_low: u128,
            _valid_after: u64,
            expires_at: u64,
        ) {
            assert_admin(@self);
            // Activation is bound to the confirming block, never a caller-selected future time.
            let valid_after = immediate_window(expires_at);
            self.fx_roots.write(
                (root_high, root_low), CatalogRootState { valid_after, expires_at, revoked: false },
            );
            self.emit(
                CatalogRootScheduled {
                    catalog_kind: 1, root_high, root_low, valid_after, expires_at,
                },
            );
        }

        fn publish_fx_root(
            ref self: ContractState,
            root_high: u128,
            root_low: u128,
            observed_at: u64,
            maximum_age_seconds: u64,
        ) {
            assert(get_caller_address() == self.fx_publisher.read(), errors::NOT_FX_PUBLISHER);
            let now = get_block_info().unbox().block_timestamp;
            assert(maximum_age_seconds > 0, errors::BAD_FX_AGE);
            assert(maximum_age_seconds <= MAX_FX_ROOT_AGE, errors::BAD_FX_AGE);
            assert(observed_at <= now, errors::BAD_FX_AGE);
            let expires_at = observed_at + maximum_age_seconds;
            assert(now <= expires_at, errors::BAD_FX_AGE);
            self.fx_roots.write(
                (root_high, root_low),
                CatalogRootState { valid_after: observed_at, expires_at, revoked: false },
            );
            self.emit(
                CatalogRootScheduled {
                    catalog_kind: 1,
                    root_high,
                    root_low,
                    valid_after: observed_at,
                    expires_at,
                },
            );
        }

        fn schedule_fx_publisher(
            ref self: ContractState, new_publisher: ContractAddress, _valid_after: u64,
        ) {
            assert_admin(@self);
            assert(!new_publisher.is_zero(), errors::ZERO_ADDRESS);
            // The second activation call can execute in the same multicall.
            let valid_after = get_block_info().unbox().block_timestamp;
            self.pending_fx_publisher.write(new_publisher);
            self.pending_fx_publisher_valid_after.write(valid_after);
            self.emit(FxPublisherScheduled { new_publisher, valid_after });
        }

        fn activate_fx_publisher(ref self: ContractState) {
            let new_publisher = self.pending_fx_publisher.read();
            assert(!new_publisher.is_zero(), errors::NO_PENDING_PUBLISHER);
            assert(
                get_block_info().unbox().block_timestamp
                    >= self.pending_fx_publisher_valid_after.read(),
                errors::FX_PUBLISHER_EARLY,
            );
            let previous_publisher = self.fx_publisher.read();
            self.fx_publisher.write(new_publisher);
            self.pending_fx_publisher.write(Zero::zero());
            self.pending_fx_publisher_valid_after.write(0);
            self.emit(FxPublisherActivated { previous_publisher, new_publisher });
        }

        fn schedule_verifier(
            ref self: ContractState,
            mode: u8,
            proof_version: u32,
            verifier: ContractAddress,
            _valid_after: u64,
            expires_at: u64,
        ) {
            assert_admin(@self);
            assert(mode <= MAX_MODE, errors::BAD_MODE);
            assert(!verifier.is_zero(), errors::ZERO_ADDRESS);
            // Verifier versions become usable as soon as this transaction confirms.
            let valid_after = immediate_window(expires_at);
            self.verifiers.write(
                (mode, proof_version),
                VerifierState { verifier, valid_after, expires_at, revoked: false },
            );
            self.emit(
                VerifierScheduled { mode, proof_version, verifier, valid_after, expires_at },
            );
        }

        fn revoke_policy_root(ref self: ContractState, root_high: u128, root_low: u128) {
            assert_admin(@self);
            let mut root = self.policy_roots.read((root_high, root_low));
            root.revoked = true;
            self.policy_roots.write((root_high, root_low), root);
            self.emit(CatalogRootRevoked { catalog_kind: 0, root_high, root_low });
        }

        fn revoke_fx_root(ref self: ContractState, root_high: u128, root_low: u128) {
            assert_admin(@self);
            let mut root = self.fx_roots.read((root_high, root_low));
            root.revoked = true;
            self.fx_roots.write((root_high, root_low), root);
            self.emit(CatalogRootRevoked { catalog_kind: 1, root_high, root_low });
        }

        fn revoke_verifier(ref self: ContractState, mode: u8, proof_version: u32) {
            assert_admin(@self);
            let mut verifier = self.verifiers.read((mode, proof_version));
            verifier.revoked = true;
            self.verifiers.write((mode, proof_version), verifier);
            self.emit(VerifierRevoked { mode, proof_version });
        }

        fn is_policy_root_valid(self: @ContractState, root_high: u128, root_low: u128) -> bool {
            root_is_valid(
                self.policy_roots.read((root_high, root_low)),
                get_block_info().unbox().block_timestamp,
            )
        }

        fn is_fx_root_valid(self: @ContractState, root_high: u128, root_low: u128) -> bool {
            root_is_valid(
                self.fx_roots.read((root_high, root_low)),
                get_block_info().unbox().block_timestamp,
            )
        }

        fn is_verifier_valid(self: @ContractState, mode: u8, proof_version: u32) -> bool {
            verifier_is_valid(
                self.verifiers.read((mode, proof_version)),
                get_block_info().unbox().block_timestamp,
            )
        }

        fn get_verifier(
            self: @ContractState, mode: u8, proof_version: u32,
        ) -> ContractAddress {
            let verifier = self.verifiers.read((mode, proof_version));
            let verifier_address = verifier.verifier;
            assert(
                verifier_is_valid(verifier, get_block_info().unbox().block_timestamp),
                errors::VERIFIER_INACTIVE,
            );
            verifier_address
        }

        fn get_fx_publisher(self: @ContractState) -> ContractAddress {
            self.fx_publisher.read()
        }

        fn transfer_admin(ref self: ContractState, new_admin: ContractAddress) {
            assert_admin(@self);
            assert(!new_admin.is_zero(), errors::ZERO_ADDRESS);
            let previous_admin = self.admin.read();
            self.admin.write(new_admin);
            self.emit(AdminTransferred { previous_admin, new_admin });
        }

        fn get_admin(self: @ContractState) -> ContractAddress {
            self.admin.read()
        }
    }
}
