use starknet::ContractAddress;

#[derive(Drop, Serde, starknet::Store)]
pub struct PolicyRootState {
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
        valid_after: u64,
        expires_at: u64,
    );
    fn revoke_policy_root(ref self: TContractState, root_high: u128, root_low: u128);
    fn is_policy_root_valid(self: @TContractState, root_high: u128, root_low: u128) -> bool;
    fn transfer_admin(ref self: TContractState, new_admin: ContractAddress);
    fn get_admin(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PayoPolicyRegistry {
    use core::num::traits::Zero;
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, get_block_info, get_caller_address};
    use super::PolicyRootState;

    mod errors {
        pub const NOT_ADMIN: felt252 = 'PAYO_NOT_ADMIN';
        pub const BAD_WINDOW: felt252 = 'PAYO_BAD_WINDOW';
        pub const DELAY_REQUIRED: felt252 = 'PAYO_DELAY_REQUIRED';
        pub const ZERO_ADDRESS: felt252 = 'PAYO_ZERO_ADDRESS';
    }

    const MIN_POLICY_DELAY: u64 = 86400;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        policy_roots: Map<(u128, u128), PolicyRootState>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        PolicyRootScheduled: PolicyRootScheduled,
        PolicyRootRevoked: PolicyRootRevoked,
        AdminTransferred: AdminTransferred,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PolicyRootScheduled {
        #[key]
        pub root_high: u128,
        #[key]
        pub root_low: u128,
        pub valid_after: u64,
        pub expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PolicyRootRevoked {
        #[key]
        pub root_high: u128,
        #[key]
        pub root_low: u128,
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
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), errors::NOT_ADMIN);
    }

    #[abi(embed_v0)]
    impl RegistryImpl of super::IPayoPolicyRegistry<ContractState> {
        fn schedule_policy_root(
            ref self: ContractState,
            root_high: u128,
            root_low: u128,
            valid_after: u64,
            expires_at: u64,
        ) {
            assert_admin(@self);
            let now = get_block_info().unbox().block_timestamp;
            assert(valid_after >= now + MIN_POLICY_DELAY, errors::DELAY_REQUIRED);
            assert(expires_at > valid_after, errors::BAD_WINDOW);
            self.policy_roots.write(
                (root_high, root_low), PolicyRootState { valid_after, expires_at, revoked: false },
            );
            self.emit(PolicyRootScheduled { root_high, root_low, valid_after, expires_at });
        }

        fn revoke_policy_root(ref self: ContractState, root_high: u128, root_low: u128) {
            assert_admin(@self);
            let mut policy = self.policy_roots.read((root_high, root_low));
            policy.revoked = true;
            self.policy_roots.write((root_high, root_low), policy);
            self.emit(PolicyRootRevoked { root_high, root_low });
        }

        fn is_policy_root_valid(self: @ContractState, root_high: u128, root_low: u128) -> bool {
            let policy = self.policy_roots.read((root_high, root_low));
            let now = get_block_info().unbox().block_timestamp;
            !policy.revoked && policy.valid_after <= now && now <= policy.expires_at
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
