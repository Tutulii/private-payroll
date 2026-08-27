use starknet::ContractAddress;

#[derive(Drop, Serde, starknet::Store)]
pub struct TenantObligationRootState {
    pub valid_after: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

/// Multi-tenant obligation authorization. The first account that schedules a
/// commitment becomes its owner; only that account may refresh or transfer it.
/// The protocol administrator is retained solely for emergency revocation and
/// cannot schedule a payroll root on behalf of an organization.
#[starknet::interface]
pub trait IPayoTenantObligationRootRegistry<TContractState> {
    fn schedule_obligation_root(
        ref self: TContractState,
        root_high: u128,
        root_low: u128,
        _valid_after: u64,
        expires_at: u64,
    );
    fn revoke_obligation_root(ref self: TContractState, root_high: u128, root_low: u128);
    fn transfer_obligation_root_owner(
        ref self: TContractState,
        root_high: u128,
        root_low: u128,
        new_owner: ContractAddress,
    );
    fn is_obligation_root_valid(
        self: @TContractState, root_high: u128, root_low: u128,
    ) -> bool;
    fn get_obligation_root_owner(
        self: @TContractState, root_high: u128, root_low: u128,
    ) -> ContractAddress;
    fn transfer_admin(ref self: TContractState, new_admin: ContractAddress);
    fn get_admin(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PayoTenantObligationRootRegistry {
    use core::num::traits::Zero;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_info, get_caller_address};
    use super::TenantObligationRootState;

    mod errors {
        pub const NOT_ADMIN: felt252 = 'PAYO_NOT_ADMIN';
        pub const NOT_ROOT_OWNER: felt252 = 'PAYO_NOT_ROOT_OWNER';
        pub const BAD_WINDOW: felt252 = 'PAYO_BAD_WINDOW';
        pub const ZERO_ADDRESS: felt252 = 'PAYO_ZERO_ADDRESS';
    }

    #[storage]
    struct Storage {
        admin: ContractAddress,
        roots: Map<(u128, u128), TenantObligationRootState>,
        root_owners: Map<(u128, u128), ContractAddress>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ObligationRootScheduled: ObligationRootScheduled,
        ObligationRootRevoked: ObligationRootRevoked,
        ObligationRootOwnerTransferred: ObligationRootOwnerTransferred,
        AdminTransferred: AdminTransferred,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ObligationRootScheduled {
        #[key]
        pub root_high: u128,
        #[key]
        pub root_low: u128,
        #[key]
        pub owner: ContractAddress,
        pub valid_after: u64,
        pub expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ObligationRootRevoked {
        #[key]
        pub root_high: u128,
        #[key]
        pub root_low: u128,
        #[key]
        pub owner: ContractAddress,
        pub revoked_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ObligationRootOwnerTransferred {
        #[key]
        pub root_high: u128,
        #[key]
        pub root_low: u128,
        pub previous_owner: ContractAddress,
        pub new_owner: ContractAddress,
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

    #[abi(embed_v0)]
    impl RegistryImpl of super::IPayoTenantObligationRootRegistry<ContractState> {
        fn schedule_obligation_root(
            ref self: ContractState,
            root_high: u128,
            root_low: u128,
            _valid_after: u64,
            expires_at: u64,
        ) {
            let caller = get_caller_address();
            assert(!caller.is_zero(), errors::ZERO_ADDRESS);
            let key = (root_high, root_low);
            let mut owner = self.root_owners.read(key);
            if owner.is_zero() {
                owner = caller;
                self.root_owners.write(key, caller);
            } else {
                assert(caller == owner, errors::NOT_ROOT_OWNER);
            }
            let now = get_block_info().unbox().block_timestamp;
            assert(expires_at > now, errors::BAD_WINDOW);
            self.roots.write(
                key,
                TenantObligationRootState { valid_after: now, expires_at, revoked: false },
            );
            self.emit(
                ObligationRootScheduled {
                    root_high, root_low, owner, valid_after: now, expires_at,
                },
            );
        }

        fn revoke_obligation_root(ref self: ContractState, root_high: u128, root_low: u128) {
            let key = (root_high, root_low);
            let owner = self.root_owners.read(key);
            assert(!owner.is_zero(), errors::NOT_ROOT_OWNER);
            let caller = get_caller_address();
            assert(caller == owner || caller == self.admin.read(), errors::NOT_ROOT_OWNER);
            let mut root = self.roots.read(key);
            root.revoked = true;
            self.roots.write(key, root);
            self.emit(
                ObligationRootRevoked {
                    root_high, root_low, owner, revoked_by: caller,
                },
            );
        }

        fn transfer_obligation_root_owner(
            ref self: ContractState,
            root_high: u128,
            root_low: u128,
            new_owner: ContractAddress,
        ) {
            assert(!new_owner.is_zero(), errors::ZERO_ADDRESS);
            let key = (root_high, root_low);
            let previous_owner = self.root_owners.read(key);
            assert(
                !previous_owner.is_zero() && get_caller_address() == previous_owner,
                errors::NOT_ROOT_OWNER,
            );
            self.root_owners.write(key, new_owner);
            self.emit(
                ObligationRootOwnerTransferred {
                    root_high, root_low, previous_owner, new_owner,
                },
            );
        }

        fn is_obligation_root_valid(
            self: @ContractState, root_high: u128, root_low: u128,
        ) -> bool {
            let root = self.roots.read((root_high, root_low));
            let now = get_block_info().unbox().block_timestamp;
            !root.revoked && root.valid_after <= now && now <= root.expires_at
        }

        fn get_obligation_root_owner(
            self: @ContractState, root_high: u128, root_low: u128,
        ) -> ContractAddress {
            self.root_owners.read((root_high, root_low))
        }

        fn transfer_admin(ref self: ContractState, new_admin: ContractAddress) {
            assert(get_caller_address() == self.admin.read(), errors::NOT_ADMIN);
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
