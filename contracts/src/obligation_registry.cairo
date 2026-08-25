use starknet::ContractAddress;

#[derive(Drop, Serde, starknet::Store)]
pub struct ObligationRootState {
    pub valid_after: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

#[starknet::interface]
pub trait IPayoObligationRootRegistry<TContractState> {
    fn schedule_obligation_root(
        ref self: TContractState,
        root_high: u128,
        root_low: u128,
        _valid_after: u64,
        expires_at: u64,
    );
    fn revoke_obligation_root(ref self: TContractState, root_high: u128, root_low: u128);
    fn is_obligation_root_valid(
        self: @TContractState, root_high: u128, root_low: u128,
    ) -> bool;
    fn transfer_admin(ref self: TContractState, new_admin: ContractAddress);
    fn get_admin(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PayoObligationRootRegistry {
    use core::num::traits::Zero;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_info, get_caller_address};
    use super::ObligationRootState;

    mod errors {
        pub const NOT_ADMIN: felt252 = 'PAYO_NOT_ADMIN';
        pub const BAD_WINDOW: felt252 = 'PAYO_BAD_WINDOW';
        pub const ZERO_ADDRESS: felt252 = 'PAYO_ZERO_ADDRESS';
    }

    #[storage]
    struct Storage {
        admin: ContractAddress,
        roots: Map<(u128, u128), ObligationRootState>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ObligationRootScheduled: ObligationRootScheduled,
        ObligationRootRevoked: ObligationRootRevoked,
        AdminTransferred: AdminTransferred,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ObligationRootScheduled {
        #[key]
        pub root_high: u128,
        #[key]
        pub root_low: u128,
        pub valid_after: u64,
        pub expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ObligationRootRevoked {
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
    impl RegistryImpl of super::IPayoObligationRootRegistry<ContractState> {
        fn schedule_obligation_root(
            ref self: ContractState,
            root_high: u128,
            root_low: u128,
            _valid_after: u64,
            expires_at: u64,
        ) {
            assert_admin(@self);
            let now = get_block_info().unbox().block_timestamp;
            assert(expires_at > now, errors::BAD_WINDOW);
            // Keep the legacy positional ABI but bind activation to the confirming block.
            let valid_after = now;
            self.roots.write(
                (root_high, root_low),
                ObligationRootState { valid_after, expires_at, revoked: false },
            );
            self.emit(
                ObligationRootScheduled { root_high, root_low, valid_after, expires_at },
            );
        }

        fn revoke_obligation_root(ref self: ContractState, root_high: u128, root_low: u128) {
            assert_admin(@self);
            let mut root = self.roots.read((root_high, root_low));
            root.revoked = true;
            self.roots.write((root_high, root_low), root);
            self.emit(ObligationRootRevoked { root_high, root_low });
        }

        fn is_obligation_root_valid(
            self: @ContractState, root_high: u128, root_low: u128,
        ) -> bool {
            let root = self.roots.read((root_high, root_low));
            let now = get_block_info().unbox().block_timestamp;
            !root.revoked && root.valid_after <= now && now <= root.expires_at
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
