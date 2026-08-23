use starknet::ContractAddress;

// Must remain positionally compatible with privacy::objects::OpenNoteDeposit.
#[derive(Serde, Copy, Drop, PartialEq, Debug)]
pub struct OpenNoteDeposit {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u128,
}

#[starknet::interface]
pub trait IIntegrityVerifier<TContractState> {
    fn verify_ultra_keccak_zk_honk_proof(
        self: @TContractState, full_proof_with_hints: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
}

#[starknet::interface]
pub trait IPayoPayrollSeal<TContractState> {
    /// Called only by the configured STRK20 pool through its INVOKE action.
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
        proof_calldata: Span<felt252>,
    ) -> Span<OpenNoteDeposit>;

    fn get_run_status(
        self: @TContractState, run_nullifier_high: u128, run_nullifier_low: u128,
    ) -> u8;
    fn get_pool(self: @TContractState) -> ContractAddress;
    fn get_verifier(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PayoPayrollSeal {
    use core::num::traits::Zero;
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, get_block_info, get_caller_address, get_contract_address};
    use super::{IIntegrityVerifierDispatcher, IIntegrityVerifierDispatcherTrait, OpenNoteDeposit};

    mod errors {
        pub const BAD_POOL: felt252 = 'PAYO_BAD_POOL';
        pub const BAD_MODE: felt252 = 'PAYO_BAD_MODE';
        pub const BAD_VERSION: felt252 = 'PAYO_BAD_VERSION';
        pub const BAD_WINDOW: felt252 = 'PAYO_BAD_WINDOW';
        pub const REPLAY: felt252 = 'PAYO_REPLAY';
        pub const PROOF_FAILED: felt252 = 'PAYO_PROOF_FAILED';
        pub const PUBLIC_INPUTS: felt252 = 'PAYO_PUBLIC_INPUTS';
        pub const ZERO_ADDRESS: felt252 = 'PAYO_ZERO_ADDRESS';
    }

    const MODE_PRECOMMIT: u8 = 0;
    const STATUS_PROVEN: u8 = 1;

    #[storage]
    struct Storage {
        pool: ContractAddress,
        verifier: ContractAddress,
        chain_id: felt252,
        run_status: Map<(u128, u128), u8>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        PayrollProven: PayrollProven,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PayrollProven {
        #[key]
        pub run_nullifier_high: u128,
        #[key]
        pub run_nullifier_low: u128,
        pub manifest_root_high: u128,
        pub manifest_root_low: u128,
        pub proof_version: u32,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        pool: ContractAddress,
        verifier: ContractAddress,
        chain_id: felt252,
    ) {
        assert(!pool.is_zero(), errors::ZERO_ADDRESS);
        assert(!verifier.is_zero(), errors::ZERO_ADDRESS);
        assert(chain_id != 0, errors::ZERO_ADDRESS);
        self.pool.write(pool);
        self.verifier.write(verifier);
        self.chain_id.write(chain_id);
    }

    fn assert_public_input(inputs: Span<u256>, index: usize, expected: u256) {
        assert(inputs.len() > index, errors::PUBLIC_INPUTS);
        assert(*inputs.at(index) == expected, errors::PUBLIC_INPUTS);
    }

    fn as_u256<T, +Into<T, u256>>(value: T) -> u256 {
        value.into()
    }

    #[abi(embed_v0)]
    impl PayrollSealImpl of super::IPayoPayrollSeal<ContractState> {
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
            proof_calldata: Span<felt252>,
        ) -> Span<OpenNoteDeposit> {
            assert(get_caller_address() == self.pool.read(), errors::BAD_POOL);
            assert(mode == MODE_PRECOMMIT, errors::BAD_MODE);
            assert(proof_version == 1, errors::BAD_VERSION);
            assert(schema_version == 1, errors::BAD_VERSION);
            let now = get_block_info().unbox().block_timestamp;
            assert(validity_start <= now && now <= validity_expiry, errors::BAD_WINDOW);

            let nullifier = (run_nullifier_high, run_nullifier_low);
            assert(self.run_status.read(nullifier) == 0, errors::REPLAY);

            let verifier = IIntegrityVerifierDispatcher { contract_address: self.verifier.read() };
            let public_inputs = verifier
                .verify_ultra_keccak_zk_honk_proof(proof_calldata)
                .expect(errors::PROOF_FAILED);
            assert(public_inputs.len() == 16, errors::PUBLIC_INPUTS);

            // Public input order is fixed by circuits/payroll_integrity/src/main.nr.
            let seal_address: felt252 = get_contract_address().into();
            assert_public_input(public_inputs, 0, as_u256(self.chain_id.read()));
            assert_public_input(public_inputs, 1, as_u256(seal_address));
            assert_public_input(public_inputs, 2, as_u256(proof_version));
            assert_public_input(public_inputs, 3, as_u256(schema_version));
            assert_public_input(public_inputs, 4, as_u256(agreement_root_high));
            assert_public_input(public_inputs, 5, as_u256(agreement_root_low));
            assert_public_input(public_inputs, 6, as_u256(manifest_root_high));
            assert_public_input(public_inputs, 7, as_u256(manifest_root_low));
            assert_public_input(public_inputs, 8, as_u256(policy_root_high));
            assert_public_input(public_inputs, 9, as_u256(policy_root_low));
            assert_public_input(public_inputs, 10, as_u256(fx_root_high));
            assert_public_input(public_inputs, 11, as_u256(fx_root_low));
            assert_public_input(public_inputs, 12, as_u256(run_nullifier_high));
            assert_public_input(public_inputs, 13, as_u256(run_nullifier_low));
            assert_public_input(public_inputs, 14, as_u256(validity_start));
            assert_public_input(public_inputs, 15, as_u256(validity_expiry));

            self.run_status.write(nullifier, STATUS_PROVEN);
            self.emit(PayrollProven {
                run_nullifier_high,
                run_nullifier_low,
                manifest_root_high,
                manifest_root_low,
                proof_version,
            });

            // The seal never receives or custodies payroll tokens.
            array![].span()
        }

        fn get_run_status(
            self: @ContractState, run_nullifier_high: u128, run_nullifier_low: u128,
        ) -> u8 {
            self.run_status.read((run_nullifier_high, run_nullifier_low))
        }

        fn get_pool(self: @ContractState) -> ContractAddress {
            self.pool.read()
        }

        fn get_verifier(self: @ContractState) -> ContractAddress {
            self.verifier.read()
        }
    }
}
