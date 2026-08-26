use starknet::ContractAddress;

#[starknet::interface]
pub trait IGaragaAdvancedVerifier<TContractState> {
    fn verify_ultra_keccak_zk_honk_proof(
        self: @TContractState, full_proof_with_hints: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
}

#[starknet::interface]
pub trait IAdvancedBundleVerifier<TContractState> {
    fn verify_payroll_integrity_bundle(
        self: @TContractState, shard_0_proof: Span<felt252>, shard_1_proof: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
    fn verify_payroll_integrity_shard(
        self: @TContractState, shard_proof: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
    fn get_base_verifier(self: @TContractState) -> ContractAddress;
    fn get_advanced_verifier(self: @TContractState) -> ContractAddress;
}

/// Verifies PayrollIntegrity v1 and AdvancedObligation v2 against the same
/// private agreement/manifest trees. Each packed shard is encoded as
/// `[base_calldata_len, base_calldata..., advanced_calldata...]`.
#[starknet::contract]
pub mod PayoAdvancedBundleVerifier {
    use core::num::traits::Zero;
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use super::{IGaragaAdvancedVerifierDispatcher, IGaragaAdvancedVerifierDispatcherTrait};

    mod errors {
        pub const ZERO_ADDRESS: felt252 = 'PAYO_ZERO_ADDRESS';
        pub const BAD_PACKING: felt252 = 'PAYO_ADV_PACKING';
        pub const BAD_INPUTS: felt252 = 'PAYO_ADV_INPUTS';
    }

    #[storage]
    struct Storage {
        base_verifier: ContractAddress,
        advanced_verifier: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, base_verifier: ContractAddress, advanced_verifier: ContractAddress,
    ) {
        assert(!base_verifier.is_zero(), errors::ZERO_ADDRESS);
        assert(!advanced_verifier.is_zero(), errors::ZERO_ADDRESS);
        assert(base_verifier != advanced_verifier, errors::BAD_INPUTS);
        self.base_verifier.write(base_verifier);
        self.advanced_verifier.write(advanced_verifier);
    }

    fn verify_linked_shard(
        self: @ContractState, packed: Span<felt252>,
    ) -> Result<Span<u256>, felt252> {
        if packed.len() < 3 {
            return Result::Err(errors::BAD_PACKING);
        }
        let base_length: usize = match (*packed.at(0)).try_into() {
            Option::Some(value) => value,
            Option::None => { return Result::Err(errors::BAD_PACKING); },
        };
        if base_length == 0 || base_length + 1 >= packed.len() {
            return Result::Err(errors::BAD_PACKING);
        }
        let base_proof = packed.slice(1, base_length);
        let advanced_proof = packed.slice(base_length + 1, packed.len() - base_length - 1);
        let base = IGaragaAdvancedVerifierDispatcher {
            contract_address: self.base_verifier.read(),
        };
        let advanced = IGaragaAdvancedVerifierDispatcher {
            contract_address: self.advanced_verifier.read(),
        };
        let base_inputs = match base.verify_ultra_keccak_zk_honk_proof(base_proof) {
            Result::Ok(inputs) => inputs,
            Result::Err(error) => { return Result::Err(error); },
        };
        let advanced_inputs = match advanced.verify_ultra_keccak_zk_honk_proof(advanced_proof) {
            Result::Ok(inputs) => inputs,
            Result::Err(error) => { return Result::Err(error); },
        };
        if base_inputs.len() != 17 || advanced_inputs.len() != 17 {
            return Result::Err(errors::BAD_INPUTS);
        }
        if *base_inputs.at(2) != 1 || *advanced_inputs.at(2) != 2 {
            return Result::Err(errors::BAD_INPUTS);
        }
        for index in 0..17_usize {
            if index != 2 && *base_inputs.at(index) != *advanced_inputs.at(index) {
                return Result::Err(errors::BAD_INPUTS);
            }
        }
        Result::Ok(advanced_inputs)
    }

    #[abi(embed_v0)]
    impl AdvancedBundleVerifierImpl of super::IAdvancedBundleVerifier<ContractState> {
        fn verify_payroll_integrity_bundle(
            self: @ContractState, shard_0_proof: Span<felt252>, shard_1_proof: Span<felt252>,
        ) -> Result<Span<u256>, felt252> {
            let shard_0_inputs = match verify_linked_shard(self, shard_0_proof) {
                Result::Ok(inputs) => inputs,
                Result::Err(error) => { return Result::Err(error); },
            };
            let shard_1_inputs = match verify_linked_shard(self, shard_1_proof) {
                Result::Ok(inputs) => inputs,
                Result::Err(error) => { return Result::Err(error); },
            };
            let mut combined = array![];
            for input in shard_0_inputs {
                combined.append(*input);
            }
            for input in shard_1_inputs {
                combined.append(*input);
            }
            Result::Ok(combined.span())
        }

        fn verify_payroll_integrity_shard(
            self: @ContractState, shard_proof: Span<felt252>,
        ) -> Result<Span<u256>, felt252> {
            verify_linked_shard(self, shard_proof)
        }

        fn get_base_verifier(self: @ContractState) -> ContractAddress {
            self.base_verifier.read()
        }

        fn get_advanced_verifier(self: @ContractState) -> ContractAddress {
            self.advanced_verifier.read()
        }
    }
}
