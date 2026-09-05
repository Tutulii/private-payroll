use starknet::ContractAddress;

#[starknet::interface]
pub trait IGaragaVestingVerifier<TContractState> {
    fn verify_ultra_keccak_zk_honk_proof(
        self: @TContractState, full_proof_with_hints: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
}

#[starknet::interface]
pub trait IVestingBookV3BundleVerifier<TContractState> {
    fn verify_payroll_integrity_bundle(
        self: @TContractState, shard_0_proof: Span<felt252>, shard_1_proof: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
    fn verify_payroll_integrity_shard(
        self: @TContractState, shard_proof: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
    fn get_underlying_verifier(self: @TContractState) -> ContractAddress;
}

/// Stable PAYO adapter around the proof-bound Garaga verifier. The catalog
/// registers this contract—not the generated verifier—because seals consume
/// PAYO's `verify_payroll_integrity_shard` interface.
#[starknet::contract]
pub mod PayoVestingBookV3BundleVerifier {
    use core::num::traits::Zero;
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use super::{IGaragaVestingVerifierDispatcher, IGaragaVestingVerifierDispatcherTrait};

    mod errors {
        pub const ZERO_ADDRESS: felt252 = 'PAYO_ZERO_ADDRESS';
        pub const BAD_INPUTS: felt252 = 'PAYO_VEST_INPUTS';
    }

    #[storage]
    struct Storage {
        underlying_verifier: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, underlying_verifier: ContractAddress) {
        assert(!underlying_verifier.is_zero(), errors::ZERO_ADDRESS);
        self.underlying_verifier.write(underlying_verifier);
    }

    fn verify_one(self: @ContractState, proof: Span<felt252>) -> Result<Span<u256>, felt252> {
        let verifier = IGaragaVestingVerifierDispatcher {
            contract_address: self.underlying_verifier.read(),
        };
        let inputs = match verifier.verify_ultra_keccak_zk_honk_proof(proof) {
            Result::Ok(inputs) => inputs,
            Result::Err(error) => { return Result::Err(error); },
        };
        if inputs.len() != 58
            || *inputs.at(2) != 3
            || *inputs.at(3) != 1
            || *inputs.at(4) > 4
            || *inputs.at(57) > 1 {
            return Result::Err(errors::BAD_INPUTS);
        }
        Result::Ok(inputs)
    }

    #[abi(embed_v0)]
    impl VestingBookV3BundleVerifierImpl of super::IVestingBookV3BundleVerifier<ContractState> {
        fn verify_payroll_integrity_bundle(
            self: @ContractState, shard_0_proof: Span<felt252>, shard_1_proof: Span<felt252>,
        ) -> Result<Span<u256>, felt252> {
            let shard_0 = match verify_one(self, shard_0_proof) {
                Result::Ok(inputs) => inputs,
                Result::Err(error) => { return Result::Err(error); },
            };
            let shard_1 = match verify_one(self, shard_1_proof) {
                Result::Ok(inputs) => inputs,
                Result::Err(error) => { return Result::Err(error); },
            };
            if *shard_0.at(57) != 0 || *shard_1.at(57) != 1 {
                return Result::Err(errors::BAD_INPUTS);
            }
            for index in 0..57_usize {
                if *shard_0.at(index) != *shard_1.at(index) {
                    return Result::Err(errors::BAD_INPUTS);
                }
            }
            let mut combined = array![];
            for input in shard_0 {
                combined.append(*input);
            }
            for input in shard_1 {
                combined.append(*input);
            }
            Result::Ok(combined.span())
        }

        fn verify_payroll_integrity_shard(
            self: @ContractState, shard_proof: Span<felt252>,
        ) -> Result<Span<u256>, felt252> {
            verify_one(self, shard_proof)
        }

        fn get_underlying_verifier(self: @ContractState) -> ContractAddress {
            self.underlying_verifier.read()
        }
    }
}
