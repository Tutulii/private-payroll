use starknet::ContractAddress;

#[starknet::interface]
pub trait IGaragaIntegrityVerifier<TContractState> {
    fn verify_ultra_keccak_zk_honk_proof(
        self: @TContractState, full_proof_with_hints: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
}

#[starknet::interface]
pub trait IIntegrityBundleVerifier<TContractState> {
    /// Verifies both linked payroll shards against one deployment-bound Garaga verifier and
    /// returns shard 0's 17 public inputs followed by shard 1's 17 public inputs.
    fn verify_payroll_integrity_bundle(
        self: @TContractState, shard_0_proof: Span<felt252>, shard_1_proof: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;

    fn get_underlying_verifier(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PayoIntegrityBundleVerifier {
    use core::num::traits::Zero;
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use super::{IGaragaIntegrityVerifierDispatcher, IGaragaIntegrityVerifierDispatcherTrait};

    mod errors {
        pub const ZERO_ADDRESS: felt252 = 'PAYO_ZERO_ADDRESS';
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

    #[abi(embed_v0)]
    impl IntegrityBundleVerifierImpl of super::IIntegrityBundleVerifier<ContractState> {
        fn verify_payroll_integrity_bundle(
            self: @ContractState, shard_0_proof: Span<felt252>, shard_1_proof: Span<felt252>,
        ) -> Result<Span<u256>, felt252> {
            let verifier = IGaragaIntegrityVerifierDispatcher {
                contract_address: self.underlying_verifier.read(),
            };
            let shard_0_inputs = match verifier.verify_ultra_keccak_zk_honk_proof(shard_0_proof) {
                Result::Ok(inputs) => inputs,
                Result::Err(error) => { return Result::Err(error); },
            };
            let shard_1_inputs = match verifier.verify_ultra_keccak_zk_honk_proof(shard_1_proof) {
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

        fn get_underlying_verifier(self: @ContractState) -> ContractAddress {
            self.underlying_verifier.read()
        }
    }
}
