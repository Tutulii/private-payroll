#[starknet::interface]
pub trait IPayoVestingDevnetPublicInputHarness<TContractState> {
    fn verify_payroll_integrity_shard(
        self: @TContractState, proof: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
}

/// Test-only Devnet harness. It lets the standalone lifecycle exercise PAYO's
/// production registries and state/book seal without generating deployment-
/// specific proofs on the phone. Real v3 proof verification is covered by the
/// separate vesting_integration package and must pass in the same gate.
#[starknet::contract]
pub mod PayoVestingDevnetPublicInputHarness {
    mod errors {
        pub const BAD_INPUTS: felt252 = 'PAYO_DEVNET_INPUTS';
    }

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl Harness of super::IPayoVestingDevnetPublicInputHarness<ContractState> {
        fn verify_payroll_integrity_shard(
            self: @ContractState, proof: Span<felt252>,
        ) -> Result<Span<u256>, felt252> {
            if proof.len() != 17 && proof.len() != 58 {
                return Result::Err(errors::BAD_INPUTS);
            }
            let mut inputs = array![];
            for value in proof {
                inputs.append((*value).into());
            }
            Result::Ok(inputs.span())
        }
    }
}
