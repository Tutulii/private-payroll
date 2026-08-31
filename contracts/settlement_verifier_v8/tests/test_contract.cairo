use settlement_verifier_v8::honk_verifier::{
    IUltraKeccakZKHonkVerifierDispatcherTrait, IUltraKeccakZKHonkVerifierLibraryDispatcher,
};
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{DeclareResultTrait, declare};

#[test]
fn real_settlement_match_v8_proof_verifies_and_exposes_bound_inputs() {
    let class_hash = *declare("PayoSettlementMatchV8Verifier")
        .unwrap()
        .contract_class()
        .class_hash;
    let verifier = IUltraKeccakZKHonkVerifierLibraryDispatcher { class_hash };
    let file = FileTrait::new("tests/proof_calldata.txt");
    let calldata = read_txt(@file);
    let result = verifier.verify_ultra_keccak_zk_honk_proof(calldata.span());
    assert(result.is_ok(), 'settlement proof failed');
    let public_inputs = result.unwrap();
    assert(public_inputs.len() == 11, 'wrong public input count');
    assert(*public_inputs.at(0) == u256 { low: 8, high: 0 }, 'wrong proof version');
    assert(
        *public_inputs.at(9) == u256 { low: 0, high: 0 },
        'wrong settlement chunk',
    );
    assert(
        *public_inputs.at(10) == u256 { low: 1, high: 0 },
        'wrong settlement count',
    );
}
