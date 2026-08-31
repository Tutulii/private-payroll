use payo_contracts::settlement_commitments::{
    SettlementNote, build_settlement_root_v1, hash_settlement_note_leaf_v1,
    settlement_empty_leaf_v1, settlement_transaction_reference_v1,
};

fn address(value: felt252) -> starknet::ContractAddress {
    value.try_into().unwrap()
}

#[test]
fn settlement_commitments_match_typescript_keccak_vectors() {
    assert(
        settlement_empty_leaf_v1()
            == 0x277b107dfd3579a341a8cdbff6eadc0520c57d0504499a17b290e1981ad18ea6,
        'empty leaf vector',
    );
    assert(
        hash_settlement_note_leaf_v1(0, 1, 2)
            == 0xb70f9edcb391b2f320ffe8e56a36115171da2d5d6697632967c3abccb7e6af2a,
        'note leaf vector',
    );

    let notes = array![
        SettlementNote { note_id: 1, packed_value: 2 },
        SettlementNote { note_id: 3, packed_value: 4 },
    ];
    assert(
        build_settlement_root_v1(notes.span())
            == 0x83d5ea2f5c550292de32fc619c8b5eb6b58c1f566734da572b7d0ad86f8d0114,
        'settlement root vector',
    );
    let calldata = array![5, 6, 7];
    assert(
        settlement_transaction_reference_v1(
            'SN_MAIN', address(0x123), address(0x456), calldata.span(),
        ) == 0xdbc7ed10ebcc2d87c3ab4e2addd9fc11cb0dd911d3b079270883952f381f7764,
        'transaction ref vector',
    );
}

#[test]
fn settlement_root_binds_note_order_and_ciphertext() {
    let original = array![
        SettlementNote { note_id: 1, packed_value: 2 },
        SettlementNote { note_id: 3, packed_value: 4 },
    ];
    let reordered = array![
        SettlementNote { note_id: 3, packed_value: 4 },
        SettlementNote { note_id: 1, packed_value: 2 },
    ];
    let changed = array![
        SettlementNote { note_id: 1, packed_value: 2 },
        SettlementNote { note_id: 3, packed_value: 5 },
    ];
    let root = build_settlement_root_v1(original.span());
    assert(root != build_settlement_root_v1(reordered.span()), 'order unbound');
    assert(root != build_settlement_root_v1(changed.span()), 'cipher unbound');
}

#[test]
#[should_panic(expected: 'PAYO_SETTLEMENT_EMPTY')]
fn empty_settlement_is_rejected() {
    build_settlement_root_v1(array![].span());
}
