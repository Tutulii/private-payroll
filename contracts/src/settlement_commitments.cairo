use core::byte_array::ByteArrayTrait;
use core::integer::u128_byte_reverse;
use core::keccak::compute_keccak_byte_array;
use starknet::ContractAddress;

pub const PAYO_SETTLEMENT_LEAF_COUNT: usize = 64;

#[derive(Copy, Drop, Serde, PartialEq, Debug)]
pub struct SettlementNote {
    pub note_id: felt252,
    pub packed_value: felt252,
}

fn canonical_keccak(message: @ByteArray) -> u256 {
    // Cairo's ByteArray helper returns a little-endian u256. PAYO exposes the
    // conventional big-endian digest used by Noir and TypeScript.
    let digest = compute_keccak_byte_array(message);
    u256 { high: u128_byte_reverse(digest.low), low: u128_byte_reverse(digest.high) }
}

fn append_u32_be(ref output: ByteArray, value: u32) {
    output.append_word(value.into(), 4);
}

fn append_u128_be(ref output: ByteArray, value: u128) {
    output.append_word(value.into(), 16);
}

fn append_u256_be(ref output: ByteArray, value: u256) {
    append_u128_be(ref output, value.high);
    append_u128_be(ref output, value.low);
}

fn append_felt_be(ref output: ByteArray, value: felt252) {
    append_u256_be(ref output, value.into());
}

pub fn settlement_empty_leaf_v1() -> u256 {
    let domain: ByteArray = "PAYO_SETTLEMENT_EMPTY_V1";
    canonical_keccak(@domain)
}

pub fn hash_settlement_note_leaf_v1(
    position: u32, note_id: felt252, packed_value: felt252,
) -> u256 {
    let mut message: ByteArray = "PAYO_SETTLEMENT_NOTE_V1";
    append_u32_be(ref message, position);
    append_felt_be(ref message, note_id);
    append_felt_be(ref message, packed_value);
    canonical_keccak(@message)
}

pub fn hash_settlement_node_v1(left: u256, right: u256) -> u256 {
    let mut message: ByteArray = "PAYO_SETTLEMENT_NODE_V1";
    append_u256_be(ref message, left);
    append_u256_be(ref message, right);
    canonical_keccak(@message)
}

/// Commits every encrypted note emitted by the exact STRK20 action list.
/// Positions are part of each leaf, so reordering changes the root.
pub fn build_settlement_root_v1(notes: Span<SettlementNote>) -> u256 {
    assert(!notes.is_empty(), 'PAYO_SETTLEMENT_EMPTY');
    assert(notes.len() <= PAYO_SETTLEMENT_LEAF_COUNT, 'PAYO_SETTLEMENT_MAX');

    let empty = settlement_empty_leaf_v1();
    let mut leaves: Array<u256> = ArrayTrait::new();
    for position in 0..PAYO_SETTLEMENT_LEAF_COUNT {
        leaves.append(
            if position < notes.len() {
                let note = *notes.at(position);
                hash_settlement_note_leaf_v1(
                    position.try_into().unwrap(), note.note_id, note.packed_value,
                )
            } else {
                empty
            },
        );
    }

    let mut width = PAYO_SETTLEMENT_LEAF_COUNT;
    loop {
        if width == 1 {
            break;
        }
        let mut next: Array<u256> = ArrayTrait::new();
        for position in 0..32_usize {
            if position < width / 2 {
                next.append(
                    hash_settlement_node_v1(
                        *leaves.at(position * 2), *leaves.at(position * 2 + 1),
                    ),
                );
            }
        }
        leaves = next;
        width /= 2;
    };
    *leaves.at(0)
}

/// Deterministic reference to the exact pool call authorized by the policy
/// account. This is intentionally not a transaction hash: the hash is not
/// available from inside the executing account.
pub fn settlement_transaction_reference_v1(
    chain_id: felt252,
    policy_account: ContractAddress,
    pool: ContractAddress,
    pool_calldata: Span<felt252>,
) -> u256 {
    assert(!pool_calldata.is_empty(), 'PAYO_SETTLEMENT_CALL');
    assert(pool_calldata.len() <= 12_000, 'PAYO_SETTLEMENT_CALL');
    let mut message: ByteArray = "PAYO_SETTLEMENT_TX_V1";
    append_felt_be(ref message, chain_id);
    append_felt_be(ref message, policy_account.into());
    append_felt_be(ref message, pool.into());
    append_u32_be(ref message, pool_calldata.len().try_into().unwrap());
    for value in pool_calldata {
        append_felt_be(ref message, *value);
    }
    canonical_keccak(@message)
}
