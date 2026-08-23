use core::byte_array::ByteArrayTrait;
use core::integer::u128_byte_reverse;
use core::keccak::compute_keccak_byte_array;

pub const PAYO_MERKLE_LEAF_COUNT: usize = 64;
pub const PAYO_MAX_REAL_LINES: usize = 50;

fn canonical_keccak(message: @ByteArray) -> u256 {
    // Cairo's ByteArray helper returns a little-endian u256. PAYO hashes cross language
    // boundaries as the conventional big-endian hexadecimal digest.
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

fn append_field_u32(ref output: ByteArray, value: u32) {
    append_u32_be(ref output, 4);
    append_u32_be(ref output, value);
}

fn append_field_u256(ref output: ByteArray, value: u256) {
    append_u32_be(ref output, 32);
    append_u256_be(ref output, value);
}

fn append_field_u128_as_u256(ref output: ByteArray, value: u128) {
    append_u32_be(ref output, 32);
    append_u128_be(ref output, 0);
    append_u128_be(ref output, value);
}

pub fn hash_text_commitment(domain: @ByteArray, value: @ByteArray) -> u256 {
    let mut message = domain.clone();
    append_u32_be(ref message, value.len().try_into().unwrap());
    message.append(value);
    canonical_keccak(@message)
}

pub fn hash_recipient_commitment(address: u256, salt: u256) -> u256 {
    let mut message: ByteArray = "PAYO_RECIPIENT_V1";
    append_field_u256(ref message, address);
    append_field_u256(ref message, salt);
    canonical_keccak(@message)
}

pub fn hash_deductions_commitment(values: Span<u128>) -> u256 {
    assert(values.len() <= 8, 'PAYO_DEDUCTIONS_MAX');
    let mut message: ByteArray = "PAYO_DEDUCTIONS_V1";
    append_field_u32(ref message, values.len().try_into().unwrap());
    for value in values {
        append_field_u128_as_u256(ref message, *value);
    }
    canonical_keccak(@message)
}

pub fn hash_payroll_leaf_v1(
    schema_version: u32,
    agreement_commitment: u256,
    recipient_commitment: u256,
    gross_atomic: u128,
    deductions_commitment: u256,
    net_atomic: u128,
    token_address: u256,
    policy_commitment: u256,
    schedule_commitment: u256,
    salt: u256,
) -> u256 {
    let mut message: ByteArray = "PAYO_LEAF_V1";
    append_field_u32(ref message, schema_version);
    append_field_u256(ref message, agreement_commitment);
    append_field_u256(ref message, recipient_commitment);
    append_field_u128_as_u256(ref message, gross_atomic);
    append_field_u256(ref message, deductions_commitment);
    append_field_u128_as_u256(ref message, net_atomic);
    append_field_u256(ref message, token_address);
    append_field_u256(ref message, policy_commitment);
    append_field_u256(ref message, schedule_commitment);
    append_field_u256(ref message, salt);
    canonical_keccak(@message)
}

pub fn empty_payroll_leaf_v1() -> u256 {
    let domain: ByteArray = "PAYO_EMPTY_LEAF_V1";
    canonical_keccak(@domain)
}

pub fn hash_merkle_node_v1(left: u256, right: u256) -> u256 {
    let mut message: ByteArray = "PAYO_MERKLE_NODE_V1";
    append_field_u256(ref message, left);
    append_field_u256(ref message, right);
    canonical_keccak(@message)
}

pub fn derive_run_nullifier_v1(
    organization_secret: u256, cycle_id: @ByteArray, revision: u32,
) -> u256 {
    let mut message: ByteArray = "PAYO_RUN_V1";
    append_field_u256(ref message, organization_secret);
    append_u32_be(ref message, cycle_id.len().try_into().unwrap());
    message.append(cycle_id);
    append_field_u32(ref message, revision);
    canonical_keccak(@message)
}

pub fn build_fixed_merkle_root_v1(real_leaves: Span<u256>) -> u256 {
    assert(real_leaves.len() <= PAYO_MAX_REAL_LINES, 'PAYO_TOO_MANY_LEAVES');
    let empty = empty_payroll_leaf_v1();
    let mut leaves: Array<u256> = ArrayTrait::new();
    for index in 0..PAYO_MERKLE_LEAF_COUNT {
        leaves.append(if index < real_leaves.len() { *real_leaves.at(index) } else { empty });
    }

    let mut width = PAYO_MERKLE_LEAF_COUNT;
    loop {
        if width == 1 { break; }
        let mut next: Array<u256> = ArrayTrait::new();
        for index in 0..32_usize {
            if index < width / 2 {
                next.append(hash_merkle_node_v1(*leaves.at(index * 2), *leaves.at(index * 2 + 1)));
            }
        }
        leaves = next;
        width = width / 2;
    };
    *leaves.at(0)
}
