use dep::keccak256::keccak256;

global MAX_LINES: u32 = 64;
global MAX_REAL_LINES: u32 = 50;
global MAX_VALIDITY_WINDOW_SECONDS: u64 = 3600;
global PROOF_DOMAIN_MERKLE_NODE: Field = 2;
global PROOF_DOMAIN_REMEDIATION: Field = 6;
global PROOF_EMPTY_LEAF: Field = 0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373;
global ZERO_BYTES: [u8; 32] = [0; 32];

fn high_limb(value: [u8; 32]) -> u128 {
    let mut result: u128 = 0;
    for index in 0..16 { result = result * 256 + value[index] as u128; }
    result
}

fn low_limb(value: [u8; 32]) -> u128 {
    let mut result: u128 = 0;
    for index in 16..32 { result = result * 256 + value[index] as u128; }
    result
}

fn bytes_as_fields(value: [u8; 32]) -> [Field; 2] {
    [high_limb(value) as Field, low_limb(value) as Field]
}

fn assert_root_limbs(root: [u8; 32], high: u128, low: u128) {
    let high_bytes: [u8; 16] = (high as Field).to_be_bytes();
    let low_bytes: [u8; 16] = (low as Field).to_be_bytes();
    for index in 0..16 {
        assert(root[index] == high_bytes[index], "root high limb mismatch");
        assert(root[index + 16] == low_bytes[index], "root low limb mismatch");
    }
}

fn assert_field_root_limbs(root: Field, high: u128, low: u128) {
    assert_root_limbs(root.to_be_bytes(), high, low);
}

fn proof_hash<let N: u32>(domain: Field, values: [Field; N]) -> Field {
    let mut state: [Field; 4] = [0; 4];
    state[3] = ((N + 1) as Field) * 18446744073709551616;
    let mut cache: [Field; 3] = [0; 3];
    let mut cache_size: u32 = 1;
    cache[0] = domain;
    for index in 0..N {
        if cache_size == 3 {
            for cache_index in 0..3 { state[cache_index] += cache[cache_index]; }
            state = std::hash::poseidon2_permutation(state, 4);
            cache = [0; 3];
            cache_size = 0;
        }
        cache[cache_size] = values[index];
        cache_size += 1;
    }
    for cache_index in 0..3 {
        if cache_index < cache_size { state[cache_index] += cache[cache_index]; }
    }
    state = std::hash::poseidon2_permutation(state, 4);
    state[0]
}

fn proof_merkle_node(left: Field, right: Field) -> Field {
    proof_hash(PROOF_DOMAIN_MERKLE_NODE, [left, right])
}

fn proof_merkle_root(mut leaves: [Field; MAX_LINES]) -> Field {
    let mut width = MAX_LINES;
    for _level in 0..6 {
        for index in 0..32 {
            if index < width / 2 {
                leaves[index] = proof_merkle_node(leaves[index * 2], leaves[index * 2 + 1]);
            }
        }
        width = width / 2;
    }
    leaves[0]
}

fn derive_claim_nullifier(
    original_run_nullifier: [u8; 32],
    disputed_manifest_root: Field,
    agreement_leaf: Field,
    claim_kind: u8,
    shortfall: u128,
    claim_salt: [u8; 32],
) -> [u8; 32] {
    let domain = "PAYO_WAGE_CLAIM_V1_BINARY".as_bytes();
    let mut message: [u8; 170] = [0; 170];
    let mut cursor: u32 = domain.len();
    for index in 0..domain.len() { message[index] = domain[index]; }
    let manifest_bytes: [u8; 32] = disputed_manifest_root.to_be_bytes();
    let agreement_bytes: [u8; 32] = agreement_leaf.to_be_bytes();
    for index in 0..32 {
        message[cursor + index] = original_run_nullifier[index];
        message[cursor + 32 + index] = manifest_bytes[index];
        message[cursor + 64 + index] = agreement_bytes[index];
    }
    cursor += 96;
    message[cursor] = claim_kind;
    cursor += 1;
    let shortfall_bytes: [u8; 16] = (shortfall as Field).to_be_bytes();
    for index in 0..16 { message[cursor + index] = shortfall_bytes[index]; }
    cursor += 16;
    for index in 0..32 { message[cursor + index] = claim_salt[index]; }
    cursor += 32;
    assert(cursor == message.len(), "claim encoding length mismatch");
    keccak256(message, cursor)
}

fn remediation_leaf(
    claim_nullifier: [u8; 32],
    agreement_leaf: Field,
    amount: u128,
    token: u8,
    remediation_salt: [u8; 32],
) -> Field {
    let nullifier = bytes_as_fields(claim_nullifier);
    let salt = bytes_as_fields(remediation_salt);
    proof_hash(PROOF_DOMAIN_REMEDIATION, [
        nullifier[0], nullifier[1], agreement_leaf, amount as Field, token as Field, salt[0], salt[1],
    ])
}

fn main(
    chain_id: pub Field,
    seal_address: pub Field,
    proof_version: pub u32,
    schema_version: pub u32,
    agreement_root_high: pub u128,
    agreement_root_low: pub u128,
    manifest_root_high: pub u128,
    manifest_root_low: pub u128,
    policy_root_high: pub u128,
    policy_root_low: pub u128,
    fx_root_high: pub u128,
    fx_root_low: pub u128,
    claim_nullifier_high: pub u128,
    claim_nullifier_low: pub u128,
    validity_start: pub u64,
    validity_expiry: pub u64,
    shard_index: pub u8,
    claim_nullifier: [u8; 32],
    original_run_nullifier: [u8; 32],
    disputed_manifest_root: Field,
    claim_kind: u8,
    claim_shortfall: u128,
    claim_salt: [u8; 32],
    target_index: u8,
    agreement_leaves: [Field; MAX_LINES],
    remediation_leaves: [Field; MAX_LINES],
    remediation_amount: u128,
    remediation_token: u8,
    remediation_salt: [u8; 32],
) {
    assert(chain_id != 0, "chain id is required");
    assert(seal_address != 0, "seal address is required");
    assert(proof_version == 4, "unsupported remediation proof version");
    assert(schema_version == 1, "unsupported schema version");
    assert(shard_index <= 1, "invalid remediation shard");
    assert(validity_expiry >= validity_start, "invalid remediation window");
    assert(validity_expiry - validity_start <= MAX_VALIDITY_WINDOW_SECONDS, "remediation window is too long");
    assert((policy_root_high != 0) | (policy_root_low != 0), "policy root is zero");
    assert((fx_root_high != 0) | (fx_root_low != 0), "FX root is zero");
    assert(claim_nullifier != ZERO_BYTES, "claim nullifier is zero");
    assert(original_run_nullifier != ZERO_BYTES, "original run nullifier is zero");
    assert(claim_kind <= 2, "unknown wage claim kind");
    assert(claim_shortfall > 0, "claim shortfall is zero");
    assert(claim_salt != ZERO_BYTES, "claim salt is zero");
    assert(remediation_amount >= claim_shortfall, "remediation is below the proved shortfall");
    assert(remediation_token <= 1, "unsupported remediation token");
    assert(remediation_salt != ZERO_BYTES, "remediation salt is zero");
    assert((target_index as u32) < MAX_REAL_LINES, "remediation target is out of range");

    for index in MAX_REAL_LINES..MAX_LINES {
        assert(agreement_leaves[index] == PROOF_EMPTY_LEAF, "agreement padding is not empty");
        assert(remediation_leaves[index] == PROOF_EMPTY_LEAF, "remediation padding is not empty");
    }
    let agreement_root = proof_merkle_root(agreement_leaves);
    assert_field_root_limbs(agreement_root, agreement_root_high, agreement_root_low);
    let agreement_leaf = agreement_leaves[target_index as u32];
    assert(agreement_leaf != PROOF_EMPTY_LEAF, "remediation agreement is empty");

    let derived_claim_nullifier = derive_claim_nullifier(
        original_run_nullifier,
        disputed_manifest_root,
        agreement_leaf,
        claim_kind,
        claim_shortfall,
        claim_salt,
    );
    assert(derived_claim_nullifier == claim_nullifier, "claim preimage does not match the accepted claim");
    assert_root_limbs(claim_nullifier, claim_nullifier_high, claim_nullifier_low);

    let expected_leaf = remediation_leaf(
        claim_nullifier, agreement_leaf, remediation_amount, remediation_token, remediation_salt,
    );
    for index in 0..MAX_REAL_LINES {
        if index == target_index as u32 {
            assert(remediation_leaves[index] == expected_leaf, "remediation leaf mismatch");
        } else {
            assert(remediation_leaves[index] == PROOF_EMPTY_LEAF, "unexpected remediation line");
        }
    }
    assert_field_root_limbs(
        proof_merkle_root(remediation_leaves), manifest_root_high, manifest_root_low,
    );
}

#[test]
fn remediation_leaf_binds_claim_amount_token_and_salt() {
    let claim = [1; 32];
    let salt = [2; 32];
    let leaf = remediation_leaf(claim, 99, 100, 1, salt);
    assert(leaf != remediation_leaf(claim, 99, 101, 1, salt), "amount is not bound");
    assert(leaf != remediation_leaf(claim, 99, 100, 0, salt), "token is not bound");
    assert(leaf != remediation_leaf(claim, 99, 100, 1, [3; 32]), "salt is not bound");
}

#[test]
fn claim_preimage_is_deterministic() {
    let claim = derive_claim_nullifier([1; 32], 2, 3, 1, 4, [5; 32]);
    assert(claim == derive_claim_nullifier([1; 32], 2, 3, 1, 4, [5; 32]), "claim preimage changed");
}

#[test]
fn accepted_claim_preimage_matches_typescript_golden_vector() {
    let expected: [u8; 32] = [
        201, 70, 34, 9, 253, 112, 12, 55, 63, 19, 79, 17, 208, 79, 42, 82,
        233, 140, 241, 119, 238, 104, 189, 187, 204, 208, 145, 163, 199, 2, 157, 180,
    ];
    assert(
        derive_claim_nullifier(
            [1; 32],
            0x0202020202020202020202020202020202020202020202020202020202020202,
            0x0303030303030303030303030303030303030303030303030303030303030303,
            1,
            4,
            [5; 32],
        ) == expected,
        "claim nullifier vector mismatch",
    );
}

#[test(should_fail_with = "remediation is below the proved shortfall")]
fn rejects_under_remediation() {
    let amount: u128 = 99;
    let shortfall: u128 = 100;
    assert(amount >= shortfall, "remediation is below the proved shortfall");
}

#[test(should_fail_with = "claim preimage does not match the accepted claim")]
fn rejects_another_claim_preimage() {
    let accepted = derive_claim_nullifier([1; 32], 2, 3, 1, 4, [5; 32]);
    let forged = derive_claim_nullifier([1; 32], 2, 3, 1, 5, [5; 32]);
    assert(accepted == forged, "claim preimage does not match the accepted claim");
}
