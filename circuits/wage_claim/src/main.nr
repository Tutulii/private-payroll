use dep::keccak256::keccak256;

global MAX_LINES: u32 = 64;
global MAX_REAL_LINES: u32 = 50;
global MAX_COMPONENTS: u32 = 8;
global MAX_FINAL_COMPONENTS: u32 = 5;
global MAX_VALIDITY_WINDOW_SECONDS: u64 = 3600;
global PACKED_AMOUNT_LIMIT: u128 = 1329227995784915872903807060280344576;
global PACKED_AMOUNT_BASE: Field = 1329227995784915872903807060280344576;
global TWO_POW_64: Field = 18446744073709551616;
global PROOF_DOMAIN_MERKLE_NODE: Field = 2;
global PROOF_DOMAIN_AGREEMENT: Field = 3;
global PROOF_DOMAIN_PAYROLL_LINE: Field = 4;
global PROOF_EMPTY_LEAF: Field = 0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373;
global ZERO_BYTES: [u8; 32] = [0; 32];

struct AgreementWitness {
    enabled: bool,
    id_commitment: [u8; 32],
    recipient_commitment: [u8; 32],
    earnings: [u128; MAX_COMPONENTS],
    earnings_count: u32,
    token: u8,
    policy_commitment: [u8; 32],
    schedule_commitment: [u8; 32],
    due_at: u64,
    valid_until: u64,
    classification_declared: u8,
    classification_score: u16,
    classification_employee_threshold: u16,
    final_pay_mode: bool,
    final_required_mask: u8,
    final_components: [u128; MAX_FINAL_COMPONENTS],
    fx_floor_atomic: u128,
    reference_currency: u8,
    salt: [u8; 32],
}

struct PayrollLine {
    active: bool,
    deductions: [u128; MAX_COMPONENTS],
    deductions_count: u32,
    policy_slot: u8,
    fx_slot: u8,
    salt: [u8; 32],
    classification_treatment: u8,
    final_included_mask: u8,
    reference_value_atomic: u128,
}

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

fn pack_amount_pair(left: u128, right: u128) -> Field {
    assert(left < PACKED_AMOUNT_LIMIT, "amount exceeds proof packing limit");
    assert(right < PACKED_AMOUNT_LIMIT, "amount exceeds proof packing limit");
    left as Field + (right as Field) * PACKED_AMOUNT_BASE
}

fn pack_agreement_metadata(agreement: AgreementWitness) -> Field {
    let mut metadata = agreement.earnings_count as Field;
    metadata += (agreement.token as Field) * 16;
    metadata += (agreement.classification_declared as Field) * 32;
    metadata += (agreement.classification_score as Field) * 128;
    metadata += (agreement.classification_employee_threshold as Field) * 8388608;
    metadata += (if agreement.final_pay_mode { 1 } else { 0 }) * 549755813888;
    metadata += (agreement.final_required_mask as Field) * 1099511627776;
    metadata += (agreement.reference_currency as Field) * 35184372088832;
    agreement.fx_floor_atomic as Field + metadata * PACKED_AMOUNT_BASE
}

fn pack_line_metadata(line: PayrollLine) -> Field {
    let mut metadata = line.deductions_count as Field;
    metadata += (line.classification_treatment as Field) * 16;
    metadata += (line.final_included_mask as Field) * 64;
    line.reference_value_atomic as Field + metadata * PACKED_AMOUNT_BASE
}

fn proof_hash_agreement_terms(agreement: AgreementWitness) -> Field {
    let id = bytes_as_fields(agreement.id_commitment);
    let recipient = bytes_as_fields(agreement.recipient_commitment);
    let policy = bytes_as_fields(agreement.policy_commitment);
    let schedule = bytes_as_fields(agreement.schedule_commitment);
    let salt = bytes_as_fields(agreement.salt);
    let mut fields: [Field; 19] = [0; 19];
    fields[0] = id[0]; fields[1] = id[1]; fields[2] = recipient[0]; fields[3] = recipient[1];
    for pair in 0..4 { fields[4 + pair] = pack_amount_pair(agreement.earnings[pair * 2], agreement.earnings[pair * 2 + 1]); }
    fields[8] = policy[0]; fields[9] = policy[1]; fields[10] = schedule[0]; fields[11] = schedule[1];
    fields[12] = agreement.due_at as Field + (agreement.valid_until as Field) * TWO_POW_64;
    fields[13] = pack_amount_pair(agreement.final_components[0], agreement.final_components[1]);
    fields[14] = pack_amount_pair(agreement.final_components[2], agreement.final_components[3]);
    fields[15] = pack_amount_pair(agreement.final_components[4], 0);
    fields[16] = pack_agreement_metadata(agreement); fields[17] = salt[0]; fields[18] = salt[1];
    proof_hash(PROOF_DOMAIN_AGREEMENT, fields)
}

fn proof_hash_payroll_line(line: PayrollLine, agreement_commitment: Field) -> Field {
    let salt = bytes_as_fields(line.salt);
    let mut fields: [Field; 8] = [0; 8];
    fields[0] = agreement_commitment;
    for pair in 0..4 { fields[1 + pair] = pack_amount_pair(line.deductions[pair * 2], line.deductions[pair * 2 + 1]); }
    fields[5] = pack_line_metadata(line); fields[6] = salt[0]; fields[7] = salt[1];
    proof_hash(PROOF_DOMAIN_PAYROLL_LINE, fields)
}

fn proof_merkle_node(left: Field, right: Field) -> Field { proof_hash(PROOF_DOMAIN_MERKLE_NODE, [left, right]) }

fn proof_merkle_root(mut leaves: [Field; MAX_LINES]) -> Field {
    let mut width = MAX_LINES;
    for _level in 0..6 {
        for index in 0..32 {
            if index < width / 2 { leaves[index] = proof_merkle_node(leaves[index * 2], leaves[index * 2 + 1]); }
        }
        width = width / 2;
    }
    leaves[0]
}

fn gross(agreement: AgreementWitness) -> u128 {
    assert(agreement.enabled, "claim agreement is disabled");
    assert(agreement.earnings_count > 0, "claim agreement has no earnings");
    assert(agreement.earnings_count <= MAX_COMPONENTS, "claim agreement has too many earnings");
    let mut total: u128 = 0;
    for index in 0..MAX_COMPONENTS {
        if index < agreement.earnings_count { total += agreement.earnings[index]; }
        else { assert(agreement.earnings[index] == 0, "unused earning is nonzero"); }
    }
    total
}

fn missing_component_shortfall(agreement: AgreementWitness, included: u8) -> u128 {
    let mut shortfall: u128 = 0;
    for index in 0..MAX_FINAL_COMPONENTS {
        let divisor: u32 = 1 << index as u32;
        let required = (agreement.final_required_mask as u32 / divisor) % 2 == 1;
        let provided = (included as u32 / divisor) % 2 == 1;
        if required & (!provided) { shortfall += agreement.final_components[index]; }
    }
    shortfall
}

fn validate_claim(
    claim_kind: u8,
    agreement: AgreementWitness,
    line: PayrollLine,
    agreement_leaf: Field,
    payroll_leaf: Field,
    validity_start: u64,
) -> u128 {
    assert(claim_kind <= 2, "unknown wage claim kind");
    assert(agreement.due_at <= validity_start, "claimed obligation is not due");
    assert(validity_start <= agreement.valid_until, "claimed obligation is expired");
    let expected_agreement_leaf = proof_hash_agreement_terms(agreement);
    assert(expected_agreement_leaf == agreement_leaf, "claim agreement preimage mismatch");
    let agreement_gross = gross(agreement);
    if claim_kind == 0 {
        assert(payroll_leaf == PROOF_EMPTY_LEAF, "claimed obligation is present");
        agreement_gross
    } else {
        assert(line.active, "claim payroll line is inactive");
        assert(line.salt != ZERO_BYTES, "claim payroll salt is zero");
        assert(proof_hash_payroll_line(line, agreement_leaf) == payroll_leaf, "claim payroll preimage mismatch");
        if claim_kind == 1 {
            assert(agreement.fx_floor_atomic > 0, "claim FX floor is zero");
            assert(line.reference_value_atomic < agreement.fx_floor_atomic, "payroll met the committed floor");
            agreement.fx_floor_atomic - line.reference_value_atomic
        } else {
            assert(agreement.final_pay_mode, "claim is not final pay");
            let shortfall = missing_component_shortfall(agreement, line.final_included_mask);
            assert(shortfall > 0, "all required final components are present");
            shortfall
        }
    }
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
    original_run_nullifier: [u8; 32],
    claim_kind: u8,
    claim_salt: [u8; 32],
    target_index: u8,
    agreement_leaves: [Field; MAX_LINES],
    payroll_leaves: [Field; MAX_LINES],
    agreement: AgreementWitness,
    line: PayrollLine,
) {
    assert(chain_id != 0, "chain id is required");
    assert(seal_address != 0, "seal address is required");
    assert(proof_version == 3, "unsupported claim proof version");
    assert(schema_version == 1, "unsupported schema version");
    assert(shard_index <= 1, "invalid claim shard");
    assert(validity_expiry >= validity_start, "invalid claim window");
    assert(validity_expiry - validity_start <= MAX_VALIDITY_WINDOW_SECONDS, "claim window is too long");
    assert((policy_root_high != 0) | (policy_root_low != 0), "policy root is zero");
    assert((fx_root_high != 0) | (fx_root_low != 0), "FX root is zero");
    assert(original_run_nullifier != ZERO_BYTES, "original run nullifier is zero");
    assert(claim_salt != ZERO_BYTES, "claim salt is zero");
    assert((target_index as u32) < MAX_REAL_LINES, "claim target is out of range");
    for index in MAX_REAL_LINES..MAX_LINES {
        assert(agreement_leaves[index] == PROOF_EMPTY_LEAF, "agreement padding is not empty");
        assert(payroll_leaves[index] == PROOF_EMPTY_LEAF, "payroll padding is not empty");
    }
    let agreement_root = proof_merkle_root(agreement_leaves);
    let manifest_root = proof_merkle_root(payroll_leaves);
    assert_field_root_limbs(agreement_root, agreement_root_high, agreement_root_low);
    assert_field_root_limbs(manifest_root, manifest_root_high, manifest_root_low);
    let agreement_leaf = agreement_leaves[target_index as u32];
    let payroll_leaf = payroll_leaves[target_index as u32];
    let shortfall = validate_claim(claim_kind, agreement, line, agreement_leaf, payroll_leaf, validity_start);
    let nullifier = derive_claim_nullifier(
        original_run_nullifier, manifest_root, agreement_leaf, claim_kind, shortfall, claim_salt,
    );
    assert_root_limbs(nullifier, claim_nullifier_high, claim_nullifier_low);
}

fn base_agreement() -> AgreementWitness {
    AgreementWitness {
        enabled: true,
        id_commitment: [1; 32], recipient_commitment: [2; 32],
        earnings: [100, 0, 0, 0, 0, 0, 0, 0], earnings_count: 1, token: 1,
        policy_commitment: [3; 32], schedule_commitment: [4; 32], due_at: 100, valid_until: 200,
        classification_declared: 2, classification_score: 2, classification_employee_threshold: 5,
        final_pay_mode: false, final_required_mask: 0, final_components: [0; 5],
        fx_floor_atomic: 0, reference_currency: 0, salt: [5; 32],
    }
}

fn base_line() -> PayrollLine {
    PayrollLine {
        active: true, deductions: [0; 8], deductions_count: 0, policy_slot: 0, fx_slot: 0,
        salt: [6; 32], classification_treatment: 2, final_included_mask: 0, reference_value_atomic: 100,
    }
}

#[test]
fn claim_nullifier_matches_typescript_golden_vector() {
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

#[test]
fn proves_missing_due_obligation_shortfall() {
    let agreement = base_agreement();
    let agreement_leaf = proof_hash_agreement_terms(agreement);
    let shortfall = validate_claim(0, agreement, base_line(), agreement_leaf, PROOF_EMPTY_LEAF, 100);
    assert(shortfall == 100, "missing claim shortfall mismatch");
}

#[test]
fn proves_below_committed_floor_shortfall() {
    let mut agreement = base_agreement();
    agreement.fx_floor_atomic = 120;
    let agreement_leaf = proof_hash_agreement_terms(agreement);
    let line = base_line();
    let payroll_leaf = proof_hash_payroll_line(line, agreement_leaf);
    let shortfall = validate_claim(1, agreement, line, agreement_leaf, payroll_leaf, 100);
    assert(shortfall == 20, "floor claim shortfall mismatch");
}

#[test(should_fail_with = "payroll met the committed floor")]
fn rejects_satisfied_fx_floor_claim() {
    let mut agreement = base_agreement();
    agreement.fx_floor_atomic = 100;
    let agreement_leaf = proof_hash_agreement_terms(agreement);
    let line = base_line();
    let _shortfall = validate_claim(
        1, agreement, line, agreement_leaf, proof_hash_payroll_line(line, agreement_leaf), 100,
    );
}

#[test]
fn proves_incomplete_final_pay_shortfall() {
    let mut agreement = base_agreement();
    agreement.final_pay_mode = true;
    agreement.final_required_mask = 3;
    agreement.final_components = [70, 30, 0, 0, 0];
    let agreement_leaf = proof_hash_agreement_terms(agreement);
    let mut line = base_line();
    line.final_included_mask = 1;
    let payroll_leaf = proof_hash_payroll_line(line, agreement_leaf);
    assert(validate_claim(2, agreement, line, agreement_leaf, payroll_leaf, 100) == 30, "final claim shortfall mismatch");
}
