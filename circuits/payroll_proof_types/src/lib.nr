pub global MAX_LINES: u32 = 64;
pub global MAX_REAL_LINES: u32 = 50;
pub global MAX_COMPONENTS: u32 = 8;
pub global MAX_FINAL_COMPONENTS: u32 = 5;
pub global PACKED_AMOUNT_LIMIT: u128 = 1329227995784915872903807060280344576;
pub global PACKED_AMOUNT_BASE: Field = 1329227995784915872903807060280344576;
pub global TWO_POW_64: Field = 18446744073709551616;
pub global PROOF_DOMAIN_MERKLE_NODE: Field = 2;
pub global PROOF_DOMAIN_AGREEMENT: Field = 3;
pub global PROOF_DOMAIN_PAYROLL_LINE: Field = 4;
pub global PROOF_DOMAIN_CLAIM_OBLIGATION: Field = 8;
pub global PROOF_DOMAIN_REMEDIATION_ACTION: Field = 9;
pub global PROOF_DOMAIN_EXTERNAL_ATTESTATION: Field = 10;
pub global PROOF_EMPTY_LEAF: Field = 0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373;
pub global ZERO_BYTES: [u8; 32] = [0; 32];

pub struct AgreementWitness {
    pub enabled: bool,
    pub id_commitment: [u8; 32],
    pub recipient_commitment: [u8; 32],
    pub earnings: [u128; MAX_COMPONENTS],
    pub earnings_count: u32,
    pub token: u8,
    pub policy_commitment: [u8; 32],
    pub schedule_commitment: [u8; 32],
    pub due_at: u64,
    pub valid_until: u64,
    pub classification_declared: u8,
    pub classification_score: u16,
    pub classification_employee_threshold: u16,
    pub final_pay_mode: bool,
    pub final_required_mask: u8,
    pub final_components: [u128; MAX_FINAL_COMPONENTS],
    pub fx_floor_atomic: u128,
    pub reference_currency: u8,
    pub salt: [u8; 32],
}

pub struct PayrollLine {
    pub active: bool,
    pub deductions: [u128; MAX_COMPONENTS],
    pub deductions_count: u32,
    pub policy_slot: u8,
    pub fx_slot: u8,
    pub salt: [u8; 32],
    pub classification_treatment: u8,
    pub final_included_mask: u8,
    pub reference_value_atomic: u128,
}

pub fn high_limb(value: [u8; 32]) -> u128 {
    let mut result: u128 = 0;
    for index in 0..16 { result = result * 256 + value[index] as u128; }
    result
}

pub fn low_limb(value: [u8; 32]) -> u128 {
    let mut result: u128 = 0;
    for index in 16..32 { result = result * 256 + value[index] as u128; }
    result
}

pub fn bytes_as_fields(value: [u8; 32]) -> [Field; 2] {
    [high_limb(value) as Field, low_limb(value) as Field]
}

pub fn assert_root_limbs(root: [u8; 32], high: u128, low: u128) {
    let high_bytes: [u8; 16] = (high as Field).to_be_bytes();
    let low_bytes: [u8; 16] = (low as Field).to_be_bytes();
    for index in 0..16 {
        assert(root[index] == high_bytes[index], "root high limb mismatch");
        assert(root[index + 16] == low_bytes[index], "root low limb mismatch");
    }
}

pub fn assert_field_root_limbs(root: Field, high: u128, low: u128) {
    assert_root_limbs(root.to_be_bytes(), high, low);
}

pub fn proof_hash<let N: u32>(domain: Field, values: [Field; N]) -> Field {
    let mut state: [Field; 4] = [0; 4];
    state[3] = ((N + 1) as Field) * TWO_POW_64;
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

pub fn proof_merkle_node(left: Field, right: Field) -> Field {
    proof_hash(PROOF_DOMAIN_MERKLE_NODE, [left, right])
}

pub fn proof_merkle_root(mut leaves: [Field; MAX_LINES]) -> Field {
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

pub fn proof_merkle_membership(
    leaf: Field,
    siblings: [Field; 6],
    path_bits: [bool; 6],
) -> Field {
    let mut current = leaf;
    for level in 0..6 {
        current = if path_bits[level] {
            proof_merkle_node(siblings[level], current)
        } else {
            proof_merkle_node(current, siblings[level])
        };
    }
    current
}

pub fn assert_membership_index(path_bits: [bool; 6], target_index: u8) {
    assert((target_index as u32) < MAX_REAL_LINES, "target index is out of range");
    let mut reconstructed: u32 = 0;
    let mut power: u32 = 1;
    for level in 0..6 {
        if path_bits[level] { reconstructed += power; }
        power *= 2;
    }
    assert(reconstructed == target_index as u32, "membership path selects another slot");
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
    assert(agreement.fx_floor_atomic < PACKED_AMOUNT_LIMIT, "amount exceeds proof packing limit");
    agreement.fx_floor_atomic as Field + metadata * PACKED_AMOUNT_BASE
}

fn pack_line_metadata(line: PayrollLine) -> Field {
    let mut metadata = line.deductions_count as Field;
    metadata += (line.classification_treatment as Field) * 16;
    metadata += (line.final_included_mask as Field) * 64;
    assert(line.reference_value_atomic < PACKED_AMOUNT_LIMIT, "amount exceeds proof packing limit");
    line.reference_value_atomic as Field + metadata * PACKED_AMOUNT_BASE
}

pub fn proof_hash_agreement_terms(agreement: AgreementWitness) -> Field {
    let id = bytes_as_fields(agreement.id_commitment);
    let recipient = bytes_as_fields(agreement.recipient_commitment);
    let policy = bytes_as_fields(agreement.policy_commitment);
    let schedule = bytes_as_fields(agreement.schedule_commitment);
    let salt = bytes_as_fields(agreement.salt);
    proof_hash(PROOF_DOMAIN_AGREEMENT, [
        id[0], id[1], recipient[0], recipient[1],
        pack_amount_pair(agreement.earnings[0], agreement.earnings[1]),
        pack_amount_pair(agreement.earnings[2], agreement.earnings[3]),
        pack_amount_pair(agreement.earnings[4], agreement.earnings[5]),
        pack_amount_pair(agreement.earnings[6], agreement.earnings[7]),
        policy[0], policy[1], schedule[0], schedule[1],
        agreement.due_at as Field + (agreement.valid_until as Field) * TWO_POW_64,
        pack_amount_pair(agreement.final_components[0], agreement.final_components[1]),
        pack_amount_pair(agreement.final_components[2], agreement.final_components[3]),
        pack_amount_pair(agreement.final_components[4], 0),
        pack_agreement_metadata(agreement), salt[0], salt[1],
    ])
}

pub fn proof_hash_payroll_line(line: PayrollLine, agreement_leaf: Field) -> Field {
    let salt = bytes_as_fields(line.salt);
    proof_hash(PROOF_DOMAIN_PAYROLL_LINE, [
        agreement_leaf,
        pack_amount_pair(line.deductions[0], line.deductions[1]),
        pack_amount_pair(line.deductions[2], line.deductions[3]),
        pack_amount_pair(line.deductions[4], line.deductions[5]),
        pack_amount_pair(line.deductions[6], line.deductions[7]),
        pack_line_metadata(line),
        salt[0], salt[1],
    ])
}

pub fn proof_claim_obligation_leaf(
    agreement_leaf: Field,
    claim_capability_commitment: [u8; 32],
    expected_net_atomic: u128,
) -> Field {
    assert(expected_net_atomic > 0, "claim minimum net is zero");
    assert(expected_net_atomic < PACKED_AMOUNT_LIMIT, "amount exceeds proof packing limit");
    let capability = bytes_as_fields(claim_capability_commitment);
    proof_hash(PROOF_DOMAIN_CLAIM_OBLIGATION, [
        agreement_leaf, capability[0], capability[1], expected_net_atomic as Field,
    ])
}

pub fn proof_remediation_action(
    claim_subject_nullifier: [u8; 32],
    recipient_commitment: [u8; 32],
    token: u8,
    amount_atomic: u128,
    salt: [u8; 32],
) -> Field {
    assert(token <= 1, "unsupported remediation token");
    assert(amount_atomic > 0, "remediation amount is zero");
    assert(amount_atomic < PACKED_AMOUNT_LIMIT, "amount exceeds proof packing limit");
    assert(salt != ZERO_BYTES, "remediation action salt is zero");
    let claim = bytes_as_fields(claim_subject_nullifier);
    let recipient = bytes_as_fields(recipient_commitment);
    let action_salt = bytes_as_fields(salt);
    proof_hash(PROOF_DOMAIN_REMEDIATION_ACTION, [
        claim[0], claim[1], recipient[0], recipient[1], token as Field,
        amount_atomic as Field, action_salt[0], action_salt[1],
    ])
}

pub fn proof_external_attestation_leaf(commitment: [u8; 32]) -> Field {
    let limbs = bytes_as_fields(commitment);
    proof_hash(PROOF_DOMAIN_EXTERNAL_ATTESTATION, [limbs[0], limbs[1]])
}

pub fn gross(agreement: AgreementWitness) -> u128 {
    assert(agreement.earnings_count > 0, "agreement has no earnings");
    assert(agreement.earnings_count <= MAX_COMPONENTS, "too many earnings");
    let mut total: u128 = 0;
    for index in 0..MAX_COMPONENTS {
        if index < agreement.earnings_count {
            assert(agreement.earnings[index] > 0, "active earning is zero");
            total += agreement.earnings[index];
        } else {
            assert(agreement.earnings[index] == 0, "unused earning is nonzero");
        }
    }
    total
}

pub fn empty_agreement() -> AgreementWitness {
    AgreementWitness {
        enabled: false,
        id_commitment: ZERO_BYTES,
        recipient_commitment: ZERO_BYTES,
        earnings: [0; MAX_COMPONENTS],
        earnings_count: 0,
        token: 0,
        policy_commitment: ZERO_BYTES,
        schedule_commitment: ZERO_BYTES,
        due_at: 0,
        valid_until: 0,
        classification_declared: 0,
        classification_score: 0,
        classification_employee_threshold: 0,
        final_pay_mode: false,
        final_required_mask: 0,
        final_components: [0; MAX_FINAL_COMPONENTS],
        fx_floor_atomic: 0,
        reference_currency: 0,
        salt: ZERO_BYTES,
    }
}

pub fn empty_line() -> PayrollLine {
    PayrollLine {
        active: false,
        deductions: [0; MAX_COMPONENTS],
        deductions_count: 0,
        policy_slot: 0,
        fx_slot: 0,
        salt: ZERO_BYTES,
        classification_treatment: 0,
        final_included_mask: 0,
        reference_value_atomic: 0,
    }
}
