use dep::keccak256::keccak256;

global MAX_LINES: u32 = 64;
global MAX_REAL_LINES: u32 = 50;
global SHARD_LINES: u32 = 25;
global SHARD_AGREEMENTS: u32 = 26;
global MAX_COMPONENTS: u32 = 8;
global MAX_FINAL_COMPONENTS: u32 = 5;
global MAX_POLICY_STEPS: u32 = 16;
global MAX_POLICIES: u32 = 4;
global MAX_FX_SNAPSHOTS: u32 = 2;
global CATALOG_DEPTH: u32 = 6;
global BPS_DENOMINATOR: u128 = 10000;
global MAX_VALIDITY_WINDOW_SECONDS: u64 = 3600;
global PACKED_AMOUNT_LIMIT: u128 = 1329227995784915872903807060280344576;
global PACKED_AMOUNT_BASE: Field = 1329227995784915872903807060280344576;
global TWO_POW_64: Field = 18446744073709551616;

global EMPTY_LEAF: [u8; 32] = [
    124, 184, 142, 24, 181, 228, 45, 54, 9, 124, 167, 114, 226, 92, 164, 141, 83, 79, 196, 30, 45,
    120, 210, 146, 253, 205, 86, 6, 89, 140, 59, 219,
];

global ZERO_BYTES: [u8; 32] = [0; 32];

// Circuit-internal commitments use the BN254 Poseidon2 permutation. Keeping the
// fixed tree SNARK-native is what makes a 64-leaf proof viable in a browser;
// externally disclosed identity/text commitments remain canonical Keccak values.
global PROOF_DOMAIN_EMPTY: Field = 1;
global PROOF_DOMAIN_MERKLE_NODE: Field = 2;
global PROOF_DOMAIN_AGREEMENT: Field = 3;
global PROOF_DOMAIN_PAYROLL_LINE: Field = 4;
global PROOF_DOMAIN_CATALOG_LEAF: Field = 5;
global PROOF_DOMAIN_ADVANCED_PLAN: Field = 7;
global PROOF_EMPTY_LEAF: Field = 0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373;

global STRK_ADDRESS: [u8; 32] = [
    4, 113, 143, 90, 15, 195, 76, 193, 175, 22, 161, 205, 238, 152, 255, 178, 12, 49, 245, 205, 97,
    214, 171, 7, 32, 24, 88, 244, 40, 124, 147, 141,
];

global USDC_ADDRESS: [u8; 32] = [
    3, 48, 104, 246, 83, 159, 142, 110, 107, 19, 30, 107, 43, 129, 78, 108, 52, 165, 34, 75, 198,
    105, 71, 196, 125, 171, 157, 254, 233, 59, 53, 251,
];

struct MerkleMembership {
    siblings: [Field; CATALOG_DEPTH],
    path_bits: [bool; CATALOG_DEPTH],
}

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

// Opcodes: 0 NOP, 1 CONST, 2 INPUT_GROSS, 3 INPUT_EARNING,
// 4 ADD, 5 SUB, 6 MUL_DIV, 7 MIN, 8 MAX.
// BRACKET instructions are deterministically compiled into these primitives.
struct PolicyProgram {
    metadata_commitment: [u8; 32],
    instruction_count: u32,
    opcodes: [u8; MAX_POLICY_STEPS],
    left: [u8; MAX_POLICY_STEPS],
    right: [u8; MAX_POLICY_STEPS],
    immediate: [u128; MAX_POLICY_STEPS],
    numerator: [u64; MAX_POLICY_STEPS],
    denominator: [u64; MAX_POLICY_STEPS],
    output_register: u8,
}

struct PolicySlot {
    enabled: bool,
    program: PolicyProgram,
    membership: MerkleMembership,
}

struct FxSnapshot {
    token: u8,
    token_decimals: u8,
    reference_currency: u8,
    quote_decimals: u8,
    feed_commitment: [u8; 32],
    sources_commitment: [u8; 32],
    price_numerator: u128,
    price_denominator: u128,
    observed_at: u64,
    source_count: u8,
    minimum_source_count: u8,
    maximum_age_seconds: u64,
    haircut_bps: u16,
}

struct FxSlot {
    enabled: bool,
    snapshot: FxSnapshot,
    membership: MerkleMembership,
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

struct AdvancedPlanWitness {
    enabled: bool,
    kind: u8,
    cadence: u8,
    flags: u8,
    occurrence: u32,
    release_sequence: u32,
    checkpoint_sequence: u32,
    minimum_checkpoint_seconds: u32,
    timestamps: [u64; 12],
    amounts: [u128; 10],
    required_mask: u8,
    included_mask: u8,
    commitments: [[u8; 32]; 6],
    salt: [u8; 32],
}

fn sum_components(values: [u128; MAX_COMPONENTS], count: u32) -> u128 {
    assert(count <= MAX_COMPONENTS, "too many pay components");
    let mut total: u128 = 0;
    for index in 0..MAX_COMPONENTS {
        if index < count {
            total += values[index];
        } else {
            assert(values[index] == 0, "unused component must be zero");
        }
    }
    total
}

fn sum_final_components(values: [u128; MAX_FINAL_COMPONENTS]) -> u128 {
    let mut total: u128 = 0;
    for index in 0..MAX_FINAL_COMPONENTS {
        total += values[index];
    }
    total
}

fn hash_deductions(values: [u128; MAX_COMPONENTS], count: u32) -> [u8; 32] {
    let domain = "PAYO_DEDUCTIONS_V1".as_bytes();
    let mut message: [u8; 314] = [0; 314];
    for index in 0..domain.len() {
        message[index] = domain[index];
    }
    message[18] = 0;
    message[19] = 0;
    message[20] = 0;
    message[21] = 4;
    let count_bytes: [u8; 4] = (count as Field).to_be_bytes();
    for index in 0..4 {
        message[22 + index] = count_bytes[index];
    }
    for component in 0..MAX_COMPONENTS {
        let offset = 26 + component * 36;
        message[offset + 3] = 32;
        let amount: [u8; 16] = (values[component] as Field).to_be_bytes();
        for index in 0..16 {
            message[offset + 20 + index] = amount[index];
        }
    }
    keccak256(message, 26 + count * 36)
}

fn hash_merkle_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let domain = "PAYO_MERKLE_NODE_V1".as_bytes();
    let mut message: [u8; 91] = [0; 91];
    for index in 0..domain.len() {
        message[index] = domain[index];
    }
    message[22] = 32;
    message[58] = 32;
    for index in 0..32 {
        message[23 + index] = left[index];
        message[59 + index] = right[index];
    }
    keccak256(message, message.len())
}

fn merkle_root(mut leaves: [[u8; 32]; MAX_LINES]) -> [u8; 32] {
    let mut width = MAX_LINES;
    for _level in 0..6 {
        for index in 0..32 {
            if index < width / 2 {
                leaves[index] = hash_merkle_node(leaves[index * 2], leaves[index * 2 + 1]);
            }
        }
        width = width / 2;
    }
    leaves[0]
}

fn bytes_less_than(left: [u8; 32], right: [u8; 32]) -> bool {
    let mut decided = false;
    let mut less = false;
    for index in 0..32 {
        if !decided {
            if left[index] < right[index] {
                less = true;
                decided = true;
            } else if left[index] > right[index] {
                decided = true;
            }
        }
    }
    decided & less
}

fn assert_root_limbs(root: [u8; 32], expected_high: u128, expected_low: u128) {
    let high: [u8; 16] = (expected_high as Field).to_be_bytes();
    let low: [u8; 16] = (expected_low as Field).to_be_bytes();
    for index in 0..16 {
        assert(root[index] == high[index], "root high limb mismatch");
        assert(root[index + 16] == low[index], "root low limb mismatch");
    }
}

fn assert_field_root_limbs(root: Field, expected_high: u128, expected_low: u128) {
    let root_bytes: [u8; 32] = root.to_be_bytes();
    assert_root_limbs(root_bytes, expected_high, expected_low);
}

fn high_limb(value: [u8; 32]) -> u128 {
    let mut result: u128 = 0;
    for index in 0..16 {
        result = result * 256 + value[index] as u128;
    }
    result
}

fn low_limb(value: [u8; 32]) -> u128 {
    let mut result: u128 = 0;
    for index in 16..32 {
        result = result * 256 + value[index] as u128;
    }
    result
}

// Matches Barretenberg's Poseidon2::hash fixed-length sponge: the IV is
// input_length << 64, the rate is three, and the domain is the first input.
fn proof_hash<let N: u32>(domain: Field, values: [Field; N]) -> Field {
    let mut state: [Field; 4] = [0; 4];
    state[3] = ((N + 1) as Field) * 18446744073709551616;
    let mut cache: [Field; 3] = [0; 3];
    let mut cache_size: u32 = 1;
    cache[0] = domain;
    for index in 0..N {
        if cache_size == 3 {
            for cache_index in 0..3 {
                state[cache_index] += cache[cache_index];
            }
            state = std::hash::poseidon2_permutation(state, 4);
            cache = [0; 3];
            cache_size = 0;
        }
        cache[cache_size] = values[index];
        cache_size += 1;
    }
    for cache_index in 0..3 {
        if cache_index < cache_size {
            state[cache_index] += cache[cache_index];
        }
    }
    state = std::hash::poseidon2_permutation(state, 4);
    state[0]
}

fn bytes_as_fields(value: [u8; 32]) -> [Field; 2] {
    [high_limb(value) as Field, low_limb(value) as Field]
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

fn proof_catalog_leaf(commitment: [u8; 32]) -> Field {
    let limbs = bytes_as_fields(commitment);
    proof_hash(PROOF_DOMAIN_CATALOG_LEAF, limbs)
}

fn proof_root_from_membership(commitment: [u8; 32], membership: MerkleMembership) -> Field {
    let mut current = proof_catalog_leaf(commitment);
    for level in 0..CATALOG_DEPTH {
        current = if membership.path_bits[level] {
            proof_merkle_node(membership.siblings[level], current)
        } else {
            proof_merkle_node(current, membership.siblings[level])
        };
    }
    current
}

fn proof_hash_agreement_terms(agreement: AgreementWitness) -> Field {
    let id = bytes_as_fields(agreement.id_commitment);
    let recipient = bytes_as_fields(agreement.recipient_commitment);
    let policy = bytes_as_fields(agreement.policy_commitment);
    let schedule = bytes_as_fields(agreement.schedule_commitment);
    let salt = bytes_as_fields(agreement.salt);
    let mut fields: [Field; 19] = [0; 19];
    fields[0] = id[0];
    fields[1] = id[1];
    fields[2] = recipient[0];
    fields[3] = recipient[1];
    for pair in 0..4 {
        fields[4 + pair] = pack_amount_pair(
            agreement.earnings[pair * 2],
            agreement.earnings[pair * 2 + 1],
        );
    }
    fields[8] = policy[0];
    fields[9] = policy[1];
    fields[10] = schedule[0];
    fields[11] = schedule[1];
    fields[12] = agreement.due_at as Field + (agreement.valid_until as Field) * TWO_POW_64;
    fields[13] = pack_amount_pair(agreement.final_components[0], agreement.final_components[1]);
    fields[14] = pack_amount_pair(agreement.final_components[2], agreement.final_components[3]);
    fields[15] = pack_amount_pair(agreement.final_components[4], 0);
    fields[16] = pack_agreement_metadata(agreement);
    fields[17] = salt[0];
    fields[18] = salt[1];
    proof_hash(PROOF_DOMAIN_AGREEMENT, fields)
}

fn proof_hash_payroll_line(line: PayrollLine, agreement_commitment: Field) -> Field {
    let salt = bytes_as_fields(line.salt);
    let mut fields: [Field; 8] = [0; 8];
    fields[0] = agreement_commitment;
    for pair in 0..4 {
        fields[1 + pair] =
            pack_amount_pair(line.deductions[pair * 2], line.deductions[pair * 2 + 1]);
    }
    fields[5] = pack_line_metadata(line);
    fields[6] = salt[0];
    fields[7] = salt[1];
    proof_hash(PROOF_DOMAIN_PAYROLL_LINE, fields)
}

fn hash_policy_program(program: PolicyProgram) -> [u8; 32] {
    let domain = "PAYO_POLICY_PROGRAM_V1".as_bytes();
    let mut message: [u8; 640] = [0; 640];
    let mut cursor: u32 = domain.len();
    for index in 0..domain.len() {
        message[index] = domain[index];
    }
    for index in 0..32 {
        message[cursor + index] = program.metadata_commitment[index];
    }
    cursor += 32;
    let count: [u8; 4] = (program.instruction_count as Field).to_be_bytes();
    for index in 0..4 {
        message[cursor + index] = count[index];
    }
    cursor += 4;
    message[cursor] = program.output_register;
    cursor += 1;
    for step in 0..MAX_POLICY_STEPS {
        message[cursor] = program.opcodes[step];
        message[cursor + 1] = program.left[step];
        message[cursor + 2] = program.right[step];
        cursor += 3;
        let immediate: [u8; 16] = (program.immediate[step] as Field).to_be_bytes();
        let numerator: [u8; 8] = (program.numerator[step] as Field).to_be_bytes();
        let denominator: [u8; 8] = (program.denominator[step] as Field).to_be_bytes();
        for index in 0..16 {
            message[cursor + index] = immediate[index];
        }
        cursor += 16;
        for index in 0..8 {
            message[cursor + index] = numerator[index];
        }
        cursor += 8;
        for index in 0..8 {
            message[cursor + index] = denominator[index];
        }
        cursor += 8;
    }
    keccak256(message, cursor)
}

// Canonically binds every authoritative obligation term used by PayrollIntegrity.
// Fixed-width packing avoids ambiguous encodings; every numeric field is big-endian.
fn hash_agreement_terms(agreement: AgreementWitness) -> [u8; 32] {
    let domain = "PAYO_AGREEMENT_TERMS_V1".as_bytes();
    let mut message: [u8; 438] = [0; 438];
    let mut cursor: u32 = domain.len();
    for index in 0..domain.len() {
        message[index] = domain[index];
    }
    for index in 0..32 {
        message[cursor + index] = agreement.id_commitment[index];
        message[cursor + 32 + index] = agreement.recipient_commitment[index];
    }
    cursor += 64;
    let earnings_count: [u8; 4] = (agreement.earnings_count as Field).to_be_bytes();
    for index in 0..4 {
        message[cursor + index] = earnings_count[index];
    }
    cursor += 4;
    for component in 0..MAX_COMPONENTS {
        let amount: [u8; 16] = (agreement.earnings[component] as Field).to_be_bytes();
        for index in 0..16 {
            message[cursor + index] = amount[index];
        }
        cursor += 16;
    }
    message[cursor] = agreement.token;
    cursor += 1;
    for index in 0..32 {
        message[cursor + index] = agreement.policy_commitment[index];
        message[cursor + 32 + index] = agreement.schedule_commitment[index];
    }
    cursor += 64;
    let due_at: [u8; 8] = (agreement.due_at as Field).to_be_bytes();
    let valid_until: [u8; 8] = (agreement.valid_until as Field).to_be_bytes();
    for index in 0..8 {
        message[cursor + index] = due_at[index];
        message[cursor + 8 + index] = valid_until[index];
    }
    cursor += 16;
    message[cursor] = agreement.classification_declared;
    cursor += 1;
    let classification_score: [u8; 2] = (agreement.classification_score as Field).to_be_bytes();
    let classification_threshold: [u8; 2] =
        (agreement.classification_employee_threshold as Field).to_be_bytes();
    for index in 0..2 {
        message[cursor + index] = classification_score[index];
        message[cursor + 2 + index] = classification_threshold[index];
    }
    cursor += 4;
    message[cursor] = if agreement.final_pay_mode { 1 } else { 0 };
    message[cursor + 1] = agreement.final_required_mask;
    cursor += 2;
    for component in 0..MAX_FINAL_COMPONENTS {
        let amount: [u8; 16] = (agreement.final_components[component] as Field).to_be_bytes();
        for index in 0..16 {
            message[cursor + index] = amount[index];
        }
        cursor += 16;
    }
    let floor: [u8; 16] = (agreement.fx_floor_atomic as Field).to_be_bytes();
    for index in 0..16 {
        message[cursor + index] = floor[index];
    }
    cursor += 16;
    message[cursor] = agreement.reference_currency;
    cursor += 1;
    for index in 0..32 {
        message[cursor + index] = agreement.salt[index];
    }
    cursor += 32;
    keccak256(message, cursor)
}

fn evaluate_policy(program: PolicyProgram, gross: u128, earnings: [u128; MAX_COMPONENTS]) -> u128 {
    assert(program.metadata_commitment != ZERO_BYTES, "policy metadata commitment is zero");
    assert(program.instruction_count > 0, "empty policy program");
    assert(program.instruction_count <= MAX_POLICY_STEPS, "policy program too long");
    assert((program.output_register as u32) < program.instruction_count, "invalid policy output");
    let mut registers: [u128; MAX_POLICY_STEPS] = [0; MAX_POLICY_STEPS];
    for step in 0..MAX_POLICY_STEPS {
        if step < program.instruction_count {
            let opcode = program.opcodes[step];
            let left = program.left[step] as u32;
            let right = program.right[step] as u32;
            let mut value: u128 = 0;
            if opcode == 1 {
                value = program.immediate[step];
            } else if opcode == 2 {
                value = gross;
            } else if opcode == 3 {
                assert(left < MAX_COMPONENTS, "invalid earnings input");
                value = earnings[left];
            } else {
                assert((opcode >= 4) & (opcode <= 8), "unknown policy opcode");
                assert(left < step, "policy left dependency is not prior");
                if opcode != 6 {
                    assert(right < step, "policy right dependency is not prior");
                }
                let left_value = registers[left];
                let right_value = registers[right];
                if opcode == 4 {
                    value = left_value + right_value;
                } else if opcode == 5 {
                    assert(right_value <= left_value, "policy subtraction underflow");
                    value = left_value - right_value;
                } else if opcode == 6 {
                    assert(program.denominator[step] > 0, "policy division by zero");
                    value = left_value * program.numerator[step] as u128
                        / program.denominator[step] as u128;
                } else if opcode == 7 {
                    value = if left_value < right_value {
                        left_value
                    } else {
                        right_value
                    };
                } else {
                    value = if left_value > right_value {
                        left_value
                    } else {
                        right_value
                    };
                }
            }
            registers[step] = value;
        } else {
            assert(program.opcodes[step] == 0, "unused policy opcode must be zero");
            assert(program.left[step] == 0, "unused policy left must be zero");
            assert(program.right[step] == 0, "unused policy right must be zero");
            assert(program.immediate[step] == 0, "unused policy immediate must be zero");
            assert(program.numerator[step] == 0, "unused policy numerator must be zero");
            assert(program.denominator[step] == 0, "unused policy denominator must be zero");
        }
    }
    registers[program.output_register as u32]
}

fn hash_fx_snapshot(snapshot: FxSnapshot) -> [u8; 32] {
    let domain = "PAYO_FX_SNAPSHOT_V1".as_bytes();
    let mut message: [u8; 161] = [0; 161];
    let mut cursor: u32 = domain.len();
    for index in 0..domain.len() {
        message[index] = domain[index];
    }
    message[cursor] = snapshot.token;
    message[cursor + 1] = snapshot.token_decimals;
    message[cursor + 2] = snapshot.reference_currency;
    message[cursor + 3] = snapshot.quote_decimals;
    cursor += 4;
    for index in 0..32 {
        message[cursor + index] = snapshot.feed_commitment[index];
        message[cursor + 32 + index] = snapshot.sources_commitment[index];
    }
    cursor += 64;
    let numerator: [u8; 16] = (snapshot.price_numerator as Field).to_be_bytes();
    let denominator: [u8; 16] = (snapshot.price_denominator as Field).to_be_bytes();
    let observed: [u8; 8] = (snapshot.observed_at as Field).to_be_bytes();
    let maximum_age: [u8; 8] = (snapshot.maximum_age_seconds as Field).to_be_bytes();
    let haircut: [u8; 2] = (snapshot.haircut_bps as Field).to_be_bytes();
    for index in 0..16 {
        message[cursor + index] = numerator[index];
    }
    cursor += 16;
    for index in 0..16 {
        message[cursor + index] = denominator[index];
    }
    cursor += 16;
    for index in 0..8 {
        message[cursor + index] = observed[index];
    }
    cursor += 8;
    message[cursor] = snapshot.source_count;
    message[cursor + 1] = snapshot.minimum_source_count;
    cursor += 2;
    for index in 0..8 {
        message[cursor + index] = maximum_age[index];
    }
    cursor += 8;
    for index in 0..2 {
        message[cursor + index] = haircut[index];
    }
    cursor += 2;
    keccak256(message, cursor)
}

fn hash_payroll_line(
    line: PayrollLine,
    agreement: AgreementWitness,
    gross: u128,
    deductions_total: u128,
    policy_commitment: [u8; 32],
) -> [u8; 32] {
    let domain = "PAYO_LEAF_V1".as_bytes();
    let mut message: [u8; 344] = [0; 344];
    for index in 0..domain.len() {
        message[index] = domain[index];
    }
    message[15] = 4;
    message[19] = 1;
    let mut gross_bytes: [u8; 32] = [0; 32];
    let gross_u128: [u8; 16] = (gross as Field).to_be_bytes();
    let mut net_bytes: [u8; 32] = [0; 32];
    let net_u128: [u8; 16] = ((gross - deductions_total) as Field).to_be_bytes();
    for index in 0..16 {
        gross_bytes[index + 16] = gross_u128[index];
        net_bytes[index + 16] = net_u128[index];
    }
    let token_address = if agreement.token == 0 {
        STRK_ADDRESS
    } else {
        USDC_ADDRESS
    };
    let fields: [[u8; 32]; 9] = [
        agreement.id_commitment,
        agreement.recipient_commitment,
        gross_bytes,
        hash_deductions(line.deductions, line.deductions_count),
        net_bytes,
        token_address,
        policy_commitment,
        agreement.schedule_commitment,
        line.salt,
    ];
    for field_index in 0..9 {
        let offset = 20 + field_index * 36;
        message[offset + 3] = 32;
        for byte_index in 0..32 {
            message[offset + 4 + byte_index] = fields[field_index][byte_index];
        }
    }
    keccak256(message, message.len())
}

fn derive_run_nullifier_v1(
    organization_secret: [u8; 32],
    cycle_id: [u8; 64],
    cycle_id_len: u32,
    revision: u32,
) -> [u8; 32] {
    assert(cycle_id_len > 0, "cycle id is required");
    assert(cycle_id_len <= 64, "cycle id is too long");
    let domain = "PAYO_RUN_V1".as_bytes();
    let mut message: [u8; 123] = [0; 123];
    for index in 0..domain.len() {
        message[index] = domain[index];
    }
    message[14] = 32;
    for index in 0..32 {
        message[15 + index] = organization_secret[index];
    }
    let cycle_len_bytes: [u8; 4] = (cycle_id_len as Field).to_be_bytes();
    for index in 0..4 {
        message[47 + index] = cycle_len_bytes[index];
    }
    for index in 0..64 {
        if index < cycle_id_len {
            message[51 + index] = cycle_id[index];
        } else {
            assert(cycle_id[index] == 0, "unused cycle byte must be zero");
        }
    }
    let revision_offset = 51 + cycle_id_len;
    message[revision_offset + 3] = 4;
    let revision_bytes: [u8; 4] = (revision as Field).to_be_bytes();
    for index in 0..4 {
        message[revision_offset + 4 + index] = revision_bytes[index];
    }
    keccak256(message, 59 + cycle_id_len)
}

fn assert_final_pay(agreement: AgreementWitness, included_mask: u8, gross: u128) {
    assert(agreement.final_required_mask <= 31, "invalid final component mask");
    assert(included_mask <= 31, "invalid final inclusion mask");
    if agreement.final_pay_mode {
        assert(agreement.final_required_mask != 0, "final pay has no required components");
        assert(included_mask == agreement.final_required_mask, "final pay component mask mismatch");
        assert(
            sum_final_components(agreement.final_components) == gross,
            "final pay components do not equal gross",
        );
        for index in 0..MAX_FINAL_COMPONENTS {
            let divisor: u32 = 1 << index as u32;
            let required = (agreement.final_required_mask as u32 / divisor) % 2 == 1;
            if required {
                assert(agreement.final_components[index] > 0, "required final component is zero");
            }
        }
    } else {
        assert(agreement.final_required_mask == 0, "ordinary pay has final requirements");
        assert(included_mask == 0, "ordinary pay has final inclusions");
        for index in 0..MAX_FINAL_COMPONENTS {
            assert(
                agreement.final_components[index] == 0,
                "ordinary pay has final component value",
            );
        }
    }
}

fn validate_active_line_bound(
    line: PayrollLine,
    agreement: AgreementWitness,
    agreement_commitment: Field,
    policy: PolicyProgram,
    policy_commitment: [u8; 32],
    snapshot: FxSnapshot,
    validity_start: u64,
) -> Field {
    assert(policy_commitment == agreement.policy_commitment, "policy does not match agreement");
    assert(agreement.recipient_commitment != ZERO_BYTES, "recipient commitment is zero");
    assert(agreement.schedule_commitment != ZERO_BYTES, "schedule commitment is zero");
    assert(line.salt != ZERO_BYTES, "line salt is zero");
    assert(agreement.due_at <= validity_start, "obligation is not due");
    assert(validity_start <= agreement.valid_until, "agreement is expired");
    assert(agreement.earnings_count > 0, "active line has no earnings");
    assert((agreement.token == 0) | (agreement.token == 1), "unsupported token");

    let expected_treatment: u8 = if agreement.classification_score
        >= agreement.classification_employee_threshold {
        1
    } else {
        2
    };
    assert(agreement.classification_employee_threshold > 0, "classification threshold is zero");
    assert(
        agreement.classification_declared == expected_treatment,
        "classification facts mismatch",
    );
    assert(
        line.classification_treatment == agreement.classification_declared,
        "classification treatment mismatch",
    );

    let gross = sum_components(agreement.earnings, agreement.earnings_count);
    let deductions = sum_components(line.deductions, line.deductions_count);
    assert(gross > 0, "gross must be positive");
    assert(deductions <= gross, "deductions exceed gross");
    assert(
        evaluate_policy(policy, gross, agreement.earnings) == deductions,
        "policy output does not match deductions",
    );
    assert_final_pay(agreement, line.final_included_mask, gross);

    assert(snapshot.token == agreement.token, "FX token mismatch");
    let expected_decimals: u8 = if agreement.token == 0 { 18 } else { 6 };
    assert(snapshot.token_decimals == expected_decimals, "token decimals mismatch");
    assert(snapshot.reference_currency <= 1, "unsupported reference currency");
    assert(snapshot.quote_decimals == 6, "FX quote decimals mismatch");
    assert(
        snapshot.reference_currency == agreement.reference_currency,
        "FX currency does not match agreement",
    );
    assert(snapshot.feed_commitment != ZERO_BYTES, "FX feed commitment is zero");
    assert(snapshot.sources_commitment != ZERO_BYTES, "FX sources commitment is zero");
    assert(snapshot.price_denominator > 0, "invalid FX denominator");
    assert(snapshot.minimum_source_count > 0, "minimum FX sources is zero");
    assert(snapshot.source_count >= snapshot.minimum_source_count, "insufficient FX sources");
    assert(snapshot.observed_at <= validity_start, "FX snapshot is from the future");
    assert(snapshot.maximum_age_seconds > 0, "maximum FX age is zero");
    assert(
        validity_start - snapshot.observed_at <= snapshot.maximum_age_seconds,
        "FX snapshot is stale",
    );
    assert(snapshot.haircut_bps <= 10000, "invalid FX haircut");

    let net = gross - deductions;
    let priced = net * snapshot.price_numerator;
    // Canonical integer conversion rounds down once at the declared token/quote boundary.
    let raw_reference = priced / snapshot.price_denominator;
    let adjusted_reference =
        raw_reference * (BPS_DENOMINATOR - snapshot.haircut_bps as u128) / BPS_DENOMINATOR;
    assert(line.reference_value_atomic == adjusted_reference, "FX reference value mismatch");
    assert(line.reference_value_atomic >= agreement.fx_floor_atomic, "FX floor not met");

    proof_hash_payroll_line(line, agreement_commitment)
}

fn validate_active_line(
    line: PayrollLine,
    agreement: AgreementWitness,
    policy: PolicyProgram,
    policy_commitment: [u8; 32],
    snapshot: FxSnapshot,
    validity_start: u64,
) -> Field {
    let agreement_commitment = proof_hash_agreement_terms(agreement);
    validate_active_line_bound(
        line,
        agreement,
        agreement_commitment,
        policy,
        policy_commitment,
        snapshot,
        validity_start,
    )
}

fn assert_inactive_line(line: PayrollLine) {
    assert(line.deductions_count == 0, "inactive deductions count must be zero");
    assert(line.policy_slot == 0, "inactive policy slot must be zero");
    assert(line.fx_slot == 0, "inactive FX slot must be zero");
    for index in 0..MAX_COMPONENTS {
        assert(line.deductions[index] == 0, "inactive deduction must be zero");
    }
    assert(line.salt == ZERO_BYTES, "inactive salt must be zero");
    assert(line.classification_treatment == 0, "inactive treatment must be zero");
    assert(line.final_included_mask == 0, "inactive final inclusions must be zero");
    assert(line.reference_value_atomic == 0, "inactive reference value must be zero");
}

fn assert_empty_membership(membership: MerkleMembership) {
    for level in 0..CATALOG_DEPTH {
        assert(membership.siblings[level] == 0, "disabled catalog path must be zero");
        assert(!membership.path_bits[level], "disabled catalog bit must be false");
    }
}

fn assert_disabled_policy(slot: PolicySlot) {
    assert(slot.program.metadata_commitment == ZERO_BYTES, "disabled policy metadata must be zero");
    assert(slot.program.instruction_count == 0, "disabled policy count must be zero");
    assert(slot.program.output_register == 0, "disabled policy output must be zero");
    for step in 0..MAX_POLICY_STEPS {
        assert(slot.program.opcodes[step] == 0, "disabled policy opcode must be zero");
        assert(slot.program.left[step] == 0, "disabled policy left must be zero");
        assert(slot.program.right[step] == 0, "disabled policy right must be zero");
        assert(slot.program.immediate[step] == 0, "disabled policy immediate must be zero");
        assert(slot.program.numerator[step] == 0, "disabled policy numerator must be zero");
        assert(slot.program.denominator[step] == 0, "disabled policy denominator must be zero");
    }
    assert_empty_membership(slot.membership);
}

fn assert_disabled_fx(slot: FxSlot) {
    assert(slot.snapshot.token == 0, "disabled FX token must be zero");
    assert(slot.snapshot.token_decimals == 0, "disabled FX decimals must be zero");
    assert(slot.snapshot.reference_currency == 0, "disabled FX currency must be zero");
    assert(slot.snapshot.quote_decimals == 0, "disabled FX quote decimals must be zero");
    assert(slot.snapshot.feed_commitment == ZERO_BYTES, "disabled FX feed must be zero");
    assert(slot.snapshot.sources_commitment == ZERO_BYTES, "disabled FX sources must be zero");
    assert(slot.snapshot.price_numerator == 0, "disabled FX numerator must be zero");
    assert(slot.snapshot.price_denominator == 0, "disabled FX denominator must be zero");
    assert(slot.snapshot.observed_at == 0, "disabled FX timestamp must be zero");
    assert(slot.snapshot.source_count == 0, "disabled FX source count must be zero");
    assert(slot.snapshot.minimum_source_count == 0, "disabled FX minimum must be zero");
    assert(slot.snapshot.maximum_age_seconds == 0, "disabled FX age must be zero");
    assert(slot.snapshot.haircut_bps == 0, "disabled FX haircut must be zero");
    assert_empty_membership(slot.membership);
}

fn assert_disabled_agreement(agreement: AgreementWitness) {
    assert(agreement.id_commitment == ZERO_BYTES, "disabled agreement id must be zero");
    assert(
        agreement.recipient_commitment == ZERO_BYTES,
        "disabled agreement recipient must be zero",
    );
    assert(agreement.earnings_count == 0, "disabled agreement earnings count must be zero");
    for component in 0..MAX_COMPONENTS {
        assert(agreement.earnings[component] == 0, "disabled agreement earning must be zero");
    }
    assert(agreement.token == 0, "disabled agreement token must be zero");
    assert(agreement.policy_commitment == ZERO_BYTES, "disabled agreement policy must be zero");
    assert(agreement.schedule_commitment == ZERO_BYTES, "disabled agreement schedule must be zero");
    assert(agreement.due_at == 0, "disabled agreement due time must be zero");
    assert(agreement.valid_until == 0, "disabled agreement expiry must be zero");
    assert(
        agreement.classification_declared == 0,
        "disabled agreement classification must be zero",
    );
    assert(agreement.classification_score == 0, "disabled agreement score must be zero");
    assert(
        agreement.classification_employee_threshold == 0,
        "disabled agreement threshold must be zero",
    );
    assert(!agreement.final_pay_mode, "disabled agreement final mode must be false");
    assert(agreement.final_required_mask == 0, "disabled agreement final mask must be zero");
    for component in 0..MAX_FINAL_COMPONENTS {
        assert(agreement.final_components[component] == 0, "disabled final component must be zero");
    }
    assert(agreement.fx_floor_atomic == 0, "disabled agreement FX floor must be zero");
    assert(agreement.reference_currency == 0, "disabled agreement currency must be zero");
    assert(agreement.salt == ZERO_BYTES, "disabled agreement salt must be zero");
}

fn sum_earnings(agreement: AgreementWitness) -> u128 {
    assert(agreement.earnings_count > 0, "advanced obligation has no earnings");
    assert(agreement.earnings_count <= MAX_COMPONENTS, "too many earnings");
    let mut total: u128 = 0;
    for index in 0..MAX_COMPONENTS {
        if index < agreement.earnings_count {
            total += agreement.earnings[index];
        } else {
            assert(agreement.earnings[index] == 0, "unused earning is nonzero");
        }
    }
    total
}

fn encode_plan_commitment(plan: AdvancedPlanWitness) -> Field {
    let mut fields: [Field; 27] = [0; 27];
    fields[0] = 1
        + (plan.kind as Field) * 256
        + (plan.cadence as Field) * 65536
        + (plan.flags as Field) * 16777216
        + (plan.occurrence as Field) * 4294967296
        + (plan.release_sequence as Field) * 18446744073709551616
        + (plan.checkpoint_sequence as Field) * 79228162514264337593543950336
        + (plan.minimum_checkpoint_seconds as Field) * 340282366920938463463374607431768211456;
    for pair in 0..6 {
        fields[1 + pair] = plan.timestamps[pair * 2] as Field
            + (plan.timestamps[pair * 2 + 1] as Field) * TWO_POW_64;
    }
    for pair in 0..5 {
        fields[7 + pair] = pack_amount_pair(plan.amounts[pair * 2], plan.amounts[pair * 2 + 1]);
    }
    fields[12] = plan.required_mask as Field + (plan.included_mask as Field) * 256;
    for commitment in 0..6 {
        let value = bytes_as_fields(plan.commitments[commitment]);
        fields[13 + commitment * 2] = value[0];
        fields[14 + commitment * 2] = value[1];
    }
    let salt = bytes_as_fields(plan.salt);
    fields[25] = salt[0];
    fields[26] = salt[1];
    proof_hash(PROOF_DOMAIN_ADVANCED_PLAN, fields)
}

fn assert_plan_commitment(plan: AdvancedPlanWitness, expected: [u8; 32]) {
    let actual: [u8; 32] = encode_plan_commitment(plan).to_be_bytes();
    for index in 0..32 { assert(actual[index] == expected[index], "advanced plan commitment mismatch"); }
}

fn linear_entitlement(total: u128, start: u64, end: u64, at: u64) -> u128 {
    assert(end > start, "advanced obligation window is invalid");
    assert(at >= start, "advanced obligation checkpoint precedes start");
    assert(at <= end, "advanced obligation checkpoint exceeds end");
    let duration: u128 = (end - start) as u128;
    let elapsed: u128 = (at - start) as u128;
    let quotient = total / duration;
    let remainder = total % duration;
    quotient * elapsed + (remainder * elapsed) / duration
}

fn mask_contains(included: u8, required: u8) -> bool {
    (included & required) == required
}

fn validate_advanced_plan(
    agreement: AgreementWitness,
    plan: AdvancedPlanWitness,
    validity_start: u64,
) {
    assert(plan.enabled, "advanced plan is disabled");
    assert(plan.kind <= 3, "unknown advanced plan kind");
    assert(plan.salt != ZERO_BYTES, "advanced plan salt is zero");
    assert_plan_commitment(plan, agreement.schedule_commitment);
    let gross = sum_earnings(agreement);
    assert(gross > 0, "advanced gross is zero");

    if plan.kind == 0 {
        assert(plan.cadence <= 2, "invalid recurring cadence");
        assert(plan.timestamps[1] >= plan.timestamps[0], "recurring due precedes anchor");
        if plan.timestamps[2] > 0 {
            assert(plan.timestamps[1] <= plan.timestamps[2], "recurring due exceeds plan end");
        }
        assert(validity_start >= plan.timestamps[1], "recurring obligation is early");
        assert(agreement.due_at == plan.timestamps[1], "recurring due binding mismatch");
    } else if plan.kind == 1 {
        let start = plan.timestamps[3];
        let end = plan.timestamps[2];
        let checkpoint = plan.timestamps[5];
        let last = plan.timestamps[6];
        assert(plan.minimum_checkpoint_seconds > 0, "checkpoint interval is zero");
        if last > 0 {
            assert(checkpoint >= last, "checkpoint moved backwards");
            if checkpoint > last {
                assert(checkpoint - last >= plan.minimum_checkpoint_seconds as u64, "checkpoint interval is too short");
            }
        }
        let earned = linear_entitlement(plan.amounts[0], start, end, checkpoint);
        assert(earned == plan.amounts[2], "checkpoint entitlement is forged");
        assert(plan.amounts[2] > plan.amounts[1], "checkpoint has no unpaid value");
        assert(gross == plan.amounts[2] - plan.amounts[1], "checkpoint payroll amount is wrong");
        assert(validity_start >= checkpoint, "checkpoint obligation is early");
        assert(agreement.due_at == checkpoint, "checkpoint due binding mismatch");
        assert(plan.commitments[2] != ZERO_BYTES, "checkpoint attestation is missing");
    } else if plan.kind == 2 {
        let due = plan.timestamps[7];
        let approved = plan.timestamps[8];
        assert(plan.commitments[0] != ZERO_BYTES, "milestone commitment is zero");
        assert(plan.commitments[1] != ZERO_BYTES, "milestone approver is zero");
        assert(plan.commitments[2] != ZERO_BYTES, "milestone attestation is zero");
        assert(approved > 0, "milestone is unapproved");
        assert(approved <= due, "milestone was approved after due");
        assert(plan.timestamps[9] == 0, "milestone approval was revoked");
        assert(plan.timestamps[10] == 0, "milestone was already settled");
        assert(validity_start >= due, "milestone obligation is early");
        assert(agreement.due_at == due, "milestone due binding mismatch");
    } else {
        let start = plan.timestamps[3];
        let cliff = plan.timestamps[4];
        let release = plan.timestamps[5];
        let end = plan.timestamps[2];
        assert(cliff >= start, "vesting cliff precedes start");
        assert(release >= cliff, "vesting release precedes cliff");
        let earned = linear_entitlement(plan.amounts[0], start, end, release);
        assert(earned > plan.amounts[1], "vesting has no unreleased value");
        assert(gross == earned - plan.amounts[1], "vesting payroll amount is wrong");
        assert(validity_start >= release, "vesting obligation is early");
        assert(agreement.due_at == release, "vesting due binding mismatch");
    }

    let has_termination = (plan.flags & 1) == 1;
    assert(has_termination == agreement.final_pay_mode, "termination mode binding mismatch");
    if has_termination {
        assert(plan.timestamps[11] > 0, "termination time is zero");
        assert(plan.commitments[3] != ZERO_BYTES, "termination reason is zero");
        assert(plan.required_mask == agreement.final_required_mask, "termination required mask mismatch");
        assert(plan.included_mask == agreement.final_required_mask, "termination component is missing");
        assert(mask_contains(plan.included_mask, plan.required_mask), "termination mask is incomplete");
        let mut final_total: u128 = 0;
        for index in 0..MAX_FINAL_COMPONENTS {
            assert(plan.amounts[4 + index] == agreement.final_components[index], "termination amount mismatch");
            final_total += plan.amounts[4 + index];
        }
        assert(final_total == gross, "termination gross mismatch");
    } else {
        assert(plan.required_mask == 0, "ordinary plan has a required mask");
        assert(plan.included_mask == 0, "ordinary plan has an included mask");
    }

    let has_adjustment = (plan.flags & 2) == 2;
    if has_adjustment {
        assert(plan.amounts[3] > 0, "adjustment amount is zero");
        assert(plan.commitments[4] != ZERO_BYTES, "adjustment reason is zero");
        assert(plan.commitments[5] != ZERO_BYTES, "adjustment approver is zero");
        let mut found = false;
        for index in 0..MAX_COMPONENTS {
            if index < agreement.earnings_count {
                found = found | (agreement.earnings[index] == plan.amounts[3]);
            }
        }
        assert(found, "approved adjustment is absent from earnings");
    }
}

fn assert_disabled_plan(plan: AdvancedPlanWitness) {
    assert(!plan.enabled, "disabled plan is enabled");
    assert(plan.kind == 0, "disabled plan kind is nonzero");
    assert(plan.cadence == 0, "disabled plan cadence is nonzero");
    assert(plan.flags == 0, "disabled plan flags are nonzero");
    assert(plan.occurrence == 0, "disabled plan occurrence is nonzero");
    assert(plan.release_sequence == 0, "disabled release sequence is nonzero");
    assert(plan.checkpoint_sequence == 0, "disabled checkpoint sequence is nonzero");
    assert(plan.minimum_checkpoint_seconds == 0, "disabled checkpoint interval is nonzero");
    for index in 0..12 { assert(plan.timestamps[index] == 0, "disabled timestamp is nonzero"); }
    for index in 0..10 { assert(plan.amounts[index] == 0, "disabled amount is nonzero"); }
    assert(plan.required_mask == 0, "disabled required mask is nonzero");
    assert(plan.included_mask == 0, "disabled included mask is nonzero");
    for commitment in 0..6 {
        assert(plan.commitments[commitment] == ZERO_BYTES, "disabled commitment is nonzero");
    }
    assert(plan.salt == ZERO_BYTES, "disabled salt is nonzero");
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
    run_nullifier_high: pub u128,
    run_nullifier_low: pub u128,
    validity_start: pub u64,
    validity_expiry: pub u64,
    shard_index: pub u8,
    organization_secret: [u8; 32],
    cycle_id: [u8; 64],
    cycle_id_len: u32,
    revision: u32,
    agreement_leaves: [Field; MAX_LINES],
    payroll_leaves: [Field; MAX_LINES],
    agreements: [AgreementWitness; SHARD_AGREEMENTS],
    lines: [PayrollLine; SHARD_LINES],
    policies: [PolicySlot; MAX_POLICIES],
    fx_snapshots: [FxSlot; MAX_FX_SNAPSHOTS],
    plans: [AdvancedPlanWitness; SHARD_LINES],
) {
    assert(chain_id != 0, "chain id is required");
    assert(seal_address != 0, "seal address is required");
    assert((proof_version == 1) | (proof_version == 2), "unsupported proof version");
    assert(schema_version == 1, "unsupported schema version");
    assert(shard_index <= 1, "invalid payroll shard");
    assert(validity_expiry >= validity_start, "invalid proof validity window");
    assert(
        validity_expiry - validity_start <= MAX_VALIDITY_WINDOW_SECONDS,
        "proof validity window is too long",
    );
    assert(organization_secret != ZERO_BYTES, "organization secret is zero");
    assert(revision > 0, "revision is zero");

    let expected_nullifier =
        derive_run_nullifier_v1(organization_secret, cycle_id, cycle_id_len, revision);
    assert_root_limbs(expected_nullifier, run_nullifier_high, run_nullifier_low);

    let mut policy_commitments: [[u8; 32]; MAX_POLICIES] = [ZERO_BYTES; MAX_POLICIES];
    for index in 0..MAX_POLICIES {
        if index > 0 {
            assert(
                policies[index - 1].enabled | (!policies[index].enabled),
                "policy slots must be packed",
            );
        }
        if policies[index].enabled {
            policy_commitments[index] = hash_policy_program(policies[index].program);
            let root =
                proof_root_from_membership(policy_commitments[index], policies[index].membership);
            assert_field_root_limbs(root, policy_root_high, policy_root_low);
        } else {
            assert_disabled_policy(policies[index]);
        }
    }

    let mut fx_commitments: [[u8; 32]; MAX_FX_SNAPSHOTS] = [ZERO_BYTES; MAX_FX_SNAPSHOTS];
    for index in 0..MAX_FX_SNAPSHOTS {
        if index > 0 {
            assert(
                fx_snapshots[index - 1].enabled | (!fx_snapshots[index].enabled),
                "FX slots must be packed",
            );
        }
        if fx_snapshots[index].enabled {
            fx_commitments[index] = hash_fx_snapshot(fx_snapshots[index].snapshot);
            let root =
                proof_root_from_membership(fx_commitments[index], fx_snapshots[index].membership);
            assert_field_root_limbs(root, fx_root_high, fx_root_low);
        } else {
            assert_disabled_fx(fx_snapshots[index]);
        }
    }

    // Both shards privately receive the same full leaf arrays and expose the
    // same roots. Shard 0 authenticates agreements 0..25 and payroll lines
    // 0..24; shard 1 authenticates agreements 24..49 and lines 25..49. The
    // two-agreement overlap proves the global sort boundary without revealing
    // agreement identifiers.
    for index in MAX_REAL_LINES..MAX_LINES {
        assert(agreement_leaves[index] == PROOF_EMPTY_LEAF, "agreement padding is not empty");
        assert(payroll_leaves[index] == PROOF_EMPTY_LEAF, "payroll padding is not empty");
    }

    let mut shard_agreement_commitments: [Field; SHARD_AGREEMENTS] =
        [PROOF_EMPTY_LEAF; SHARD_AGREEMENTS];
    for index in 0..SHARD_AGREEMENTS {
        if index > 0 {
            assert(
                agreements[index - 1].enabled | (!agreements[index].enabled),
                "agreement slots must be packed",
            );
            if agreements[index].enabled {
                assert(
                    bytes_less_than(
                        agreements[index - 1].id_commitment,
                        agreements[index].id_commitment,
                    ),
                    "agreements must be sorted and unique",
                );
            }
        }
        if agreements[index].enabled {
            assert(agreements[index].id_commitment != ZERO_BYTES, "agreement commitment is zero");
            assert(agreements[index].salt != ZERO_BYTES, "agreement salt is zero");
            assert(
                agreements[index].valid_until >= agreements[index].due_at,
                "invalid agreement window",
            );
            shard_agreement_commitments[index] = proof_hash_agreement_terms(agreements[index]);
        } else {
            assert_disabled_agreement(agreements[index]);
        }

        let committed_leaf = if shard_index == 0 {
            agreement_leaves[index]
        } else {
            agreement_leaves[index + 24]
        };
        assert(
            committed_leaf == shard_agreement_commitments[index],
            "shard agreement leaf mismatch",
        );
    }

    let mut real_line_count: u32 = 0;
    for index in 0..SHARD_LINES {
        let agreement_index = if shard_index == 0 { index } else { index + 1 };
        let agreement = agreements[agreement_index];
        let agreement_is_due = agreement.enabled
            & (agreement.due_at <= validity_start)
            & (validity_start <= agreement.valid_until);
        assert(lines[index].active == agreement_is_due, "due agreement coverage mismatch");
        let mut payroll_commitment = PROOF_EMPTY_LEAF;
        if lines[index].active {
            real_line_count += 1;
            assert((lines[index].policy_slot as u32) < MAX_POLICIES, "invalid policy slot");
            assert((lines[index].fx_slot as u32) < MAX_FX_SNAPSHOTS, "invalid FX slot");
            assert(
                policies[lines[index].policy_slot as u32].enabled,
                "selected policy is disabled",
            );
            assert(
                fx_snapshots[lines[index].fx_slot as u32].enabled,
                "selected FX snapshot is disabled",
            );
            if proof_version == 2 {
                validate_advanced_plan(agreement, plans[index], validity_start);
            } else {
                assert_disabled_plan(plans[index]);
            }
            payroll_commitment = validate_active_line_bound(
                lines[index],
                agreement,
                shard_agreement_commitments[agreement_index],
                policies[lines[index].policy_slot as u32].program,
                policy_commitments[lines[index].policy_slot as u32],
                fx_snapshots[lines[index].fx_slot as u32].snapshot,
                validity_start,
            );
        } else {
            assert_inactive_line(lines[index]);
            assert_disabled_plan(plans[index]);
        }
        let committed_leaf = if shard_index == 0 {
            payroll_leaves[index]
        } else {
            payroll_leaves[index + SHARD_LINES]
        };
        assert(committed_leaf == payroll_commitment, "shard payroll leaf mismatch");
    }
    if shard_index == 0 {
        assert(real_line_count > 0, "empty payroll run");
    }
    assert_field_root_limbs(
        proof_merkle_root(agreement_leaves),
        agreement_root_high,
        agreement_root_low,
    );
    assert_field_root_limbs(
        proof_merkle_root(payroll_leaves),
        manifest_root_high,
        manifest_root_low,
    );
}

fn empty_plan() -> AdvancedPlanWitness {
    AdvancedPlanWitness {
        enabled: false,
        kind: 0,
        cadence: 0,
        flags: 0,
        occurrence: 0,
        release_sequence: 0,
        checkpoint_sequence: 0,
        minimum_checkpoint_seconds: 0,
        timestamps: [0; 12],
        amounts: [0; 10],
        required_mask: 0,
        included_mask: 0,
        commitments: [ZERO_BYTES; 6],
        salt: ZERO_BYTES,
    }
}

fn empty_membership() -> MerkleMembership {
    MerkleMembership { siblings: [0; CATALOG_DEPTH], path_bits: [false; CATALOG_DEPTH] }
}

fn empty_agreement() -> AgreementWitness {
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

fn empty_program() -> PolicyProgram {
    PolicyProgram {
        metadata_commitment: ZERO_BYTES,
        instruction_count: 0,
        opcodes: [0; MAX_POLICY_STEPS],
        left: [0; MAX_POLICY_STEPS],
        right: [0; MAX_POLICY_STEPS],
        immediate: [0; MAX_POLICY_STEPS],
        numerator: [0; MAX_POLICY_STEPS],
        denominator: [0; MAX_POLICY_STEPS],
        output_register: 0,
    }
}

fn valid_program() -> PolicyProgram {
    let mut program = empty_program();
    program.metadata_commitment = [7; 32];
    program.instruction_count = 2;
    program.opcodes[0] = 2;
    program.opcodes[1] = 6;
    program.left[1] = 0;
    program.numerator[1] = 1;
    program.denominator[1] = 10;
    program.output_register = 1;
    program
}

fn empty_snapshot() -> FxSnapshot {
    FxSnapshot {
        token: 0,
        token_decimals: 0,
        reference_currency: 0,
        quote_decimals: 0,
        feed_commitment: ZERO_BYTES,
        sources_commitment: ZERO_BYTES,
        price_numerator: 0,
        price_denominator: 0,
        observed_at: 0,
        source_count: 0,
        minimum_source_count: 0,
        maximum_age_seconds: 0,
        haircut_bps: 0,
    }
}

fn valid_snapshot() -> FxSnapshot {
    FxSnapshot {
        token: 0,
        token_decimals: 18,
        reference_currency: 0,
        quote_decimals: 6,
        feed_commitment: [8; 32],
        sources_commitment: [9; 32],
        price_numerator: 1,
        price_denominator: 1,
        observed_at: 90,
        source_count: 3,
        minimum_source_count: 2,
        maximum_age_seconds: 20,
        haircut_bps: 0,
    }
}

fn empty_line() -> PayrollLine {
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

fn valid_line() -> PayrollLine {
    let mut line = empty_line();
    line.active = true;
    line.deductions[0] = 10;
    line.deductions_count = 1;
    line.salt = [5; 32];
    line.classification_treatment = 1;
    line.reference_value_atomic = 90;
    line
}

fn valid_agreement() -> AgreementWitness {
    AgreementWitness {
        enabled: true,
        id_commitment: [1; 32],
        recipient_commitment: [2; 32],
        earnings: [100, 0, 0, 0, 0, 0, 0, 0],
        earnings_count: 1,
        token: 0,
        policy_commitment: hash_policy_program(valid_program()),
        schedule_commitment: [4; 32],
        due_at: 100,
        valid_until: 200,
        classification_declared: 1,
        classification_score: 10,
        classification_employee_threshold: 5,
        final_pay_mode: false,
        final_required_mask: 0,
        final_components: [0; MAX_FINAL_COMPONENTS],
        fx_floor_atomic: 0,
        reference_currency: 0,
        salt: [6; 32],
    }
}

fn first_catalog_membership() -> MerkleMembership {
    let mut membership = empty_membership();
    let mut empty_subtree = PROOF_EMPTY_LEAF;
    for level in 0..CATALOG_DEPTH {
        membership.siblings[level] = empty_subtree;
        empty_subtree = proof_merkle_node(empty_subtree, empty_subtree);
    }
    membership
}

fn empty_policy_slot() -> PolicySlot {
    PolicySlot { enabled: false, program: empty_program(), membership: empty_membership() }
}

fn empty_fx_slot() -> FxSlot {
    FxSlot { enabled: false, snapshot: empty_snapshot(), membership: empty_membership() }
}

fn valid_policy_slot() -> PolicySlot {
    PolicySlot { enabled: true, program: valid_program(), membership: first_catalog_membership() }
}

fn valid_fx_slot() -> FxSlot {
    FxSlot { enabled: true, snapshot: valid_snapshot(), membership: first_catalog_membership() }
}

fn valid_nullifier() -> [u8; 32] {
    let mut cycle_id: [u8; 64] = [0; 64];
    cycle_id[0] = 50;
    cycle_id[1] = 48;
    cycle_id[2] = 50;
    cycle_id[3] = 54;
    cycle_id[4] = 45;
    cycle_id[5] = 48;
    cycle_id[6] = 56;
    derive_run_nullifier_v1([51; 32], cycle_id, 7, 1)
}

fn invoke_valid_main(
    agreement_root_high: u128,
    agreement_root_low: u128,
    manifest_root_high: u128,
    manifest_root_low: u128,
    policy_root_high: u128,
    policy_root_low: u128,
    fx_root_high: u128,
    fx_root_low: u128,
    run_nullifier_high: u128,
    run_nullifier_low: u128,
    agreements: [AgreementWitness; SHARD_AGREEMENTS],
    lines: [PayrollLine; SHARD_LINES],
) {
    let mut policies = [empty_policy_slot(); MAX_POLICIES];
    policies[0] = valid_policy_slot();
    let mut fx_snapshots = [empty_fx_slot(); MAX_FX_SNAPSHOTS];
    fx_snapshots[0] = valid_fx_slot();
    let mut cycle_id: [u8; 64] = [0; 64];
    cycle_id[0] = 50;
    cycle_id[1] = 48;
    cycle_id[2] = 50;
    cycle_id[3] = 54;
    cycle_id[4] = 45;
    cycle_id[5] = 48;
    cycle_id[6] = 56;
    let mut agreement_leaves = [PROOF_EMPTY_LEAF; MAX_LINES];
    for index in 0..SHARD_AGREEMENTS {
        if agreements[index].enabled {
            agreement_leaves[index] = proof_hash_agreement_terms(agreements[index]);
        }
    }
    let mut payroll_leaves = [PROOF_EMPTY_LEAF; MAX_LINES];
    for index in 0..SHARD_LINES {
        if lines[index].active {
            payroll_leaves[index] = proof_hash_payroll_line(lines[index], agreement_leaves[index]);
        }
    }
    main(
        1,
        1,
        1,
        1,
        agreement_root_high,
        agreement_root_low,
        manifest_root_high,
        manifest_root_low,
        policy_root_high,
        policy_root_low,
        fx_root_high,
        fx_root_low,
        run_nullifier_high,
        run_nullifier_low,
        100,
        200,
        0,
        [51; 32],
        cycle_id,
        7,
        1,
        agreement_leaves,
        payroll_leaves,
        agreements,
        lines,
        policies,
        fx_snapshots,
        [empty_plan(); SHARD_LINES],
    );
}

fn invoke_bound_shard(
    shard_index: u8,
    agreement_leaves: [Field; MAX_LINES],
    payroll_leaves: [Field; MAX_LINES],
    agreements: [AgreementWitness; SHARD_AGREEMENTS],
    lines: [PayrollLine; SHARD_LINES],
) {
    let mut policies = [empty_policy_slot(); MAX_POLICIES];
    policies[0] = valid_policy_slot();
    let mut fx_snapshots = [empty_fx_slot(); MAX_FX_SNAPSHOTS];
    fx_snapshots[0] = valid_fx_slot();
    let mut cycle_id: [u8; 64] = [0; 64];
    cycle_id[0] = 50;
    cycle_id[1] = 48;
    cycle_id[2] = 50;
    cycle_id[3] = 54;
    cycle_id[4] = 45;
    cycle_id[5] = 48;
    cycle_id[6] = 56;
    let agreement_root = proof_merkle_root(agreement_leaves).to_be_bytes();
    let payroll_root = proof_merkle_root(payroll_leaves).to_be_bytes();
    let policy_root = proof_root_from_membership(
        hash_policy_program(valid_program()),
        first_catalog_membership(),
    )
        .to_be_bytes();
    let fx_root = proof_root_from_membership(
        hash_fx_snapshot(valid_snapshot()),
        first_catalog_membership(),
    )
        .to_be_bytes();
    let nullifier = valid_nullifier();
    main(
        1,
        1,
        1,
        1,
        high_limb(agreement_root),
        low_limb(agreement_root),
        high_limb(payroll_root),
        low_limb(payroll_root),
        high_limb(policy_root),
        low_limb(policy_root),
        high_limb(fx_root),
        low_limb(fx_root),
        high_limb(nullifier),
        low_limb(nullifier),
        100,
        200,
        shard_index,
        [51; 32],
        cycle_id,
        7,
        1,
        agreement_leaves,
        payroll_leaves,
        agreements,
        lines,
        policies,
        fx_snapshots,
        [empty_plan(); SHARD_LINES],
    );
}

fn valid_public_roots() -> [[u8; 32]; 5] {
    let agreement = valid_agreement();
    let line = valid_line();
    let policy = valid_program();
    let mut agreement_leaves = [PROOF_EMPTY_LEAF; MAX_LINES];
    agreement_leaves[0] = proof_hash_agreement_terms(agreement);
    let mut manifest_leaves = [PROOF_EMPTY_LEAF; MAX_LINES];
    manifest_leaves[0] = proof_hash_payroll_line(line, proof_hash_agreement_terms(agreement));
    [
        proof_merkle_root(agreement_leaves).to_be_bytes(),
        proof_merkle_root(manifest_leaves).to_be_bytes(),
        proof_root_from_membership(hash_policy_program(policy), first_catalog_membership())
            .to_be_bytes(),
        proof_root_from_membership(
            hash_fx_snapshot(valid_snapshot()),
            first_catalog_membership(),
        )
            .to_be_bytes(),
        valid_nullifier(),
    ]
}

#[test]
fn legacy_keccak_empty_tree_matches_cross_language_vector() {
    let mut leaves = [EMPTY_LEAF; MAX_LINES];
    leaves[0] = [
        227, 148, 180, 125, 92, 114, 78, 100, 101, 165, 225, 165, 34, 213, 156, 32, 242, 58, 167,
        135, 61, 173, 51, 178, 202, 200, 181, 2, 114, 33, 38, 1,
    ];
    let root = merkle_root(leaves);
    let expected = [
        85, 218, 152, 239, 242, 83, 224, 55, 206, 123, 240, 63, 143, 148, 177, 32, 84, 121, 133,
        131, 171, 168, 18, 19, 140, 166, 98, 77, 146, 79, 50, 133,
    ];
    assert(root == expected);
}

#[test]
fn proof_empty_leaf_matches_poseidon2_vector() {
    assert(proof_hash(PROOF_DOMAIN_EMPTY, []) == PROOF_EMPTY_LEAF);
}

#[test]
fn final_main_accepts_bound_obligation_catalogs_and_nullifier() {
    let mut agreements = [empty_agreement(); SHARD_AGREEMENTS];
    agreements[0] = valid_agreement();
    let mut lines = [empty_line(); SHARD_LINES];
    lines[0] = valid_line();
    let roots = valid_public_roots();
    invoke_valid_main(
        high_limb(roots[0]),
        low_limb(roots[0]),
        high_limb(roots[1]),
        low_limb(roots[1]),
        high_limb(roots[2]),
        low_limb(roots[2]),
        high_limb(roots[3]),
        low_limb(roots[3]),
        high_limb(roots[4]),
        low_limb(roots[4]),
        agreements,
        lines,
    );
}

#[test]
fn shard_one_accepts_the_same_roots_when_the_second_half_is_empty() {
    let mut agreement_leaves = [PROOF_EMPTY_LEAF; MAX_LINES];
    agreement_leaves[0] = proof_hash_agreement_terms(valid_agreement());
    let mut payroll_leaves = [PROOF_EMPTY_LEAF; MAX_LINES];
    payroll_leaves[0] =
        proof_hash_payroll_line(valid_line(), proof_hash_agreement_terms(valid_agreement()));
    invoke_bound_shard(
        1,
        agreement_leaves,
        payroll_leaves,
        [empty_agreement(); SHARD_AGREEMENTS],
        [empty_line(); SHARD_LINES],
    );
}

#[test]
fn shard_one_accepts_the_private_cross_boundary_overlap() {
    let mut first = valid_agreement();
    first.id_commitment = [1; 32];
    let mut second = valid_agreement();
    second.id_commitment = [2; 32];
    let mut agreement_leaves = [PROOF_EMPTY_LEAF; MAX_LINES];
    agreement_leaves[24] = proof_hash_agreement_terms(first);
    agreement_leaves[25] = proof_hash_agreement_terms(second);
    let mut payroll_leaves = [PROOF_EMPTY_LEAF; MAX_LINES];
    payroll_leaves[25] = proof_hash_payroll_line(valid_line(), agreement_leaves[25]);
    let mut agreements = [empty_agreement(); SHARD_AGREEMENTS];
    agreements[0] = first;
    agreements[1] = second;
    let mut lines = [empty_line(); SHARD_LINES];
    lines[0] = valid_line();
    invoke_bound_shard(1, agreement_leaves, payroll_leaves, agreements, lines);
}

#[test(should_fail_with = "invalid payroll shard")]
fn rejects_an_unknown_shard_index() {
    invoke_bound_shard(
        2,
        [PROOF_EMPTY_LEAF; MAX_LINES],
        [PROOF_EMPTY_LEAF; MAX_LINES],
        [empty_agreement(); SHARD_AGREEMENTS],
        [empty_line(); SHARD_LINES],
    );
}

#[test(should_fail_with = "shard agreement leaf mismatch")]
fn shard_one_rejects_a_leaf_outside_its_private_witness() {
    let mut agreement_leaves = [PROOF_EMPTY_LEAF; MAX_LINES];
    agreement_leaves[24] = 1;
    invoke_bound_shard(
        1,
        agreement_leaves,
        [PROOF_EMPTY_LEAF; MAX_LINES],
        [empty_agreement(); SHARD_AGREEMENTS],
        [empty_line(); SHARD_LINES],
    );
}

#[test]
fn payroll_leaf_matches_typescript_golden_vector() {
    let mut line = empty_line();
    line.active = true;
    let mut agreement = valid_agreement();
    agreement.id_commitment = [
        214, 188, 151, 147, 134, 89, 81, 32, 139, 34, 25, 72, 134, 2, 153, 240, 136, 144, 229, 198,
        254, 171, 186, 219, 42, 233, 240, 50, 118, 81, 133, 216,
    ];
    agreement.recipient_commitment = [
        4, 143, 107, 224, 205, 92, 232, 113, 85, 13, 228, 209, 109, 98, 227, 72, 245, 183, 146, 28,
        93, 145, 248, 143, 201, 32, 143, 149, 17, 86, 22, 87,
    ];
    agreement.earnings = [1000000, 250000, 0, 0, 0, 0, 0, 0];
    agreement.earnings_count = 2;
    line.deductions = [100000, 0, 0, 0, 0, 0, 0, 0];
    line.deductions_count = 1;
    agreement.token = 1;
    agreement.schedule_commitment = [17; 32];
    line.salt = [34; 32];
    let policy_commitment = [
        131, 46, 245, 7, 100, 25, 130, 244, 174, 180, 9, 97, 101, 148, 32, 250, 45, 50, 37, 65, 170,
        233, 139, 58, 28, 16, 168, 210, 122, 241, 1, 245,
    ];
    let expected = [
        227, 148, 180, 125, 92, 114, 78, 100, 101, 165, 225, 165, 34, 213, 156, 32, 242, 58, 167,
        135, 61, 173, 51, 178, 202, 200, 181, 2, 114, 33, 38, 1,
    ];
    assert(hash_payroll_line(line, agreement, 1250000, 100000, policy_commitment) == expected);
}

#[test(should_fail_with = "due agreement coverage mismatch")]
fn rejects_omitted_due_agreement_in_main() {
    let mut agreements = [empty_agreement(); SHARD_AGREEMENTS];
    agreements[0] = valid_agreement();
    let lines = [empty_line(); SHARD_LINES];
    let roots = valid_public_roots();
    invoke_valid_main(
        high_limb(roots[0]),
        low_limb(roots[0]),
        high_limb(roots[1]),
        low_limb(roots[1]),
        high_limb(roots[2]),
        low_limb(roots[2]),
        high_limb(roots[3]),
        low_limb(roots[3]),
        high_limb(roots[4]),
        low_limb(roots[4]),
        agreements,
        lines,
    );
}

#[test(should_fail_with = "policy does not match agreement")]
fn rejects_uncommitted_policy_selection() {
    let line = valid_line();
    let mut agreement = valid_agreement();
    agreement.policy_commitment = [9; 32];
    let policy = valid_program();
    let _ = validate_active_line(
        line,
        agreement,
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
}

#[test(should_fail_with = "recipient commitment is zero")]
fn rejects_zero_committed_recipient() {
    let line = valid_line();
    let mut agreement = valid_agreement();
    agreement.recipient_commitment = ZERO_BYTES;
    let policy = valid_program();
    let _ = validate_active_line(
        line,
        agreement,
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
}

#[test(should_fail_with = "active line has no earnings")]
fn rejects_committed_agreement_without_earnings() {
    let line = valid_line();
    let mut agreement = valid_agreement();
    agreement.earnings = [0; MAX_COMPONENTS];
    agreement.earnings_count = 0;
    let policy = valid_program();
    let _ = validate_active_line(
        line,
        agreement,
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
}

#[test(should_fail_with = "deductions exceed gross")]
fn rejects_deductions_above_gross() {
    let mut line = valid_line();
    line.deductions[0] = 101;
    let policy = valid_program();
    let _ = validate_active_line(
        line,
        valid_agreement(),
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
}

#[test]
fn validates_contractor_classification_branch() {
    let mut line = valid_line();
    line.classification_treatment = 2;
    let mut agreement = valid_agreement();
    agreement.classification_declared = 2;
    agreement.classification_score = 2;
    let policy = valid_program();
    let leaf = validate_active_line(
        line,
        agreement,
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
    assert(leaf != 0);
}

#[test]
fn validates_complete_final_pay_components() {
    let mut line = valid_line();
    line.final_included_mask = 3;
    let mut agreement = valid_agreement();
    agreement.final_pay_mode = true;
    agreement.final_required_mask = 3;
    agreement.final_components[0] = 70;
    agreement.final_components[1] = 30;
    let policy = valid_program();
    let leaf = validate_active_line(
        line,
        agreement,
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
    assert(leaf != 0);
}

#[test]
fn fx_conversion_uses_canonical_floor_rounding() {
    let mut line = valid_line();
    line.reference_value_atomic = 22;
    let mut snapshot = valid_snapshot();
    snapshot.price_numerator = 1;
    snapshot.price_denominator = 4;
    let policy = valid_program();
    let leaf = validate_active_line(
        line,
        valid_agreement(),
        policy,
        hash_policy_program(policy),
        snapshot,
        100,
    );
    assert(leaf != 0);
}

#[test(should_fail_with = "root high limb mismatch")]
fn rejects_wrong_policy_catalog_root() {
    let policy = valid_program();
    let root = proof_root_from_membership(hash_policy_program(policy), first_catalog_membership());
    let root_bytes = root.to_be_bytes();
    assert_field_root_limbs(root, 0, low_limb(root_bytes));
}

#[test(should_fail_with = "root low limb mismatch")]
fn rejects_wrong_fx_catalog_root() {
    let root = proof_root_from_membership(
        hash_fx_snapshot(valid_snapshot()),
        first_catalog_membership(),
    );
    let root_bytes = root.to_be_bytes();
    assert_field_root_limbs(root, high_limb(root_bytes), 0);
}

#[test(should_fail_with = "disabled agreement recipient must be zero")]
fn rejects_noncanonical_agreement_padding() {
    let mut agreement = empty_agreement();
    agreement.recipient_commitment = [1; 32];
    assert_disabled_agreement(agreement);
}

#[test(should_fail_with = "inactive reference value must be zero")]
fn rejects_noncanonical_line_padding() {
    let mut line = empty_line();
    line.reference_value_atomic = 1;
    assert_inactive_line(line);
}

#[test]
fn validates_committed_policy_fx_and_line() {
    let line = valid_line();
    let policy = valid_program();
    let snapshot = valid_snapshot();
    let leaf = validate_active_line(
        line,
        valid_agreement(),
        policy,
        hash_policy_program(policy),
        snapshot,
        100,
    );
    assert(leaf != 0);
}

#[test]
fn agreement_terms_match_typescript_golden_vector() {
    let expected = [
        228, 43, 169, 88, 146, 103, 215, 118, 98, 61, 107, 71, 145, 102, 140, 188, 225, 109, 88,
        110, 18, 228, 153, 163, 112, 88, 252, 208, 127, 73, 226, 120,
    ];
    assert(hash_agreement_terms(valid_agreement()) == expected);
}

#[test]
fn policy_program_applies_exact_deductions() {
    assert(evaluate_policy(valid_program(), 100, [100, 0, 0, 0, 0, 0, 0, 0]) == 10);
}

#[test]
fn compiled_policy_matches_typescript_golden_vector() {
    let mut program = empty_program();
    program.metadata_commitment = [
        209, 122, 63, 12, 83, 237, 5, 24, 93, 40, 43, 190, 162, 176, 204, 98, 118, 176, 137, 124,
        48, 49, 138, 182, 155, 155, 96, 32, 223, 209, 217, 45,
    ];
    program.instruction_count = 16;
    program.opcodes = [2, 1, 7, 6, 1, 7, 1, 8, 5, 6, 4, 1, 8, 5, 6, 4];
    program.left = [0, 0, 0, 2, 0, 0, 0, 5, 7, 8, 3, 0, 0, 12, 13, 10];
    program.right = [0, 0, 1, 0, 0, 4, 0, 6, 6, 0, 9, 0, 11, 11, 0, 14];
    program.immediate = [0, 1000, 0, 0, 5000, 0, 1000, 0, 0, 0, 0, 5000, 0, 0, 0, 0];
    program.numerator = [0, 0, 0, 1000, 0, 0, 0, 0, 0, 2000, 0, 0, 0, 0, 3000, 0];
    program.denominator = [0, 0, 0, 10000, 0, 0, 0, 0, 0, 10000, 0, 0, 0, 0, 10000, 0];
    program.output_register = 15;
    let expected = [
        135, 223, 179, 220, 102, 49, 253, 83, 129, 1, 3, 246, 169, 226, 222, 106, 32, 220, 83, 163,
        7, 237, 106, 100, 11, 211, 99, 253, 188, 104, 153, 237,
    ];
    assert(hash_policy_program(program) == expected);
    assert(evaluate_policy(program, 6000, [6000, 0, 0, 0, 0, 0, 0, 0]) == 1200);
}

#[test]
fn fx_snapshot_matches_typescript_golden_vector() {
    let snapshot = FxSnapshot {
        token: 0,
        token_decimals: 18,
        reference_currency: 0,
        quote_decimals: 6,
        feed_commitment: [
            241, 149, 156, 106, 86, 57, 133, 154, 227, 183, 226, 234, 102, 114, 1, 25, 148, 162,
            200, 44, 48, 116, 180, 13, 162, 234, 184, 246, 253, 45, 0, 120,
        ],
        sources_commitment: [
            207, 106, 242, 86, 243, 20, 120, 44, 55, 59, 103, 243, 120, 118, 132, 168, 144, 58, 10,
            8, 232, 200, 201, 91, 161, 150, 206, 241, 112, 184, 203, 156,
        ],
        price_numerator: 1000000,
        price_denominator: 1000000000000000000,
        observed_at: 1787479180,
        source_count: 3,
        minimum_source_count: 3,
        maximum_age_seconds: 60,
        haircut_bps: 500,
    };
    let expected = [
        174, 15, 215, 33, 128, 120, 15, 40, 155, 252, 81, 152, 219, 56, 245, 5, 14, 235, 199, 66,
        174, 150, 30, 213, 96, 55, 239, 46, 88, 64, 190, 24,
    ];
    assert(hash_fx_snapshot(snapshot) == expected);
}

#[test(should_fail_with = "policy output does not match deductions")]
fn rejects_policy_deduction_mismatch() {
    let mut line = valid_line();
    line.deductions[0] = 11;
    let policy = valid_program();
    let _ = validate_active_line(
        line,
        valid_agreement(),
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
}

#[test(should_fail_with = "policy subtraction underflow")]
fn rejects_policy_underflow() {
    let mut program = empty_program();
    program.metadata_commitment = [1; 32];
    program.instruction_count = 3;
    program.opcodes[0] = 1;
    program.immediate[0] = 1;
    program.opcodes[1] = 1;
    program.immediate[1] = 2;
    program.opcodes[2] = 5;
    program.left[2] = 0;
    program.right[2] = 1;
    program.output_register = 2;
    let _ = evaluate_policy(program, 100, [0; MAX_COMPONENTS]);
}

#[test(should_fail_with = "classification facts mismatch")]
fn rejects_classification_fact_mismatch() {
    let line = valid_line();
    let mut agreement = valid_agreement();
    agreement.classification_declared = 2;
    let policy = valid_program();
    let _ = validate_active_line(
        line,
        agreement,
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
}

#[test(should_fail_with = "classification treatment mismatch")]
fn rejects_classification_treatment_mismatch() {
    let mut line = valid_line();
    line.classification_treatment = 2;
    let policy = valid_program();
    let _ = validate_active_line(
        line,
        valid_agreement(),
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
}

#[test(should_fail_with = "final pay component mask mismatch")]
fn rejects_missing_final_component() {
    let mut line = valid_line();
    line.final_included_mask = 1;
    let mut agreement = valid_agreement();
    agreement.final_pay_mode = true;
    agreement.final_required_mask = 3;
    agreement.final_components[0] = 100;
    let policy = valid_program();
    let _ = validate_active_line(
        line,
        agreement,
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
}

#[test(should_fail_with = "final pay components do not equal gross")]
fn rejects_incorrect_final_component_total() {
    let mut line = valid_line();
    line.final_included_mask = 1;
    let mut agreement = valid_agreement();
    agreement.final_pay_mode = true;
    agreement.final_required_mask = 1;
    agreement.final_components[0] = 99;
    let policy = valid_program();
    let _ = validate_active_line(
        line,
        agreement,
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
}

#[test(should_fail_with = "token decimals mismatch")]
fn rejects_wrong_token_decimals() {
    let mut snapshot = valid_snapshot();
    snapshot.token_decimals = 6;
    let policy = valid_program();
    let _ = validate_active_line(
        valid_line(),
        valid_agreement(),
        policy,
        hash_policy_program(policy),
        snapshot,
        100,
    );
}

#[test(should_fail_with = "FX quote decimals mismatch")]
fn rejects_wrong_quote_decimals() {
    let mut snapshot = valid_snapshot();
    snapshot.quote_decimals = 18;
    let policy = valid_program();
    let _ = validate_active_line(
        valid_line(),
        valid_agreement(),
        policy,
        hash_policy_program(policy),
        snapshot,
        100,
    );
}

#[test(should_fail_with = "insufficient FX sources")]
fn rejects_insufficient_fx_sources() {
    let mut snapshot = valid_snapshot();
    snapshot.source_count = 1;
    let policy = valid_program();
    let _ = validate_active_line(
        valid_line(),
        valid_agreement(),
        policy,
        hash_policy_program(policy),
        snapshot,
        100,
    );
}

#[test(should_fail_with = "FX snapshot is stale")]
fn rejects_stale_fx_snapshot() {
    let mut snapshot = valid_snapshot();
    snapshot.observed_at = 70;
    let policy = valid_program();
    let _ = validate_active_line(
        valid_line(),
        valid_agreement(),
        policy,
        hash_policy_program(policy),
        snapshot,
        100,
    );
}

#[test(should_fail_with = "FX snapshot is from the future")]
fn rejects_future_fx_snapshot() {
    let mut snapshot = valid_snapshot();
    snapshot.observed_at = 101;
    let policy = valid_program();
    let _ = validate_active_line(
        valid_line(),
        valid_agreement(),
        policy,
        hash_policy_program(policy),
        snapshot,
        100,
    );
}

#[test(should_fail_with = "FX floor not met")]
fn rejects_fx_floor_shortfall() {
    let line = valid_line();
    let mut agreement = valid_agreement();
    agreement.fx_floor_atomic = 91;
    let policy = valid_program();
    let _ = validate_active_line(
        line,
        agreement,
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
}

#[test(should_fail_with = "schedule commitment is zero")]
fn rejects_zero_committed_schedule() {
    let line = valid_line();
    let mut agreement = valid_agreement();
    agreement.schedule_commitment = ZERO_BYTES;
    let policy = valid_program();
    let _ = validate_active_line(
        line,
        agreement,
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
}

#[test(should_fail_with = "obligation is not due")]
fn rejects_early_obligation() {
    let line = valid_line();
    let mut agreement = valid_agreement();
    agreement.due_at = 101;
    let policy = valid_program();
    let _ = validate_active_line(
        line,
        agreement,
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
}

#[test(should_fail_with = "agreement is expired")]
fn rejects_expired_obligation() {
    let mut agreement = valid_agreement();
    agreement.valid_until = 99;
    let policy = valid_program();
    let _ = validate_active_line(
        valid_line(),
        agreement,
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
}

#[test(should_fail_with = "FX token mismatch")]
fn rejects_fx_snapshot_for_another_token() {
    let mut snapshot = valid_snapshot();
    snapshot.token = 1;
    let policy = valid_program();
    let _ = validate_active_line(
        valid_line(),
        valid_agreement(),
        policy,
        hash_policy_program(policy),
        snapshot,
        100,
    );
}

#[test(should_fail_with = "FX reference value mismatch")]
fn rejects_incorrect_fx_conversion() {
    let mut line = valid_line();
    line.reference_value_atomic = 89;
    let policy = valid_program();
    let _ = validate_active_line(
        line,
        valid_agreement(),
        policy,
        hash_policy_program(policy),
        valid_snapshot(),
        100,
    );
}

#[test(should_fail_with = "agreements must be sorted and unique")]
fn rejects_unsorted_agreements() {
    assert(bytes_less_than([2; 32], [1; 32]), "agreements must be sorted and unique");
}

#[test(should_fail_with = "agreements must be sorted and unique")]
fn rejects_duplicate_agreements_in_main() {
    let mut agreements = [empty_agreement(); SHARD_AGREEMENTS];
    agreements[0] = valid_agreement();
    agreements[1] = valid_agreement();
    let mut lines = [empty_line(); SHARD_LINES];
    lines[0] = valid_line();
    lines[1] = valid_line();
    let roots = valid_public_roots();
    invoke_valid_main(
        high_limb(roots[0]),
        low_limb(roots[0]),
        high_limb(roots[1]),
        low_limb(roots[1]),
        high_limb(roots[2]),
        low_limb(roots[2]),
        high_limb(roots[3]),
        low_limb(roots[3]),
        high_limb(roots[4]),
        low_limb(roots[4]),
        agreements,
        lines,
    );
}

#[test]
fn run_nullifier_matches_v1_golden_vector() {
    let organization_secret = [51; 32];
    let mut cycle_id: [u8; 64] = [0; 64];
    cycle_id[0] = 50;
    cycle_id[1] = 48;
    cycle_id[2] = 50;
    cycle_id[3] = 54;
    cycle_id[4] = 45;
    cycle_id[5] = 48;
    cycle_id[6] = 56;
    let expected = [
        62, 222, 34, 213, 184, 148, 129, 144, 77, 36, 173, 9, 234, 231, 102, 108, 116, 31, 20, 52,
        109, 175, 80, 197, 131, 42, 91, 74, 173, 74, 185, 202,
    ];
    assert(derive_run_nullifier_v1(organization_secret, cycle_id, 7, 1) == expected);
}

fn base_advanced_plan() -> AdvancedPlanWitness {
    let mut plan = empty_plan();
    plan.enabled = true;
    plan.salt = [3; 32];
    plan
}

fn base_advanced_agreement() -> AgreementWitness {
    AgreementWitness {
        enabled: true,
        id_commitment: [1; 32],
        recipient_commitment: [2; 32],
        earnings: [500, 0, 0, 0, 0, 0, 0, 0],
        earnings_count: 1,
        token: 1,
        policy_commitment: [4; 32],
        schedule_commitment: ZERO_BYTES,
        due_at: 500,
        valid_until: 1000,
        classification_declared: 2,
        classification_score: 2,
        classification_employee_threshold: 5,
        final_pay_mode: false,
        final_required_mask: 0,
        final_components: [0; 5],
        fx_floor_atomic: 0,
        reference_currency: 0,
        salt: [6; 32],
    }
}

#[test]
fn advanced_checkpoint_plan_commitment_is_field_canonical() {
    let mut plan = base_advanced_plan();
    plan.kind = 1;
    plan.minimum_checkpoint_seconds = 300;
    plan.checkpoint_sequence = 1;
    plan.timestamps[2] = 1768089600;
    plan.timestamps[3] = 1767225600;
    plan.timestamps[5] = 1767657600;
    plan.amounts[0] = 1000;
    plan.amounts[2] = 500;
    plan.commitments[2] = [2; 32];
    let expected: [u8; 32] = [
        14, 93, 169, 24, 99, 112, 9, 98, 210, 170, 56, 77, 155, 88, 213, 238,
        12, 30, 123, 40, 164, 114, 85, 173, 81, 216, 57, 45, 244, 77, 222, 124,
    ];
    assert(encode_plan_commitment(plan).to_be_bytes() == expected, "advanced commitment vector mismatch");
}

#[test]
fn validates_exact_checkpoint_entitlement() {
    let mut plan = base_advanced_plan();
    plan.kind = 1;
    plan.minimum_checkpoint_seconds = 300;
    plan.timestamps[2] = 1000;
    plan.timestamps[3] = 0;
    plan.timestamps[5] = 500;
    plan.amounts[0] = 1000;
    plan.amounts[1] = 0;
    plan.amounts[2] = 500;
    plan.commitments[2] = [7; 32];
    let mut agreement = base_advanced_agreement();
    agreement.due_at = 500;
    agreement.schedule_commitment = encode_plan_commitment(plan).to_be_bytes();
    validate_advanced_plan(agreement, plan, 500);
}

#[test(should_fail_with = "checkpoint entitlement is forged")]
fn rejects_forged_checkpoint_entitlement() {
    let mut plan = base_advanced_plan();
    plan.kind = 1;
    plan.minimum_checkpoint_seconds = 300;
    plan.timestamps[2] = 1000;
    plan.timestamps[3] = 0;
    plan.timestamps[5] = 500;
    plan.amounts[0] = 1000;
    plan.amounts[2] = 501;
    plan.commitments[2] = [7; 32];
    let mut agreement = base_advanced_agreement();
    agreement.earnings[0] = 501;
    agreement.due_at = 500;
    agreement.schedule_commitment = encode_plan_commitment(plan).to_be_bytes();
    validate_advanced_plan(agreement, plan, 500);
}

#[test(should_fail_with = "milestone is unapproved")]
fn rejects_unapproved_milestone() {
    let mut plan = base_advanced_plan();
    plan.kind = 2;
    plan.timestamps[7] = 500;
    plan.commitments[0] = [1; 32];
    plan.commitments[1] = [2; 32];
    plan.commitments[2] = [3; 32];
    let mut agreement = base_advanced_agreement();
    agreement.schedule_commitment = encode_plan_commitment(plan).to_be_bytes();
    validate_advanced_plan(agreement, plan, 500);
}

#[test(should_fail_with = "termination component is missing")]
fn rejects_incomplete_advanced_final_pay() {
    let mut plan = base_advanced_plan();
    plan.kind = 2;
    plan.flags = 1;
    plan.timestamps[7] = 500;
    plan.timestamps[8] = 400;
    plan.timestamps[11] = 450;
    plan.required_mask = 3;
    plan.included_mask = 1;
    plan.commitments[0] = [1; 32];
    plan.commitments[1] = [2; 32];
    plan.commitments[2] = [3; 32];
    plan.commitments[3] = [4; 32];
    plan.amounts[4] = 500;
    let mut agreement = base_advanced_agreement();
    agreement.final_pay_mode = true;
    agreement.final_required_mask = 3;
    agreement.final_components[0] = 500;
    agreement.schedule_commitment = encode_plan_commitment(plan).to_be_bytes();
    validate_advanced_plan(agreement, plan, 500);
}
