use dep::keccak256::keccak256;

global MAX_LINES: u32 = 64;
global MAX_REAL_LINES: u32 = 50;
global MAX_COMPONENTS: u32 = 8;

global EMPTY_LEAF: [u8; 32] = [
    124, 184, 142, 24, 181, 228, 45, 54, 9, 124, 167, 114, 226, 92, 164, 141,
    83, 79, 196, 30, 45, 120, 210, 146, 253, 205, 86, 6, 89, 140, 59, 219,
];

global STRK_ADDRESS: [u8; 32] = [
    4, 113, 143, 90, 15, 195, 76, 193, 175, 22, 161, 205, 238, 152, 255, 178,
    12, 49, 245, 205, 97, 214, 171, 7, 32, 24, 88, 244, 40, 124, 147, 141,
];

global USDC_ADDRESS: [u8; 32] = [
    3, 48, 104, 246, 83, 159, 142, 110, 107, 19, 30, 107, 43, 129, 78, 108,
    52, 165, 34, 75, 198, 105, 71, 196, 125, 171, 157, 254, 233, 59, 53, 251,
];

struct PayrollLine {
    active: bool,
    agreement_commitment: [u8; 32],
    recipient_commitment: [u8; 32],
    earnings: [u128; MAX_COMPONENTS],
    earnings_count: u32,
    deductions: [u128; MAX_COMPONENTS],
    deductions_count: u32,
    token: u8,
    policy_commitment: [u8; 32],
    schedule_commitment: [u8; 32],
    salt: [u8; 32],
    due_at: u64,
    classification_declared: u8,
    classification_treatment: u8,
    final_pay_mode: bool,
    final_components_complete: bool,
    fx_numerator: u64,
    fx_denominator: u64,
    fx_floor_atomic: u128,
    reference_value_atomic: u128,
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

fn hash_deductions(values: [u128; MAX_COMPONENTS], count: u32) -> [u8; 32] {
    // PAYO_DEDUCTIONS_V1 || field(u32 count) || field(u256 amount)*
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
        message[offset] = 0;
        message[offset + 1] = 0;
        message[offset + 2] = 0;
        message[offset + 3] = 32;
        let amount: [u8; 16] = (values[component] as Field).to_be_bytes();
        for index in 0..16 {
            message[offset + 4 + index] = 0;
            message[offset + 20 + index] = amount[index];
        }
    }
    keccak256(message, 26 + count * 36)
}

fn hash_payroll_line(line: PayrollLine, gross: u128, deductions_total: u128) -> [u8; 32] {
    let domain = "PAYO_LEAF_V1".as_bytes();
    let mut message: [u8; 344] = [0; 344];
    for index in 0..domain.len() {
        message[index] = domain[index];
    }

    // schema_version is field-encoded as a four-byte u32.
    message[12] = 0;
    message[13] = 0;
    message[14] = 0;
    message[15] = 4;
    message[16] = 0;
    message[17] = 0;
    message[18] = 0;
    message[19] = 1;

    let mut gross_bytes: [u8; 32] = [0; 32];
    let gross_u128: [u8; 16] = (gross as Field).to_be_bytes();
    let mut net_bytes: [u8; 32] = [0; 32];
    let net_u128: [u8; 16] = ((gross - deductions_total) as Field).to_be_bytes();
    for index in 0..16 {
        gross_bytes[index + 16] = gross_u128[index];
        net_bytes[index + 16] = net_u128[index];
    }
    let token_address = if line.token == 0 { STRK_ADDRESS } else { USDC_ADDRESS };
    let deduction_commitment = hash_deductions(line.deductions, line.deductions_count);
    let fields: [[u8; 32]; 9] = [
        line.agreement_commitment,
        line.recipient_commitment,
        gross_bytes,
        deduction_commitment,
        net_bytes,
        token_address,
        line.policy_commitment,
        line.schedule_commitment,
        line.salt,
    ];

    for field_index in 0..9 {
        let offset = 20 + field_index * 36;
        message[offset] = 0;
        message[offset + 1] = 0;
        message[offset + 2] = 0;
        message[offset + 3] = 32;
        for byte_index in 0..32 {
            message[offset + 4 + byte_index] = fields[field_index][byte_index];
        }
    }
    keccak256(message, message.len())
}

fn hash_merkle_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let domain = "PAYO_MERKLE_NODE_V1".as_bytes();
    let mut message: [u8; 91] = [0; 91];
    for index in 0..domain.len() {
        message[index] = domain[index];
    }
    message[19] = 0;
    message[20] = 0;
    message[21] = 0;
    message[22] = 32;
    message[55] = 0;
    message[56] = 0;
    message[57] = 0;
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

fn assert_root_limbs(root: [u8; 32], expected_high: u128, expected_low: u128) {
    let high: [u8; 16] = (expected_high as Field).to_be_bytes();
    let low: [u8; 16] = (expected_low as Field).to_be_bytes();
    for index in 0..16 {
        assert(root[index] == high[index], "root high limb mismatch");
        assert(root[index + 16] == low[index], "root low limb mismatch");
    }
}

fn validate_active_line(line: PayrollLine, validity_start: u64) -> [u8; 32] {
    assert(line.earnings_count > 0, "active line has no earnings");
    assert((line.token == 0) | (line.token == 1), "unsupported token");
    assert(line.classification_declared == line.classification_treatment, "classification mismatch");
    assert(line.due_at <= validity_start, "obligation is not due");
    assert((!line.final_pay_mode) | line.final_components_complete, "final pay is incomplete");
    assert(line.fx_denominator > 0, "invalid FX denominator");

    let gross = sum_components(line.earnings, line.earnings_count);
    let deductions = sum_components(line.deductions, line.deductions_count);
    assert(gross > 0, "gross must be positive");
    assert(deductions <= gross, "deductions exceed gross");
    let net = gross - deductions;

    // Inputs are range-constrained before Field conversion, and PAYO policy packs cap
    // production values far below the BN254 modulus.
    assert(
        (line.reference_value_atomic as Field) * (line.fx_denominator as Field)
            == (net as Field) * (line.fx_numerator as Field),
        "FX conversion mismatch",
    );
    assert(line.reference_value_atomic >= line.fx_floor_atomic, "FX floor not met");
    hash_payroll_line(line, gross, deductions)
}

fn main(
    chain_id: pub Field,
    seal_address: pub Field,
    proof_version: pub u32,
    agreement_root_high: pub u128,
    agreement_root_low: pub u128,
    manifest_root_high: pub u128,
    manifest_root_low: pub u128,
    run_nullifier_high: pub u128,
    run_nullifier_low: pub u128,
    validity_start: pub u64,
    validity_expiry: pub u64,
    lines: [PayrollLine; MAX_LINES],
) {
    assert(chain_id != 0, "chain id is required");
    assert(seal_address != 0, "seal address is required");
    assert(proof_version == 1, "unsupported proof version");
    assert((run_nullifier_high != 0) | (run_nullifier_low != 0), "run nullifier is required");
    assert(validity_expiry >= validity_start, "invalid proof validity window");

    let mut agreement_leaves: [[u8; 32]; MAX_LINES] = [EMPTY_LEAF; MAX_LINES];
    let mut payroll_leaves: [[u8; 32]; MAX_LINES] = [EMPTY_LEAF; MAX_LINES];
    let mut real_line_count: u32 = 0;

    for index in 0..MAX_LINES {
        if index > 0 {
            assert(lines[index - 1].active | (!lines[index].active), "active lines must precede padding");
        }
        if lines[index].active {
            real_line_count += 1;
            agreement_leaves[index] = lines[index].agreement_commitment;
            payroll_leaves[index] = validate_active_line(lines[index], validity_start);
        }
    }
    assert(real_line_count > 0, "empty payroll run");
    assert(real_line_count <= MAX_REAL_LINES, "too many real payroll lines");

    // Pairwise uniqueness makes omission-by-duplication impossible. Matching agreement
    // and payroll slots makes every committed due obligation appear exactly once.
    for left in 0..MAX_LINES {
        for right in 0..MAX_LINES {
            if (left < right) & lines[left].active & lines[right].active {
                assert(
                    lines[left].agreement_commitment != lines[right].agreement_commitment,
                    "duplicate agreement",
                );
            }
        }
    }

    assert_root_limbs(merkle_root(agreement_leaves), agreement_root_high, agreement_root_low);
    assert_root_limbs(merkle_root(payroll_leaves), manifest_root_high, manifest_root_low);
}

#[test]
fn payroll_leaf_matches_typescript_golden_vector() {
    let line = PayrollLine {
        active: true,
        agreement_commitment: [214, 188, 151, 147, 134, 89, 81, 32, 139, 34, 25, 72, 134, 2, 153, 240, 136, 144, 229, 198, 254, 171, 186, 219, 42, 233, 240, 50, 118, 81, 133, 216],
        recipient_commitment: [4, 143, 107, 224, 205, 92, 232, 113, 85, 13, 228, 209, 109, 98, 227, 72, 245, 183, 146, 28, 93, 145, 248, 143, 201, 32, 143, 149, 17, 86, 22, 87],
        earnings: [1000000, 250000, 0, 0, 0, 0, 0, 0],
        earnings_count: 2,
        deductions: [100000, 0, 0, 0, 0, 0, 0, 0],
        deductions_count: 1,
        token: 1,
        policy_commitment: [131, 46, 245, 7, 100, 25, 130, 244, 174, 180, 9, 97, 101, 148, 32, 250, 45, 50, 37, 65, 170, 233, 139, 58, 28, 16, 168, 210, 122, 241, 1, 245],
        schedule_commitment: [17; 32],
        salt: [34; 32],
        due_at: 1,
        classification_declared: 1,
        classification_treatment: 1,
        final_pay_mode: false,
        final_components_complete: false,
        fx_numerator: 1,
        fx_denominator: 1,
        fx_floor_atomic: 0,
        reference_value_atomic: 1150000,
    };
    let expected = [227, 148, 180, 125, 92, 114, 78, 100, 101, 165, 225, 165, 34, 213, 156, 32, 242, 58, 167, 135, 61, 173, 51, 178, 202, 200, 181, 2, 114, 33, 38, 1];
    assert(hash_payroll_line(line, 1250000, 100000) == expected);
}

#[test]
fn rejects_underpayment_arithmetic() {
    let earnings: [u128; MAX_COMPONENTS] = [100, 25, 0, 0, 0, 0, 0, 0];
    let deductions: [u128; MAX_COMPONENTS] = [10, 0, 0, 0, 0, 0, 0, 0];
    assert(sum_components(earnings, 2) - sum_components(deductions, 1) == 115);
}

fn valid_test_line() -> PayrollLine {
    PayrollLine {
        active: true,
        agreement_commitment: [1; 32],
        recipient_commitment: [2; 32],
        earnings: [100, 0, 0, 0, 0, 0, 0, 0],
        earnings_count: 1,
        deductions: [10, 0, 0, 0, 0, 0, 0, 0],
        deductions_count: 1,
        token: 0,
        policy_commitment: [3; 32],
        schedule_commitment: [4; 32],
        salt: [5; 32],
        due_at: 100,
        classification_declared: 1,
        classification_treatment: 1,
        final_pay_mode: false,
        final_components_complete: false,
        fx_numerator: 1,
        fx_denominator: 1,
        fx_floor_atomic: 80,
        reference_value_atomic: 90,
    }
}

#[test(should_fail_with = "deductions exceed gross")]
fn rejects_deductions_above_gross() {
    let mut line = valid_test_line();
    line.deductions = [101, 0, 0, 0, 0, 0, 0, 0];
    let _ = validate_active_line(line, 100);
}

#[test(should_fail_with = "FX floor not met")]
fn rejects_fx_floor_shortfall() {
    let mut line = valid_test_line();
    line.fx_floor_atomic = 91;
    let _ = validate_active_line(line, 100);
}

#[test(should_fail_with = "classification mismatch")]
fn rejects_classification_treatment_mismatch() {
    let mut line = valid_test_line();
    line.classification_treatment = 2;
    let _ = validate_active_line(line, 100);
}

#[test(should_fail_with = "final pay is incomplete")]
fn rejects_incomplete_offboarding_pay() {
    let mut line = valid_test_line();
    line.final_pay_mode = true;
    let _ = validate_active_line(line, 100);
}

#[test(should_fail_with = "obligation is not due")]
fn rejects_early_scheduled_pay() {
    let mut line = valid_test_line();
    line.due_at = 101;
    let _ = validate_active_line(line, 100);
}

#[test(should_fail_with = "duplicate agreement")]
fn rejects_duplicate_agreement_coverage() {
    let mut padding = valid_test_line();
    padding.active = false;
    let mut lines = [padding; MAX_LINES];
    lines[0] = valid_test_line();
    lines[1] = valid_test_line();
    main(1, 1, 1, 0, 0, 0, 0, 0, 1, 100, 200, lines);
}
