use dep::keccak256::keccak256;

pub fn claim_capability_commitment_v2(secret: [u8; 32]) -> [u8; 32] {
    let domain = "PAYO_CLAIM_CAPABILITY_V2".as_bytes();
    let mut message: [u8; 56] = [0; 56];
    for index in 0..domain.len() { message[index] = domain[index]; }
    for index in 0..32 { message[domain.len() + index] = secret[index]; }
    keccak256(message, message.len())
}

pub fn obligation_snapshot_commitment_v2(
    schema_version: u8,
    run_nullifier: [u8; 32],
    base_agreement_root: [u8; 32],
    obligation_root: [u8; 32],
    policy_root: [u8; 32],
    owner_address: [u8; 32],
    due_at: u64,
    grace_ends_at: u64,
    claim_ends_at: u64,
    availability_commitment: [u8; 32],
) -> [u8; 32] {
    let domain = "PAYO_OBLIGATION_SNAPSHOT_V2".as_bytes();
    let mut message: [u8; 244] = [0; 244];
    let mut cursor: u32 = domain.len();
    for index in 0..domain.len() { message[index] = domain[index]; }
    message[cursor] = schema_version;
    cursor += 1;
    for index in 0..32 {
        message[cursor + index] = run_nullifier[index];
        message[cursor + 32 + index] = base_agreement_root[index];
        message[cursor + 64 + index] = obligation_root[index];
        message[cursor + 96 + index] = policy_root[index];
        message[cursor + 128 + index] = owner_address[index];
    }
    cursor += 160;
    let due_bytes: [u8; 8] = (due_at as Field).to_be_bytes();
    let grace_bytes: [u8; 8] = (grace_ends_at as Field).to_be_bytes();
    let claim_bytes: [u8; 8] = (claim_ends_at as Field).to_be_bytes();
    for index in 0..8 {
        message[cursor + index] = due_bytes[index];
        message[cursor + 8 + index] = grace_bytes[index];
        message[cursor + 16 + index] = claim_bytes[index];
    }
    cursor += 24;
    for index in 0..32 { message[cursor + index] = availability_commitment[index]; }
    cursor += 32;
    assert(cursor == message.len(), "snapshot encoding length mismatch");
    keccak256(message, cursor)
}

pub fn payroll_statement_commitment_v2(
    schema_version: u8,
    run_nullifier: [u8; 32],
    snapshot_commitment: [u8; 32],
    manifest_root: [u8; 32],
    fx_root: [u8; 32],
    availability_commitment: [u8; 32],
    observed_at: u64,
    source: u8,
) -> [u8; 32] {
    let domain = "PAYO_PAYROLL_STATEMENT_V2".as_bytes();
    let mut message: [u8; 195] = [0; 195];
    let mut cursor: u32 = domain.len();
    for index in 0..domain.len() { message[index] = domain[index]; }
    message[cursor] = schema_version;
    cursor += 1;
    for index in 0..32 {
        message[cursor + index] = run_nullifier[index];
        message[cursor + 32 + index] = snapshot_commitment[index];
        message[cursor + 64 + index] = manifest_root[index];
        message[cursor + 96 + index] = fx_root[index];
        message[cursor + 128 + index] = availability_commitment[index];
    }
    cursor += 160;
    let observed_bytes: [u8; 8] = (observed_at as Field).to_be_bytes();
    for index in 0..8 { message[cursor + index] = observed_bytes[index]; }
    cursor += 8;
    message[cursor] = source;
    cursor += 1;
    assert(cursor == message.len(), "statement encoding length mismatch");
    keccak256(message, cursor)
}

pub fn claim_subject_nullifier_v2(
    claim_capability_secret: [u8; 32],
    run_nullifier: [u8; 32],
    agreement_leaf: [u8; 32],
    claim_kind: u8,
) -> [u8; 32] {
    let domain = "PAYO_CLAIM_SUBJECT_V2".as_bytes();
    let mut message: [u8; 118] = [0; 118];
    let mut cursor: u32 = domain.len();
    for index in 0..domain.len() { message[index] = domain[index]; }
    for index in 0..32 {
        message[cursor + index] = claim_capability_secret[index];
        message[cursor + 32 + index] = run_nullifier[index];
        message[cursor + 64 + index] = agreement_leaf[index];
    }
    cursor += 96;
    message[cursor] = claim_kind;
    cursor += 1;
    assert(cursor == message.len(), "claim subject encoding length mismatch");
    keccak256(message, cursor)
}

pub fn claim_fact_commitment_v2(
    claim_subject_nullifier: [u8; 32],
    run_nullifier: [u8; 32],
    snapshot_commitment: [u8; 32],
    statement_commitment: [u8; 32],
    manifest_root: [u8; 32],
    agreement_leaf: [u8; 32],
    target_index: u8,
    claim_kind: u8,
    shortfall_atomic: u128,
    shortfall_unit: u8,
    obligation_token: u8,
    evidence_source: u8,
) -> [u8; 32] {
    let domain = "PAYO_CLAIM_FACT_V2".as_bytes();
    let mut message: [u8; 231] = [0; 231];
    let mut cursor: u32 = domain.len();
    for index in 0..domain.len() { message[index] = domain[index]; }
    for index in 0..32 {
        message[cursor + index] = claim_subject_nullifier[index];
        message[cursor + 32 + index] = run_nullifier[index];
        message[cursor + 64 + index] = snapshot_commitment[index];
        message[cursor + 96 + index] = statement_commitment[index];
        message[cursor + 128 + index] = manifest_root[index];
        message[cursor + 160 + index] = agreement_leaf[index];
    }
    cursor += 192;
    message[cursor] = target_index;
    message[cursor + 1] = claim_kind;
    cursor += 2;
    let shortfall_bytes: [u8; 16] = (shortfall_atomic as Field).to_be_bytes();
    for index in 0..16 { message[cursor + index] = shortfall_bytes[index]; }
    cursor += 16;
    message[cursor] = shortfall_unit;
    message[cursor + 1] = obligation_token;
    message[cursor + 2] = evidence_source;
    cursor += 3;
    assert(cursor == message.len(), "claim fact encoding length mismatch");
    keccak256(message, cursor)
}

pub fn remediation_subject_nullifier_v2(
    claim_subject_nullifier: [u8; 32],
    remediation_secret: [u8; 32],
) -> [u8; 32] {
    let domain = "PAYO_REMEDIATION_SUBJECT_V2".as_bytes();
    let mut message: [u8; 91] = [0; 91];
    let mut cursor: u32 = domain.len();
    for index in 0..domain.len() { message[index] = domain[index]; }
    for index in 0..32 {
        message[cursor + index] = claim_subject_nullifier[index];
        message[cursor + 32 + index] = remediation_secret[index];
    }
    cursor += 64;
    assert(cursor == message.len(), "remediation subject encoding length mismatch");
    keccak256(message, cursor)
}

pub fn remediation_fact_commitment_v2(
    remediation_subject_nullifier: [u8; 32],
    claim_subject_nullifier: [u8; 32],
    claim_fact_commitment: [u8; 32],
    recipient_commitment: [u8; 32],
    token: u8,
    amount_atomic: u128,
    reference_value_atomic: u128,
    reference_unit: u8,
    fx_root: [u8; 32],
) -> [u8; 32] {
    let domain = "PAYO_REMEDIATION_FACT_V2".as_bytes();
    let mut message: [u8; 218] = [0; 218];
    let mut cursor: u32 = domain.len();
    for index in 0..domain.len() { message[index] = domain[index]; }
    for index in 0..32 {
        message[cursor + index] = remediation_subject_nullifier[index];
        message[cursor + 32 + index] = claim_subject_nullifier[index];
        message[cursor + 64 + index] = claim_fact_commitment[index];
        message[cursor + 96 + index] = recipient_commitment[index];
    }
    cursor += 128;
    message[cursor] = token;
    cursor += 1;
    let amount_bytes: [u8; 16] = (amount_atomic as Field).to_be_bytes();
    let reference_bytes: [u8; 16] = (reference_value_atomic as Field).to_be_bytes();
    for index in 0..16 {
        message[cursor + index] = amount_bytes[index];
        message[cursor + 16 + index] = reference_bytes[index];
    }
    cursor += 32;
    message[cursor] = reference_unit;
    cursor += 1;
    for index in 0..32 { message[cursor + index] = fx_root[index]; }
    cursor += 32;
    assert(cursor == message.len(), "remediation fact encoding length mismatch");
    keccak256(message, cursor)
}

#[test]
fn exception_v2_commitments_match_typescript_and_cairo() {
    let run = [17; 32];
    let mut owner = [0; 32];
    owner[30] = 0x12;
    owner[31] = 0x34;
    let snapshot = obligation_snapshot_commitment_v2(
        2, run, [33; 32], [34; 32], [51; 32],
        owner,
        100, 200, 500, [68; 32],
    );
    assert(snapshot == [247, 87, 57, 166, 46, 51, 56, 214, 138, 241, 195, 12, 152, 215, 2, 155, 211, 43, 162, 159, 198, 31, 185, 174, 253, 181, 96, 213, 214, 172, 138, 196], "snapshot vector mismatch");
    let statement = payroll_statement_commitment_v2(
        2, run, snapshot, [85; 32], [102; 32], [119; 32], 210, 2,
    );
    assert(statement == [167, 150, 141, 109, 146, 219, 95, 245, 226, 156, 140, 218, 46, 193, 207, 113, 77, 228, 136, 94, 103, 177, 211, 83, 167, 66, 138, 10, 70, 181, 168, 107], "statement vector mismatch");
    let capability_secret = [136; 32];
    assert(claim_capability_commitment_v2(capability_secret) == [23, 226, 161, 4, 80, 228, 124, 90, 52, 161, 239, 156, 62, 66, 182, 125, 217, 54, 203, 2, 36, 200, 229, 116, 196, 176, 174, 227, 237, 190, 96, 98], "capability vector mismatch");
    let claim_subject = claim_subject_nullifier_v2(capability_secret, run, [153; 32], 1);
    assert(claim_subject == [255, 29, 115, 254, 185, 171, 69, 231, 140, 3, 253, 109, 235, 161, 24, 193, 118, 129, 197, 116, 208, 170, 71, 74, 102, 54, 131, 89, 12, 116, 96, 154], "claim subject vector mismatch");
    let claim_fact = claim_fact_commitment_v2(
        claim_subject, run, snapshot, [170; 32], [187; 32], [153; 32],
        4, 1, 250000, 2, 0, 2,
    );
    assert(claim_fact == [166, 237, 81, 23, 130, 191, 231, 95, 159, 170, 124, 66, 197, 94, 22, 112, 249, 9, 139, 207, 8, 206, 151, 183, 203, 8, 140, 11, 74, 146, 194, 172], "claim fact vector mismatch");
    let remediation_subject = remediation_subject_nullifier_v2(claim_subject, [204; 32]);
    assert(remediation_subject == [120, 177, 53, 37, 243, 180, 0, 121, 229, 159, 201, 141, 170, 242, 33, 92, 254, 179, 42, 254, 216, 227, 80, 104, 18, 20, 218, 147, 18, 16, 158, 125], "remediation subject vector mismatch");
    let remediation_fact = remediation_fact_commitment_v2(
        remediation_subject, claim_subject, claim_fact, [221; 32], 0,
        1000000000000000000, 300000, 2, [102; 32],
    );
    assert(remediation_fact == [214, 92, 0, 180, 193, 153, 28, 203, 36, 141, 232, 40, 39, 120, 76, 127, 84, 252, 245, 43, 72, 242, 26, 24, 14, 5, 24, 219, 237, 150, 246, 37], "remediation fact vector mismatch");
}
