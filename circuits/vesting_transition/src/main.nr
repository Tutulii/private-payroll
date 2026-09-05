use dep::keccak256::keccak256;
use dep::exception_protocol::{
    claim_fact_commitment_v2, remediation_fact_commitment_v2,
    remediation_subject_nullifier_v2,
};
use dep::payroll_types::{
    AgreementWitness, MAX_LINES, PROOF_EMPTY_LEAF, PayrollLine, ZERO_BYTES,
    assert_field_root_limbs, assert_membership_index, assert_root_limbs, gross,
    proof_external_attestation_leaf, proof_hash_agreement_terms, proof_hash_payroll_line,
    proof_merkle_membership, proof_merkle_root, proof_remediation_action,
};

global VESTING_TRANSITION_PROOF_VERSION: u32 = 3;
global PAYROLL_PROOF_VERSION: u32 = 2;
global SCHEMA_VERSION: u32 = 1;
global MAX_VALIDITY_WINDOW_SECONDS: u64 = 3600;
global PACKED_AMOUNT_LIMIT: u128 = 1329227995784915872903807060280344576;
global PACKED_AMOUNT_BASE: Field = 1329227995784915872903807060280344576;
global TWO_POW_64: Field = 18446744073709551616;
global PROOF_DOMAIN_ADVANCED_PLAN: Field = 7;
global AGGREGATE_SHARD_LINES: u32 = 25;
global ALL_EXTERNAL_ATTESTATION_FACTS: u8 = 7;
global ACTIVE_ATTESTATION_STATUS: [u8; 32] = [
    50, 39, 104, 117, 21, 47, 106, 26, 210, 210, 108, 66, 62, 24, 135, 91,
    81, 32, 118, 110, 226, 114, 191, 102, 225, 113, 217, 12, 129, 161, 162, 16,
];

global STRK_ADDRESS: [u8; 32] = [
    4, 113, 143, 90, 15, 195, 76, 193, 175, 22, 161, 205, 238, 152, 255, 178,
    12, 49, 245, 205, 97, 214, 171, 7, 32, 24, 88, 244, 40, 124, 147, 141,
];
global USDC_ADDRESS: [u8; 32] = [
    3, 48, 104, 246, 83, 159, 142, 110, 107, 19, 30, 107, 43, 129, 78, 108,
    52, 165, 34, 75, 198, 105, 71, 196, 125, 171, 157, 254, 233, 59, 53, 251,
];

struct MerkleMembership {
    siblings: [Field; 6],
    path_bits: [bool; 6],
}

struct ExceptionEntryWitness {
    enabled: bool,
    claim_subject_nullifier: [u8; 32],
    snapshot_commitment: [u8; 32],
    statement_commitment: [u8; 32],
    claim_manifest_root: [u8; 32],
    agreement_leaf: [u8; 32],
    target_index: u8,
    claim_kind: u8,
    shortfall_atomic: u128,
    shortfall_unit: u8,
    obligation_token: u8,
    evidence_source: u8,
    remediation_secret: [u8; 32],
    recipient_commitment: [u8; 32],
    remediation_amount_atomic: u128,
    remediation_reference_value_atomic: u128,
    remediation_action_salt: [u8; 32],
}

struct ExternalAttestationWitness {
    enabled: bool,
    issuer_public_key: [u8; 32],
    subject_commitment: [u8; 32],
    fact_mask: u8,
    jurisdiction_commitment: [u8; 32],
    status_commitment: [u8; 32],
    valid_from: u64,
    valid_until: u64,
    nonce: [u8; 32],
    policy_root: [u8; 32],
}

// Positionally identical to AdvancedObligation v2. Re-encoding this complete
// witness binds the transition to the immutable plan already proved in v2.
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

fn put_bytes<let N: u32, let M: u32>(
    mut output: [u8; N], offset: u32, value: [u8; M],
) -> [u8; N] {
    for index in 0..M { output[offset + index] = value[index]; }
    output
}

fn u32_bytes(value: u32) -> [u8; 4] {
    (value as Field).to_be_bytes()
}

fn u64_bytes(value: u64) -> [u8; 8] {
    (value as Field).to_be_bytes()
}

fn u128_bytes(value: u128) -> [u8; 16] {
    (value as Field).to_be_bytes()
}

fn field_bytes(value: Field) -> [u8; 32] {
    value.to_be_bytes()
}

fn root_bytes(high: u128, low: u128) -> [u8; 32] {
    let mut value: [u8; 32] = [0; 32];
    value = put_bytes(value, 0, u128_bytes(high));
    put_bytes(value, 16, u128_bytes(low))
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

// Matches Barretenberg's Poseidon2 fixed-length sponge used by Advanced v2.
fn proof_hash<let N: u32>(domain: Field, values: [Field; N]) -> Field {
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

fn packed_amount(value: u128) -> Field {
    assert(value < PACKED_AMOUNT_LIMIT, "amount exceeds proof packing limit");
    value as Field
}

fn pack_amount_pair(left: u128, right: u128) -> Field {
    packed_amount(left) + packed_amount(right) * PACKED_AMOUNT_BASE
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
    for index in 0..6 {
        let limbs = bytes_as_fields(plan.commitments[index]);
        fields[13 + index * 2] = limbs[0];
        fields[14 + index * 2] = limbs[1];
    }
    let salt = bytes_as_fields(plan.salt);
    fields[25] = salt[0];
    fields[26] = salt[1];
    proof_hash(PROOF_DOMAIN_ADVANCED_PLAN, fields)
}

fn linear_entitlement(total: u128, start: u64, end: u64, at: u64) -> u128 {
    assert(end > start, "vesting window is invalid");
    assert(at >= start, "vesting release precedes start");
    assert(at <= end, "vesting release exceeds end");
    let duration = (end - start) as u128;
    let elapsed = (at - start) as u128;
    let quotient = total / duration;
    let remainder = total % duration;
    quotient * elapsed + (remainder * elapsed) / duration
}

fn schedule_id(agreement: AgreementWitness, plan: AdvancedPlanWitness) -> [u8; 32] {
    let domain = "PAYO_VESTING_SCHEDULE_V1".as_bytes();
    let mut message: [u8; 192] = [0; 192];
    message = put_bytes(message, 0, domain);
    message = put_bytes(message, 24, agreement.id_commitment);
    message = put_bytes(message, 56, agreement.recipient_commitment);
    message = put_bytes(message, 88, if agreement.token == 0 { STRK_ADDRESS } else { USDC_ADDRESS });
    message = put_bytes(message, 120, u64_bytes(plan.timestamps[3]));
    message = put_bytes(message, 128, u64_bytes(plan.timestamps[4]));
    message = put_bytes(message, 136, u64_bytes(plan.timestamps[2]));
    message = put_bytes(message, 144, u128_bytes(plan.amounts[0]));
    message = put_bytes(message, 160, plan.salt);
    keccak256(message, message.len())
}

fn state_commitment(
    schedule: [u8; 32], released: u128, sequence: u32, salt: [u8; 32],
) -> [u8; 32] {
    let domain = "PAYO_VESTING_STATE_V1".as_bytes();
    let mut message: [u8; 105] = [0; 105];
    message = put_bytes(message, 0, domain);
    message = put_bytes(message, 21, schedule);
    message = put_bytes(message, 53, u128_bytes(released));
    message = put_bytes(message, 69, u32_bytes(sequence));
    message = put_bytes(message, 73, salt);
    keccak256(message, message.len())
}

fn release_nullifier(
    schedule: [u8; 32], next_sequence: u32, release_at: u64,
    next_state: [u8; 32], run_nullifier: [u8; 32],
) -> [u8; 32] {
    let domain = "PAYO_VESTING_RELEASE_V1".as_bytes();
    let mut message: [u8; 131] = [0; 131];
    message = put_bytes(message, 0, domain);
    message = put_bytes(message, 23, schedule);
    message = put_bytes(message, 55, u32_bytes(next_sequence));
    message = put_bytes(message, 59, u64_bytes(release_at));
    message = put_bytes(message, 67, next_state);
    message = put_bytes(message, 99, run_nullifier);
    keccak256(message, message.len())
}

fn sum_deductions(line: PayrollLine) -> u128 {
    assert(line.deductions_count <= 8, "too many payroll deductions");
    let mut total: u128 = 0;
    for index in 0..8 {
        if index < line.deductions_count {
            total += line.deductions[index];
        } else {
            assert(line.deductions[index] == 0, "unused payroll deduction is nonzero");
        }
    }
    total
}

fn assert_aggregate_shard(
    shard_index: u8,
    agreement_root_high: u128,
    agreement_root_low: u128,
    manifest_root_high: u128,
    manifest_root_low: u128,
    totals_disclosed: u8,
    shard_0_contributor_count: u32,
    shard_1_contributor_count: u32,
    shard_0_strk_gross: u128,
    shard_0_strk_deductions: u128,
    shard_0_strk_net: u128,
    shard_0_usdc_gross: u128,
    shard_0_usdc_deductions: u128,
    shard_0_usdc_net: u128,
    shard_1_strk_gross: u128,
    shard_1_strk_deductions: u128,
    shard_1_strk_net: u128,
    shard_1_usdc_gross: u128,
    shard_1_usdc_deductions: u128,
    shard_1_usdc_net: u128,
    private_shard_0_strk_gross: u128,
    private_shard_0_strk_deductions: u128,
    private_shard_0_strk_net: u128,
    private_shard_0_usdc_gross: u128,
    private_shard_0_usdc_deductions: u128,
    private_shard_0_usdc_net: u128,
    private_shard_1_strk_gross: u128,
    private_shard_1_strk_deductions: u128,
    private_shard_1_strk_net: u128,
    private_shard_1_usdc_gross: u128,
    private_shard_1_usdc_deductions: u128,
    private_shard_1_usdc_net: u128,
    agreement_leaves: [Field; MAX_LINES],
    payroll_leaves: [Field; MAX_LINES],
    agreements: [AgreementWitness; AGGREGATE_SHARD_LINES],
    lines: [PayrollLine; AGGREGATE_SHARD_LINES],
) {
    assert_field_root_limbs(proof_merkle_root(agreement_leaves), agreement_root_high, agreement_root_low);
    assert_field_root_limbs(proof_merkle_root(payroll_leaves), manifest_root_high, manifest_root_low);
    for index in 50..MAX_LINES {
        assert(agreement_leaves[index] == PROOF_EMPTY_LEAF, "aggregate agreement padding is not empty");
        assert(payroll_leaves[index] == PROOF_EMPTY_LEAF, "aggregate payroll padding is not empty");
    }

    let offset = if shard_index == 0 { 0 } else { AGGREGATE_SHARD_LINES };
    let mut contributor_count: u32 = 0;
    let mut strk_gross: u128 = 0;
    let mut strk_deductions: u128 = 0;
    let mut strk_net: u128 = 0;
    let mut usdc_gross: u128 = 0;
    let mut usdc_deductions: u128 = 0;
    let mut usdc_net: u128 = 0;
    for index in 0..AGGREGATE_SHARD_LINES {
        let leaf_index = offset + index;
        let agreement = agreements[index];
        let line = lines[index];
        if line.active {
            assert(agreement.enabled, "active aggregate line has no agreement");
            let agreement_leaf = proof_hash_agreement_terms(agreement);
            assert(agreement_leaves[leaf_index] == agreement_leaf, "aggregate agreement leaf mismatch");
            assert(
                payroll_leaves[leaf_index] == proof_hash_payroll_line(line, agreement_leaf),
                "aggregate payroll leaf mismatch",
            );
            let gross_value = gross(agreement);
            let deductions_value = sum_deductions(line);
            assert(deductions_value <= gross_value, "aggregate deductions exceed gross");
            let net_value = gross_value - deductions_value;
            contributor_count += 1;
            if agreement.token == 0 {
                strk_gross += gross_value;
                strk_deductions += deductions_value;
                strk_net += net_value;
            } else {
                assert(agreement.token == 1, "aggregate line uses unsupported token");
                usdc_gross += gross_value;
                usdc_deductions += deductions_value;
                usdc_net += net_value;
            }
        } else {
            assert(!agreement.enabled, "inactive aggregate line has an agreement");
            assert(agreement_leaves[leaf_index] == PROOF_EMPTY_LEAF, "inactive aggregate agreement leaf is not empty");
            assert(payroll_leaves[leaf_index] == PROOF_EMPTY_LEAF, "inactive aggregate payroll leaf is not empty");
        }
    }

    if shard_index == 0 {
        assert(contributor_count == shard_0_contributor_count, "shard zero contributor count mismatch");
        assert(strk_gross == private_shard_0_strk_gross, "private shard zero STRK gross mismatch");
        assert(strk_deductions == private_shard_0_strk_deductions, "private shard zero STRK deductions mismatch");
        assert(strk_net == private_shard_0_strk_net, "private shard zero STRK net mismatch");
        assert(usdc_gross == private_shard_0_usdc_gross, "private shard zero USDC gross mismatch");
        assert(usdc_deductions == private_shard_0_usdc_deductions, "private shard zero USDC deductions mismatch");
        assert(usdc_net == private_shard_0_usdc_net, "private shard zero USDC net mismatch");
        if totals_disclosed == 1 {
            assert(strk_gross == shard_0_strk_gross, "shard zero STRK gross mismatch");
            assert(strk_deductions == shard_0_strk_deductions, "shard zero STRK deductions mismatch");
            assert(strk_net == shard_0_strk_net, "shard zero STRK net mismatch");
            assert(usdc_gross == shard_0_usdc_gross, "shard zero USDC gross mismatch");
            assert(usdc_deductions == shard_0_usdc_deductions, "shard zero USDC deductions mismatch");
            assert(usdc_net == shard_0_usdc_net, "shard zero USDC net mismatch");
        }
    } else {
        assert(contributor_count == shard_1_contributor_count, "shard one contributor count mismatch");
        assert(strk_gross == private_shard_1_strk_gross, "private shard one STRK gross mismatch");
        assert(strk_deductions == private_shard_1_strk_deductions, "private shard one STRK deductions mismatch");
        assert(strk_net == private_shard_1_strk_net, "private shard one STRK net mismatch");
        assert(usdc_gross == private_shard_1_usdc_gross, "private shard one USDC gross mismatch");
        assert(usdc_deductions == private_shard_1_usdc_deductions, "private shard one USDC deductions mismatch");
        assert(usdc_net == private_shard_1_usdc_net, "private shard one USDC net mismatch");
        if totals_disclosed == 1 {
            assert(strk_gross == shard_1_strk_gross, "shard one STRK gross mismatch");
            assert(strk_deductions == shard_1_strk_deductions, "shard one STRK deductions mismatch");
            assert(strk_net == shard_1_strk_net, "shard one STRK net mismatch");
            assert(usdc_gross == shard_1_usdc_gross, "shard one USDC gross mismatch");
            assert(usdc_deductions == shard_1_usdc_deductions, "shard one USDC deductions mismatch");
            assert(usdc_net == shard_1_usdc_net, "shard one USDC net mismatch");
        }
    }
    if totals_disclosed == 0 {
        assert(
            (shard_0_strk_gross == 0)
                & (shard_0_strk_deductions == 0)
                & (shard_0_strk_net == 0)
                & (shard_0_usdc_gross == 0)
                & (shard_0_usdc_deductions == 0)
                & (shard_0_usdc_net == 0)
                & (shard_1_strk_gross == 0)
                & (shard_1_strk_deductions == 0)
                & (shard_1_strk_net == 0)
                & (shard_1_usdc_gross == 0)
                & (shard_1_usdc_deductions == 0)
                & (shard_1_usdc_net == 0),
            "hidden aggregate totals are not canonical zeros",
        );
    }
}

fn totals_commitment(
    subject_nullifier: [u8; 32],
    contributor_count: u32,
    strk_gross: u128,
    strk_deductions: u128,
    strk_net: u128,
    usdc_gross: u128,
    usdc_deductions: u128,
    usdc_net: u128,
    salt: [u8; 32],
) -> [u8; 32] {
    assert(salt != ZERO_BYTES, "payroll-book totals salt is zero");
    let domain = "PAYO_PAYROLL_BOOK_TOTALS_V1".as_bytes();
    let mut message: [u8; 191] = [0; 191];
    message = put_bytes(message, 0, domain);
    message = put_bytes(message, 27, subject_nullifier);
    message = put_bytes(message, 59, u32_bytes(contributor_count));
    message = put_bytes(message, 63, u128_bytes(strk_gross));
    message = put_bytes(message, 79, u128_bytes(strk_deductions));
    message = put_bytes(message, 95, u128_bytes(strk_net));
    message = put_bytes(message, 111, u128_bytes(usdc_gross));
    message = put_bytes(message, 127, u128_bytes(usdc_deductions));
    message = put_bytes(message, 143, u128_bytes(usdc_net));
    message = put_bytes(message, 159, salt);
    keccak256(message, message.len())
}

fn book_entry_commitment(
    chain_id: Field,
    seal_address: Field,
    source_seal_address: Field,
    owner_address: Field,
    period_start: u64,
    period_end: u64,
    entry_kind: u8,
    agreement_root: [u8; 32],
    manifest_root: [u8; 32],
    policy_root: [u8; 32],
    fx_root: [u8; 32],
    run_nullifier: [u8; 32],
    subject_nullifier: [u8; 32],
    parent_fact: [u8; 32],
    fact: [u8; 32],
    source_proof_version: u32,
    attestation_root: [u8; 32],
    contributor_count: u32,
    totals_disclosed: u8,
    totals_root: [u8; 32],
    strk_gross: u128,
    strk_deductions: u128,
    strk_net: u128,
    usdc_gross: u128,
    usdc_deductions: u128,
    usdc_net: u128,
    schedule: [u8; 32],
    next_state: [u8; 32],
) -> [u8; 32] {
    let domain = "PAYO_PAYROLL_BOOK_ENTRY_V2".as_bytes();
    let mut message: [u8; 660] = [0; 660];
    message = put_bytes(message, 0, domain);
    message = put_bytes(message, 26, field_bytes(chain_id));
    message = put_bytes(message, 58, field_bytes(seal_address));
    message = put_bytes(message, 90, field_bytes(source_seal_address));
    message = put_bytes(message, 122, field_bytes(owner_address));
    message = put_bytes(message, 154, u64_bytes(period_start));
    message = put_bytes(message, 162, u64_bytes(period_end));
    message[170] = entry_kind;
    message = put_bytes(message, 171, agreement_root);
    message = put_bytes(message, 203, manifest_root);
    message = put_bytes(message, 235, policy_root);
    message = put_bytes(message, 267, fx_root);
    message = put_bytes(message, 299, run_nullifier);
    message = put_bytes(message, 331, subject_nullifier);
    message = put_bytes(message, 363, parent_fact);
    message = put_bytes(message, 395, fact);
    message = put_bytes(message, 427, u32_bytes(source_proof_version));
    message = put_bytes(message, 431, attestation_root);
    message = put_bytes(message, 463, u32_bytes(contributor_count));
    message[467] = totals_disclosed;
    message = put_bytes(message, 468, totals_root);
    message = put_bytes(message, 500, u128_bytes(strk_gross));
    message = put_bytes(message, 516, u128_bytes(strk_deductions));
    message = put_bytes(message, 532, u128_bytes(strk_net));
    message = put_bytes(message, 548, u128_bytes(usdc_gross));
    message = put_bytes(message, 564, u128_bytes(usdc_deductions));
    message = put_bytes(message, 580, u128_bytes(usdc_net));
    message = put_bytes(message, 596, schedule);
    message = put_bytes(message, 628, next_state);
    keccak256(message, message.len())
}

fn assert_exception_entry(
    entry_kind: u8,
    run_nullifier: [u8; 32],
    subject_nullifier: [u8; 32],
    parent_fact: [u8; 32],
    fact: [u8; 32],
    manifest_root: [u8; 32],
    fx_root: [u8; 32],
    witness: ExceptionEntryWitness,
) -> u128 {
    let mut exception_amount: u128 = 0;
    if entry_kind < 3 {
        assert(!witness.enabled, "payroll entry contains exception witness");
    } else {
        assert(witness.enabled, "exception book witness is disabled");
        assert((entry_kind == 3) | (entry_kind == 4), "unknown exception book kind");
        assert(witness.claim_subject_nullifier != ZERO_BYTES, "claim subject is zero");
        assert(witness.snapshot_commitment != ZERO_BYTES, "claim snapshot is zero");
        assert(witness.agreement_leaf != ZERO_BYTES, "claim agreement leaf is zero");
        assert(witness.target_index < 50, "claim target is out of range");
        assert(witness.claim_kind <= 2, "claim kind is invalid");
        assert(witness.shortfall_atomic > 0, "claim shortfall is zero");
        assert(witness.shortfall_unit <= 3, "claim shortfall unit is invalid");
        assert(witness.obligation_token <= 1, "claim token is invalid");
        assert(witness.evidence_source <= 3, "claim evidence source is invalid");

        let claim_fact = claim_fact_commitment_v2(
            witness.claim_subject_nullifier,
            run_nullifier,
            witness.snapshot_commitment,
            witness.statement_commitment,
            witness.claim_manifest_root,
            witness.agreement_leaf,
            witness.target_index,
            witness.claim_kind,
            witness.shortfall_atomic,
            witness.shortfall_unit,
            witness.obligation_token,
            witness.evidence_source,
        );
        if entry_kind == 3 {
            assert(subject_nullifier == witness.claim_subject_nullifier, "claim subject mismatch");
            assert(manifest_root == witness.claim_manifest_root, "claim manifest mismatch");
            let expected_parent = if witness.statement_commitment == ZERO_BYTES {
                witness.snapshot_commitment
            } else {
                witness.statement_commitment
            };
            assert(parent_fact == expected_parent, "claim parent fact mismatch");
            assert(fact == claim_fact, "claim fact mismatch");
            assert(witness.remediation_secret == ZERO_BYTES, "claim contains remediation secret");
            assert(witness.recipient_commitment == ZERO_BYTES, "claim contains remediation recipient");
            assert(witness.remediation_amount_atomic == 0, "claim contains remediation amount");
            assert(witness.remediation_reference_value_atomic == 0, "claim contains remediation reference value");
            assert(witness.remediation_action_salt == ZERO_BYTES, "claim contains remediation action salt");
        } else {
            assert(parent_fact == claim_fact, "remediation parent claim mismatch");
            assert(witness.remediation_secret != ZERO_BYTES, "remediation secret is zero");
            assert(witness.recipient_commitment != ZERO_BYTES, "remediation recipient is zero");
            assert(witness.remediation_amount_atomic > 0, "remediation amount is zero");
            assert(witness.remediation_reference_value_atomic > 0, "remediation reference value is zero");
            assert(witness.remediation_action_salt != ZERO_BYTES, "remediation action salt is zero");
            assert(
                subject_nullifier == remediation_subject_nullifier_v2(
                    witness.claim_subject_nullifier, witness.remediation_secret,
                ),
                "remediation subject mismatch",
            );
            let action = proof_remediation_action(
                witness.claim_subject_nullifier,
                witness.recipient_commitment,
                witness.obligation_token,
                witness.remediation_amount_atomic,
                witness.remediation_action_salt,
            );
            assert(action.to_be_bytes() == manifest_root, "remediation action mismatch");
            assert(
                fact == remediation_fact_commitment_v2(
                    subject_nullifier,
                    witness.claim_subject_nullifier,
                    claim_fact,
                    witness.recipient_commitment,
                    witness.obligation_token,
                    witness.remediation_amount_atomic,
                    witness.remediation_reference_value_atomic,
                    witness.shortfall_unit,
                    fx_root,
                ),
                "remediation fact mismatch",
            );
            exception_amount = witness.remediation_amount_atomic;
        }
    }
    exception_amount
}

fn external_attestation_commitment(attestation: ExternalAttestationWitness) -> [u8; 32] {
    let domain = "PAYO_EXTERNAL_ATTESTATION_V1".as_bytes();
    let mut message: [u8; 238] = [0; 238];
    message = put_bytes(message, 0, domain);
    message[28] = 1;
    message = put_bytes(message, 29, attestation.issuer_public_key);
    message = put_bytes(message, 61, attestation.subject_commitment);
    message[93] = attestation.fact_mask;
    message = put_bytes(message, 94, attestation.jurisdiction_commitment);
    message = put_bytes(message, 126, attestation.status_commitment);
    message = put_bytes(message, 158, u64_bytes(attestation.valid_from));
    message = put_bytes(message, 166, u64_bytes(attestation.valid_until));
    message = put_bytes(message, 174, attestation.nonce);
    message = put_bytes(message, 206, attestation.policy_root);
    keccak256(message, message.len())
}

fn assert_external_attestation(
    expected_subject: [u8; 32],
    validity_start: u64,
    validity_expiry: u64,
    root_high: u128,
    root_low: u128,
    policy_root: [u8; 32],
    attestation: ExternalAttestationWitness,
    membership: MerkleMembership,
) {
    if attestation.enabled {
        assert((root_high != 0) | (root_low != 0), "attestation root is zero");
        assert(attestation.issuer_public_key != ZERO_BYTES, "attestation issuer is zero");
        assert(attestation.subject_commitment == expected_subject, "attestation subject mismatch");
        assert(attestation.fact_mask == ALL_EXTERNAL_ATTESTATION_FACTS, "attestation does not cover every required fact");
        assert(attestation.jurisdiction_commitment != ZERO_BYTES, "attestation jurisdiction is zero");
        assert(attestation.policy_root == policy_root, "attestation policy root mismatch");
        assert(attestation.status_commitment == ACTIVE_ATTESTATION_STATUS, "attestation status is not active");
        assert(attestation.nonce != ZERO_BYTES, "attestation nonce is zero");
        assert(attestation.valid_until > attestation.valid_from, "attestation validity window is invalid");
        assert(attestation.valid_from <= validity_start, "attestation is not active yet");
        assert(attestation.valid_until >= validity_expiry, "attestation expires before proof");
        let leaf = proof_external_attestation_leaf(external_attestation_commitment(attestation));
        assert_field_root_limbs(
            proof_merkle_membership(leaf, membership.siblings, membership.path_bits),
            root_high,
            root_low,
        );
    } else {
        assert((root_high == 0) & (root_low == 0), "unproved attestation root is not zero");
        assert(attestation.issuer_public_key == ZERO_BYTES, "disabled attestation issuer is not empty");
        assert(attestation.subject_commitment == ZERO_BYTES, "disabled attestation subject is not empty");
        assert(attestation.fact_mask == 0, "disabled attestation facts are not empty");
        assert(attestation.jurisdiction_commitment == ZERO_BYTES, "disabled attestation jurisdiction is not empty");
        assert(attestation.status_commitment == ZERO_BYTES, "disabled attestation status is not empty");
        assert((attestation.valid_from == 0) & (attestation.valid_until == 0), "disabled attestation validity is not empty");
        assert(attestation.nonce == ZERO_BYTES, "disabled attestation nonce is not empty");
        assert(attestation.policy_root == ZERO_BYTES, "disabled attestation policy root is not empty");
        for level in 0..6 {
            assert(membership.siblings[level] == 0, "disabled attestation sibling is not empty");
            assert(!membership.path_bits[level], "disabled attestation path is not empty");
        }
    }
}

fn assert_transition(
    agreement: AgreementWitness,
    line: PayrollLine,
    plan: AdvancedPlanWitness,
    validity_start: u64,
) -> u128 {
    assert(agreement.enabled, "vesting agreement is disabled");
    assert(line.active, "vesting payroll line is inactive");
    assert(agreement.token <= 1, "unsupported vesting token");
    assert(plan.enabled, "vesting plan is disabled");
    assert(plan.kind == 3, "payment plan is not private vesting");
    assert(plan.salt != ZERO_BYTES, "vesting plan salt is zero");
    assert(
        encode_plan_commitment(plan).to_be_bytes() == agreement.schedule_commitment,
        "vesting plan commitment mismatch",
    );
    let start = plan.timestamps[3];
    let cliff = plan.timestamps[4];
    let release = plan.timestamps[5];
    let end = plan.timestamps[2];
    assert(cliff >= start, "vesting cliff precedes start");
    assert(cliff <= end, "vesting cliff exceeds end");
    assert(release >= cliff, "vesting release precedes cliff");
    let earned = linear_entitlement(plan.amounts[0], start, end, release);
    assert(earned > plan.amounts[1], "vesting has no unreleased value");
    assert(gross(agreement) == earned - plan.amounts[1], "vesting payroll amount is wrong");
    assert(agreement.due_at == release, "vesting due binding mismatch");
    assert(validity_start >= release, "vesting obligation is early");
    assert(validity_start <= agreement.valid_until, "vesting obligation expired");
    earned
}

fn main(
    chain_id: pub Field,
    seal_address: pub Field,
    proof_version: pub u32,
    schema_version: pub u32,
    entry_kind: pub u8,
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
    subject_nullifier_high: pub u128,
    subject_nullifier_low: pub u128,
    parent_fact_high: pub u128,
    parent_fact_low: pub u128,
    fact_high: pub u128,
    fact_low: pub u128,
    owner_address: pub Field,
    source_seal_address: pub Field,
    source_proof_version: pub u32,
    attestation_root_high: pub u128,
    attestation_root_low: pub u128,
    shard_0_contributor_count: pub u32,
    shard_1_contributor_count: pub u32,
    totals_disclosed: pub u8,
    totals_commitment_high: pub u128,
    totals_commitment_low: pub u128,
    shard_0_strk_gross: pub u128,
    shard_0_strk_deductions: pub u128,
    shard_0_strk_net: pub u128,
    shard_0_usdc_gross: pub u128,
    shard_0_usdc_deductions: pub u128,
    shard_0_usdc_net: pub u128,
    shard_1_strk_gross: pub u128,
    shard_1_strk_deductions: pub u128,
    shard_1_strk_net: pub u128,
    shard_1_usdc_gross: pub u128,
    shard_1_usdc_deductions: pub u128,
    shard_1_usdc_net: pub u128,
    schedule_id_high: pub u128,
    schedule_id_low: pub u128,
    previous_state_high: pub u128,
    previous_state_low: pub u128,
    next_state_high: pub u128,
    next_state_low: pub u128,
    release_nullifier_high: pub u128,
    release_nullifier_low: pub u128,
    book_entry_high: pub u128,
    book_entry_low: pub u128,
    period_start: pub u64,
    period_end: pub u64,
    validity_start: pub u64,
    validity_expiry: pub u64,
    shard_index: pub u8,
    external_attestation: ExternalAttestationWitness,
    external_attestation_membership: MerkleMembership,
    exception_entry: ExceptionEntryWitness,
    private_shard_0_strk_gross: u128,
    private_shard_0_strk_deductions: u128,
    private_shard_0_strk_net: u128,
    private_shard_0_usdc_gross: u128,
    private_shard_0_usdc_deductions: u128,
    private_shard_0_usdc_net: u128,
    private_shard_1_strk_gross: u128,
    private_shard_1_strk_deductions: u128,
    private_shard_1_strk_net: u128,
    private_shard_1_usdc_gross: u128,
    private_shard_1_usdc_deductions: u128,
    private_shard_1_usdc_net: u128,
    totals_salt: [u8; 32],
    target_index: u8,
    agreement: AgreementWitness,
    line: PayrollLine,
    plan: AdvancedPlanWitness,
    agreement_membership: MerkleMembership,
    payroll_membership: MerkleMembership,
    previous_state_salt: [u8; 32],
    next_state_salt: [u8; 32],
    aggregate_agreement_leaves: [Field; MAX_LINES],
    aggregate_payroll_leaves: [Field; MAX_LINES],
    aggregate_agreements: [AgreementWitness; AGGREGATE_SHARD_LINES],
    aggregate_lines: [PayrollLine; AGGREGATE_SHARD_LINES],
) {
    assert(chain_id != 0, "chain id is required");
    assert(seal_address != 0, "seal address is required");
    assert(source_seal_address != 0, "source seal address is required");
    assert(owner_address != 0, "book owner is required");
    assert(proof_version == VESTING_TRANSITION_PROOF_VERSION, "unsupported vesting proof version");
    assert(schema_version == SCHEMA_VERSION, "unsupported vesting schema version");
    assert(entry_kind <= 4, "unsupported payroll-book entry kind");
    let payroll_entry = entry_kind <= 2;
    if payroll_entry {
        assert(source_proof_version == PAYROLL_PROOF_VERSION, "unsupported source proof version");
        if entry_kind != 2 {
            assert(source_seal_address == seal_address, "payroll source seal differs from book seal");
        }
    } else if entry_kind == 3 {
        assert(source_proof_version == 6, "claim source is not v6");
    } else {
        assert(source_proof_version == 7, "remediation source is not v7");
    }
    assert(shard_index <= 1, "invalid vesting shard");
    assert(totals_disclosed <= 1, "invalid totals disclosure mode");
    assert(validity_expiry >= validity_start, "invalid proof validity window");
    assert(validity_expiry - validity_start <= MAX_VALIDITY_WINDOW_SECONDS, "proof validity window is too long");
    assert(period_end > period_start, "payroll-book period is invalid");
    assert(validity_start >= period_start, "payroll precedes its reporting period");
    assert(validity_start < period_end, "payroll exceeds its reporting period");

    let run_nullifier = root_bytes(run_nullifier_high, run_nullifier_low);
    let subject_nullifier = root_bytes(subject_nullifier_high, subject_nullifier_low);
    assert(run_nullifier != ZERO_BYTES, "run nullifier is zero");
    let parent_fact = root_bytes(parent_fact_high, parent_fact_low);
    let fact = root_bytes(fact_high, fact_low);
    if payroll_entry {
        assert(subject_nullifier == run_nullifier, "payroll subject is not its run nullifier");
        assert(parent_fact == ZERO_BYTES, "payroll entry contains parent fact");
        assert(fact == ZERO_BYTES, "payroll entry contains exception fact");
    } else {
        assert(subject_nullifier != ZERO_BYTES, "exception subject is zero");
        assert(parent_fact != ZERO_BYTES, "exception parent fact is zero");
        assert(fact != ZERO_BYTES, "exception fact is zero");
    }
    assert(shard_0_contributor_count <= 25, "shard zero contributor count is too large");
    assert(shard_1_contributor_count <= 25, "shard one contributor count is too large");
    let contributor_count = shard_0_contributor_count + shard_1_contributor_count;
    assert(contributor_count > 0, "payroll-book entry has no contributors");

    let exception_amount = assert_exception_entry(
        entry_kind,
        run_nullifier,
        subject_nullifier,
        parent_fact,
        fact,
        root_bytes(manifest_root_high, manifest_root_low),
        root_bytes(fx_root_high, fx_root_low),
        exception_entry,
    );
    if payroll_entry {
        assert_aggregate_shard(
            shard_index,
            agreement_root_high,
            agreement_root_low,
            manifest_root_high,
            manifest_root_low,
            totals_disclosed,
            shard_0_contributor_count,
            shard_1_contributor_count,
            shard_0_strk_gross,
            shard_0_strk_deductions,
            shard_0_strk_net,
            shard_0_usdc_gross,
            shard_0_usdc_deductions,
            shard_0_usdc_net,
            shard_1_strk_gross,
            shard_1_strk_deductions,
            shard_1_strk_net,
            shard_1_usdc_gross,
            shard_1_usdc_deductions,
            shard_1_usdc_net,
            private_shard_0_strk_gross,
            private_shard_0_strk_deductions,
            private_shard_0_strk_net,
            private_shard_0_usdc_gross,
            private_shard_0_usdc_deductions,
            private_shard_0_usdc_net,
            private_shard_1_strk_gross,
            private_shard_1_strk_deductions,
            private_shard_1_strk_net,
            private_shard_1_usdc_gross,
            private_shard_1_usdc_deductions,
            private_shard_1_usdc_net,
            aggregate_agreement_leaves,
            aggregate_payroll_leaves,
            aggregate_agreements,
            aggregate_lines,
        );
        } else {
        assert(shard_0_contributor_count == 1, "exception contributor count is not one");
        assert(shard_1_contributor_count == 0, "exception second shard is not empty");
        assert(private_shard_1_strk_gross == 0, "exception second shard STRK is nonzero");
        assert(private_shard_1_strk_deductions == 0, "exception second shard STRK deductions are nonzero");
        assert(private_shard_1_strk_net == 0, "exception second shard STRK net is nonzero");
        assert(private_shard_1_usdc_gross == 0, "exception second shard USDC is nonzero");
        assert(private_shard_1_usdc_deductions == 0, "exception second shard USDC deductions are nonzero");
        assert(private_shard_1_usdc_net == 0, "exception second shard USDC net is nonzero");
        if entry_kind == 3 {
            assert(private_shard_0_strk_gross == 0, "claim contains STRK value");
            assert(private_shard_0_strk_deductions == 0, "claim contains STRK deductions");
            assert(private_shard_0_strk_net == 0, "claim contains STRK net");
            assert(private_shard_0_usdc_gross == 0, "claim contains USDC value");
            assert(private_shard_0_usdc_deductions == 0, "claim contains USDC deductions");
            assert(private_shard_0_usdc_net == 0, "claim contains USDC net");
            assert(totals_disclosed == 0, "claim publishes payment totals");
        } else if exception_entry.obligation_token == 0 {
            assert(private_shard_0_strk_gross == exception_amount, "remediation STRK gross mismatch");
            assert(private_shard_0_strk_deductions == 0, "remediation STRK deductions are nonzero");
            assert(private_shard_0_strk_net == exception_amount, "remediation STRK net mismatch");
            assert(private_shard_0_usdc_gross == 0, "STRK remediation contains USDC value");
            assert(private_shard_0_usdc_deductions == 0, "STRK remediation contains USDC deductions");
            assert(private_shard_0_usdc_net == 0, "STRK remediation contains USDC net");
        } else {
            assert(private_shard_0_strk_gross == 0, "USDC remediation contains STRK value");
            assert(private_shard_0_strk_deductions == 0, "USDC remediation contains STRK deductions");
            assert(private_shard_0_strk_net == 0, "USDC remediation contains STRK net");
            assert(private_shard_0_usdc_gross == exception_amount, "remediation USDC gross mismatch");
            assert(private_shard_0_usdc_deductions == 0, "remediation USDC deductions are nonzero");
            assert(private_shard_0_usdc_net == exception_amount, "remediation USDC net mismatch");
        }
    }

    let strk_gross = private_shard_0_strk_gross + private_shard_1_strk_gross;
    let strk_deductions = private_shard_0_strk_deductions + private_shard_1_strk_deductions;
    let strk_net = private_shard_0_strk_net + private_shard_1_strk_net;
    let usdc_gross = private_shard_0_usdc_gross + private_shard_1_usdc_gross;
    let usdc_deductions = private_shard_0_usdc_deductions + private_shard_1_usdc_deductions;
    let usdc_net = private_shard_0_usdc_net + private_shard_1_usdc_net;
    assert(strk_gross - strk_deductions == strk_net, "combined STRK totals do not balance");
    assert(usdc_gross - usdc_deductions == usdc_net, "combined USDC totals do not balance");
    if totals_disclosed == 1 {
        assert(strk_net + usdc_net > 0, "public payroll totals are empty");
        assert(shard_0_strk_gross == private_shard_0_strk_gross, "disclosed shard zero STRK mismatch");
        assert(shard_0_strk_deductions == private_shard_0_strk_deductions, "disclosed shard zero STRK deduction mismatch");
        assert(shard_0_strk_net == private_shard_0_strk_net, "disclosed shard zero STRK net mismatch");
        assert(shard_0_usdc_gross == private_shard_0_usdc_gross, "disclosed shard zero USDC mismatch");
        assert(shard_0_usdc_deductions == private_shard_0_usdc_deductions, "disclosed shard zero USDC deduction mismatch");
        assert(shard_0_usdc_net == private_shard_0_usdc_net, "disclosed shard zero USDC net mismatch");
        assert(shard_1_strk_gross == private_shard_1_strk_gross, "disclosed shard one STRK mismatch");
        assert(shard_1_strk_deductions == private_shard_1_strk_deductions, "disclosed shard one STRK deduction mismatch");
        assert(shard_1_strk_net == private_shard_1_strk_net, "disclosed shard one STRK net mismatch");
        assert(shard_1_usdc_gross == private_shard_1_usdc_gross, "disclosed shard one USDC mismatch");
        assert(shard_1_usdc_deductions == private_shard_1_usdc_deductions, "disclosed shard one USDC deduction mismatch");
        assert(shard_1_usdc_net == private_shard_1_usdc_net, "disclosed shard one USDC net mismatch");
    }
    let totals_root = totals_commitment(
        subject_nullifier, contributor_count, strk_gross, strk_deductions, strk_net,
        usdc_gross, usdc_deductions, usdc_net, totals_salt,
    );
    assert_root_limbs(totals_root, totals_commitment_high, totals_commitment_low);
    if external_attestation.enabled {
        assert(agreement.enabled, "attested agreement is disabled");
        assert_membership_index(agreement_membership.path_bits, target_index);
        assert_field_root_limbs(
            proof_merkle_membership(
                proof_hash_agreement_terms(agreement),
                agreement_membership.siblings,
                agreement_membership.path_bits,
            ),
            agreement_root_high,
            agreement_root_low,
        );
    }
    assert_external_attestation(
        agreement.recipient_commitment, validity_start, validity_expiry,
        attestation_root_high, attestation_root_low,
        root_bytes(policy_root_high, policy_root_low),
        external_attestation, external_attestation_membership,
    );

    let mut schedule: [u8; 32] = ZERO_BYTES;
    let mut next_state: [u8; 32] = ZERO_BYTES;
    if entry_kind == 1 {
        assert(previous_state_salt != ZERO_BYTES, "previous vesting state salt is zero");
        assert(next_state_salt != ZERO_BYTES, "next vesting state salt is zero");

        assert_membership_index(agreement_membership.path_bits, target_index);
        assert_membership_index(payroll_membership.path_bits, target_index);
        let agreement_leaf = proof_hash_agreement_terms(agreement);
        assert_field_root_limbs(
            proof_merkle_membership(
                agreement_leaf, agreement_membership.siblings, agreement_membership.path_bits,
            ),
            agreement_root_high,
            agreement_root_low,
        );
        assert_field_root_limbs(
            proof_merkle_membership(
                proof_hash_payroll_line(line, agreement_leaf),
                payroll_membership.siblings,
                payroll_membership.path_bits,
            ),
            manifest_root_high,
            manifest_root_low,
        );

        let earned = assert_transition(agreement, line, plan, validity_start);
        schedule = schedule_id(agreement, plan);
        assert_root_limbs(schedule, schedule_id_high, schedule_id_low);

        if (plan.release_sequence == 0) & (plan.amounts[1] == 0) {
            assert(
                (previous_state_high == 0) & (previous_state_low == 0),
                "genesis vesting state is not zero",
            );
        } else {
            assert_root_limbs(
                state_commitment(
                    schedule, plan.amounts[1], plan.release_sequence, previous_state_salt,
                ),
                previous_state_high,
                previous_state_low,
            );
        }
        assert(plan.release_sequence < 0xffffffff, "vesting release sequence exhausted");
        let next_sequence = plan.release_sequence + 1;
        next_state = state_commitment(schedule, earned, next_sequence, next_state_salt);
        assert_root_limbs(next_state, next_state_high, next_state_low);
        assert_root_limbs(
            release_nullifier(
                schedule, next_sequence, plan.timestamps[5], next_state, run_nullifier,
            ),
            release_nullifier_high,
            release_nullifier_low,
        );
    } else {
        assert(
            (schedule_id_high == 0) & (schedule_id_low == 0),
            "ordinary book entry has vesting schedule",
        );
        assert(
            (previous_state_high == 0) & (previous_state_low == 0),
            "ordinary book entry has previous state",
        );
        assert(
            (next_state_high == 0) & (next_state_low == 0),
            "ordinary book entry has next state",
        );
        assert(
            (release_nullifier_high == 0) & (release_nullifier_low == 0),
            "ordinary book entry has release nullifier",
        );
        if external_attestation.enabled {
            assert(agreement.enabled, "attested ordinary agreement is disabled");
        } else {
            assert(!agreement.enabled, "ordinary book witness must be empty");
        }
        assert(!line.active, "ordinary payroll-line witness must be empty");
        assert(!plan.enabled, "ordinary vesting-plan witness must be empty");
        assert(
            previous_state_salt == ZERO_BYTES,
            "ordinary previous-state salt must be empty",
        );
        assert(next_state_salt == ZERO_BYTES, "ordinary next-state salt must be empty");
    }

    assert_root_limbs(
        book_entry_commitment(
            chain_id,
            seal_address,
            source_seal_address,
            owner_address,
            period_start,
            period_end,
            entry_kind,
            root_bytes(agreement_root_high, agreement_root_low),
            root_bytes(manifest_root_high, manifest_root_low),
            root_bytes(policy_root_high, policy_root_low),
            root_bytes(fx_root_high, fx_root_low),
            run_nullifier,
            subject_nullifier,
            root_bytes(parent_fact_high, parent_fact_low),
            root_bytes(fact_high, fact_low),
            source_proof_version,
            root_bytes(attestation_root_high, attestation_root_low),
            contributor_count,
            totals_disclosed,
            totals_root,
            if totals_disclosed == 1 { strk_gross } else { 0 },
            if totals_disclosed == 1 { strk_deductions } else { 0 },
            if totals_disclosed == 1 { strk_net } else { 0 },
            if totals_disclosed == 1 { usdc_gross } else { 0 },
            if totals_disclosed == 1 { usdc_deductions } else { 0 },
            if totals_disclosed == 1 { usdc_net } else { 0 },
            schedule,
            next_state,
        ),
        book_entry_high,
        book_entry_low,
    );
}

fn empty_plan() -> AdvancedPlanWitness {
    AdvancedPlanWitness {
        enabled: true,
        kind: 3,
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
        salt: [4; 32],
    }
}

fn valid_plan() -> AdvancedPlanWitness {
    let mut plan = empty_plan();
    plan.timestamps[2] = 1100;
    plan.timestamps[3] = 100;
    plan.timestamps[4] = 200;
    plan.timestamps[5] = 600;
    plan.amounts[0] = 1000;
    plan.amounts[1] = 0;
    plan
}

fn valid_agreement(plan: AdvancedPlanWitness) -> AgreementWitness {
    let mut agreement = dep::payroll_types::empty_agreement();
    agreement.enabled = true;
    agreement.id_commitment = [1; 32];
    agreement.recipient_commitment = [2; 32];
    agreement.earnings[0] = 500;
    agreement.earnings_count = 1;
    agreement.token = 0;
    agreement.policy_commitment = [3; 32];
    agreement.schedule_commitment = encode_plan_commitment(plan).to_be_bytes();
    agreement.due_at = 600;
    agreement.valid_until = 900;
    agreement.classification_declared = 1;
    agreement.classification_score = 1;
    agreement.classification_employee_threshold = 1;
    agreement.salt = [7; 32];
    agreement
}

fn valid_line() -> PayrollLine {
    let mut line = dep::payroll_types::empty_line();
    line.active = true;
    line.salt = [8; 32];
    line
}

#[test]
fn accepts_exact_private_vesting_delta() {
    let plan = valid_plan();
    let earned = assert_transition(valid_agreement(plan), valid_line(), plan, 600);
    assert(earned == 500);
}

#[test(should_fail_with = "vesting release precedes cliff")]
fn rejects_early_private_vesting() {
    let mut plan = valid_plan();
    plan.timestamps[5] = 199;
    let mut agreement = valid_agreement(plan);
    agreement.due_at = 199;
    let _ = assert_transition(agreement, valid_line(), plan, 199);
}

#[test(should_fail_with = "vesting payroll amount is wrong")]
fn rejects_changed_private_vesting_amount() {
    let plan = valid_plan();
    let mut agreement = valid_agreement(plan);
    agreement.earnings[0] = 499;
    let _ = assert_transition(agreement, valid_line(), plan, 600);
}

#[test]
fn commitment_domains_are_distinct_and_state_changes_with_sequence() {
    let plan = valid_plan();
    let agreement = valid_agreement(plan);
    let schedule = schedule_id(agreement, plan);
    let first = state_commitment(schedule, 500, 1, [9; 32]);
    let second = state_commitment(schedule, 500, 2, [9; 32]);
    assert(schedule != first);
    assert(first != second);
    assert(
        release_nullifier(schedule, 1, 600, first, [10; 32])
            != release_nullifier(schedule, 2, 600, second, [10; 32]),
    );
}
