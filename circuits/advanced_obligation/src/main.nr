global MAX_LINES: u32 = 64;
global MAX_REAL_LINES: u32 = 50;
global SHARD_LINES: u32 = 25;
global SHARD_AGREEMENTS: u32 = 26;
global MAX_COMPONENTS: u32 = 8;
global MAX_FINAL_COMPONENTS: u32 = 5;
global MAX_VALIDITY_WINDOW_SECONDS: u64 = 3600;
global PACKED_AMOUNT_LIMIT: u128 = 1329227995784915872903807060280344576;
global PACKED_AMOUNT_BASE: Field = 1329227995784915872903807060280344576;
global TWO_POW_64: Field = 18446744073709551616;
global PROOF_DOMAIN_MERKLE_NODE: Field = 2;
global PROOF_DOMAIN_AGREEMENT: Field = 3;
global PROOF_DOMAIN_PAYROLL_LINE: Field = 4;
global PROOF_DOMAIN_ADVANCED_PLAN: Field = 7;
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

// The fixed binary encoding is reproduced by
// lib/domain/advanced-obligation-commitment.ts.
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

fn bytes_as_fields(value: [u8; 32]) -> [Field; 2] {
    [high_limb(value) as Field, low_limb(value) as Field]
}

fn assert_field_root_limbs(root: Field, expected_high: u128, expected_low: u128) {
    let root_bytes: [u8; 32] = root.to_be_bytes();
    let high: [u8; 16] = (expected_high as Field).to_be_bytes();
    let low: [u8; 16] = (expected_low as Field).to_be_bytes();
    for index in 0..16 {
        assert(root_bytes[index] == high[index], "root high limb mismatch");
        assert(root_bytes[index + 16] == low[index], "root low limb mismatch");
    }
}

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
        fields[4 + pair] = pack_amount_pair(agreement.earnings[pair * 2], agreement.earnings[pair * 2 + 1]);
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
        fields[1 + pair] = pack_amount_pair(line.deductions[pair * 2], line.deductions[pair * 2 + 1]);
    }
    fields[5] = pack_line_metadata(line);
    fields[6] = salt[0];
    fields[7] = salt[1];
    proof_hash(PROOF_DOMAIN_PAYROLL_LINE, fields)
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
    agreement_leaves: [Field; MAX_LINES],
    payroll_leaves: [Field; MAX_LINES],
    agreements: [AgreementWitness; SHARD_AGREEMENTS],
    lines: [PayrollLine; SHARD_LINES],
    plans: [AdvancedPlanWitness; SHARD_LINES],
) {
    assert(chain_id != 0, "chain id is required");
    assert(seal_address != 0, "seal address is required");
    assert(proof_version == 2, "unsupported advanced proof version");
    assert(schema_version == 1, "unsupported schema version");
    assert(shard_index <= 1, "invalid advanced shard");
    assert((policy_root_high != 0) | (policy_root_low != 0), "policy root is zero");
    assert((fx_root_high != 0) | (fx_root_low != 0), "FX root is zero");
    assert((run_nullifier_high != 0) | (run_nullifier_low != 0), "run nullifier is zero");
    assert(validity_expiry >= validity_start, "invalid proof window");
    assert(validity_expiry - validity_start <= MAX_VALIDITY_WINDOW_SECONDS, "proof window is too long");

    for index in MAX_REAL_LINES..MAX_LINES {
        assert(agreement_leaves[index] == PROOF_EMPTY_LEAF, "agreement padding is not empty");
        assert(payroll_leaves[index] == PROOF_EMPTY_LEAF, "payroll padding is not empty");
    }
    let mut advanced_count: u32 = 0;
    for index in 0..SHARD_LINES {
        let agreement_index = if shard_index == 0 { index } else { index + 1 };
        let global_agreement_index = if shard_index == 0 { index } else { index + 25 };
        let agreement = agreements[agreement_index];
        let line = lines[index];
        let plan = plans[index];
        let agreement_commitment = if agreement.enabled {
            proof_hash_agreement_terms(agreement)
        } else {
            PROOF_EMPTY_LEAF
        };
        assert(agreement_leaves[global_agreement_index] == agreement_commitment, "advanced agreement leaf mismatch");
        let payroll_commitment = if line.active {
            assert(agreement.enabled, "advanced line has no agreement");
            advanced_count += 1;
            validate_advanced_plan(agreement, plan, validity_start);
            proof_hash_payroll_line(line, agreement_commitment)
        } else {
            assert_disabled_plan(plan);
            PROOF_EMPTY_LEAF
        };
        let global_line_index = if shard_index == 0 { index } else { index + 25 };
        assert(payroll_leaves[global_line_index] == payroll_commitment, "advanced payroll leaf mismatch");
    }
    if shard_index == 0 { assert(advanced_count > 0, "empty advanced obligation bundle"); }
    assert_field_root_limbs(proof_merkle_root(agreement_leaves), agreement_root_high, agreement_root_low);
    assert_field_root_limbs(proof_merkle_root(payroll_leaves), manifest_root_high, manifest_root_low);
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

fn base_plan() -> AdvancedPlanWitness {
    let mut plan = empty_plan();
    plan.enabled = true;
    plan.salt = [3; 32];
    plan
}

fn base_agreement() -> AgreementWitness {
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
fn checkpoint_plan_commitment_is_field_canonical() {
    let mut plan = base_plan();
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
    let mut plan = base_plan();
    plan.kind = 1;
    plan.minimum_checkpoint_seconds = 300;
    plan.timestamps[2] = 1000;
    plan.timestamps[3] = 0;
    plan.timestamps[5] = 500;
    plan.amounts[0] = 1000;
    plan.amounts[1] = 0;
    plan.amounts[2] = 500;
    plan.commitments[2] = [7; 32];
    let mut agreement = base_agreement();
    agreement.due_at = 500;
    agreement.schedule_commitment = encode_plan_commitment(plan).to_be_bytes();
    validate_advanced_plan(agreement, plan, 500);
}

#[test(should_fail_with = "checkpoint entitlement is forged")]
fn rejects_forged_checkpoint_entitlement() {
    let mut plan = base_plan();
    plan.kind = 1;
    plan.minimum_checkpoint_seconds = 300;
    plan.timestamps[2] = 1000;
    plan.timestamps[3] = 0;
    plan.timestamps[5] = 500;
    plan.amounts[0] = 1000;
    plan.amounts[2] = 501;
    plan.commitments[2] = [7; 32];
    let mut agreement = base_agreement();
    agreement.earnings[0] = 501;
    agreement.due_at = 500;
    agreement.schedule_commitment = encode_plan_commitment(plan).to_be_bytes();
    validate_advanced_plan(agreement, plan, 500);
}

#[test(should_fail_with = "milestone is unapproved")]
fn rejects_unapproved_milestone() {
    let mut plan = base_plan();
    plan.kind = 2;
    plan.timestamps[7] = 500;
    plan.commitments[0] = [1; 32];
    plan.commitments[1] = [2; 32];
    plan.commitments[2] = [3; 32];
    let mut agreement = base_agreement();
    agreement.schedule_commitment = encode_plan_commitment(plan).to_be_bytes();
    validate_advanced_plan(agreement, plan, 500);
}

#[test(should_fail_with = "termination component is missing")]
fn rejects_incomplete_final_pay() {
    let mut plan = base_plan();
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
    let mut agreement = base_agreement();
    agreement.final_pay_mode = true;
    agreement.final_required_mask = 3;
    agreement.final_components[0] = 500;
    agreement.schedule_commitment = encode_plan_commitment(plan).to_be_bytes();
    validate_advanced_plan(agreement, plan, 500);
}
