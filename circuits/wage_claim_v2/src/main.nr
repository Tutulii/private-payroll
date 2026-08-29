use dep::exception_protocol::{
    claim_capability_commitment_v2, claim_fact_commitment_v2,
    claim_subject_nullifier_v2, obligation_snapshot_commitment_v2,
    payroll_statement_commitment_v2,
};
use dep::fx_types::{
    CatalogMembership, FxSnapshot, assert_empty_fx, assert_fx_root,
    reference_value_atomic,
};
use dep::payroll_types::{
    MAX_COMPONENTS, MAX_FINAL_COMPONENTS, PROOF_EMPTY_LEAF, ZERO_BYTES,
    AgreementWitness, PayrollLine, assert_field_root_limbs,
    assert_membership_index, assert_root_limbs, gross,
    proof_claim_obligation_leaf, proof_hash_agreement_terms,
    proof_hash_payroll_line, proof_merkle_membership,
};

global MAX_VALIDITY_WINDOW_SECONDS: u64 = 3600;
global EVIDENCE_UNSETTLED_PERIOD: u8 = 0;
global EVIDENCE_PAYO_RUN: u8 = 1;
global EVIDENCE_EMPLOYER_STATEMENT: u8 = 2;
global EVIDENCE_SETTLEMENT_MATCH: u8 = 3;
global CLAIM_MISSING_OBLIGATION: u8 = 0;
global CLAIM_BELOW_COMMITTED_FLOOR: u8 = 1;
global CLAIM_INCOMPLETE_FINAL_PAY: u8 = 2;
global UNIT_STRK_ATOMIC: u8 = 0;
global UNIT_USDC_ATOMIC: u8 = 1;
global UNIT_USD_6: u8 = 2;
global UNIT_GBP_6: u8 = 3;

fn assert_zero_path(siblings: [Field; 6], path_bits: [bool; 6]) {
    for level in 0..6 {
        assert(siblings[level] == 0, "unused Merkle sibling is nonzero");
        assert(!path_bits[level], "unused Merkle path bit is true");
    }
}

fn assert_empty_line(line: PayrollLine) {
    assert(!line.active, "unused payroll line is active");
    assert(line.deductions_count == 0, "unused deduction count is nonzero");
    assert(line.policy_slot == 0, "unused policy slot is nonzero");
    assert(line.fx_slot == 0, "unused FX slot is nonzero");
    for index in 0..MAX_COMPONENTS {
        assert(line.deductions[index] == 0, "unused deduction is nonzero");
    }
    assert(line.salt == ZERO_BYTES, "unused payroll salt is nonzero");
    assert(line.classification_treatment == 0, "unused treatment is nonzero");
    assert(line.final_included_mask == 0, "unused final mask is nonzero");
    assert(line.reference_value_atomic == 0, "unused reference value is nonzero");
}

fn deductions_total(line: PayrollLine) -> u128 {
    assert(line.deductions_count <= MAX_COMPONENTS, "too many deductions");
    let mut total: u128 = 0;
    for index in 0..MAX_COMPONENTS {
        if index < line.deductions_count {
            total += line.deductions[index];
        } else {
            assert(line.deductions[index] == 0, "unused deduction is nonzero");
        }
    }
    total
}

fn assert_statement_line(line: PayrollLine, agreement: AgreementWitness) -> u128 {
    assert(line.active, "statement payroll line is inactive");
    assert(line.salt != ZERO_BYTES, "statement payroll salt is zero");
    assert(line.classification_treatment <= 2, "invalid statement treatment");
    let agreement_gross = gross(agreement);
    let deductions = deductions_total(line);
    assert(deductions <= agreement_gross, "statement deductions exceed gross");
    agreement_gross - deductions
}

fn missing_final_shortfall(agreement: AgreementWitness, included_mask: u8) -> u128 {
    assert(agreement.final_pay_mode, "claim is not final pay");
    assert(agreement.final_required_mask > 0, "final-pay required mask is zero");
    let mut shortfall: u128 = 0;
    for index in 0..MAX_FINAL_COMPONENTS {
        let divisor: u32 = 1 << index as u32;
        let required = (agreement.final_required_mask as u32 / divisor) % 2 == 1;
        let included = (included_mask as u32 / divisor) % 2 == 1;
        if required {
            assert(agreement.final_components[index] > 0, "required final component is zero");
            if !included { shortfall += agreement.final_components[index]; }
        }
    }
    assert(shortfall > 0, "all required final components are present");
    shortfall
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
    subject_nullifier_high: pub u128,
    subject_nullifier_low: pub u128,
    parent_nullifier_high: pub u128,
    parent_nullifier_low: pub u128,
    fact_commitment_high: pub u128,
    fact_commitment_low: pub u128,
    parent_fact_commitment_high: pub u128,
    parent_fact_commitment_low: pub u128,
    validity_start: pub u64,
    validity_expiry: pub u64,
    shard_index: pub u8,
    run_nullifier: [u8; 32],
    policy_root: [u8; 32],
    snapshot_owner_address: [u8; 32],
    snapshot_due_at: u64,
    snapshot_grace_ends_at: u64,
    snapshot_claim_ends_at: u64,
    target_index: u8,
    agreement: AgreementWitness,
    agreement_siblings: [Field; 6],
    agreement_path_bits: [bool; 6],
    claim_capability_secret: [u8; 32],
    expected_net_atomic: u128,
    claim_siblings: [Field; 6],
    claim_path_bits: [bool; 6],
    claim_kind: u8,
    evidence_source: u8,
    statement_availability_commitment: [u8; 32],
    statement_observed_at: u64,
    line: PayrollLine,
    manifest_siblings: [Field; 6],
    manifest_path_bits: [bool; 6],
    fx_snapshot: FxSnapshot,
    fx_membership: CatalogMembership,
) {
    assert(chain_id != 0, "chain id is required");
    assert(seal_address != 0, "seal address is required");
    assert(proof_version == 6, "unsupported claim proof version");
    assert(schema_version == 2, "unsupported exception schema version");
    assert(shard_index == 0, "wage claim uses one proof");
    assert(validity_expiry >= validity_start, "invalid claim validity window");
    assert(
        validity_expiry - validity_start <= MAX_VALIDITY_WINDOW_SECONDS,
        "claim validity window is too long",
    );
    assert(run_nullifier != ZERO_BYTES, "run nullifier is zero");
    assert(policy_root != ZERO_BYTES, "policy root is zero");
    assert(snapshot_owner_address != ZERO_BYTES, "snapshot owner is zero");
    assert(snapshot_due_at <= snapshot_grace_ends_at, "snapshot grace precedes payday");
    assert(snapshot_grace_ends_at < snapshot_claim_ends_at, "claim deadline precedes grace");
    assert(validity_start >= snapshot_grace_ends_at, "claim grace period has not ended");
    assert(validity_start <= snapshot_claim_ends_at, "claim deadline has passed");
    assert(claim_kind <= CLAIM_INCOMPLETE_FINAL_PAY, "unknown wage claim kind");
    assert(evidence_source != EVIDENCE_PAYO_RUN, "native PAYO run cannot evidence a rejected condition");
    assert(
        (evidence_source == EVIDENCE_UNSETTLED_PERIOD)
            | (evidence_source == EVIDENCE_EMPLOYER_STATEMENT)
            | (evidence_source == EVIDENCE_SETTLEMENT_MATCH),
        "unsupported claim evidence source",
    );
    assert(agreement.enabled, "claim agreement is disabled");
    assert(agreement.token <= 1, "unsupported obligation token");
    assert(agreement.due_at == snapshot_due_at, "agreement payday does not match snapshot");
    assert(agreement.valid_until >= snapshot_due_at, "agreement expired before payday");
    assert(claim_capability_secret != ZERO_BYTES, "claim capability secret is zero");
    assert(expected_net_atomic > 0, "claim minimum net is zero");

    assert_membership_index(agreement_path_bits, target_index);
    assert_membership_index(claim_path_bits, target_index);
    let agreement_leaf = proof_hash_agreement_terms(agreement);
    let base_agreement_root = proof_merkle_membership(
        agreement_leaf, agreement_siblings, agreement_path_bits,
    );
    assert_field_root_limbs(base_agreement_root, agreement_root_high, agreement_root_low);
    let agreement_gross = gross(agreement);
    assert(expected_net_atomic <= agreement_gross, "claim minimum net exceeds gross");

    let capability_commitment = claim_capability_commitment_v2(claim_capability_secret);
    let claim_leaf = proof_claim_obligation_leaf(
        agreement_leaf, capability_commitment, expected_net_atomic,
    );
    let claim_root = proof_merkle_membership(claim_leaf, claim_siblings, claim_path_bits);
    let claim_root_bytes = claim_root.to_be_bytes();
    assert_root_limbs(policy_root, policy_root_high, policy_root_low);
    let snapshot_commitment = obligation_snapshot_commitment_v2(
        2,
        run_nullifier,
        base_agreement_root.to_be_bytes(),
        claim_root_bytes,
        policy_root,
        snapshot_owner_address,
        snapshot_due_at,
        snapshot_grace_ends_at,
        snapshot_claim_ends_at,
        claim_root_bytes,
    );

    let has_statement = (evidence_source == EVIDENCE_EMPLOYER_STATEMENT)
        | (evidence_source == EVIDENCE_SETTLEMENT_MATCH);
    if !has_statement {
        assert(claim_kind == CLAIM_MISSING_OBLIGATION, "unsettled evidence only proves omission");
        assert(statement_availability_commitment == ZERO_BYTES, "unsettled claim has statement availability");
        assert(statement_observed_at == 0, "unsettled claim has statement timestamp");
        assert_empty_line(line);
        assert_zero_path(manifest_siblings, manifest_path_bits);
    } else {
        assert(statement_availability_commitment != ZERO_BYTES, "statement availability is zero");
        assert(statement_observed_at >= snapshot_due_at, "statement predates payday");
        assert(statement_observed_at <= validity_start, "statement is from the future");
        assert_membership_index(manifest_path_bits, target_index);
    }

    let statement_leaf = if claim_kind == CLAIM_MISSING_OBLIGATION {
        if has_statement { assert_empty_line(line); }
        PROOF_EMPTY_LEAF
    } else {
        assert(has_statement, "non-omission claim requires a statement");
        let _net = assert_statement_line(line, agreement);
        proof_hash_payroll_line(line, agreement_leaf)
    };
    let manifest_root = if has_statement {
        proof_merkle_membership(statement_leaf, manifest_siblings, manifest_path_bits)
    } else {
        0
    };
    assert_field_root_limbs(manifest_root, manifest_root_high, manifest_root_low);

    let shortfall_unit: u8 = if claim_kind == CLAIM_BELOW_COMMITTED_FLOOR {
        assert(agreement.fx_floor_atomic > 0, "committed FX floor is zero");
        assert(has_statement, "FX-floor claim requires a statement");
        assert_fx_root(fx_snapshot, fx_membership, fx_root_high, fx_root_low);
        let net = assert_statement_line(line, agreement);
        let reference = reference_value_atomic(
            fx_snapshot,
            agreement.token,
            agreement.reference_currency,
            net,
            statement_observed_at,
        );
        assert(line.reference_value_atomic == reference, "statement FX value mismatch");
        assert(reference < agreement.fx_floor_atomic, "statement met the committed FX floor");
        if agreement.reference_currency == 0 { UNIT_USD_6 } else { UNIT_GBP_6 }
    } else {
        assert_empty_fx(fx_snapshot, fx_membership);
        assert((fx_root_high == 0) & (fx_root_low == 0), "non-FX claim exposes an FX root");
        if agreement.token == 0 { UNIT_STRK_ATOMIC } else { UNIT_USDC_ATOMIC }
    };

    let shortfall: u128 = if claim_kind == CLAIM_MISSING_OBLIGATION {
        expected_net_atomic
    } else if claim_kind == CLAIM_BELOW_COMMITTED_FLOOR {
        agreement.fx_floor_atomic - line.reference_value_atomic
    } else {
        missing_final_shortfall(agreement, line.final_included_mask)
    };
    assert(shortfall > 0, "claim shortfall is zero");

    let statement_commitment = if has_statement {
        payroll_statement_commitment_v2(
            2,
            run_nullifier,
            snapshot_commitment,
            manifest_root.to_be_bytes(),
            if claim_kind == CLAIM_BELOW_COMMITTED_FLOOR {
                fx_snapshot_commitment_root_bytes(fx_root_high, fx_root_low)
            } else {
                ZERO_BYTES
            },
            statement_availability_commitment,
            statement_observed_at,
            evidence_source,
        )
    } else {
        ZERO_BYTES
    };
    let parent_fact = if has_statement { statement_commitment } else { snapshot_commitment };
    assert_root_limbs(parent_fact, parent_fact_commitment_high, parent_fact_commitment_low);

    let claim_subject = claim_subject_nullifier_v2(
        claim_capability_secret,
        run_nullifier,
        agreement_leaf.to_be_bytes(),
        claim_kind,
    );
    assert_root_limbs(claim_subject, subject_nullifier_high, subject_nullifier_low);
    assert_root_limbs(run_nullifier, parent_nullifier_high, parent_nullifier_low);
    let claim_fact = claim_fact_commitment_v2(
        claim_subject,
        run_nullifier,
        snapshot_commitment,
        statement_commitment,
        manifest_root.to_be_bytes(),
        agreement_leaf.to_be_bytes(),
        target_index,
        claim_kind,
        shortfall,
        shortfall_unit,
        agreement.token,
        evidence_source,
    );
    assert_root_limbs(claim_fact, fact_commitment_high, fact_commitment_low);
}

fn fx_snapshot_commitment_root_bytes(high: u128, low: u128) -> [u8; 32] {
    let high_bytes: [u8; 16] = (high as Field).to_be_bytes();
    let low_bytes: [u8; 16] = (low as Field).to_be_bytes();
    let mut result: [u8; 32] = [0; 32];
    for index in 0..16 {
        result[index] = high_bytes[index];
        result[index + 16] = low_bytes[index];
    }
    result
}

#[test(should_fail_with = "native PAYO run cannot evidence a rejected condition")]
fn rejects_native_run_as_claim_evidence() {
    let source = EVIDENCE_PAYO_RUN;
    assert(source != EVIDENCE_PAYO_RUN, "native PAYO run cannot evidence a rejected condition");
}

#[test(should_fail_with = "all required final components are present")]
fn rejects_false_final_pay_claim() {
    let mut agreement = dep::payroll_types::empty_agreement();
    agreement.enabled = true;
    agreement.final_pay_mode = true;
    agreement.final_required_mask = 1;
    agreement.final_components[0] = 10;
    let _ = missing_final_shortfall(agreement, 1);
}

#[test(should_fail_with = "claim grace period has not ended")]
fn rejects_claim_before_grace() {
    let validity_start: u64 = 99;
    let grace_ends_at: u64 = 100;
    assert(validity_start >= grace_ends_at, "claim grace period has not ended");
}
