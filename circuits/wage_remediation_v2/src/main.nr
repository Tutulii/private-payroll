use dep::exception_protocol::{
    claim_fact_commitment_v2, remediation_fact_commitment_v2,
    remediation_subject_nullifier_v2,
};
use dep::fx_types::{
    CatalogMembership, FxSnapshot, assert_empty_fx, assert_fx_root,
    reference_value_atomic,
};
use dep::payroll_types::{
    ZERO_BYTES, AgreementWitness, assert_field_root_limbs,
    assert_membership_index, assert_root_limbs, proof_hash_agreement_terms,
    proof_merkle_membership, proof_remediation_action,
};

global MAX_VALIDITY_WINDOW_SECONDS: u64 = 3600;
global CLAIM_BELOW_COMMITTED_FLOOR: u8 = 1;
global CLAIM_INCOMPLETE_FINAL_PAY: u8 = 2;
global UNIT_STRK_ATOMIC: u8 = 0;
global UNIT_USDC_ATOMIC: u8 = 1;
global UNIT_USD_6: u8 = 2;
global UNIT_GBP_6: u8 = 3;

fn assert_claim_dimensions(
    claim_kind: u8,
    claim_shortfall_unit: u8,
    obligation_token: u8,
    reference_currency: u8,
) {
    assert(claim_kind <= CLAIM_INCOMPLETE_FINAL_PAY, "unknown accepted claim kind");
    assert(obligation_token <= 1, "unsupported accepted claim token");
    if claim_kind == CLAIM_BELOW_COMMITTED_FLOOR {
        assert(reference_currency <= 1, "unsupported accepted claim currency");
        let expected_unit = if reference_currency == 0 { UNIT_USD_6 } else { UNIT_GBP_6 };
        assert(claim_shortfall_unit == expected_unit, "accepted FX claim has wrong unit");
    } else {
        let expected_unit = if obligation_token == 0 { UNIT_STRK_ATOMIC } else { UNIT_USDC_ATOMIC };
        assert(claim_shortfall_unit == expected_unit, "accepted token claim has wrong unit");
    }
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
    policy_root: [u8; 32],
    accepted_claim_subject: [u8; 32],
    accepted_claim_run_nullifier: [u8; 32],
    accepted_snapshot_commitment: [u8; 32],
    accepted_statement_commitment: [u8; 32],
    accepted_manifest_root: [u8; 32],
    accepted_target_index: u8,
    accepted_claim_kind: u8,
    accepted_claim_shortfall: u128,
    accepted_claim_shortfall_unit: u8,
    accepted_obligation_token: u8,
    accepted_evidence_source: u8,
    agreement: AgreementWitness,
    agreement_siblings: [Field; 6],
    agreement_path_bits: [bool; 6],
    remediation_secret: [u8; 32],
    remediation_action_salt: [u8; 32],
    remediation_amount_atomic: u128,
    remediation_token: u8,
    fx_snapshot: FxSnapshot,
    fx_membership: CatalogMembership,
) {
    assert(chain_id != 0, "chain id is required");
    assert(seal_address != 0, "seal address is required");
    assert(proof_version == 7, "unsupported remediation proof version");
    assert(schema_version == 2, "unsupported exception schema version");
    assert(shard_index == 0, "wage remediation uses one proof");
    assert(validity_expiry >= validity_start, "invalid remediation validity window");
    assert(
        validity_expiry - validity_start <= MAX_VALIDITY_WINDOW_SECONDS,
        "remediation validity window is too long",
    );
    assert(policy_root != ZERO_BYTES, "policy root is zero");
    assert_root_limbs(policy_root, policy_root_high, policy_root_low);
    assert(accepted_claim_subject != ZERO_BYTES, "accepted claim subject is zero");
    assert(accepted_claim_run_nullifier != ZERO_BYTES, "accepted run nullifier is zero");
    assert(accepted_snapshot_commitment != ZERO_BYTES, "accepted snapshot is zero");
    assert(accepted_claim_shortfall > 0, "accepted claim shortfall is zero");
    assert(accepted_evidence_source <= 3, "unsupported accepted evidence source");
    assert(remediation_secret != ZERO_BYTES, "remediation secret is zero");
    assert(remediation_action_salt != ZERO_BYTES, "remediation action salt is zero");
    assert(remediation_amount_atomic > 0, "remediation amount is zero");
    assert(remediation_token == accepted_obligation_token, "remediation token differs from obligation");
    assert(agreement.enabled, "remediation agreement is disabled");
    assert(agreement.token == accepted_obligation_token, "agreement token differs from accepted claim");
    assert(agreement.recipient_commitment != ZERO_BYTES, "remediation recipient is zero");
    assert_claim_dimensions(
        accepted_claim_kind,
        accepted_claim_shortfall_unit,
        accepted_obligation_token,
        agreement.reference_currency,
    );

    assert_membership_index(agreement_path_bits, accepted_target_index);
    let agreement_leaf = proof_hash_agreement_terms(agreement);
    let agreement_root = proof_merkle_membership(
        agreement_leaf, agreement_siblings, agreement_path_bits,
    );
    assert_field_root_limbs(agreement_root, agreement_root_high, agreement_root_low);

    let accepted_claim_fact = claim_fact_commitment_v2(
        accepted_claim_subject,
        accepted_claim_run_nullifier,
        accepted_snapshot_commitment,
        accepted_statement_commitment,
        accepted_manifest_root,
        agreement_leaf.to_be_bytes(),
        accepted_target_index,
        accepted_claim_kind,
        accepted_claim_shortfall,
        accepted_claim_shortfall_unit,
        accepted_obligation_token,
        accepted_evidence_source,
    );
    assert_root_limbs(
        accepted_claim_fact,
        parent_fact_commitment_high,
        parent_fact_commitment_low,
    );
    assert_root_limbs(
        accepted_claim_subject,
        parent_nullifier_high,
        parent_nullifier_low,
    );

    let remediation_reference_value: u128 = if accepted_claim_kind
        == CLAIM_BELOW_COMMITTED_FLOOR {
        assert_fx_root(fx_snapshot, fx_membership, fx_root_high, fx_root_low);
        let reference = reference_value_atomic(
            fx_snapshot,
            remediation_token,
            agreement.reference_currency,
            remediation_amount_atomic,
            validity_start,
        );
        assert(reference >= accepted_claim_shortfall, "FX remediation is below the accepted shortfall");
        reference
    } else {
        assert_empty_fx(fx_snapshot, fx_membership);
        assert((fx_root_high == 0) & (fx_root_low == 0), "token remediation exposes an FX root");
        assert(
            remediation_amount_atomic >= accepted_claim_shortfall,
            "remediation is below the accepted shortfall",
        );
        remediation_amount_atomic
    };

    let remediation_subject = remediation_subject_nullifier_v2(
        accepted_claim_subject, remediation_secret,
    );
    assert_root_limbs(remediation_subject, subject_nullifier_high, subject_nullifier_low);
    let action_commitment = proof_remediation_action(
        accepted_claim_subject,
        agreement.recipient_commitment,
        remediation_token,
        remediation_amount_atomic,
        remediation_action_salt,
    );
    assert_field_root_limbs(action_commitment, manifest_root_high, manifest_root_low);

    let remediation_fx_root = if accepted_claim_kind == CLAIM_BELOW_COMMITTED_FLOOR {
        limbs_to_bytes(fx_root_high, fx_root_low)
    } else {
        ZERO_BYTES
    };
    let remediation_fact = remediation_fact_commitment_v2(
        remediation_subject,
        accepted_claim_subject,
        accepted_claim_fact,
        agreement.recipient_commitment,
        remediation_token,
        remediation_amount_atomic,
        remediation_reference_value,
        accepted_claim_shortfall_unit,
        remediation_fx_root,
    );
    assert_root_limbs(remediation_fact, fact_commitment_high, fact_commitment_low);
}

fn limbs_to_bytes(high: u128, low: u128) -> [u8; 32] {
    let high_bytes: [u8; 16] = (high as Field).to_be_bytes();
    let low_bytes: [u8; 16] = (low as Field).to_be_bytes();
    let mut result: [u8; 32] = [0; 32];
    for index in 0..16 {
        result[index] = high_bytes[index];
        result[index + 16] = low_bytes[index];
    }
    result
}

#[test(should_fail_with = "remediation token differs from obligation")]
fn rejects_wrong_token() {
    let remediation_token: u8 = 1;
    let obligation_token: u8 = 0;
    assert(remediation_token == obligation_token, "remediation token differs from obligation");
}

#[test(should_fail_with = "remediation is below the accepted shortfall")]
fn rejects_token_underpayment() {
    let amount: u128 = 99;
    let shortfall: u128 = 100;
    assert(amount >= shortfall, "remediation is below the accepted shortfall");
}

#[test]
fn remediation_subject_is_distinct_from_claim_subject() {
    let claim = [1; 32];
    let remediation = remediation_subject_nullifier_v2(claim, [2; 32]);
    assert(remediation != claim, "remediation reused the claim subject");
    assert(remediation != remediation_subject_nullifier_v2(claim, [3; 32]), "attempt secret is not bound");
}
