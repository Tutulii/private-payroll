use core::byte_array::ByteArrayTrait;
use core::integer::u128_byte_reverse;
use core::keccak::compute_keccak_byte_array;

fn canonical_keccak(message: @ByteArray) -> u256 {
    let digest = compute_keccak_byte_array(message);
    u256 { high: u128_byte_reverse(digest.low), low: u128_byte_reverse(digest.high) }
}

fn append_u8(ref output: ByteArray, value: u8) {
    output.append_word(value.into(), 1);
}

fn append_u64(ref output: ByteArray, value: u64) {
    output.append_word(value.into(), 8);
}

fn append_u128(ref output: ByteArray, value: u128) {
    output.append_word(value.into(), 16);
}

fn append_u256(ref output: ByteArray, value: u256) {
    append_u128(ref output, value.high);
    append_u128(ref output, value.low);
}

pub fn claim_capability_commitment_v2(secret: u256) -> u256 {
    let mut message: ByteArray = "PAYO_CLAIM_CAPABILITY_V2";
    append_u256(ref message, secret);
    canonical_keccak(@message)
}

pub fn obligation_snapshot_commitment_v2(
    schema_version: u8,
    run_nullifier: u256,
    base_agreement_root: u256,
    obligation_root: u256,
    policy_root: u256,
    owner_address: u256,
    due_at: u64,
    grace_ends_at: u64,
    claim_ends_at: u64,
    availability_commitment: u256,
) -> u256 {
    let mut message: ByteArray = "PAYO_OBLIGATION_SNAPSHOT_V2";
    append_u8(ref message, schema_version);
    append_u256(ref message, run_nullifier);
    append_u256(ref message, base_agreement_root);
    append_u256(ref message, obligation_root);
    append_u256(ref message, policy_root);
    append_u256(ref message, owner_address);
    append_u64(ref message, due_at);
    append_u64(ref message, grace_ends_at);
    append_u64(ref message, claim_ends_at);
    append_u256(ref message, availability_commitment);
    canonical_keccak(@message)
}

pub fn payroll_statement_commitment_v2(
    schema_version: u8,
    run_nullifier: u256,
    snapshot_commitment: u256,
    manifest_root: u256,
    fx_root: u256,
    availability_commitment: u256,
    observed_at: u64,
    source: u8,
) -> u256 {
    let mut message: ByteArray = "PAYO_PAYROLL_STATEMENT_V2";
    append_u8(ref message, schema_version);
    append_u256(ref message, run_nullifier);
    append_u256(ref message, snapshot_commitment);
    append_u256(ref message, manifest_root);
    append_u256(ref message, fx_root);
    append_u256(ref message, availability_commitment);
    append_u64(ref message, observed_at);
    append_u8(ref message, source);
    canonical_keccak(@message)
}

pub fn claim_subject_nullifier_v2(
    claim_capability_secret: u256,
    run_nullifier: u256,
    agreement_leaf: u256,
    claim_kind: u8,
) -> u256 {
    let mut message: ByteArray = "PAYO_CLAIM_SUBJECT_V2";
    append_u256(ref message, claim_capability_secret);
    append_u256(ref message, run_nullifier);
    append_u256(ref message, agreement_leaf);
    append_u8(ref message, claim_kind);
    canonical_keccak(@message)
}

pub fn claim_fact_commitment_v2(
    claim_subject_nullifier: u256,
    run_nullifier: u256,
    snapshot_commitment: u256,
    statement_commitment: u256,
    manifest_root: u256,
    agreement_leaf: u256,
    target_index: u8,
    claim_kind: u8,
    shortfall_atomic: u128,
    shortfall_unit: u8,
    obligation_token: u8,
    evidence_source: u8,
) -> u256 {
    let mut message: ByteArray = "PAYO_CLAIM_FACT_V2";
    append_u256(ref message, claim_subject_nullifier);
    append_u256(ref message, run_nullifier);
    append_u256(ref message, snapshot_commitment);
    append_u256(ref message, statement_commitment);
    append_u256(ref message, manifest_root);
    append_u256(ref message, agreement_leaf);
    append_u8(ref message, target_index);
    append_u8(ref message, claim_kind);
    append_u128(ref message, shortfall_atomic);
    append_u8(ref message, shortfall_unit);
    append_u8(ref message, obligation_token);
    append_u8(ref message, evidence_source);
    canonical_keccak(@message)
}

pub fn remediation_subject_nullifier_v2(
    claim_subject_nullifier: u256,
    remediation_secret: u256,
) -> u256 {
    let mut message: ByteArray = "PAYO_REMEDIATION_SUBJECT_V2";
    append_u256(ref message, claim_subject_nullifier);
    append_u256(ref message, remediation_secret);
    canonical_keccak(@message)
}

pub fn remediation_fact_commitment_v2(
    remediation_subject_nullifier: u256,
    claim_subject_nullifier: u256,
    claim_fact_commitment: u256,
    recipient_commitment: u256,
    token: u8,
    amount_atomic: u128,
    reference_value_atomic: u128,
    reference_unit: u8,
    fx_root: u256,
) -> u256 {
    let mut message: ByteArray = "PAYO_REMEDIATION_FACT_V2";
    append_u256(ref message, remediation_subject_nullifier);
    append_u256(ref message, claim_subject_nullifier);
    append_u256(ref message, claim_fact_commitment);
    append_u256(ref message, recipient_commitment);
    append_u8(ref message, token);
    append_u128(ref message, amount_atomic);
    append_u128(ref message, reference_value_atomic);
    append_u8(ref message, reference_unit);
    append_u256(ref message, fx_root);
    canonical_keccak(@message)
}
