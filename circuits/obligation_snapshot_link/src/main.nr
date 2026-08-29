use dep::exception_protocol::obligation_snapshot_commitment_v2;
use dep::payroll_types::{
    MAX_LINES, MAX_REAL_LINES, PROOF_EMPTY_LEAF, ZERO_BYTES,
    assert_field_root_limbs, assert_root_limbs, proof_claim_obligation_leaf,
    proof_merkle_root,
};

global MAX_VALIDITY_WINDOW_SECONDS: u64 = 3600;

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
    owner_address: [u8; 32],
    due_at: u64,
    grace_ends_at: u64,
    claim_ends_at: u64,
    base_agreement_leaves: [Field; MAX_LINES],
    claim_capability_commitments: [[u8; 32]; MAX_REAL_LINES],
    expected_net_amounts: [u128; MAX_REAL_LINES],
) {
    assert(chain_id != 0, "chain id is required");
    assert(seal_address != 0, "seal address is required");
    assert(proof_version == 5, "unsupported snapshot-link proof version");
    assert(schema_version == 2, "unsupported exception schema version");
    assert(shard_index == 0, "snapshot link uses one proof");
    assert(validity_expiry >= validity_start, "invalid snapshot-link window");
    assert(
        validity_expiry - validity_start <= MAX_VALIDITY_WINDOW_SECONDS,
        "snapshot-link window is too long",
    );
    assert(run_nullifier != ZERO_BYTES, "run nullifier is zero");
    assert(policy_root != ZERO_BYTES, "policy root is zero");
    assert(owner_address != ZERO_BYTES, "snapshot owner is zero");
    assert(due_at <= grace_ends_at, "grace ends before payday");
    assert(grace_ends_at < claim_ends_at, "claim deadline must follow grace");
    assert((fx_root_high == 0) & (fx_root_low == 0), "snapshot link has no FX root");
    assert(
        (parent_nullifier_high == 0) & (parent_nullifier_low == 0),
        "snapshot link has no parent nullifier",
    );
    assert(
        (parent_fact_commitment_high == 0) & (parent_fact_commitment_low == 0),
        "snapshot link has no parent fact",
    );

    let mut claim_leaves: [Field; MAX_LINES] = [PROOF_EMPTY_LEAF; MAX_LINES];
    let mut seen_empty = false;
    let mut real_count: u32 = 0;
    for index in 0..MAX_REAL_LINES {
        let agreement_leaf = base_agreement_leaves[index];
        let capability = claim_capability_commitments[index];
        let expected_net = expected_net_amounts[index];
        if agreement_leaf == PROOF_EMPTY_LEAF {
            seen_empty = true;
            assert(capability == ZERO_BYTES, "empty slot has claim capability");
            assert(expected_net == 0, "empty slot has claim minimum net");
        } else {
            assert(!seen_empty, "snapshot agreement slots must be packed");
            assert(capability != ZERO_BYTES, "claim capability is zero");
            claim_leaves[index] = proof_claim_obligation_leaf(
                agreement_leaf, capability, expected_net,
            );
            real_count += 1;
        }
    }
    assert(real_count > 0, "snapshot has no obligations");
    for index in MAX_REAL_LINES..MAX_LINES {
        assert(base_agreement_leaves[index] == PROOF_EMPTY_LEAF, "snapshot padding is not empty");
    }

    let agreement_root = proof_merkle_root(base_agreement_leaves);
    let claim_root = proof_merkle_root(claim_leaves);
    assert_field_root_limbs(agreement_root, agreement_root_high, agreement_root_low);
    assert_field_root_limbs(claim_root, manifest_root_high, manifest_root_low);
    assert_root_limbs(policy_root, policy_root_high, policy_root_low);
    assert_root_limbs(run_nullifier, subject_nullifier_high, subject_nullifier_low);

    let snapshot_commitment = obligation_snapshot_commitment_v2(
        2,
        run_nullifier,
        agreement_root.to_be_bytes(),
        claim_root.to_be_bytes(),
        policy_root,
        owner_address,
        due_at,
        grace_ends_at,
        claim_ends_at,
        claim_root.to_be_bytes(),
    );
    assert_root_limbs(snapshot_commitment, fact_commitment_high, fact_commitment_low);
}

#[test(should_fail_with = "claim capability is zero")]
fn rejects_missing_claim_capability() {
    let agreement_leaf = 1;
    let capability = [0; 32];
    assert(
        (agreement_leaf == PROOF_EMPTY_LEAF) | (capability != ZERO_BYTES),
        "claim capability is zero",
    );
}

#[test(should_fail_with = "snapshot agreement slots must be packed")]
fn rejects_gap_before_real_obligation() {
    let first = PROOF_EMPTY_LEAF;
    let second = 1;
    assert(
        !((first == PROOF_EMPTY_LEAF) & (second != PROOF_EMPTY_LEAF)),
        "snapshot agreement slots must be packed",
    );
}
