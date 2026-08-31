mod settlement_commitments;
mod stark_poseidon;
mod stark_poseidon_constants;

use dep::payroll_types::{
    MAX_COMPONENTS, MAX_FINAL_COMPONENTS, MAX_LINES, MAX_REAL_LINES,
    PACKED_AMOUNT_LIMIT, PROOF_EMPTY_LEAF, ZERO_BYTES,
    AgreementWitness, PayrollLine, assert_field_root_limbs, assert_root_limbs,
    gross, proof_hash_agreement_terms, proof_hash_payroll_line, proof_merkle_root,
};
use settlement_commitments::{
    SETTLEMENT_TREE_DEPTH, ZERO_DIGEST, assert_path_index, recipient_commitment,
    settlement_membership, settlement_note_leaf,
};
use stark_poseidon::{
    StarkFelt, STARK_FIELD_PARAMS, from_limbs, from_u128, hash_many_5, hash_many_6,
};

global SETTLEMENT_PROOF_VERSION: u32 = 8;
global CHUNK_LINES: u32 = 3;
global MAX_CHUNKS: u32 = 17;

global CHANNEL_KEY_TAG: [u128; 3] = [
    0x4e4e454c5f4b45595f5441473a5631,
    0x434841,
    0,
];
global NOTE_ID_TAG: [u128; 3] = [0x4e4f54455f49445f5441473a5631, 0, 0];
global ENC_AMOUNT_TAG: [u128; 3] = [
    0x435f414d4f554e545f5441473a5631,
    0x454e,
    0,
];

global STRK_ADDRESS: [u8; 32] = [
    4, 113, 143, 90, 15, 195, 76, 193, 175, 22, 161, 205, 238, 152, 255, 178,
    12, 49, 245, 205, 97, 214, 171, 7, 32, 24, 88, 244, 40, 124, 147, 141,
];
global USDC_ADDRESS: [u8; 32] = [
    3, 48, 104, 246, 83, 159, 142, 110, 107, 19, 30, 107, 43, 129, 78, 108,
    52, 165, 34, 75, 198, 105, 71, 196, 125, 171, 157, 254, 233, 59, 53, 251,
];

struct SettlementNoteWitness {
    recipient_address: [u8; 32],
    recipient_public_key: [u8; 32],
    recipient_commitment_salt: [u8; 32],
    note_index: u32,
    note_id: [u8; 32],
    packed_value: [u8; 32],
    settlement_siblings: [[u8; 32]; SETTLEMENT_TREE_DEPTH],
    settlement_path_bits: [bool; SETTLEMENT_TREE_DEPTH],
}

fn stark_felt_from_be_bytes(value: [u8; 32]) -> StarkFelt {
    let mut limb_2: u128 = 0;
    for index in 0..2 { limb_2 = limb_2 * 256 + value[index] as u128; }
    let mut limb_1: u128 = 0;
    for index in 2..17 { limb_1 = limb_1 * 256 + value[index] as u128; }
    let mut limb_0: u128 = 0;
    for index in 17..32 { limb_0 = limb_0 * 256 + value[index] as u128; }
    let result = from_limbs([limb_0, limb_1, limb_2]);
    result.validate_in_field();
    result
}

fn assert_nonzero_digest<let N: u32>(value: [u8; 32], message: str<N>) {
    assert(value != ZERO_DIGEST, message);
}

fn deductions_total(line: PayrollLine) -> u128 {
    assert(line.deductions_count <= MAX_COMPONENTS, "too many settlement deductions");
    let mut total: u128 = 0;
    for index in 0..MAX_COMPONENTS {
        if index < line.deductions_count {
            total += line.deductions[index];
        } else {
            assert(line.deductions[index] == 0, "unused settlement deduction is nonzero");
        }
    }
    total
}

fn assert_empty_agreement(agreement: AgreementWitness) {
    assert(!agreement.enabled, "padding agreement is enabled");
    assert(agreement.id_commitment == ZERO_BYTES, "padding agreement id is nonzero");
    assert(agreement.recipient_commitment == ZERO_BYTES, "padding recipient is nonzero");
    assert(agreement.earnings_count == 0, "padding earnings count is nonzero");
    for index in 0..MAX_COMPONENTS {
        assert(agreement.earnings[index] == 0, "padding earning is nonzero");
    }
    assert(agreement.token == 0, "padding token is nonzero");
    assert(agreement.policy_commitment == ZERO_BYTES, "padding policy is nonzero");
    assert(agreement.schedule_commitment == ZERO_BYTES, "padding schedule is nonzero");
    assert((agreement.due_at == 0) & (agreement.valid_until == 0), "padding dates are nonzero");
    assert(agreement.classification_declared == 0, "padding classification is nonzero");
    assert(agreement.classification_score == 0, "padding score is nonzero");
    assert(agreement.classification_employee_threshold == 0, "padding threshold is nonzero");
    assert(!agreement.final_pay_mode, "padding final-pay mode is true");
    assert(agreement.final_required_mask == 0, "padding final mask is nonzero");
    for index in 0..MAX_FINAL_COMPONENTS {
        assert(agreement.final_components[index] == 0, "padding final component is nonzero");
    }
    assert(agreement.fx_floor_atomic == 0, "padding FX floor is nonzero");
    assert(agreement.reference_currency == 0, "padding currency is nonzero");
    assert(agreement.salt == ZERO_BYTES, "padding agreement salt is nonzero");
}

fn assert_empty_line(line: PayrollLine) {
    assert(!line.active, "padding payroll line is active");
    assert(line.deductions_count == 0, "padding deduction count is nonzero");
    for index in 0..MAX_COMPONENTS {
        assert(line.deductions[index] == 0, "padding deduction is nonzero");
    }
    assert((line.policy_slot == 0) & (line.fx_slot == 0), "padding slot is nonzero");
    assert(line.salt == ZERO_BYTES, "padding line salt is nonzero");
    assert(line.classification_treatment == 0, "padding treatment is nonzero");
    assert(line.final_included_mask == 0, "padding final mask is nonzero");
    assert(line.reference_value_atomic == 0, "padding reference value is nonzero");
}

fn assert_empty_note(note: SettlementNoteWitness) {
    assert(note.recipient_address == ZERO_BYTES, "padding recipient address is nonzero");
    assert(note.recipient_public_key == ZERO_BYTES, "padding recipient key is nonzero");
    assert(note.recipient_commitment_salt == ZERO_BYTES, "padding recipient salt is nonzero");
    assert(note.note_index == 0, "padding note index is nonzero");
    assert(note.note_id == ZERO_BYTES, "padding note id is nonzero");
    assert(note.packed_value == ZERO_BYTES, "padding packed value is nonzero");
    for level in 0..SETTLEMENT_TREE_DEPTH {
        assert(note.settlement_siblings[level] == ZERO_BYTES, "padding sibling is nonzero");
        assert(!note.settlement_path_bits[level], "padding path bit is true");
    }
}

fn assert_active_note(
    target_index: u8,
    agreement: AgreementWitness,
    line: PayrollLine,
    note: SettlementNoteWitness,
    sender_address: StarkFelt,
    viewing_key: StarkFelt,
    settlement_root_high: u128,
    settlement_root_low: u128,
) {
    assert(agreement.enabled, "settlement agreement is disabled");
    assert(line.active, "settlement payroll line is inactive");
    assert(agreement.token <= 1, "unsupported settlement token");
    assert_nonzero_digest(note.recipient_address, "settlement recipient address is zero");
    assert_nonzero_digest(note.recipient_public_key, "settlement recipient public key zero");
    assert_nonzero_digest(note.recipient_commitment_salt, "settlement recipient salt is zero");
    assert(
        recipient_commitment(note.recipient_address, note.recipient_commitment_salt)
            == agreement.recipient_commitment,
        "settlement recipient commitment mismatch",
    );

    let recipient_address = stark_felt_from_be_bytes(note.recipient_address);
    let recipient_public_key = stark_felt_from_be_bytes(note.recipient_public_key);
    let token = stark_felt_from_be_bytes(if agreement.token == 0 { STRK_ADDRESS } else { USDC_ADDRESS });
    let channel_key = hash_many_5([
        from_limbs(CHANNEL_KEY_TAG), sender_address, viewing_key,
        recipient_address, recipient_public_key,
    ]);
    let expected_note_id = hash_many_5([
        from_limbs(NOTE_ID_TAG), channel_key, token, from_u128(note.note_index as u128),
        StarkFelt::zero(STARK_FIELD_PARAMS),
    ]);
    expected_note_id.validate_in_field();
    assert(expected_note_id.to_be_bytes() == note.note_id, "STRK20 note id mismatch");

    assert(note.packed_value[0] == 0, "STRK20 packed value exceeds 248 bits");
    let mut note_salt: u128 = 0;
    for index in 1..16 { note_salt = note_salt * 256 + note.packed_value[index] as u128; }
    assert(note_salt > 0, "STRK20 note salt is zero");
    let amount_hash = hash_many_6([
        from_limbs(ENC_AMOUNT_TAG), channel_key, token, from_u128(note.note_index as u128),
        StarkFelt::zero(STARK_FIELD_PARAMS), from_u128(note_salt),
    ]);
    amount_hash.validate_in_field();

    let agreement_gross = gross(agreement);
    let deductions = deductions_total(line);
    assert(deductions <= agreement_gross, "settlement deductions exceed gross");
    let amount = agreement_gross - deductions;
    assert(amount > 0, "settlement amount is zero");
    let amount_low = amount % PACKED_AMOUNT_LIMIT;
    let amount_high = amount / PACKED_AMOUNT_LIMIT;
    let low_sum = amount_hash.limbs[0] + amount_low;
    let carry = low_sum >= PACKED_AMOUNT_LIMIT;
    let encrypted_low = if carry { low_sum - PACKED_AMOUNT_LIMIT } else { low_sum };
    let encrypted_high = (
        amount_hash.limbs[1] % 256 + amount_high + if carry { 1 } else { 0 }
    ) % 256;
    let encrypted_amount = encrypted_low + encrypted_high * PACKED_AMOUNT_LIMIT;
    let encrypted_bytes: [u8; 16] = (encrypted_amount as Field).to_be_bytes();
    for index in 0..16 {
        assert(note.packed_value[16 + index] == encrypted_bytes[index], "encrypted amount mismatch");
    }

    assert_path_index(note.settlement_path_bits, target_index);
    let settlement_root = settlement_membership(
        settlement_note_leaf(target_index, note.note_id, note.packed_value),
        note.settlement_siblings,
        note.settlement_path_bits,
    );
    assert_root_limbs(settlement_root, settlement_root_high, settlement_root_low);
}

fn main(
    proof_version: pub u32,
    manifest_root_high: pub u128,
    manifest_root_low: pub u128,
    run_nullifier_high: pub u128,
    run_nullifier_low: pub u128,
    transaction_reference_high: pub u128,
    transaction_reference_low: pub u128,
    settlement_root_high: pub u128,
    settlement_root_low: pub u128,
    chunk_index: pub u8,
    chunk_count: pub u8,
    payroll_leaves: [Field; MAX_LINES],
    sender_address_bytes: [u8; 32],
    viewing_key_bytes: [u8; 32],
    agreements: [AgreementWitness; CHUNK_LINES],
    lines: [PayrollLine; CHUNK_LINES],
    notes: [SettlementNoteWitness; CHUNK_LINES],
) {
    assert(proof_version == SETTLEMENT_PROOF_VERSION, "unsupported SettlementMatch version");
    assert((manifest_root_high != 0) | (manifest_root_low != 0), "manifest root is zero");
    assert((run_nullifier_high != 0) | (run_nullifier_low != 0), "run nullifier is zero");
    assert(
        (transaction_reference_high != 0) | (transaction_reference_low != 0),
        "transaction reference is zero",
    );
    assert((settlement_root_high != 0) | (settlement_root_low != 0), "settlement root is zero");
    assert(sender_address_bytes != ZERO_BYTES, "settlement sender is zero");
    assert(viewing_key_bytes != ZERO_BYTES, "settlement viewing key is zero");

    assert_field_root_limbs(proof_merkle_root(payroll_leaves), manifest_root_high, manifest_root_low);
    let mut real_count: u32 = 0;
    let mut reached_padding = false;
    for index in 0..MAX_REAL_LINES {
        let is_empty = payroll_leaves[index] == PROOF_EMPTY_LEAF;
        if reached_padding { assert(is_empty, "manifest leaves are not packed"); }
        if is_empty { reached_padding = true; } else { real_count += 1; }
    }
    for index in MAX_REAL_LINES..MAX_LINES {
        assert(payroll_leaves[index] == PROOF_EMPTY_LEAF, "manifest padding leaf mismatch");
    }
    assert(real_count > 0, "settlement manifest is empty");
    let expected_chunk_count = (real_count + CHUNK_LINES - 1) / CHUNK_LINES;
    assert(expected_chunk_count <= MAX_CHUNKS, "too many settlement chunks");
    assert(chunk_count as u32 == expected_chunk_count, "settlement chunk count mismatch");
    assert(chunk_index < chunk_count, "settlement chunk index is out of range");

    let sender_address = stark_felt_from_be_bytes(sender_address_bytes);
    let viewing_key = stark_felt_from_be_bytes(viewing_key_bytes);
    for offset in 0..CHUNK_LINES {
        let target_u32 = chunk_index as u32 * CHUNK_LINES + offset;
        let target = target_u32 as u8;
        let is_active = target_u32 < real_count;
        if is_active {
            let agreement_leaf = proof_hash_agreement_terms(agreements[offset]);
            assert(
                proof_hash_payroll_line(lines[offset], agreement_leaf) == payroll_leaves[target_u32],
                "settlement manifest line mismatch",
            );
            assert_active_note(
                target,
                agreements[offset],
                lines[offset],
                notes[offset],
                sender_address,
                viewing_key,
                settlement_root_high,
                settlement_root_low,
            );
        } else {
            assert(payroll_leaves[target_u32] == PROOF_EMPTY_LEAF, "missing active settlement line");
            assert_empty_agreement(agreements[offset]);
            assert_empty_line(lines[offset]);
            assert_empty_note(notes[offset]);
        }
    }
}
