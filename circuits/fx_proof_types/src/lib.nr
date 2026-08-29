use dep::keccak256::keccak256;
use dep::payroll_types::{
    ZERO_BYTES, assert_field_root_limbs, bytes_as_fields, proof_hash,
    proof_merkle_membership,
};

pub global BPS_DENOMINATOR: u128 = 10000;
pub global PROOF_DOMAIN_CATALOG_LEAF: Field = 5;

pub struct CatalogMembership {
    pub siblings: [Field; 6],
    pub path_bits: [bool; 6],
}

pub struct FxSnapshot {
    pub token: u8,
    pub token_decimals: u8,
    pub reference_currency: u8,
    pub quote_decimals: u8,
    pub feed_commitment: [u8; 32],
    pub sources_commitment: [u8; 32],
    pub price_numerator: u128,
    pub price_denominator: u128,
    pub observed_at: u64,
    pub source_count: u8,
    pub minimum_source_count: u8,
    pub maximum_age_seconds: u64,
    pub haircut_bps: u16,
}

pub fn fx_snapshot_commitment_v1(snapshot: FxSnapshot) -> [u8; 32] {
    let domain = "PAYO_FX_SNAPSHOT_V1".as_bytes();
    // 19-byte domain + 120 bytes of fixed-width fields. Keep this exact: the
    // TypeScript and Cairo encoders hash the same 139-byte message.
    let mut message: [u8; 139] = [0; 139];
    let mut cursor: u32 = domain.len();
    for index in 0..domain.len() { message[index] = domain[index]; }
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
        message[cursor + 16 + index] = denominator[index];
    }
    cursor += 32;
    for index in 0..8 { message[cursor + index] = observed[index]; }
    cursor += 8;
    message[cursor] = snapshot.source_count;
    message[cursor + 1] = snapshot.minimum_source_count;
    cursor += 2;
    for index in 0..8 { message[cursor + index] = maximum_age[index]; }
    cursor += 8;
    for index in 0..2 { message[cursor + index] = haircut[index]; }
    cursor += 2;
    assert(cursor == message.len(), "FX snapshot encoding length mismatch");
    keccak256(message, cursor)
}

pub fn fx_catalog_root(snapshot: FxSnapshot, membership: CatalogMembership) -> Field {
    let commitment = bytes_as_fields(fx_snapshot_commitment_v1(snapshot));
    let leaf = proof_hash(PROOF_DOMAIN_CATALOG_LEAF, commitment);
    proof_merkle_membership(leaf, membership.siblings, membership.path_bits)
}

pub fn assert_fx_root(
    snapshot: FxSnapshot,
    membership: CatalogMembership,
    root_high: u128,
    root_low: u128,
) {
    assert_field_root_limbs(fx_catalog_root(snapshot, membership), root_high, root_low);
}

pub fn reference_value_atomic(
    snapshot: FxSnapshot,
    token: u8,
    reference_currency: u8,
    token_amount_atomic: u128,
    priced_at: u64,
) -> u128 {
    assert(token <= 1, "unsupported FX token");
    assert(snapshot.token == token, "FX token mismatch");
    let expected_decimals: u8 = if token == 0 { 18 } else { 6 };
    assert(snapshot.token_decimals == expected_decimals, "token decimals mismatch");
    assert(reference_currency <= 1, "unsupported reference currency");
    assert(snapshot.reference_currency == reference_currency, "FX currency mismatch");
    assert(snapshot.quote_decimals == 6, "FX quote decimals mismatch");
    assert(snapshot.feed_commitment != ZERO_BYTES, "FX feed commitment is zero");
    assert(snapshot.sources_commitment != ZERO_BYTES, "FX sources commitment is zero");
    assert(snapshot.price_numerator > 0, "FX numerator is zero");
    assert(snapshot.price_denominator > 0, "FX denominator is zero");
    assert(snapshot.minimum_source_count > 0, "minimum FX sources is zero");
    assert(snapshot.source_count >= snapshot.minimum_source_count, "insufficient FX sources");
    assert(snapshot.observed_at <= priced_at, "FX snapshot is from the future");
    assert(snapshot.maximum_age_seconds > 0, "maximum FX age is zero");
    assert(priced_at - snapshot.observed_at <= snapshot.maximum_age_seconds, "FX snapshot is stale");
    assert(snapshot.haircut_bps <= 10000, "invalid FX haircut");
    assert(token_amount_atomic > 0, "priced token amount is zero");
    let raw_reference = token_amount_atomic * snapshot.price_numerator / snapshot.price_denominator;
    raw_reference * (BPS_DENOMINATOR - snapshot.haircut_bps as u128) / BPS_DENOMINATOR
}

pub fn empty_catalog_membership() -> CatalogMembership {
    CatalogMembership { siblings: [0; 6], path_bits: [false; 6] }
}

pub fn empty_fx_snapshot() -> FxSnapshot {
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

pub fn assert_empty_fx(snapshot: FxSnapshot, membership: CatalogMembership) {
    assert(snapshot.token == 0, "unused FX token is nonzero");
    assert(snapshot.token_decimals == 0, "unused FX decimals are nonzero");
    assert(snapshot.reference_currency == 0, "unused FX currency is nonzero");
    assert(snapshot.quote_decimals == 0, "unused FX quote decimals are nonzero");
    assert(snapshot.feed_commitment == ZERO_BYTES, "unused FX feed is nonzero");
    assert(snapshot.sources_commitment == ZERO_BYTES, "unused FX sources are nonzero");
    assert(snapshot.price_numerator == 0, "unused FX numerator is nonzero");
    assert(snapshot.price_denominator == 0, "unused FX denominator is nonzero");
    assert(snapshot.observed_at == 0, "unused FX timestamp is nonzero");
    assert(snapshot.source_count == 0, "unused FX source count is nonzero");
    assert(snapshot.minimum_source_count == 0, "unused FX minimum is nonzero");
    assert(snapshot.maximum_age_seconds == 0, "unused FX age is nonzero");
    assert(snapshot.haircut_bps == 0, "unused FX haircut is nonzero");
    for level in 0..6 {
        assert(membership.siblings[level] == 0, "unused FX sibling is nonzero");
        assert(!membership.path_bits[level], "unused FX path bit is true");
    }
}

#[test]
fn conversion_uses_one_canonical_floor_rounding_path() {
    let snapshot = FxSnapshot {
        token: 1,
        token_decimals: 6,
        reference_currency: 0,
        quote_decimals: 6,
        feed_commitment: [1; 32],
        sources_commitment: [2; 32],
        price_numerator: 3,
        price_denominator: 2,
        observed_at: 100,
        source_count: 3,
        minimum_source_count: 2,
        maximum_age_seconds: 60,
        haircut_bps: 100,
    };
    assert(reference_value_atomic(snapshot, 1, 0, 101, 110) == 149, "FX floor rounding changed");
}

#[test]
fn fx_commitment_matches_the_fixed_139_byte_keccak_vector() {
    let snapshot = FxSnapshot {
        token: 1,
        token_decimals: 6,
        reference_currency: 0,
        quote_decimals: 6,
        feed_commitment: [1; 32],
        sources_commitment: [2; 32],
        price_numerator: 3,
        price_denominator: 2,
        observed_at: 100,
        source_count: 3,
        minimum_source_count: 2,
        maximum_age_seconds: 60,
        haircut_bps: 100,
    };
    let expected: [u8; 32] = [
        0xec, 0x32, 0x64, 0x2d, 0x54, 0x5e, 0x30, 0x35,
        0x9f, 0x61, 0x8c, 0x6f, 0x62, 0xcc, 0x46, 0xb1,
        0xc7, 0xba, 0xac, 0xfc, 0x72, 0x5c, 0xe2, 0x91,
        0x4d, 0xa9, 0x73, 0xaa, 0x0d, 0x14, 0x2d, 0x3f,
    ];
    assert(fx_snapshot_commitment_v1(snapshot) == expected, "FX commitment vector changed");
}

#[test(should_fail_with = "FX snapshot is stale")]
fn rejects_stale_snapshot() {
    let snapshot = FxSnapshot {
        token: 1,
        token_decimals: 6,
        reference_currency: 0,
        quote_decimals: 6,
        feed_commitment: [1; 32],
        sources_commitment: [2; 32],
        price_numerator: 1,
        price_denominator: 1,
        observed_at: 100,
        source_count: 2,
        minimum_source_count: 2,
        maximum_age_seconds: 10,
        haircut_bps: 0,
    };
    let _ = reference_value_atomic(snapshot, 1, 0, 100, 111);
}
