use dep::keccak256::keccak256;

pub global SETTLEMENT_TREE_DEPTH: u32 = 6;
pub global ZERO_DIGEST: [u8; 32] = [0; 32];

pub fn recipient_commitment(address: [u8; 32], salt: [u8; 32]) -> [u8; 32] {
    let domain = "PAYO_RECIPIENT_V1".as_bytes();
    let mut message: [u8; 89] = [0; 89];
    for index in 0..domain.len() { message[index] = domain[index]; }
    message[20] = 32;
    for index in 0..32 { message[21 + index] = address[index]; }
    message[56] = 32;
    for index in 0..32 { message[57 + index] = salt[index]; }
    keccak256(message, message.len())
}

pub fn settlement_note_leaf(
    position: u8,
    note_id: [u8; 32],
    packed_value: [u8; 32],
) -> [u8; 32] {
    let domain = "PAYO_SETTLEMENT_NOTE_V1".as_bytes();
    let mut message: [u8; 91] = [0; 91];
    for index in 0..domain.len() { message[index] = domain[index]; }
    let position_bytes: [u8; 4] = (position as Field).to_be_bytes();
    for index in 0..4 { message[23 + index] = position_bytes[index]; }
    for index in 0..32 {
        message[27 + index] = note_id[index];
        message[59 + index] = packed_value[index];
    }
    keccak256(message, message.len())
}

pub fn settlement_empty_leaf() -> [u8; 32] {
    let domain = "PAYO_SETTLEMENT_EMPTY_V1".as_bytes();
    keccak256(domain, domain.len())
}

pub fn settlement_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let domain = "PAYO_SETTLEMENT_NODE_V1".as_bytes();
    let mut message: [u8; 87] = [0; 87];
    for index in 0..domain.len() { message[index] = domain[index]; }
    for index in 0..32 {
        message[23 + index] = left[index];
        message[55 + index] = right[index];
    }
    keccak256(message, message.len())
}

pub fn settlement_membership(
    leaf: [u8; 32],
    siblings: [[u8; 32]; SETTLEMENT_TREE_DEPTH],
    path_bits: [bool; SETTLEMENT_TREE_DEPTH],
) -> [u8; 32] {
    let mut current = leaf;
    for level in 0..SETTLEMENT_TREE_DEPTH {
        current = if path_bits[level] {
            settlement_node(siblings[level], current)
        } else {
            settlement_node(current, siblings[level])
        };
    }
    current
}

pub fn assert_path_index(path_bits: [bool; SETTLEMENT_TREE_DEPTH], target_index: u8) {
    let mut reconstructed: u32 = 0;
    let mut power: u32 = 1;
    for level in 0..SETTLEMENT_TREE_DEPTH {
        if path_bits[level] { reconstructed += power; }
        power *= 2;
    }
    assert(reconstructed == target_index as u32, "settlement path selects another note");
}

#[test]
fn recipient_commitment_encoding_is_not_ambiguous() {
    let mut address: [u8; 32] = [0; 32];
    let mut salt: [u8; 32] = [0; 32];
    address[31] = 1;
    salt[31] = 2;
    assert(recipient_commitment(address, salt) != recipient_commitment(salt, address));
}

#[test]
fn settlement_position_is_bound() {
    let mut note_id: [u8; 32] = [0; 32];
    let mut packed: [u8; 32] = [0; 32];
    note_id[31] = 1;
    packed[31] = 2;
    assert(settlement_note_leaf(0, note_id, packed) != settlement_note_leaf(1, note_id, packed));
}
