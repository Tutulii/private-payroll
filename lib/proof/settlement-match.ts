import type { InputMap } from "@noir-lang/noir_js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { hash, shortString } from "starknet";
import {
  concatBytes,
  encodeU32,
  encodeUint,
  normalizedHexBytes,
  toHex,
  utf8,
} from "@/lib/crypto/encoding";
import { splitHashToU128 } from "@/lib/crypto/commitments";
import { PAYROLL_TOKENS, type PayrollTokenSymbol } from "@/lib/starknet/tokens";
import { PAYO_PROOF_EMPTY_LEAF } from "./commitments";
import type {
  PayrollAgreementCircuitWitness,
  PayrollIntegrityInputBuild,
  PayrollLineCircuitWitness,
} from "./input-builder";

type Hex = ReturnType<typeof toHex>;

export const PAYO_SETTLEMENT_MATCH_PROOF_VERSION = 8;
export const PAYO_SETTLEMENT_CHUNK_LINES = 3;
export const PAYO_SETTLEMENT_TREE_LEAVES = 64;
export const PAYO_SETTLEMENT_TREE_DEPTH = 6;

const STARK_FIELD_PRIME = (1n << 251n) + 17n * (1n << 192n) + 1n;
const U128_MODULUS = 1n << 128n;
const U120_LIMIT = 1n << 120n;
const ZERO_BYTES = Array(32).fill(0) as number[];
const SETTLEMENT_EMPTY_LEAF = toHex(keccak_256(utf8("PAYO_SETTLEMENT_EMPTY_V1")));

export type SettlementEmittedNote = {
  noteId: Hex;
  packedValue: Hex;
};

/** Private CreateEncNote input joined to its prover-emitted note output. */
export type SettlementPayrollNote = SettlementEmittedNote & {
  position: number;
  recipientAddress: Hex;
  recipientPublicKey: Hex;
  tokenAddress: Hex;
  amountAtomic: string;
  noteIndex: number;
  salt: string;
};

export type SettlementMatchPublicInputs = {
  proofVersion: string;
  manifestRootHigh: string;
  manifestRootLow: string;
  runNullifierHigh: string;
  runNullifierLow: string;
  transactionReferenceHigh: string;
  transactionReferenceLow: string;
  settlementRootHigh: string;
  settlementRootLow: string;
  chunkIndex: string;
  chunkCount: string;
};

export type SettlementMatchInputBuild = {
  settlementRoot: Hex;
  transactionReference: Hex;
  publicInputs: SettlementMatchPublicInputs[];
  circuitInputs: InputMap[];
};

function canonicalFelt(value: string | bigint, label: string): bigint {
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(label + " is not a Starknet felt.");
  }
  if (parsed < 0n || parsed >= STARK_FIELD_PRIME) {
    throw new Error(label + " is outside the Starknet field.");
  }
  return parsed;
}

function digest(value: string, label: string): Hex {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(label + " must be exactly 32 bytes.");
  }
  return value.toLowerCase() as Hex;
}

function feltBytes(value: string | bigint, label: string): number[] {
  return [...encodeUint(canonicalFelt(value, label), 32)];
}

function digestBytes(value: string, label: string): number[] {
  return [...normalizedHexBytes(digest(value, label), 32)];
}

function poseidon(values: readonly bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements([...values]));
}

function tag(value: string): bigint {
  return BigInt(shortString.encodeShortString(value));
}

export function deriveStrk20ChannelKey(input: {
  senderAddress: string | bigint;
  viewingKey: string | bigint;
  recipientAddress: string | bigint;
  recipientPublicKey: string | bigint;
}): bigint {
  return poseidon([
    tag("CHANNEL_KEY_TAG:V1"),
    canonicalFelt(input.senderAddress, "Settlement sender"),
    canonicalFelt(input.viewingKey, "Settlement viewing key"),
    canonicalFelt(input.recipientAddress, "Settlement recipient"),
    canonicalFelt(input.recipientPublicKey, "Settlement recipient public key"),
  ]);
}

export function deriveStrk20NoteId(input: {
  channelKey: string | bigint;
  tokenAddress: string | bigint;
  noteIndex: number;
}): bigint {
  if (!Number.isInteger(input.noteIndex) || input.noteIndex < 0 || input.noteIndex > 0xffff_ffff) {
    throw new Error("Settlement note index must fit in u32.");
  }
  return poseidon([
    tag("NOTE_ID_TAG:V1"),
    canonicalFelt(input.channelKey, "Settlement channel key"),
    canonicalFelt(input.tokenAddress, "Settlement token"),
    BigInt(input.noteIndex),
    0n,
  ]);
}

export function deriveStrk20PackedValue(input: {
  channelKey: string | bigint;
  tokenAddress: string | bigint;
  noteIndex: number;
  salt: string | bigint;
  amountAtomic: string | bigint;
}): bigint {
  if (!Number.isInteger(input.noteIndex) || input.noteIndex < 0 || input.noteIndex > 0xffff_ffff) {
    throw new Error("Settlement note index must fit in u32.");
  }
  const salt = BigInt(input.salt);
  const amount = BigInt(input.amountAtomic);
  if (salt <= 0n || salt >= U120_LIMIT) {
    throw new Error("Encrypted settlement-note salt must be a nonzero 120-bit integer.");
  }
  if (amount <= 0n || amount >= U128_MODULUS) {
    throw new Error("Encrypted settlement-note amount must be a positive u128.");
  }
  const pad = poseidon([
    tag("ENC_AMOUNT_TAG:V1"),
    canonicalFelt(input.channelKey, "Settlement channel key"),
    canonicalFelt(input.tokenAddress, "Settlement token"),
    BigInt(input.noteIndex),
    0n,
    salt,
  ]);
  return (salt << 128n) | ((pad + amount) % U128_MODULUS);
}

export function deriveStrk20EncryptedNote(input: {
  senderAddress: string | bigint;
  viewingKey: string | bigint;
  recipientAddress: string | bigint;
  recipientPublicKey: string | bigint;
  tokenAddress: string | bigint;
  noteIndex: number;
  salt: string | bigint;
  amountAtomic: string | bigint;
}): { channelKey: bigint; noteId: Hex; packedValue: Hex } {
  const channelKey = deriveStrk20ChannelKey(input);
  return {
    channelKey,
    noteId: toHex(encodeUint(deriveStrk20NoteId({ ...input, channelKey }), 32)),
    packedValue: toHex(encodeUint(deriveStrk20PackedValue({ ...input, channelKey }), 32)),
  };
}

export function hashSettlementNoteLeaf(
  position: number,
  note: SettlementEmittedNote,
): Hex {
  if (!Number.isInteger(position) || position < 0 || position >= PAYO_SETTLEMENT_TREE_LEAVES) {
    throw new Error("Settlement-note position is outside the fixed 64-leaf tree.");
  }
  return toHex(keccak_256(concatBytes(
    utf8("PAYO_SETTLEMENT_NOTE_V1"),
    encodeU32(position),
    normalizedHexBytes(digest(note.noteId, "Settlement note ID"), 32),
    normalizedHexBytes(digest(note.packedValue, "Settlement packed value"), 32),
  )));
}

export function hashSettlementNode(left: string, right: string): Hex {
  return toHex(keccak_256(concatBytes(
    utf8("PAYO_SETTLEMENT_NODE_V1"),
    normalizedHexBytes(digest(left, "Settlement left node"), 32),
    normalizedHexBytes(digest(right, "Settlement right node"), 32),
  )));
}

function settlementTree(notes: readonly SettlementEmittedNote[]): Hex[][] {
  if (notes.length < 1 || notes.length > PAYO_SETTLEMENT_TREE_LEAVES) {
    throw new Error(
      "Settlement evidence requires 1–" + PAYO_SETTLEMENT_TREE_LEAVES + " emitted notes.",
    );
  }
  const ids = new Set<string>();
  const leaves = Array.from({ length: PAYO_SETTLEMENT_TREE_LEAVES }, (_, position) => {
    if (position >= notes.length) return SETTLEMENT_EMPTY_LEAF;
    const normalizedId = digest(notes[position].noteId, "Settlement note ID " + position);
    if (ids.has(normalizedId)) throw new Error("Settlement note IDs must be unique.");
    ids.add(normalizedId);
    return hashSettlementNoteLeaf(position, notes[position]);
  });
  const levels: Hex[][] = [leaves];
  while (levels.at(-1)!.length > 1) {
    const level = levels.at(-1)!;
    levels.push(Array.from({ length: level.length / 2 }, (_, index) =>
      hashSettlementNode(level[index * 2], level[index * 2 + 1])));
  }
  return levels;
}

export function buildSettlementRoot(notes: readonly SettlementEmittedNote[]): Hex {
  return settlementTree(notes).at(-1)![0];
}

export function buildSettlementMembership(
  notes: readonly SettlementEmittedNote[],
  position: number,
): { root: Hex; siblings: Hex[]; pathBits: boolean[] } {
  if (!Number.isInteger(position) || position < 0 || position >= notes.length) {
    throw new Error("Settlement membership must select an emitted note.");
  }
  const levels = settlementTree(notes);
  const siblings: Hex[] = [];
  const pathBits: boolean[] = [];
  let cursor = position;
  for (let level = 0; level < PAYO_SETTLEMENT_TREE_DEPTH; level += 1) {
    const isRight = cursor % 2 === 1;
    siblings.push(levels[level][isRight ? cursor - 1 : cursor + 1]);
    pathBits.push(isRight);
    cursor = Math.floor(cursor / 2);
  }
  return { root: levels.at(-1)![0], siblings, pathBits };
}

/**
 * Reference committed by the policy-account receipt and FINALIZE path. It
 * binds the exact pool call to one chain and one policy account.
 */
export function settlementTransactionReference(input: {
  chainId: string;
  policyAccountAddress: string;
  poolAddress: string;
  poolCalldata: readonly string[];
}): Hex {
  if (input.poolCalldata.length < 1 || input.poolCalldata.length > 12_000) {
    throw new Error("Settlement transaction calldata is outside PAYO's bounded size.");
  }
  return toHex(keccak_256(concatBytes(
    utf8("PAYO_SETTLEMENT_TX_V1"),
    encodeUint(canonicalFelt(input.chainId, "Settlement chain ID"), 32),
    encodeUint(canonicalFelt(input.policyAccountAddress, "Settlement policy account"), 32),
    encodeUint(canonicalFelt(input.poolAddress, "Settlement pool"), 32),
    encodeU32(input.poolCalldata.length),
    ...input.poolCalldata.map((value, index) =>
      encodeUint(canonicalFelt(value, "Settlement pool calldata " + index), 32)),
  )));
}

function emptyAgreement(): PayrollAgreementCircuitWitness {
  return {
    enabled: false,
    id_commitment: [...ZERO_BYTES],
    recipient_commitment: [...ZERO_BYTES],
    earnings: Array(8).fill("0"),
    earnings_count: "0",
    token: "0",
    policy_commitment: [...ZERO_BYTES],
    schedule_commitment: [...ZERO_BYTES],
    due_at: "0",
    valid_until: "0",
    classification_declared: "0",
    classification_score: "0",
    classification_employee_threshold: "0",
    final_pay_mode: false,
    final_required_mask: "0",
    final_components: Array(5).fill("0"),
    fx_floor_atomic: "0",
    reference_currency: "0",
    salt: [...ZERO_BYTES],
  };
}

function emptyLine(): PayrollLineCircuitWitness {
  return {
    active: false,
    deductions: Array(8).fill("0"),
    deductions_count: "0",
    policy_slot: "0",
    fx_slot: "0",
    salt: [...ZERO_BYTES],
    classification_treatment: "0",
    final_included_mask: "0",
    reference_value_atomic: "0",
  };
}

function emptyNote() {
  return {
    recipient_address: [...ZERO_BYTES],
    recipient_public_key: [...ZERO_BYTES],
    recipient_commitment_salt: [...ZERO_BYTES],
    note_index: "0",
    note_id: [...ZERO_BYTES],
    packed_value: [...ZERO_BYTES],
    settlement_siblings: Array.from(
      { length: PAYO_SETTLEMENT_TREE_DEPTH },
      () => [...ZERO_BYTES],
    ),
    settlement_path_bits: Array(PAYO_SETTLEMENT_TREE_DEPTH).fill(false),
  };
}

function limbs(value: string) {
  const result = splitHashToU128(value);
  return { high: result.high.toString(), low: result.low.toString() };
}

function tokenSymbol(address: string, label: string): PayrollTokenSymbol {
  const value = canonicalFelt(address, label);
  const match = (Object.keys(PAYROLL_TOKENS) as PayrollTokenSymbol[]).find(
    (symbol) => BigInt(PAYROLL_TOKENS[symbol].address) === value,
  );
  if (!match) throw new Error(label + " is not PAYO's native STRK or USDC address.");
  return match;
}

export function buildSettlementMatchInputs(input: {
  payroll: PayrollIntegrityInputBuild;
  senderAddress: string;
  viewingKey: string;
  transactionReference: string;
  payrollNotes: readonly SettlementPayrollNote[];
  emittedNotes: readonly SettlementEmittedNote[];
}): SettlementMatchInputBuild {
  const count = input.payroll.proofBindings.length;
  if (count < 1 || count > 50 || input.payrollNotes.length !== count) {
    throw new Error(
      "Settlement payroll-note evidence must cover every manifest line exactly once.",
    );
  }
  if (input.emittedNotes.length < count) {
    throw new Error("Settlement output omits one or more payroll notes.");
  }
  const transactionReference = digest(
    input.transactionReference,
    "Settlement transaction reference",
  );
  if (BigInt(transactionReference) === 0n) {
    throw new Error("Settlement transaction reference is zero.");
  }
  const sender = canonicalFelt(input.senderAddress, "Settlement sender");
  const viewingKey = canonicalFelt(input.viewingKey, "Settlement viewing key");
  if (sender === 0n || viewingKey === 0n) {
    throw new Error("Settlement sender and viewing key must be nonzero.");
  }

  const settlementRoot = buildSettlementRoot(input.emittedNotes);
  const noteWitnesses = input.payroll.proofBindings.map((binding, index) => {
    const note = input.payrollNotes[index];
    if (note.position !== index) throw new Error("Settlement payroll notes are reordered.");
    if (
      canonicalFelt(note.recipientAddress, "Settlement recipient " + index)
      !== canonicalFelt(binding.source.recipientAddress, "Manifest recipient " + index)
    ) {
      throw new Error("Settlement recipient does not match the approved manifest.");
    }
    const symbol = tokenSymbol(note.tokenAddress, "Settlement token " + index);
    if (symbol !== binding.source.token) {
      throw new Error("Settlement token does not match the approved manifest.");
    }
    if (BigInt(note.amountAtomic) !== BigInt(binding.calculated.netAtomic)) {
      throw new Error("Settlement amount does not match the proved net payroll amount.");
    }
    const expected = deriveStrk20EncryptedNote({
      senderAddress: sender,
      viewingKey,
      recipientAddress: note.recipientAddress,
      recipientPublicKey: note.recipientPublicKey,
      tokenAddress: note.tokenAddress,
      noteIndex: note.noteIndex,
      salt: note.salt,
      amountAtomic: note.amountAtomic,
    });
    const noteId = digest(note.noteId, "Settlement note ID " + index);
    const packedValue = digest(note.packedValue, "Settlement packed value " + index);
    if (expected.noteId !== noteId || expected.packedValue !== packedValue) {
      throw new Error(
        "Settlement note ciphertext does not match its private transfer witness.",
      );
    }
    if (
      digest(input.emittedNotes[index].noteId, "Emitted note ID " + index) !== noteId
      || digest(
        input.emittedNotes[index].packedValue,
        "Emitted packed value " + index,
      ) !== packedValue
    ) {
      throw new Error(
        "Settlement output order does not match the approved payroll order.",
      );
    }
    const membership = buildSettlementMembership(input.emittedNotes, index);
    return {
      recipient_address: feltBytes(note.recipientAddress, "Settlement recipient " + index),
      recipient_public_key: feltBytes(
        note.recipientPublicKey,
        "Settlement public key " + index,
      ),
      recipient_commitment_salt: digestBytes(
        binding.source.recipientSalt,
        "Recipient salt " + index,
      ),
      note_index: note.noteIndex.toString(),
      note_id: digestBytes(noteId, "Settlement note ID " + index),
      packed_value: digestBytes(packedValue, "Settlement packed value " + index),
      settlement_siblings: membership.siblings.map((value, level) =>
        digestBytes(value, "Settlement sibling " + index + ":" + level)),
      settlement_path_bits: membership.pathBits,
    };
  });

  const manifest = limbs(input.payroll.manifestRoot);
  const nullifier = limbs(input.payroll.runNullifier);
  const reference = limbs(transactionReference);
  const root = limbs(settlementRoot);
  const chunkCount = Math.ceil(count / PAYO_SETTLEMENT_CHUNK_LINES);
  const payrollLeaves = Array.from({ length: 64 }, (_, index) =>
    BigInt(
      input.payroll.proofBindings[index]?.payrollLeaf ?? PAYO_PROOF_EMPTY_LEAF,
    ).toString());
  const publicInputs: SettlementMatchPublicInputs[] = [];
  const circuitInputs = Array.from(
    { length: chunkCount },
    (_, chunkIndex): InputMap => {
      const agreements: PayrollAgreementCircuitWitness[] = [];
      const lines: PayrollLineCircuitWitness[] = [];
      const notes = [];
      for (let offset = 0; offset < PAYO_SETTLEMENT_CHUNK_LINES; offset += 1) {
        const position = chunkIndex * PAYO_SETTLEMENT_CHUNK_LINES + offset;
        agreements.push(
          input.payroll.proofBindings[position]?.agreement ?? emptyAgreement(),
        );
        lines.push(input.payroll.proofBindings[position]?.line ?? emptyLine());
        notes.push(noteWitnesses[position] ?? emptyNote());
      }
      const currentPublic: SettlementMatchPublicInputs = {
        proofVersion: PAYO_SETTLEMENT_MATCH_PROOF_VERSION.toString(),
        manifestRootHigh: manifest.high,
        manifestRootLow: manifest.low,
        runNullifierHigh: nullifier.high,
        runNullifierLow: nullifier.low,
        transactionReferenceHigh: reference.high,
        transactionReferenceLow: reference.low,
        settlementRootHigh: root.high,
        settlementRootLow: root.low,
        chunkIndex: chunkIndex.toString(),
        chunkCount: chunkCount.toString(),
      };
      publicInputs.push(currentPublic);
      return {
        proof_version: currentPublic.proofVersion,
        manifest_root_high: currentPublic.manifestRootHigh,
        manifest_root_low: currentPublic.manifestRootLow,
        run_nullifier_high: currentPublic.runNullifierHigh,
        run_nullifier_low: currentPublic.runNullifierLow,
        transaction_reference_high: currentPublic.transactionReferenceHigh,
        transaction_reference_low: currentPublic.transactionReferenceLow,
        settlement_root_high: currentPublic.settlementRootHigh,
        settlement_root_low: currentPublic.settlementRootLow,
        chunk_index: currentPublic.chunkIndex,
        chunk_count: currentPublic.chunkCount,
        payroll_leaves: payrollLeaves,
        sender_address_bytes: feltBytes(sender, "Settlement sender"),
        viewing_key_bytes: feltBytes(viewingKey, "Settlement viewing key"),
        agreements,
        lines,
        notes,
      };
    },
  );
  return {
    settlementRoot,
    transactionReference,
    publicInputs,
    circuitInputs,
  };
}
