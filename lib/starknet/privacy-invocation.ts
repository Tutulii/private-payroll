import { hash } from "starknet";
import {
  settlementTransactionReference,
  type SettlementEmittedNote,
  type SettlementPayrollNote,
} from "@/lib/proof/settlement-match";

const STARK_FIELD_PRIME = (1n << 251n) + 17n * (1n << 192n) + 1n;
const U128_LIMIT = 1n << 128n;
const U120_LIMIT = 1n << 120n;
const U32_LIMIT = 1n << 32n;
const MAX_ACTIONS = 4_096;
const MAX_SPAN = 12_000;

type Hex = `0x${string}`;
type Felt = { bigint: bigint; hex: Hex };
type Cursor = { values: readonly unknown[]; index: number; label: string };
type ExternalInvocation = { contractAddress: Hex; calldata: Hex[] };

export type DirectPrivacySettlementEvidence = {
  senderAddress: Hex;
  viewingKey: Hex;
  poolCalldata: Hex[];
  transactionReference: Hex;
  payrollNotes: SettlementPayrollNote[];
  emittedNotes: SettlementEmittedNote[];
};

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(label + " is not an object.");
  }
  return value as Record<string, unknown>;
}

function felt(value: unknown, label: string): Felt {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) {
    throw new Error(label + " is not a canonical hexadecimal felt.");
  }
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(label + " is not a Starknet felt.");
  }
  if (parsed < 0n || parsed >= STARK_FIELD_PRIME) {
    throw new Error(label + " is outside the Starknet field.");
  }
  return { bigint: parsed, hex: ("0x" + parsed.toString(16)) as Hex };
}

function sameFelt(actual: unknown, expected: string, label: string): Felt {
  const parsed = felt(actual, label);
  if (parsed.bigint !== felt(expected, label + " expectation").bigint) {
    throw new Error(label + " was substituted.");
  }
  return parsed;
}

function word(value: Felt): Hex {
  return ("0x" + value.bigint.toString(16).padStart(64, "0")) as Hex;
}

function take(cursor: Cursor, label: string): Felt {
  if (cursor.index >= cursor.values.length) {
    throw new Error(cursor.label + " ended before " + label + ".");
  }
  const result = felt(cursor.values[cursor.index], cursor.label + " " + label);
  cursor.index += 1;
  return result;
}

function boundedNumber(value: Felt, upperExclusive: bigint, label: string): number {
  if (value.bigint >= upperExclusive || value.bigint > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(label + " is outside its canonical range.");
  }
  return Number(value.bigint);
}

function takeSpan(cursor: Cursor, label: string): Felt[] {
  const length = boundedNumber(take(cursor, label + " length"), BigInt(MAX_SPAN + 1), label);
  const output: Felt[] = [];
  for (let index = 0; index < length; index += 1) {
    output.push(take(cursor, label + " item " + index));
  }
  return output;
}

function canonicalExternalInvocation(
  value: { contractAddress: string; calldata: readonly string[] },
  label: string,
): ExternalInvocation {
  const contractAddress = felt(value.contractAddress, label + " target");
  if (contractAddress.bigint === 0n) throw new Error(label + " target is zero.");
  if (!Array.isArray(value.calldata) || value.calldata.length > MAX_SPAN) {
    throw new Error(label + " calldata is outside its canonical range.");
  }
  return {
    contractAddress: contractAddress.hex,
    calldata: value.calldata.map((entry, index) =>
      felt(entry, label + " calldata " + index).hex),
  };
}

function assertExternalInvocation(
  actual: ExternalInvocation,
  expected: ExternalInvocation,
  label: string,
): void {
  if (
    BigInt(actual.contractAddress) !== BigInt(expected.contractAddress)
    || actual.calldata.length !== expected.calldata.length
    || actual.calldata.some((entry, index) => BigInt(entry) !== BigInt(expected.calldata[index]))
  ) throw new Error(label + " was substituted.");
}

function invocationRecord(value: unknown): Record<string, unknown> {
  const outer = asRecord(value, "Privacy SDK proof invocation");
  return asRecord(outer.invocation, "Privacy SDK signed invocation");
}

function parseCreateNotes(input: {
  invocation: unknown;
  poolAddress: string;
  policyAccountAddress: string;
  viewingKey: string;
}): {
  created: Array<Omit<SettlementPayrollNote, "position" | "noteId" | "packedValue">>;
  externalInvocations: ExternalInvocation[];
} {
  const signed = invocationRecord(input.invocation);
  sameFelt(signed.sender_address, input.poolAddress, "Privacy SDK invocation sender");
  if (!Array.isArray(signed.calldata)) {
    throw new Error("Privacy SDK invocation calldata is not an array.");
  }
  const outer: Cursor = { values: signed.calldata, index: 0, label: "Privacy SDK outer calldata" };
  if (take(outer, "call count").bigint !== 1n) {
    throw new Error("Privacy SDK invocation must wrap exactly one pool call.");
  }
  sameFelt(take(outer, "pool target").hex, input.poolAddress, "Privacy SDK pool target");
  sameFelt(
    take(outer, "pool selector").hex,
    hash.getSelectorFromName("compile_actions"),
    "Privacy SDK compile_actions selector",
  );
  const innerLength = boundedNumber(
    take(outer, "inner calldata length"),
    BigInt(MAX_SPAN + 1),
    "Privacy SDK inner calldata length",
  );
  if (outer.index + innerLength !== outer.values.length) {
    throw new Error("Privacy SDK invocation contains trailing or truncated calldata.");
  }
  const inner: Cursor = {
    values: outer.values.slice(outer.index),
    index: 0,
    label: "Privacy SDK compile_actions calldata",
  };
  sameFelt(take(inner, "sender").hex, input.policyAccountAddress, "Privacy SDK payroll sender");
  sameFelt(take(inner, "viewing key").hex, input.viewingKey, "Privacy SDK viewing key");
  const actionCount = boundedNumber(
    take(inner, "action count"),
    BigInt(MAX_ACTIONS + 1),
    "Privacy SDK action count",
  );
  if (actionCount < 1) throw new Error("Privacy SDK invocation contains no actions.");

  const created: Array<Omit<SettlementPayrollNote, "position" | "noteId" | "packedValue">> = [];
  const externalInvocations: ExternalInvocation[] = [];
  for (let actionIndex = 0; actionIndex < actionCount; actionIndex += 1) {
    const variant = boundedNumber(
      take(inner, "action " + actionIndex + " variant"),
      10n,
      "Privacy SDK action variant",
    );
    if (variant === 0) {
      take(inner, "SetViewingKey random");
    } else if (variant === 1) {
      for (const field of ["recipient", "index", "random", "salt"]) take(inner, "OpenChannel " + field);
    } else if (variant === 2) {
      for (const field of ["recipient", "public key", "channel key", "index", "token", "salt"]) {
        take(inner, "OpenSubchannel " + field);
      }
    } else if (variant === 3) {
      const recipient = take(inner, "CreateEncNote recipient");
      const publicKey = take(inner, "CreateEncNote public key");
      const token = take(inner, "CreateEncNote token");
      const amount = take(inner, "CreateEncNote amount");
      const noteIndex = take(inner, "CreateEncNote index");
      const salt = take(inner, "CreateEncNote salt");
      if (recipient.bigint === 0n || publicKey.bigint === 0n || token.bigint === 0n) {
        throw new Error("Privacy SDK encrypted note contains a zero address or public key.");
      }
      if (amount.bigint === 0n || amount.bigint >= U128_LIMIT) {
        throw new Error("Privacy SDK encrypted-note amount is outside positive u128.");
      }
      if (noteIndex.bigint >= U32_LIMIT) {
        throw new Error("Privacy SDK encrypted-note index is outside u32.");
      }
      if (salt.bigint === 0n || salt.bigint >= U120_LIMIT) {
        throw new Error("Privacy SDK encrypted-note salt is outside nonzero u120.");
      }
      created.push({
        recipientAddress: recipient.hex,
        recipientPublicKey: publicKey.hex,
        tokenAddress: token.hex,
        amountAtomic: amount.bigint.toString(),
        noteIndex: Number(noteIndex.bigint),
        salt: salt.bigint.toString(),
      });
    } else if (variant === 4) {
      for (const field of ["recipient", "public key", "token", "index", "random"]) {
        take(inner, "CreateOpenNote " + field);
      }
    } else if (variant === 5) {
      take(inner, "Deposit token");
      take(inner, "Deposit amount");
    } else if (variant === 6) {
      take(inner, "UseNote channel key");
      take(inner, "UseNote token");
      take(inner, "UseNote index");
    } else if (variant === 7) {
      for (const field of ["recipient", "token", "amount", "random"]) take(inner, "Withdraw " + field);
    } else if (variant === 8) {
      const contractAddress = take(inner, "InvokeExternal target");
      if (contractAddress.bigint === 0n) {
        throw new Error("Privacy SDK InvokeExternal target is zero.");
      }
      externalInvocations.push({
        contractAddress: contractAddress.hex,
        calldata: takeSpan(inner, "InvokeExternal calldata").map((entry) => entry.hex),
      });
    } else {
      take(inner, "ComputeAndInvoke target");
      takeSpan(inner, "ComputeAndInvoke compute data");
      takeSpan(inner, "ComputeAndInvoke invoke data");
      throw new Error("Autonomous settlement forbids computed external pool invocations.");
    }
  }
  if (inner.index !== inner.values.length) {
    throw new Error("Privacy SDK client-action serialization has trailing calldata.");
  }
  return { created, externalInvocations };
}

function parseServerActions(
  poolCalldata: readonly unknown[],
  expectedExternalInvocation?: ExternalInvocation,
): { canonical: Hex[]; emitted: SettlementEmittedNote[]; externalInvocations: ExternalInvocation[] } {
  const canonical = poolCalldata.map((value, index) =>
    felt(value, "Privacy SDK pool calldata " + index).hex);
  const cursor: Cursor = { values: canonical, index: 0, label: "Privacy SDK server actions" };
  const actionCount = boundedNumber(
    take(cursor, "action count"),
    BigInt(MAX_ACTIONS + 1),
    "Privacy SDK server action count",
  );
  if (actionCount < 1) throw new Error("Privacy SDK prover emitted no server actions.");
  const emitted: SettlementEmittedNote[] = [];
  const externalInvocations: ExternalInvocation[] = [];
  for (let actionIndex = 0; actionIndex < actionCount; actionIndex += 1) {
    const variant = boundedNumber(
      take(cursor, "action " + actionIndex + " variant"),
      12n,
      "Privacy SDK server-action variant",
    );
    if (variant === 0) {
      take(cursor, "WriteOnce storage");
      takeSpan(cursor, "WriteOnce value");
    } else if (variant === 1) {
      take(cursor, "Append recipient");
      take(cursor, "Append ephemeral key");
      take(cursor, "Append encrypted channel key");
      take(cursor, "Append encrypted sender");
    } else if (variant === 8) {
      const noteId = take(cursor, "EmitEncNoteCreated note ID");
      const packedValue = take(cursor, "EmitEncNoteCreated packed value");
      if (noteId.bigint === 0n || packedValue.bigint === 0n) {
        throw new Error("Privacy SDK prover emitted a zero encrypted note.");
      }
      emitted.push({ noteId: word(noteId), packedValue: word(packedValue) });
    } else if (variant === 9) {
      take(cursor, "EmitNoteUsed nullifier");
    } else if (variant === 10) {
      if (!expectedExternalInvocation) {
        throw new Error("Autonomous settlement forbids external pool invocations.");
      }
      const invocation = {
        contractAddress: take(cursor, "Invoke target").hex,
        calldata: takeSpan(cursor, "Invoke calldata").map((entry) => entry.hex),
      };
      assertExternalInvocation(
        invocation,
        expectedExternalInvocation,
        "Privacy SDK server book callback",
      );
      externalInvocations.push(invocation);
    } else {
      throw new Error("Privacy SDK prover emitted a forbidden public or unsupported server action.");
    }
  }
  if (take(cursor, "screening option").bigint !== 1n || cursor.index !== cursor.values.length) {
    throw new Error("Autonomous private payroll requires an exact empty screening attestation.");
  }
  return { canonical, emitted, externalInvocations };
}

/**
 * Decodes proof input and output using the pinned Cairo ABI, then binds the
 * first manifest-line notes to their prover-emitted ciphertexts.
 */
export function extractDirectPrivacySettlementEvidence(input: {
  invocation: unknown;
  poolAddress: string;
  policyAccountAddress: string;
  viewingKey: string;
  chainId: string;
  poolCalldata: readonly unknown[];
  payrollLineCount: number;
  expectedExternalInvocation?: { contractAddress: string; calldata: readonly string[] };
}): DirectPrivacySettlementEvidence {
  if (
    !Number.isInteger(input.payrollLineCount)
    || input.payrollLineCount < 1
    || input.payrollLineCount > 50
  ) {
    throw new Error("Settlement payroll line count must be 1–50.");
  }
  const expectedExternalInvocation = input.expectedExternalInvocation
    ? canonicalExternalInvocation(input.expectedExternalInvocation, "Expected payroll-book callback")
    : undefined;
  const client = parseCreateNotes(input);
  const creates = client.created;
  const server = parseServerActions(input.poolCalldata, expectedExternalInvocation);
  const expectedInvocationCount = expectedExternalInvocation ? 1 : 0;
  if (
    client.externalInvocations.length !== expectedInvocationCount
    || server.externalInvocations.length !== expectedInvocationCount
  ) throw new Error("Privacy SDK did not bind exactly the expected payroll-book callback.");
  if (expectedExternalInvocation) {
    assertExternalInvocation(
      client.externalInvocations[0],
      expectedExternalInvocation,
      "Privacy SDK client book callback",
    );
  }
  if (creates.length !== server.emitted.length) {
    throw new Error("Privacy SDK proof output does not cover every encrypted note exactly once.");
  }
  if (creates.length < input.payrollLineCount || creates.length > 64) {
    throw new Error("Privacy SDK encrypted-note count cannot cover the approved payroll.");
  }
  const payrollNotes = creates.slice(0, input.payrollLineCount).map((note, position) => ({
    ...note,
    position,
    noteId: server.emitted[position].noteId,
    packedValue: server.emitted[position].packedValue,
  }));
  const senderAddress = felt(input.policyAccountAddress, "Settlement sender").hex;
  const viewingKey = felt(input.viewingKey, "Settlement viewing key").hex;
  return {
    senderAddress,
    viewingKey,
    poolCalldata: server.canonical,
    transactionReference: settlementTransactionReference({
      chainId: input.chainId,
      policyAccountAddress: senderAddress,
      poolAddress: input.poolAddress,
      poolCalldata: server.canonical,
    }),
    payrollNotes,
    emittedNotes: server.emitted,
  };
}
