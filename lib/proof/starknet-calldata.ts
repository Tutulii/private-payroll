import { hash } from "starknet";
import {
  PAYROLL_INTEGRITY_PUBLIC_INPUT_COUNT,
  type PayrollIntegrityPublicInputs,
} from "./protocol";

export const STARKNET_FIELD_PRIME = (1n << 251n) + (17n << 192n) + 1n;

const PUBLIC_INPUT_KEYS = [
  "chainId",
  "sealAddress",
  "proofVersion",
  "schemaVersion",
  "agreementRootHigh",
  "agreementRootLow",
  "manifestRootHigh",
  "manifestRootLow",
  "policyRootHigh",
  "policyRootLow",
  "fxRootHigh",
  "fxRootLow",
  "runNullifierHigh",
  "runNullifierLow",
  "validityStart",
  "validityExpiry",
  "shardIndex",
] as const satisfies readonly (keyof PayrollIntegrityPublicInputs)[];

function parseUnsigned(value: string | bigint, label: string, upperBound: bigint): bigint {
  let parsed: bigint;
  try {
    parsed = typeof value === "bigint" ? value : BigInt(value);
  } catch {
    throw new Error(`${label} is not an integer.`);
  }
  if (parsed < 0n || parsed >= upperBound) {
    throw new Error(`${label} is outside its canonical range.`);
  }
  return parsed;
}

export function orderedPayrollPublicInputs(input: PayrollIntegrityPublicInputs): string[] {
  return PUBLIC_INPUT_KEYS.map((key) => input[key]);
}

/** Barretenberg serializes each public input as one 32-byte, big-endian value. */
export function serializePayrollPublicInputs(values: readonly string[]): Uint8Array {
  if (values.length !== PAYROLL_INTEGRITY_PUBLIC_INPUT_COUNT) {
    throw new Error(
      `Expected ${PAYROLL_INTEGRITY_PUBLIC_INPUT_COUNT} PayrollIntegrity public inputs; received ${values.length}.`,
    );
  }
  const output = new Uint8Array(values.length * 32);
  values.forEach((value, index) => {
    let remaining = parseUnsigned(value, `Public input ${index}`, 1n << 256n);
    for (let byte = 31; byte >= 0; byte -= 1) {
      output[index * 32 + byte] = Number(remaining & 0xffn);
      remaining >>= 8n;
    }
  });
  return output;
}

export function decodeVerificationKeyHex(document: string): Uint8Array {
  const compact = document.replace(/\s+/g, "");
  if (!compact || compact.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(compact)) {
    throw new Error("The pinned verification key is not canonical hexadecimal.");
  }
  return Uint8Array.from(
    { length: compact.length / 2 },
    (_, index) => Number.parseInt(compact.slice(index * 2, index * 2 + 2), 16),
  );
}

/**
 * Garaga prepends the Cairo `Span` length. Starknet.js adds that length when it
 * serializes a Span argument, so PAYO persists and submits only the inner felts.
 */
export function normalizeGaragaProofCalldata(serialized: readonly bigint[]): string[] {
  if (serialized.length < 2) throw new Error("Garaga returned empty proof calldata.");
  const declaredLength = parseUnsigned(serialized[0], "Garaga calldata length", 1n << 53n);
  if (declaredLength !== BigInt(serialized.length - 1)) {
    throw new Error(
      `Garaga declared ${declaredLength} proof felts but returned ${serialized.length - 1}.`,
    );
  }
  return serialized.slice(1).map((value, index) => {
    const felt = parseUnsigned(value, `Proof calldata felt ${index}`, STARKNET_FIELD_PRIME);
    return `0x${felt.toString(16)}`;
  });
}

/** Matches Cairo core::poseidon::poseidon_hash_span exactly. */
export function hashProofCalldata(calldata: readonly string[]): string {
  if (calldata.length === 0) throw new Error("Cannot seal empty proof calldata.");
  const canonical = calldata.map((value, index) =>
    parseUnsigned(value, `Proof calldata felt ${index}`, STARKNET_FIELD_PRIME));
  return hash.computePoseidonHashOnElements(canonical);
}

/** Extracts the 17 verifier-returned u256 values from Garaga's proof calldata. */
export function parsePayrollPublicInputsFromGaragaCalldata(
  calldata: readonly string[],
): PayrollIntegrityPublicInputs {
  if (calldata.length < 1 + PAYROLL_INTEGRITY_PUBLIC_INPUT_COUNT * 2) {
    throw new Error("Garaga proof calldata is too short for PayrollIntegrity public inputs.");
  }
  const count = parseUnsigned(calldata[0], "Garaga public input count", 1n << 32n);
  if (count !== BigInt(PAYROLL_INTEGRITY_PUBLIC_INPUT_COUNT)) {
    throw new Error(
      `Expected ${PAYROLL_INTEGRITY_PUBLIC_INPUT_COUNT} Garaga public inputs; received ${count}.`,
    );
  }
  const values = Array.from({ length: PAYROLL_INTEGRITY_PUBLIC_INPUT_COUNT }, (_, index) => {
    const low = parseUnsigned(calldata[1 + index * 2], `Public input ${index} low limb`, 1n << 128n);
    const high = parseUnsigned(calldata[2 + index * 2], `Public input ${index} high limb`, 1n << 128n);
    return (low + (high << 128n)).toString();
  });
  return {
    chainId: values[0],
    sealAddress: values[1],
    proofVersion: values[2],
    schemaVersion: values[3],
    agreementRootHigh: values[4],
    agreementRootLow: values[5],
    manifestRootHigh: values[6],
    manifestRootLow: values[7],
    policyRootHigh: values[8],
    policyRootLow: values[9],
    fxRootHigh: values[10],
    fxRootLow: values[11],
    runNullifierHigh: values[12],
    runNullifierLow: values[13],
    validityStart: values[14],
    validityExpiry: values[15],
    shardIndex: values[16],
  };
}
