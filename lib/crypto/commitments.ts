import { keccak_256 } from "@noble/hashes/sha3.js";
import { PAYROLL_TOKENS } from "@/app/starknet/tokens";
import type { CalculatedPayrollLine } from "@/lib/domain/payroll";
import {
  concatBytes,
  decodeUint,
  encodeField,
  encodeU32,
  encodeUint,
  normalizedHexBytes,
  toHex,
  utf8,
} from "./encoding";

export const PAYO_MERKLE_LEAF_COUNT = 64;
export const PAYO_MAX_PAYROLL_LINES = 50;

const EMPTY_LEAF = keccak_256(utf8("PAYO_EMPTY_LEAF_V1"));
export const PAYO_EMPTY_LEAF = toHex(EMPTY_LEAF);

function hashDomain(domain: string, ...fields: readonly Uint8Array[]): Uint8Array {
  return keccak_256(concatBytes(utf8(domain), ...fields.map(encodeField)));
}

export function hashTextCommitment(domain: string, value: string): Uint8Array {
  return hashDomain(domain, utf8(value));
}

export function hashRecipientCommitment(address: string, saltHex: string): Uint8Array {
  return hashDomain(
    "PAYO_RECIPIENT_V1",
    normalizedHexBytes(address, 32),
    normalizedHexBytes(saltHex, 32),
  );
}

export function hashDeductionsCommitment(values: readonly string[]): Uint8Array {
  return hashDomain(
    "PAYO_DEDUCTIONS_V1",
    encodeU32(values.length),
    ...values.map((value) => encodeUint(BigInt(value))),
  );
}

export type AgreementTermsCommitmentInput = {
  agreementIdCommitment: string;
  recipientCommitment: string;
  earningsAtomic: readonly string[];
  token: "STRK" | "USDC";
  policyCommitment: string;
  scheduleCommitment: string;
  dueAt: bigint;
  validUntil: bigint;
  classificationDeclared: 1 | 2;
  classificationScore: number;
  classificationEmployeeThreshold: number;
  finalPayMode: boolean;
  finalRequiredMask: number;
  finalComponentsAtomic: readonly string[];
  fxFloorAtomic: string;
  referenceCurrency: "USD" | "GBP";
  salt: string;
};

/** Byte-for-byte encoding consumed by Noir's authoritative agreement root. */
export function hashAgreementTerms(input: AgreementTermsCommitmentInput): `0x${string}` {
  if (input.earningsAtomic.length < 1 || input.earningsAtomic.length > 8) {
    throw new Error("An agreement must commit between one and eight earnings components.");
  }
  if (input.finalComponentsAtomic.length > 5) {
    throw new Error("An agreement supports at most five final-pay components.");
  }
  if (!Number.isInteger(input.classificationScore) || input.classificationScore < 0 || input.classificationScore > 0xffff
    || !Number.isInteger(input.classificationEmployeeThreshold) || input.classificationEmployeeThreshold < 1
    || input.classificationEmployeeThreshold > 0xffff) {
    throw new Error("Classification score and threshold must fit in u16, with a nonzero threshold.");
  }
  if (!Number.isInteger(input.finalRequiredMask) || input.finalRequiredMask < 0 || input.finalRequiredMask > 31) {
    throw new Error("Final-pay mask must use only the five supported component bits.");
  }
  const earnings = Array.from({ length: 8 }, (_, index) =>
    encodeUint(BigInt(input.earningsAtomic[index] ?? "0"), 16));
  const finalComponents = Array.from({ length: 5 }, (_, index) =>
    encodeUint(BigInt(input.finalComponentsAtomic[index] ?? "0"), 16));
  return toHex(keccak_256(concatBytes(
    utf8("PAYO_AGREEMENT_TERMS_V1"),
    normalizedHexBytes(input.agreementIdCommitment, 32),
    normalizedHexBytes(input.recipientCommitment, 32),
    encodeU32(input.earningsAtomic.length),
    ...earnings,
    Uint8Array.of(input.token === "STRK" ? 0 : 1),
    normalizedHexBytes(input.policyCommitment, 32),
    normalizedHexBytes(input.scheduleCommitment, 32),
    encodeUint(input.dueAt, 8),
    encodeUint(input.validUntil, 8),
    Uint8Array.of(input.classificationDeclared),
    encodeUint(BigInt(input.classificationScore), 2),
    encodeUint(BigInt(input.classificationEmployeeThreshold), 2),
    Uint8Array.of(input.finalPayMode ? 1 : 0, input.finalRequiredMask),
    ...finalComponents,
    encodeUint(BigInt(input.fxFloorAtomic), 16),
    Uint8Array.of(input.referenceCurrency === "USD" ? 0 : 1),
    normalizedHexBytes(input.salt, 32),
  )));
}

export function hashPayrollLeaf(
  line: CalculatedPayrollLine,
  schemaVersion = 1,
  boundPolicyCommitment?: string,
): `0x${string}` {
  const agreementCommitment = hashTextCommitment("PAYO_AGREEMENT_ID_V1", line.agreementId);
  const recipientCommitment = hashRecipientCommitment(line.recipientAddress, line.salt);
  const deductionsCommitment = hashDeductionsCommitment(line.deductionsAtomic);
  const policyCommitment = boundPolicyCommitment === undefined
    ? hashTextCommitment("PAYO_POLICY_ID_V1", line.committedPolicyId)
    : normalizedHexBytes(boundPolicyCommitment, 32);
  const token = PAYROLL_TOKENS[line.token];

  return toHex(
    hashDomain(
      "PAYO_LEAF_V1",
      encodeU32(schemaVersion),
      agreementCommitment,
      recipientCommitment,
      encodeUint(BigInt(line.grossAtomic)),
      deductionsCommitment,
      encodeUint(BigInt(line.netAtomic)),
      normalizedHexBytes(token.address, 32),
      policyCommitment,
      normalizedHexBytes(line.scheduleCommitment, 32),
      normalizedHexBytes(line.salt, 32),
    ),
  );
}

export function buildFixedMerkleRoot(leaves: readonly string[]): `0x${string}` {
  if (leaves.length > PAYO_MAX_PAYROLL_LINES) {
    throw new Error(`PAYO supports at most ${PAYO_MAX_PAYROLL_LINES} real payroll leaves.`);
  }

  let level: Uint8Array[] = Array.from({ length: PAYO_MERKLE_LEAF_COUNT }, (_, index) =>
    index < leaves.length ? normalizedHexBytes(leaves[index], 32) : EMPTY_LEAF,
  );

  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let index = 0; index < level.length; index += 2) {
      next.push(hashDomain("PAYO_MERKLE_NODE_V1", level[index], level[index + 1]));
    }
    level = next;
  }
  return toHex(level[0]);
}

export function hashMerkleNode(left: string, right: string): `0x${string}` {
  return toHex(hashDomain(
    "PAYO_MERKLE_NODE_V1",
    normalizedHexBytes(left, 32),
    normalizedHexBytes(right, 32),
  ));
}

export function deriveRunNullifier(input: {
  organizationSecret: string;
  cycleId: string;
  revision: number;
}): `0x${string}` {
  return toHex(
    hashDomain(
      "PAYO_RUN_V1",
      normalizedHexBytes(input.organizationSecret, 32),
      utf8(input.cycleId),
      encodeU32(input.revision),
    ),
  );
}

export function splitHashToU128(hash: string): { high: bigint; low: bigint } {
  const bytes = normalizedHexBytes(hash, 32);
  return {
    high: decodeUint(bytes.subarray(0, 16)),
    low: decodeUint(bytes.subarray(16, 32)),
  };
}
