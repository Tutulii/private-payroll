import { BarretenbergSync } from "@aztec/bb.js";
import type { CalculatedPayrollLine } from "@/lib/domain/payroll";
import {
  hashAgreementTerms,
  PAYO_MAX_PAYROLL_LINES,
  PAYO_MERKLE_LEAF_COUNT,
  splitHashToU128,
  type AgreementTermsCommitmentInput,
} from "@/lib/crypto/commitments";
import { normalizedHexBytes, toHex } from "@/lib/crypto/encoding";

export const PAYO_PROOF_DOMAIN_EMPTY = 1n;
export const PAYO_PROOF_DOMAIN_MERKLE_NODE = 2n;
export const PAYO_PROOF_DOMAIN_AGREEMENT = 3n;
export const PAYO_PROOF_DOMAIN_PAYROLL_LINE = 4n;
export const PAYO_PROOF_DOMAIN_CATALOG_LEAF = 5n;
export const PAYO_PROOF_EMPTY_LEAF =
  "0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373" as const;

type ProofCommitter = {
  proofHash(domain: bigint, values: readonly bigint[]): `0x${string}`;
  proofMerkleNode(left: string, right: string): `0x${string}`;
  proofCatalogLeaf(commitment: string): `0x${string}`;
  buildProofFixedMerkleRoot(leaves: readonly string[]): `0x${string}`;
  firstProofCatalogMembership(): {
    siblings: `0x${string}`[];
    pathBits: boolean[];
  };
  proofCatalogRoot(leaf: string): `0x${string}`;
  proofAgreementCommitment(input: AgreementTermsCommitmentInput): `0x${string}`;
  proofPayrollCommitment(
    line: CalculatedPayrollLine,
    agreementCommitment: string,
    metadata: {
      classificationTreatment: number;
      finalIncludedMask: number;
      referenceValueAtomic: bigint | string;
    },
  ): `0x${string}`;
};

const PACKED_AMOUNT_LIMIT = 1n << 120n;

function packedAmount(value: bigint | string): bigint {
  const amount = BigInt(value);
  if (amount < 0n || amount >= PACKED_AMOUNT_LIMIT) {
    throw new Error("Amount exceeds the PAYO proof packing limit.");
  }
  return amount;
}

function packAmountPair(left: bigint | string, right: bigint | string): bigint {
  return packedAmount(left) + packedAmount(right) * PACKED_AMOUNT_LIMIT;
}

function fieldBytes(value: bigint): Uint8Array {
  if (value < 0n) throw new Error("Proof field values cannot be negative.");
  const hex = value.toString(16).padStart(64, "0");
  if (hex.length > 64) throw new Error("Proof field value exceeds 32 bytes.");
  return Uint8Array.from({ length: 32 }, (_, index) =>
    Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16),
  );
}

function paddedField(value: Uint8Array): `0x${string}` {
  return `0x${Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function limbs(value: string): [bigint, bigint] {
  const { high, low } = splitHashToU128(value);
  return [high, low];
}

/**
 * Creates the canonical proof-root hasher used by the Noir circuit. The public
 * disclosure commitments remain Keccak; only the fixed proof trees and their
 * private leaves use Barretenberg's BN254 Poseidon2 fixed-length sponge.
 */
export async function createProofCommitter(): Promise<ProofCommitter> {
  await BarretenbergSync.initSingleton();
  const api = BarretenbergSync.getSingleton();

  const proofHash = (
    domain: bigint,
    values: readonly bigint[],
  ): `0x${string}` =>
    paddedField(
      api.poseidon2Hash({
        inputs: [domain, ...values].map(fieldBytes),
      }).hash,
    );

  const proofMerkleNode = (left: string, right: string): `0x${string}` =>
    proofHash(PAYO_PROOF_DOMAIN_MERKLE_NODE, [BigInt(left), BigInt(right)]);

  const proofCatalogLeaf = (commitment: string): `0x${string}` =>
    proofHash(PAYO_PROOF_DOMAIN_CATALOG_LEAF, limbs(commitment));

  const buildProofFixedMerkleRoot = (
    leaves: readonly string[],
  ): `0x${string}` => {
    if (leaves.length > PAYO_MAX_PAYROLL_LINES) {
      throw new Error(
        `PAYO supports at most ${PAYO_MAX_PAYROLL_LINES} real payroll leaves.`,
      );
    }
    let level: `0x${string}`[] = Array.from(
      { length: PAYO_MERKLE_LEAF_COUNT },
      (_, index) =>
        index < leaves.length
          ? toHex(normalizedHexBytes(leaves[index], 32))
          : PAYO_PROOF_EMPTY_LEAF,
    );
    while (level.length > 1) {
      level = Array.from({ length: level.length / 2 }, (_, index) =>
        proofMerkleNode(level[index * 2], level[index * 2 + 1]),
      );
    }
    return level[0];
  };

  const firstProofCatalogMembership = () => {
    const siblings: `0x${string}`[] = [];
    let emptySubtree: `0x${string}` = PAYO_PROOF_EMPTY_LEAF;
    for (let level = 0; level < 6; level += 1) {
      siblings.push(emptySubtree);
      emptySubtree = proofMerkleNode(emptySubtree, emptySubtree);
    }
    return { siblings, pathBits: Array(6).fill(false) as boolean[] };
  };

  const proofCatalogRoot = (leaf: string): `0x${string}` => {
    let current = proofCatalogLeaf(leaf);
    for (const sibling of firstProofCatalogMembership().siblings) {
      current = proofMerkleNode(current, sibling);
    }
    return current;
  };

  const proofAgreementCommitment = (
    input: AgreementTermsCommitmentInput,
  ): `0x${string}` => {
    // Reuse the authoritative public commitment encoder for input validation.
    hashAgreementTerms(input);
    const earnings = Array.from({ length: 8 }, (_, index) =>
      BigInt(input.earningsAtomic[index] ?? "0"),
    );
    const finalComponents = Array.from({ length: 5 }, (_, index) =>
      BigInt(input.finalComponentsAtomic[index] ?? "0"),
    );
    const metadata =
      BigInt(input.earningsAtomic.length) +
      (input.token === "STRK" ? 0n : 1n) * 16n +
      BigInt(input.classificationDeclared) * 32n +
      BigInt(input.classificationScore) * 128n +
      BigInt(input.classificationEmployeeThreshold) * 8388608n +
      (input.finalPayMode ? 1n : 0n) * 549755813888n +
      BigInt(input.finalRequiredMask) * 1099511627776n +
      (input.referenceCurrency === "USD" ? 0n : 1n) * 35184372088832n;
    return proofHash(PAYO_PROOF_DOMAIN_AGREEMENT, [
      ...limbs(input.agreementIdCommitment),
      ...limbs(input.recipientCommitment),
      packAmountPair(earnings[0], earnings[1]),
      packAmountPair(earnings[2], earnings[3]),
      packAmountPair(earnings[4], earnings[5]),
      packAmountPair(earnings[6], earnings[7]),
      ...limbs(input.policyCommitment),
      ...limbs(input.scheduleCommitment),
      input.dueAt + input.validUntil * (1n << 64n),
      packAmountPair(finalComponents[0], finalComponents[1]),
      packAmountPair(finalComponents[2], finalComponents[3]),
      packAmountPair(finalComponents[4], 0n),
      packedAmount(input.fxFloorAtomic) + metadata * PACKED_AMOUNT_LIMIT,
      ...limbs(input.salt),
    ]);
  };

  const proofPayrollCommitment = (
    line: CalculatedPayrollLine,
    agreementCommitment: string,
    metadata: {
      classificationTreatment: number;
      finalIncludedMask: number;
      referenceValueAtomic: bigint | string;
    },
  ): `0x${string}` => {
    if (line.deductionsAtomic.length > 8) {
      throw new Error("A payroll line supports at most eight deductions.");
    }
    const deductions = Array.from({ length: 8 }, (_, index) =>
      BigInt(line.deductionsAtomic[index] ?? "0"),
    );
    const lineMetadata =
      BigInt(line.deductionsAtomic.length) +
      BigInt(metadata.classificationTreatment) * 16n +
      BigInt(metadata.finalIncludedMask) * 64n;
    return proofHash(PAYO_PROOF_DOMAIN_PAYROLL_LINE, [
      BigInt(agreementCommitment),
      packAmountPair(deductions[0], deductions[1]),
      packAmountPair(deductions[2], deductions[3]),
      packAmountPair(deductions[4], deductions[5]),
      packAmountPair(deductions[6], deductions[7]),
      packedAmount(metadata.referenceValueAtomic) + lineMetadata * PACKED_AMOUNT_LIMIT,
      ...limbs(line.salt),
    ]);
  };

  return {
    proofHash,
    proofMerkleNode,
    proofCatalogLeaf,
    buildProofFixedMerkleRoot,
    firstProofCatalogMembership,
    proofCatalogRoot,
    proofAgreementCommitment,
    proofPayrollCommitment,
  };
}
