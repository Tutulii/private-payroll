import { BarretenbergSync, Fr } from "@aztec/bb.js";
import type { CalculatedPayrollLine } from "@/lib/domain/payroll";
import {
  hashAgreementTerms,
  hashRecipientCommitment,
  hashTextCommitment,
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
export const PAYO_PROOF_EMPTY_LEAF =
  "0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373" as const;

type ProofCommitter = {
  proofHash(domain: bigint, values: readonly bigint[]): `0x${string}`;
  proofMerkleNode(left: string, right: string): `0x${string}`;
  buildProofFixedMerkleRoot(leaves: readonly string[]): `0x${string}`;
  firstProofCatalogMembership(): {
    siblings: `0x${string}`[];
    pathBits: boolean[];
  };
  proofCatalogRoot(leaf: string): `0x${string}`;
  proofAgreementCommitment(input: AgreementTermsCommitmentInput): `0x${string}`;
  proofPayrollCommitment(
    line: CalculatedPayrollLine,
    token: 0 | 1,
    policyCommitment: string,
  ): `0x${string}`;
};

function paddedField(value: Fr): `0x${string}` {
  return `0x${value.toString().replace(/^0x/, "").padStart(64, "0")}`;
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
      api.poseidon2Hash([domain, ...values].map((value) => new Fr(value))),
    );

  const proofMerkleNode = (left: string, right: string): `0x${string}` =>
    proofHash(PAYO_PROOF_DOMAIN_MERKLE_NODE, [...limbs(left), ...limbs(right)]);

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
    let current = leaf as `0x${string}`;
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
    return proofHash(PAYO_PROOF_DOMAIN_AGREEMENT, [
      ...limbs(input.agreementIdCommitment),
      ...limbs(input.recipientCommitment),
      BigInt(input.earningsAtomic.length),
      ...earnings,
      input.token === "STRK" ? 0n : 1n,
      ...limbs(input.policyCommitment),
      ...limbs(input.scheduleCommitment),
      input.dueAt,
      input.validUntil,
      BigInt(input.classificationDeclared),
      BigInt(input.classificationScore),
      BigInt(input.classificationEmployeeThreshold),
      input.finalPayMode ? 1n : 0n,
      BigInt(input.finalRequiredMask),
      ...finalComponents,
      BigInt(input.fxFloorAtomic),
      input.referenceCurrency === "USD" ? 0n : 1n,
      ...limbs(input.salt),
    ]);
  };

  const proofPayrollCommitment = (
    line: CalculatedPayrollLine,
    token: 0 | 1,
    policyCommitment: string,
  ): `0x${string}` => {
    if (line.deductionsAtomic.length > 8) {
      throw new Error("A payroll line supports at most eight deductions.");
    }
    const agreementCommitment = toHex(
      hashTextCommitment("PAYO_AGREEMENT_ID_V1", line.agreementId),
    );
    const recipientCommitment = toHex(
      hashRecipientCommitment(line.recipientAddress, line.salt),
    );
    const deductions = Array.from({ length: 8 }, (_, index) =>
      BigInt(line.deductionsAtomic[index] ?? "0"),
    );
    return proofHash(PAYO_PROOF_DOMAIN_PAYROLL_LINE, [
      ...limbs(agreementCommitment),
      ...limbs(recipientCommitment),
      BigInt(line.grossAtomic),
      BigInt(line.deductionsAtomic.length),
      ...deductions,
      BigInt(line.netAtomic),
      BigInt(token),
      ...limbs(policyCommitment),
      ...limbs(line.scheduleCommitment),
      ...limbs(line.salt),
    ]);
  };

  return {
    proofHash,
    proofMerkleNode,
    buildProofFixedMerkleRoot,
    firstProofCatalogMembership,
    proofCatalogRoot,
    proofAgreementCommitment,
    proofPayrollCommitment,
  };
}
