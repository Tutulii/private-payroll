import { describe, expect, it, vi } from "vitest";
import { generateVaultPrincipal } from "@/lib/crypto/vault";
import { referenceClassificationAnswers } from "@/lib/domain/classification";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  agreementProofScheduleCommitment,
  storeEncryptedAdvancedAgreement,
} from "./agreement-directory";
import { prepareEncryptedPayee } from "./payee-directory";
import {
  createVestingReleaseEvidence,
  PAYO_VESTING_V3_MAINNET_CONTRACTS,
  verifyVestingReleaseEvidence,
} from "./vesting-release-evidence";

const organizationId = "018f1000-0000-7000-8000-000000000001";
const checkpoint = "2026-08-24T12:00:00.000Z";

async function fixture() {
  const principal = generateVaultPrincipal("admin:vesting-evidence");
  const payee = prepareEncryptedPayee({
    organizationId,
    displayName: "Private vesting worker",
    principalKind: "human",
    recipientAddress: "0x456",
    tokenPreference: "USDC",
    jurisdictionCode: "US",
    principal,
    now: new Date("2026-08-24T09:00:00.000Z"),
  }).record;
  const lineAgreement = await storeEncryptedAdvancedAgreement({
    client: { storeEncryptedRecord: vi.fn().mockResolvedValue({ record: {} }) } as never,
    organizationId,
    payee,
    token: "USDC",
    classification: "contractor",
    classificationAnswers: referenceClassificationAnswers("contractor"),
    paymentPlan: {
      planVersion: "payo-payment-plan-v1",
      kind: "private_vesting",
      startsAt: "2026-08-24T10:00:00.000Z",
      cliffAt: "2026-08-24T11:00:00.000Z",
      releaseAt: checkpoint,
      endsAt: "2026-08-24T14:00:00.000Z",
      totalAtomic: "4000000",
      releasedAtomic: "0",
      releaseSequence: 0,
    },
    principal,
    now: new Date("2026-08-24T09:01:00.000Z"),
  });
  const scheduleCommitment = await agreementProofScheduleCommitment(lineAgreement.agreement);
  const roots = {
    agreementRoot: `0x${"11".repeat(32)}`,
    manifestRoot: `0x${"22".repeat(32)}`,
    policyRoot: `0x${"33".repeat(32)}`,
    fxRoot: `0x${"44".repeat(32)}`,
    runNullifier: `0x${"55".repeat(32)}`,
  };
  const runId = generateUuidV7();
  const settlementId = generateUuidV7();
  const paymentTransactionHash = "0xabc";
  const decryptedRun = {
    schemaVersion: 1 as const,
    dueAt: checkpoint,
    ...roots,
    manifest: {
      lines: [{
        agreementId: lineAgreement.agreement.id,
        recipientAddress: payee.recipientAddress,
        token: "USDC" as const,
        earningsAtomic: ["2000000"],
        deductionsAtomic: ["400000"],
        committedPolicyId: lineAgreement.agreement.statutoryPolicy.policyId,
        scheduleCommitment,
        salt: `0x${"66".repeat(32)}`,
      }],
    },
  };
  return {
    organizationId,
    payee,
    lineAgreement,
    decryptedRun,
    run: {
      id: runId,
      organizationId,
      state: "confirmed",
      ...roots,
      transactionHash: paymentTransactionHash,
    },
    settlement: {
      id: settlementId,
      runId,
      workflowType: "payroll" as const,
      subjectRecordId: runId,
      state: "confirmed",
      tokenTotalsCommitment: `0x${"77".repeat(32)}`,
      transactionHash: paymentTransactionHash,
      confirmedAt: "2026-08-24T12:05:00.000Z",
      blockNumber: "14461163",
      confirmationDepth: 8,
      proofValidityExpiry: "1787576400",
    },
    authorization: {
      id: generateUuidV7(),
      organizationId,
      runId,
      payrollProofBundleId: generateUuidV7(),
      state: "complete" as const,
      activeStep: "transition1" as const,
      transactionHash: "0x105",
      beginTransactionHash: "0x101",
      payrollShard0TransactionHash: "0x102",
      payrollShard1TransactionHash: "0x103",
      transitionShard0TransactionHash: "0x104",
      transitionShard1TransactionHash: "0x105",
      attempts: 1,
      lastErrorCode: null,
      lastErrorMessage: null,
      authorizedAt: "2026-08-24T11:58:00.000Z",
      createdAt: "2026-08-24T11:55:00.000Z",
      updatedAt: "2026-08-24T11:58:00.000Z",
    },
  };
}

describe("vesting release evidence", () => {
  it("exports one exact release with self-decoding identity, proof, contracts, and payment evidence", async () => {
    const input = await fixture();
    const evidence = createVestingReleaseEvidence({
      ...input,
      now: new Date("2026-08-24T12:10:00.000Z"),
    });
    expect(evidence).toMatchObject({
      packageVersion: "payo-vesting-release-evidence-v1",
      sourceId: input.settlement.id,
      release: {
        releaseNumber: 1,
        previouslyReleasedAtomic: "0",
        cumulativeReleasedAtomic: "2000000",
        grossReleaseAtomic: "2000000",
        deductionsAtomic: "400000",
        netPaidAtomic: "1600000",
      },
      onchain: {
        contracts: {
          vestingTransitionVerifierV3: PAYO_VESTING_V3_MAINNET_CONTRACTS.verifier,
          vestingTransitionBundleV3: PAYO_VESTING_V3_MAINNET_CONTRACTS.bundle,
          vestingBookSeal: PAYO_VESTING_V3_MAINNET_CONTRACTS.vestingBookSeal,
        },
        paymentTransactionHash: input.settlement.transactionHash,
        paymentBlockNumber: "14461163",
      },
    });
    expect(evidence.releaseReference).toContain(input.run.id);
    expect(evidence.recipient.walletPrincipalId).toContain(evidence.recipient.walletAddress);
    expect(verifyVestingReleaseEvidence(evidence)).toEqual(evidence);
  });

  it("rejects a changed release after export", async () => {
    const input = await fixture();
    const evidence = createVestingReleaseEvidence({ ...input });
    expect(() => verifyVestingReleaseEvidence({
      ...evidence,
      release: { ...evidence.release, netPaidAtomic: "1" },
    })).toThrow(/commitment/i);
  });
});
