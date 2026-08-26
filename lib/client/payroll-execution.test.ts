import { describe, expect, it, vi } from "vitest";
import { buildFxSnapshot } from "@/lib/domain/fx";
import { referenceClassificationAnswers } from "@/lib/domain/classification";
import { decryptVaultRecord, encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import { buildPayrollIntegrityInputsFromSerialized } from "@/lib/proof/input-builder";
import {
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  type EncryptedPayrollWitness,
  type ProofWorkerSuccess,
} from "@/lib/proof/protocol";
import type { PayoClient } from "./payo-client";
import {
  storeEncryptedAdvancedAgreement,
  storeEncryptedRecurringAgreement,
} from "./agreement-directory";
import { prepareEncryptedPayee } from "./payee-directory";
import {
  executeProofBoundPayroll,
  preparePayrollObligationRoot,
  recoverSealedProvenPayroll,
  resumePendingPayrollSubmission,
} from "./payroll-execution";
import { buildAdvancedPaymentPlanDraft } from "./advanced-agreement-draft";

const organizationId = "0198ddf0-9c00-7000-8000-000000000001";
const chainId = "0x1";
const sealAddress = "0x123";
const now = new Date("2026-08-24T12:00:00.000Z");
const principal = generateVaultPrincipal("did:privy:owner");

function snapshot(baseToken: "STRK" | "USDC" = "STRK") {
  return buildFxSnapshot({
    baseToken,
    referenceCurrency: "USD",
    quoteDecimals: 6,
    haircutBps: 100,
    maximumAgeSeconds: 3_600,
    minimumSources: 1,
    quotes: [{ source: "test-oracle", priceAtomic: "150000", observedAt: now.toISOString() }],
    now,
  });
}

async function prove(input: {
  encryptedWitness: Parameters<typeof decryptVaultRecord>[0];
  principal: typeof principal;
}): Promise<ProofWorkerSuccess> {
  const encrypted = decryptVaultRecord<EncryptedPayrollWitness>(input.encryptedWitness, input.principal);
  if (!("buildInput" in encrypted)) throw new Error("expected serialized build input");
  const built = await buildPayrollIntegrityInputsFromSerialized(encrypted.buildInput);
  const proofCalldata = ["0x1", "0x2"];
  return {
    version: 1,
    type: "proof-complete",
    requestId: "proof-request",
    scheme: "ultra_keccak_zk_honk",
    circuitSha256: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
    provingTimeMs: 10,
    shards: [0, 1].map((shardIndex) => ({
      shardIndex: shardIndex as 0 | 1,
      proof: new Uint8Array([shardIndex + 1]),
      proofCalldata,
      calldataHash: hashProofCalldata(proofCalldata),
      publicInputs: built.publicInputs[shardIndex],
    })) as ProofWorkerSuccess["shards"],
  };
}

function client(ready = true) {
  return {
    getFxSnapshots: vi.fn().mockImplementation((tokens: Array<"STRK" | "USDC">) =>
      Promise.resolve({ blockNumber: 1, snapshots: tokens.map((token) => snapshot(token)) })),
    getProtectedFxSnapshots: vi.fn(),
    checkDeploymentReadiness: vi.fn().mockResolvedValue({
      readiness: {
        ready,
        checks: ready ? [] : [{ code: "agreement_root", ready: false, message: "Agreement root is inactive." }],
      },
    }),
    createPayrollRun: vi.fn().mockResolvedValue({ run: {} }),
    transitionPayrollRun: vi.fn().mockResolvedValue({ run: {} }),
    storeEncryptedProofBundle: vi.fn().mockResolvedValue({ proofBundle: {} }),
    createSettlementIntent: vi.fn().mockImplementation(({ id }: { id: string }) =>
      Promise.resolve({ settlement: { id } })),
    recordSettlementSubmission: vi.fn().mockResolvedValue({ settlement: {} }),
    enqueueProofVerification: vi.fn().mockResolvedValue({ proofVerification: {} }),
    getSealedPayrollRecovery: vi.fn(),
    getEncryptedRecord: vi.fn(),
  };
}

async function unsupportedUsdcFxExecutionInput(mockClient: ReturnType<typeof client>) {
  const payee = prepareEncryptedPayee({
    organizationId,
    displayName: "Protected USDC worker",
    principalKind: "human",
    recipientAddress: "0x789",
    tokenPreference: "USDC",
    jurisdictionCode: "US",
    principal,
    now,
  }).record;
  const agreement = await storeEncryptedAdvancedAgreement({
    client: { storeEncryptedRecord: vi.fn().mockResolvedValue({ record: {} }) } as never,
    organizationId,
    payee,
    token: "USDC",
    classification: "contractor",
    classificationAnswers: referenceClassificationAnswers("contractor"),
    paymentPlan: buildAdvancedPaymentPlanDraft({
      kind: "recurring",
      cadence: "monthly",
      nextDueAt: "2026-08-23T12:00:00.000Z",
    }),
    fixedAmount: "1",
    fxProtection: {
      referenceCurrency: "USD",
      minimumReferenceAtomic: "1000000",
      maximumAgeSeconds: 900,
    },
    principal,
    now,
  });
  return {
    client: mockClient as unknown as PayoClient,
    organizationId,
    organizationSecret: `0x${"45".repeat(32)}`,
    principal,
    chainId,
    sealAddress,
    obligations: [{ agreement, payee }],
    submitPayroll: vi.fn(),
    persistPendingSubmission: vi.fn(),
    prove: vi.fn(prove),
    now: () => now,
  };
}

async function executionInput(mockClient: ReturnType<typeof client>) {
  const payee = prepareEncryptedPayee({
    organizationId,
    displayName: "Maya",
    principalKind: "human",
    recipientAddress: "0x456",
    tokenPreference: "STRK",
    jurisdictionCode: "US",
    principal,
    now,
  }).record;
  const agreement = await storeEncryptedRecurringAgreement({
    client: { storeEncryptedRecord: vi.fn().mockResolvedValue({ record: {} }) } as never,
    organizationId,
    payee,
    amount: "1",
    token: "STRK",
    classification: "contractor",
    classificationAnswers: referenceClassificationAnswers("contractor"),
    cadence: "monthly",
    nextDueAt: "2026-08-23T12:00:00.000Z",
    policyId: "payo-net-invoice-no-withholding-v1",
    policyVersion: 1,
    principal,
    now,
  });
  return {
    client: mockClient as unknown as PayoClient,
    organizationId,
    organizationSecret: `0x${"44".repeat(32)}`,
    principal,
    chainId,
    sealAddress,
    obligations: [{ agreement, payee }],
    submitPayroll: vi.fn().mockResolvedValue("0xfeed"),
    persistPendingSubmission: vi.fn(),
    prove,
    now: () => now,
  };
}

describe("proof-bound payroll browser orchestration", () => {
  it("fails closed before proving when a protected pair has no Mainnet TWAP profile", async () => {
    const mockClient = client();
    const input = await unsupportedUsdcFxExecutionInput(mockClient);
    await expect(executeProofBoundPayroll(input)).rejects.toThrow(/unavailable for USDC\/USD/);
    expect(mockClient.getProtectedFxSnapshots).not.toHaveBeenCalled();
    expect(input.prove).not.toHaveBeenCalled();
    expect(input.submitPayroll).not.toHaveBeenCalled();
  });

  it("pre-schedules the exact agreement root later produced by the proof witness", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    const planned = await preparePayrollObligationRoot({
      organizationId,
      obligations: input.obligations,
      at: now,
    });

    await executeProofBoundPayroll(input);
    expect(mockClient.checkDeploymentReadiness).toHaveBeenCalledWith(
      expect.objectContaining({ agreementRoot: planned.root }),
    );
  });

  it("authorizes the exact fresh FX root before proof generation", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    const authorizeFxRoot = vi.fn().mockResolvedValue(undefined);
    const proveSpy = vi.fn(prove);

    await executeProofBoundPayroll({ ...input, authorizeFxRoot, prove: proveSpy });
    const authorizedRoot = authorizeFxRoot.mock.calls[0][0].root;
    expect(mockClient.checkDeploymentReadiness).toHaveBeenCalledWith(
      expect.objectContaining({ fxRoot: authorizedRoot }),
    );
    expect(authorizeFxRoot.mock.invocationCallOrder[0]).toBeLessThan(
      proveSpy.mock.invocationCallOrder[0],
    );
  });

  it("does not prove or open payroll when FX-root authorization fails", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    const proveSpy = vi.fn(prove);
    await expect(executeProofBoundPayroll({
      ...input,
      prove: proveSpy,
      authorizeFxRoot: vi.fn().mockRejectedValue(new Error("FX publisher unavailable")),
    })).rejects.toThrow("FX publisher unavailable");
    expect(proveSpy).not.toHaveBeenCalled();
    expect(input.submitPayroll).not.toHaveBeenCalled();
  });


  it("persists encrypted records, submits one sealed wallet request, and queues both shards", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    const result = await executeProofBoundPayroll(input);

    expect(input.submitPayroll).toHaveBeenCalledTimes(1);
    expect(input.submitPayroll).toHaveBeenCalledWith(
      [{ address: input.obligations[0].payee.recipientAddress, amount: "1", token: "STRK" }],
      expect.any(Object),
    );
    expect(mockClient.createPayrollRun).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(mockClient.createPayrollRun.mock.calls[0][0])).not.toContain("Maya");
    const storedRun = mockClient.createPayrollRun.mock.calls[0][0];
    const privateRun = decryptVaultRecord<{ manifest: { lines: Array<{ agreementId: string }> } }>(
      storedRun.envelope,
      principal,
    );
    expect(privateRun.manifest.lines[0].agreementId).toBe(input.obligations[0].agreement.agreement.id);
    expect(mockClient.transitionPayrollRun).toHaveBeenCalledWith(expect.objectContaining({ state: "calculated" }));
    expect(mockClient.transitionPayrollRun).not.toHaveBeenCalledWith(expect.objectContaining({ state: "proven" }));
    expect(mockClient.storeEncryptedProofBundle.mock.invocationCallOrder[0]).toBeLessThan(
      input.submitPayroll.mock.invocationCallOrder[0],
    );
    expect(mockClient.storeEncryptedProofBundle).toHaveBeenCalledTimes(1);
    expect(mockClient.createSettlementIntent).toHaveBeenCalledTimes(1);
    const createdSettlementId = mockClient.createSettlementIntent.mock.calls[0][0].id;
    expect(mockClient.recordSettlementSubmission).toHaveBeenCalledWith(createdSettlementId, "0xfeed");
    expect(mockClient.enqueueProofVerification.mock.calls[0][0].shards).toHaveLength(2);
    expect(input.persistPendingSubmission).toHaveBeenNthCalledWith(1, expect.not.objectContaining({ transactionHash: expect.anything() }));
    expect(input.persistPendingSubmission).toHaveBeenNthCalledWith(2, expect.objectContaining({ transactionHash: "0xfeed" }));
    expect(input.persistPendingSubmission).toHaveBeenLastCalledWith(null);
    expect(result).toMatchObject({ settlementId: createdSettlementId, transactionHash: "0xfeed", verificationQueued: true });
  });

  it("never opens the wallet when an on-chain binding is inactive", async () => {
    const mockClient = client(false);
    const input = await executionInput(mockClient);
    await expect(executeProofBoundPayroll(input)).rejects.toThrow("Agreement root is inactive");
    expect(input.submitPayroll).not.toHaveBeenCalled();
    expect(mockClient.createPayrollRun).not.toHaveBeenCalled();
  });

  it("rejects a payee address that no longer matches the encrypted agreement commitment", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    input.obligations[0] = {
      ...input.obligations[0],
      payee: { ...input.obligations[0].payee, recipientAddress: "0x999" },
    };
    await expect(executeProofBoundPayroll(input)).rejects.toThrow(/committed payout recipient/i);
    expect(input.submitPayroll).not.toHaveBeenCalled();
    expect(mockClient.createPayrollRun).not.toHaveBeenCalled();
  });

  it("carries exact STRK and USDC agreement amounts through one sealed wallet request", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    const usdcPayee = prepareEncryptedPayee({
      organizationId,
      displayName: "Scout",
      principalKind: "agent",
      recipientAddress: "0x789",
      tokenPreference: "USDC",
      jurisdictionCode: "US",
      principal,
      now,
    }).record;
    const usdcAgreement = await storeEncryptedRecurringAgreement({
      client: { storeEncryptedRecord: vi.fn().mockResolvedValue({ record: {} }) } as never,
      organizationId,
      payee: usdcPayee,
      amount: "2.123456",
      token: "USDC",
      classification: "agent_service",
      classificationAnswers: referenceClassificationAnswers("agent_service"),
      cadence: "monthly",
      nextDueAt: "2026-08-23T12:00:00.000Z",
      policyId: "payo-net-invoice-no-withholding-v1",
      policyVersion: 1,
      principal,
      now,
    });
    input.obligations.push({ agreement: usdcAgreement, payee: usdcPayee });

    await executeProofBoundPayroll(input);
    expect(input.submitPayroll).toHaveBeenCalledTimes(1);
    expect(input.submitPayroll.mock.calls[0][0]).toEqual([
      { address: input.obligations[0].payee.recipientAddress, amount: "1", token: "STRK" },
      { address: usdcPayee.recipientAddress, amount: "2.123456", token: "USDC" },
    ]);
    const settlement = decryptVaultRecord<{ tokenTotals: { STRK: string; USDC: string } }>(
      mockClient.createSettlementIntent.mock.calls[0][0].envelope,
      principal,
    );
    expect(settlement.tokenTotals).toEqual({
      STRK: "1000000000000000000",
      USDC: "2123456",
    });
  });

  it("derives, proves, and settles a narrow employee statutory withholding policy", async () => {
    const mockClient = client();
    const payee = prepareEncryptedPayee({
      organizationId,
      displayName: "Maya",
      principalKind: "human",
      recipientAddress: "0x456",
      tokenPreference: "USDC",
      jurisdictionCode: "US-CA",
      principal,
      now,
    }).record;
    const agreement = await storeEncryptedRecurringAgreement({
      client: { storeEncryptedRecord: vi.fn().mockResolvedValue({ record: {} }) } as never,
      organizationId,
      payee,
      amount: "10",
      token: "USDC",
      classification: "employee",
      classificationAnswers: referenceClassificationAnswers("employee"),
      cadence: "monthly",
      nextDueAt: "2026-08-23T12:00:00.000Z",
      policyId: "us-irs-supplemental-flat-2026-v1",
      policyVersion: 1,
      principal,
      now,
    });
    const submitPayroll = vi.fn().mockResolvedValue("0xeeee");
    await executeProofBoundPayroll({
      client: mockClient as unknown as PayoClient,
      organizationId,
      organizationSecret: `0x${"45".repeat(32)}`,
      principal,
      chainId,
      sealAddress,
      obligations: [{ agreement, payee }],
      submitPayroll,
      prove,
      now: () => now,
    });
    expect(submitPayroll).toHaveBeenCalledWith(
      [{ address: payee.recipientAddress, amount: "7.8", token: "USDC" }],
      expect.any(Object),
    );
    const encryptedRun = mockClient.createPayrollRun.mock.calls[0][0];
    const privateRun = decryptVaultRecord<{
      manifest: { lines: Array<{ deductionsAtomic: string[]; committedPolicyId: string }> };
    }>(encryptedRun.envelope, principal);
    expect(privateRun.manifest.lines[0]).toMatchObject({
      deductionsAtomic: ["2200000"],
      committedPolicyId: "us-irs-supplemental-flat-2026-v1",
    });
  });

  it("persists a recoverable approval before the wallet and never guesses that a rejection is unsubmitted", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    input.submitPayroll.mockRejectedValue(new Error("User rejected"));
    await expect(executeProofBoundPayroll(input)).rejects.toThrow("User rejected");
    expect(mockClient.createSettlementIntent).toHaveBeenCalledTimes(1);
    expect(input.persistPendingSubmission).toHaveBeenCalledWith(
      expect.not.objectContaining({ transactionHash: expect.anything() }),
    );
    expect(mockClient.recordSettlementSubmission).not.toHaveBeenCalled();
    expect(mockClient.transitionPayrollRun).not.toHaveBeenCalledWith(expect.objectContaining({ state: "cancelled" }));
  });

  it("uses an explicit next revision for a retried cancelled cycle", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    await executeProofBoundPayroll({ ...input, runRevision: 2 });
    expect(mockClient.createPayrollRun.mock.calls[0][0]).toMatchObject({ revision: 2 });
  });

  it("resumes idempotent recording after a post-wallet browser restart", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    mockClient.recordSettlementSubmission.mockRejectedValueOnce(new Error("network offline"));
    const result = await executeProofBoundPayroll(input);
    expect(result.settlementId).toMatch(/^[0-9a-f-]{36}$/);

    const pending = input.persistPendingSubmission.mock.calls.find(([value]) => value?.transactionHash)?.[0];
    expect(pending).toBeTruthy();
    const persistence = vi.fn();
    await expect(resumePendingPayrollSubmission({
      client: mockClient as unknown as PayoClient,
      pending,
      persistPendingSubmission: persistence,
    })).resolves.toMatchObject({ settlementId: result.settlementId, verificationQueued: true });
    expect(persistence).toHaveBeenLastCalledWith(null);
  });

  it("recovers a legacy proven run from canonical seal evidence without opening the wallet", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    const proofBundleId = "0198ddf0-9c00-7000-8000-000000000099";
    mockClient.getSealedPayrollRecovery.mockResolvedValue({
      recovery: {
        runId: "0198ddf0-9c00-7000-8000-000000000088",
        proofBundleId,
        transactionHash: "0xfeed",
        blockNumber: "123",
      },
    });
    mockClient.getEncryptedRecord.mockResolvedValue({
      record: {
        envelope: encryptVaultRecord(
          {
            shards: [
              { shardIndex: 0, proofCalldata: ["0x1", "0x2"] },
              { shardIndex: 1, proofCalldata: ["0x3", "0x4"] },
            ],
          },
          {
            schemaVersion: 1,
            organizationId,
            recordType: "proof-bundle",
            recordId: proofBundleId,
            revision: 1,
          },
          [principal],
        ),
      },
    });
    const persistence = vi.fn();

    const result = await recoverSealedProvenPayroll({
      client: mockClient as unknown as PayoClient,
      organizationId,
      runId: "0198ddf0-9c00-7000-8000-000000000088",
      totals: { STRK: 10n, USDC: 20n },
      principal,
      persistPendingSubmission: persistence,
    });

    expect(input.submitPayroll).not.toHaveBeenCalled();
    expect(mockClient.createSettlementIntent).toHaveBeenCalledTimes(1);
    expect(mockClient.recordSettlementSubmission).toHaveBeenCalledWith(result.settlementId, "0xfeed");
    expect(mockClient.enqueueProofVerification).toHaveBeenCalledWith(expect.objectContaining({
      proofBundleId,
      shards: [["0x1", "0x2"], ["0x3", "0x4"]],
    }));
    expect(persistence).toHaveBeenLastCalledWith(null);
    expect(result).toMatchObject({ transactionHash: "0xfeed", verificationQueued: true });
  });
});
