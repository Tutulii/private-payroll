import { describe, expect, it, vi } from "vitest";
import { buildFxSnapshot } from "@/lib/domain/fx";
import { referenceClassificationAnswers } from "@/lib/domain/classification";
import { claimCapabilityCommitmentV2, type ExceptionPublicInputsV2 } from "@/lib/domain/exception-protocol";
import { generateUuidV7 } from "@/lib/domain/records";
import { decryptVaultRecord, encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import { buildAdvancedObligationInputs } from "@/lib/proof/advanced-obligation-input";
import { buildFxCatalogRoot, buildPayrollIntegrityInputsFromSerialized } from "@/lib/proof/input-builder";
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  OBLIGATION_SNAPSHOT_LINK_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  type ExceptionProofWorkerSuccess,
  type EncryptedPayrollWitness,
  type ProofWorkerSuccess,
} from "@/lib/proof/protocol";
import { PayoApiError, type PayoClient } from "./payo-client";
import {
  storeEncryptedAdvancedAgreement,
  storeEncryptedRecurringAgreement,
} from "./agreement-directory";
import { prepareEncryptedPayee } from "./payee-directory";
import {
  executeProofBoundPayroll,
  preparePayrollObligationRoot,
  recoverConfirmedPayrollVerification,
  recoverSealedProvenPayroll,
  resumePendingPayrollSubmission,
} from "./payroll-execution";
import { buildAdvancedPaymentPlanDraft } from "./advanced-agreement-draft";
import { prepareObligationSnapshotPlan } from "./obligation-snapshot-plan";

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
  if (!("buildInput" in encrypted) && !("advancedBuildInput" in encrypted)) {
    throw new Error("expected serialized build input");
  }
  const buildInput = "advancedBuildInput" in encrypted
    ? encrypted.advancedBuildInput.payroll
    : encrypted.buildInput;
  const built = await buildPayrollIntegrityInputsFromSerialized(buildInput);
  const advanced = "advancedBuildInput" in encrypted
    ? buildAdvancedObligationInputs({
        payroll: built,
        agreements: encrypted.advancedBuildInput.agreements,
      })
    : undefined;
  const proofCalldata = ["0x1", "0x2"];
  return {
    version: 1,
    type: "proof-complete",
    requestId: "proof-request",
    scheme: "ultra_keccak_zk_honk",
    circuitSha256: advanced
      ? ADVANCED_OBLIGATION_CIRCUIT_SHA256
      : PAYROLL_INTEGRITY_CIRCUIT_SHA256,
    provingTimeMs: 10,
    shards: [0, 1].map((shardIndex) => ({
      shardIndex: shardIndex as 0 | 1,
      proof: new Uint8Array([shardIndex + 1]),
      proofCalldata,
      calldataHash: hashProofCalldata(proofCalldata),
      publicInputs: advanced?.publicInputs[shardIndex] ?? built.publicInputs[shardIndex],
    })) as ProofWorkerSuccess["shards"],
  };
}

function exceptionPublicInputs(circuitInput: Record<string, unknown>): ExceptionPublicInputsV2 {
  const value = (key: string) => {
    const field = circuitInput[key];
    if (typeof field !== "string") throw new Error(`expected exception public input ${key}`);
    return field;
  };
  return {
    chainId: value("chain_id"),
    sealAddress: value("seal_address"),
    proofVersion: value("proof_version"),
    schemaVersion: value("schema_version"),
    agreementRootHigh: value("agreement_root_high"),
    agreementRootLow: value("agreement_root_low"),
    manifestRootHigh: value("manifest_root_high"),
    manifestRootLow: value("manifest_root_low"),
    policyRootHigh: value("policy_root_high"),
    policyRootLow: value("policy_root_low"),
    fxRootHigh: value("fx_root_high"),
    fxRootLow: value("fx_root_low"),
    subjectNullifierHigh: value("subject_nullifier_high"),
    subjectNullifierLow: value("subject_nullifier_low"),
    parentNullifierHigh: value("parent_nullifier_high"),
    parentNullifierLow: value("parent_nullifier_low"),
    factCommitmentHigh: value("fact_commitment_high"),
    factCommitmentLow: value("fact_commitment_low"),
    parentFactCommitmentHigh: value("parent_fact_commitment_high"),
    parentFactCommitmentLow: value("parent_fact_commitment_low"),
    validityStart: value("validity_start"),
    validityExpiry: value("validity_expiry"),
    shardIndex: value("shard_index"),
  };
}

async function proveSnapshot(input: {
  encryptedWitness: Parameters<typeof decryptVaultRecord>[0];
  principal: typeof principal;
}): Promise<ExceptionProofWorkerSuccess> {
  const encrypted = decryptVaultRecord<EncryptedPayrollWitness>(input.encryptedWitness, input.principal);
  if (!("exceptionCircuitProfile" in encrypted) || encrypted.exceptionCircuitProfile !== "obligation_snapshot_v5") {
    throw new Error("expected obligation snapshot witness");
  }
  const proofCalldata = Array.from({ length: 35 }, (_, index) => `0x${(index + 1).toString(16)}`);
  return {
    version: 2,
    type: "exception-proof-complete",
    requestId: "snapshot-proof-request",
    profile: "obligation_snapshot_v5",
    scheme: "ultra_keccak_zk_honk",
    circuitSha256: OBLIGATION_SNAPSHOT_LINK_CIRCUIT_SHA256,
    provingTimeMs: 10,
    proof: {
      proof: new Uint8Array([5]),
      proofCalldata,
      calldataHash: hashProofCalldata(proofCalldata),
      publicInputs: exceptionPublicInputs(encrypted.circuitInput as Record<string, unknown>),
    },
  };
}

function client(ready = true) {
  const authorization = (runId: string) => ({
    id: generateUuidV7(now.getTime() + 20),
    organizationId,
    runId,
    payrollProofBundleId: generateUuidV7(now.getTime() + 21),
    snapshotProofBundleId: generateUuidV7(now.getTime() + 22),
    state: "complete" as const,
    activeStep: "shard1" as const,
    transactionHash: "0xabc",
    beginTransactionHash: "0xa1",
    snapshotTransactionHash: "0xa2",
    shard0TransactionHash: "0xa3",
    shard1TransactionHash: "0xabc",
    attempts: 0,
    lastErrorCode: null,
    lastErrorMessage: null,
    authorizedAt: now.toISOString(),
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  });
  return {
    getFxSnapshots: vi.fn().mockImplementation((tokens: Array<"STRK" | "USDC">) =>
      Promise.resolve({ blockNumber: 1, snapshots: tokens.map((token) => snapshot(token)) })),
    getProtectedFxSnapshots: vi.fn(),
    getPayrollFxCatalog: vi.fn().mockImplementation(async (input: {
      medianTokens: Array<"STRK" | "USDC">;
      protectedTokens: Array<"STRK" | "USDC">;
    }) => {
      const snapshots = [...input.protectedTokens, ...input.medianTokens].map((token) => snapshot(token));
      return {
        snapshots,
        catalogRoot: await buildFxCatalogRoot(snapshots),
        publicationWindow: {
          observedAt: Math.floor(now.getTime() / 1_000),
          maximumAgeSeconds: 3_600,
          expiresAt: Math.floor(now.getTime() / 1_000) + 3_600,
        },
        publicationTicket: "test-publication-ticket",
        sourceBlocks: { protected: null, median: 1 },
      };
    }),
    checkDeploymentReadiness: vi.fn().mockResolvedValue({
      readiness: {
        ready,
        checks: ready ? [] : [{ code: "agreement_root", ready: false, message: "Agreement root is inactive." }],
      },
    }),
    getPayrollRun: vi.fn().mockRejectedValue(
      new PayoApiError("The encrypted run payload is missing.", "RUN_VAULT_MISSING", 500),
    ),
    createPayrollRun: vi.fn().mockResolvedValue({ run: {} }),
    transitionPayrollRun: vi.fn().mockResolvedValue({ run: {} }),
    storeEncryptedProofBundle: vi.fn().mockResolvedValue({ proofBundle: {} }),
    createSettlementIntent: vi.fn().mockImplementation(({ id }: { id: string }) =>
      Promise.resolve({ settlement: { id } })),
    linkAgentExecutionApproval: vi.fn().mockImplementation((input: {
      capabilityId: string;
      executionId: string;
      settlementId: string;
    }) => Promise.resolve({ execution: {
      ...input,
      runId: "",
      state: "approval_pending",
      requiresApproval: true,
    } })),
    cancelAgentExecutionApproval: vi.fn().mockResolvedValue({ execution: {} }),
    cancelSettlementApproval: vi.fn().mockResolvedValue({ settlement: {} }),
    getSettlement: vi.fn().mockResolvedValue({ settlement: { transactionHash: null } }),
    recordSettlementSubmission: vi.fn().mockResolvedValue({ settlement: {} }),
    enqueueProofVerification: vi.fn().mockResolvedValue({ proofVerification: {} }),
    enqueuePayrollAuthorization: vi.fn().mockImplementation(({ runId }: { runId: string }) =>
      Promise.resolve({ authorization: authorization(runId) })),
    getPayrollAuthorization: vi.fn().mockImplementation((runId: string) =>
      Promise.resolve({ authorization: authorization(runId) })),
    getSealedPayrollRecovery: vi.fn(),
    getEncryptedRecord: vi.fn(),
    provisionDirectPrivacyAccount: vi.fn().mockResolvedValue({
      account: {
        id: generateUuidV7(now.getTime() + 40),
        proofPrincipal: principal,
        activationState: "active" as const,
      },
      configurationCall: {},
    }),
    stageDirectPrivacyRunWitness: vi.fn().mockResolvedValue({
      witness: {
        runId: generateUuidV7(now.getTime() + 41),
        runVersion: 1,
        witnessCommitment: `0x${"77".repeat(32)}`,
        replayed: false,
      },
    }),
  };
}

async function snapshotExecutionInput(mockClient: ReturnType<typeof client>) {
  const preparedAt = new Date("2026-08-24T11:50:00.000Z");
  const executionAt = new Date("2026-08-24T12:01:00.000Z");
  const claimSecret = `0x${"91".repeat(32)}`;
  const payee = prepareEncryptedPayee({
    organizationId,
    displayName: "Protected worker",
    principalKind: "human",
    recipientAddress: "0x456",
    tokenPreference: "STRK",
    jurisdictionCode: "US",
    claimIdentity: {
      principalId: generateUuidV7(preparedAt.getTime() - 1),
      publicKey: principal.publicKey,
      claimCapabilityCommitment: claimCapabilityCommitmentV2(claimSecret),
    },
    principal,
    now: preparedAt,
  }).record;
  const agreement = await storeEncryptedAdvancedAgreement({
    client: { storeEncryptedRecord: vi.fn().mockResolvedValue({ record: {} }) } as never,
    organizationId,
    payee,
    token: "STRK",
    classification: "contractor",
    classificationAnswers: referenceClassificationAnswers("contractor"),
    paymentPlan: buildAdvancedPaymentPlanDraft({
      kind: "recurring",
      cadence: "monthly",
      nextDueAt: "2026-08-24T12:00:00.000Z",
    }),
    fixedAmount: "1",
    principal,
    now: preparedAt,
  });
  const obligations = [{ agreement, payee }];
  const snapshot = await prepareObligationSnapshotPlan({
    organizationId,
    organizationSecret: `0x${"44".repeat(32)}`,
    ownerAddress: "0xabc",
    obligations,
    principal,
    now: preparedAt,
  });
  return {
    client: mockClient as unknown as PayoClient,
    organizationId,
    organizationSecret: `0x${"44".repeat(32)}`,
    principal,
    chainId,
    sealAddress,
    obligations,
    snapshotPlan: snapshot.privatePlan,
    submitPayroll: vi.fn().mockResolvedValue("0xfeed"),
    persistPendingSubmission: vi.fn(),
    prove: vi.fn(prove),
    proveSnapshot: vi.fn(proveSnapshot),
    authorizationPollIntervalMs: 0,
    authorizationTimeoutMs: 1_000,
    now: () => executionAt,
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
    expect(mockClient.getPayrollFxCatalog).not.toHaveBeenCalled();
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

  it("authorizes the exact proved FX root before deployment preflight", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    const authorizeFxRoot = vi.fn().mockResolvedValue(undefined);
    const proveSpy = vi.fn(prove);

    await executeProofBoundPayroll({ ...input, authorizeFxRoot, prove: proveSpy });
    const authorizedRoot = authorizeFxRoot.mock.calls[0][0].root;
    expect(mockClient.checkDeploymentReadiness).toHaveBeenCalledWith(
      expect.objectContaining({ fxRoot: authorizedRoot }),
    );
    expect(proveSpy.mock.invocationCallOrder[0]).toBeLessThan(authorizeFxRoot.mock.invocationCallOrder[0]);
    expect(authorizeFxRoot.mock.invocationCallOrder[0]).toBeLessThan(
      mockClient.checkDeploymentReadiness.mock.invocationCallOrder[0],
    );
  });

  it("never spends an FX authorization transaction when proving fails", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    const authorizeFxRoot = vi.fn();
    await expect(executeProofBoundPayroll({
      ...input,
      prove: vi.fn().mockRejectedValue(new Error("prover unavailable")),
      authorizeFxRoot,
    })).rejects.toThrow("prover unavailable");
    expect(authorizeFxRoot).not.toHaveBeenCalled();
    expect(input.submitPayroll).not.toHaveBeenCalled();
  });

  it("proves but does not open payroll when FX-root authorization fails", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    const proveSpy = vi.fn(prove);
    await expect(executeProofBoundPayroll({
      ...input,
      prove: proveSpy,
      authorizeFxRoot: vi.fn().mockRejectedValue(new Error("FX publisher unavailable")),
    })).rejects.toThrow("FX publisher unavailable");
    expect(proveSpy).toHaveBeenCalledTimes(1);
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
    expect(mockClient.enqueueProofVerification.mock.invocationCallOrder[0]).toBeLessThan(
      input.submitPayroll.mock.invocationCallOrder[0],
    );
    expect(input.persistPendingSubmission).toHaveBeenNthCalledWith(1, expect.not.objectContaining({ transactionHash: expect.anything() }));
    expect(input.persistPendingSubmission).toHaveBeenNthCalledWith(2, expect.objectContaining({ transactionHash: "0xfeed" }));
    expect(input.persistPendingSubmission).toHaveBeenLastCalledWith(null);
    expect(result).toMatchObject({ settlementId: createdSettlementId, transactionHash: "0xfeed", verificationQueued: true });
  });

  it("finishes the browser flow from canonical settlement evidence when Ready never returns its hash", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    const onStage = vi.fn();
    const onRecoveredTransactionHash = vi.fn();
    input.submitPayroll.mockImplementation(() => new Promise<string>(() => undefined));
    mockClient.getSettlement
      .mockResolvedValueOnce({ settlement: { transactionHash: null } })
      .mockResolvedValue({ settlement: { transactionHash: "0xfeed" } });

    const result = await executeProofBoundPayroll({
      ...input,
      onStage,
      onRecoveredTransactionHash,
      walletRecoveryPollIntervalMs: 1,
      walletRecoveryTimeoutMs: 100,
      walletRecoveryNoticeDelayMs: 0,
    });

    expect(input.submitPayroll).toHaveBeenCalledTimes(1);
    expect(onStage).toHaveBeenCalledWith("wallet_recovery");
    expect(onRecoveredTransactionHash).toHaveBeenCalledOnce();
    expect(onRecoveredTransactionHash).toHaveBeenCalledWith("0xfeed");
    expect(onRecoveredTransactionHash.mock.invocationCallOrder[0]).toBeLessThan(
      mockClient.recordSettlementSubmission.mock.invocationCallOrder[0],
    );
    expect(mockClient.recordSettlementSubmission).toHaveBeenCalledWith(result.settlementId, "0xfeed");
    expect(input.persistPendingSubmission).toHaveBeenLastCalledWith(null);
    expect(result.transactionHash).toBe("0xfeed");
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
        recoveryKind: "submission",
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
              { shardIndex: 0, proofCalldata: ["0x1", "0x2"], publicInputs: { validityExpiry: String(Math.floor(Date.now() / 1_000) + 3_600) } },
              { shardIndex: 1, proofCalldata: ["0x3", "0x4"], publicInputs: { validityExpiry: String(Math.floor(Date.now() / 1_000) + 3_600) } },
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

  it("queues missing proof verification for an already confirmed private payroll", async () => {
    const mockClient = client();
    const proofBundleId = "0198ddf0-9c00-7000-8000-000000000099";
    const runId = "0198ddf0-9c00-7000-8000-000000000088";
    const settlementId = "0198ddf0-9c00-7000-8000-000000000077";
    mockClient.getSealedPayrollRecovery.mockResolvedValue({
      recovery: {
        recoveryKind: "verification",
        runId,
        proofBundleId,
        settlementId,
        transactionHash: "0xfeed",
        blockNumber: "123",
      },
    });
    mockClient.getEncryptedRecord.mockResolvedValue({
      record: {
        envelope: encryptVaultRecord(
          {
            shards: [
              { shardIndex: 0, proofCalldata: ["0x1", "0x2"], publicInputs: { validityExpiry: String(Math.floor(Date.now() / 1_000) + 3_600) } },
              { shardIndex: 1, proofCalldata: ["0x3", "0x4"], publicInputs: { validityExpiry: String(Math.floor(Date.now() / 1_000) + 3_600) } },
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

    await expect(recoverConfirmedPayrollVerification({
      client: mockClient as unknown as PayoClient,
      organizationId,
      runId,
      principal,
    })).resolves.toMatchObject({ settlementId, transactionHash: "0xfeed", verificationQueued: true });
    expect(mockClient.createSettlementIntent).not.toHaveBeenCalled();
    expect(mockClient.recordSettlementSubmission).not.toHaveBeenCalled();
    expect(mockClient.enqueueProofVerification).toHaveBeenCalledWith({
      settlementId,
      proofBundleId,
      shards: [["0x1", "0x2"], ["0x3", "0x4"]],
    });

    mockClient.enqueueProofVerification.mockClear();
    mockClient.getEncryptedRecord.mockResolvedValue({
      record: {
        envelope: encryptVaultRecord(
          {
            shards: [
              { shardIndex: 0, proofCalldata: ["0x1"], publicInputs: { validityExpiry: "1" } },
              { shardIndex: 1, proofCalldata: ["0x2"], publicInputs: { validityExpiry: "1" } },
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
    await expect(recoverConfirmedPayrollVerification({
      client: mockClient as unknown as PayoClient,
      organizationId,
      runId,
      principal,
    })).rejects.toThrow("missed its on-chain proof-delivery window");
    expect(mockClient.enqueueProofVerification).not.toHaveBeenCalled();
  });

  it("does not open Ready unless durable proof delivery is prepared", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    mockClient.enqueueProofVerification.mockRejectedValue(new Error("proof service unavailable"));

    await expect(executeProofBoundPayroll(input)).rejects.toMatchObject({
      name: "PayrollSubmissionPersistenceError",
      message: expect.stringContaining("could not prepare approval and proof delivery"),
    });
    expect(input.submitPayroll).not.toHaveBeenCalled();
    expect(mockClient.recordSettlementSubmission).not.toHaveBeenCalled();
    expect(input.persistPendingSubmission).not.toHaveBeenCalled();
  });

  it("keeps recovery evidence when durable settlement recording itself fails", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    mockClient.recordSettlementSubmission.mockRejectedValue(new Error("database unavailable"));

    await expect(executeProofBoundPayroll(input)).rejects.toMatchObject({
      name: "PayrollSubmissionPersistenceError",
      pendingSubmission: expect.objectContaining({ transactionHash: "0xfeed" }),
    });
    expect(input.persistPendingSubmission).toHaveBeenLastCalledWith(
      expect.objectContaining({ transactionHash: "0xfeed" }),
    );
    expect(mockClient.enqueueProofVerification).toHaveBeenCalledTimes(1);
    expect(mockClient.enqueueProofVerification.mock.invocationCallOrder[0]).toBeLessThan(
      input.submitPayroll.mock.invocationCallOrder[0],
    );
  });

  it("clears an old local recovery marker once its payment is durable even if proof enqueue fails", async () => {
    const mockClient = client();
    const input = await executionInput(mockClient);
    await executeProofBoundPayroll(input);
    const pending = input.persistPendingSubmission.mock.calls.find(([value]) => value?.transactionHash)?.[0];
    expect(pending).toBeTruthy();
    mockClient.enqueueProofVerification.mockRejectedValue(new Error("historical proof unavailable"));
    const persist = vi.fn();
    const onStage = vi.fn();

    await expect(resumePendingPayrollSubmission({
      client: mockClient as unknown as PayoClient,
      pending,
      persistPendingSubmission: persist,
      onStage,
    })).resolves.toMatchObject({
      verificationQueued: false,
      proofDeliveryWarning: expect.stringContaining("durably recorded"),
    });

    expect(persist).toHaveBeenLastCalledWith(null);
    expect(onStage).toHaveBeenLastCalledWith("recorded");
  });

  it("authorizes PayrollIntegrity v2 and snapshot v5 before opening Ready", async () => {
    const mockClient = client();
    const input = await snapshotExecutionInput(mockClient);

    const result = await executeProofBoundPayroll(input);

    expect(input.prove).toHaveBeenCalledOnce();
    expect(input.proveSnapshot).toHaveBeenCalledOnce();
    expect(input.prove.mock.invocationCallOrder[0]).toBeLessThan(
      input.proveSnapshot.mock.invocationCallOrder[0],
    );
    expect(mockClient.storeEncryptedProofBundle).toHaveBeenCalledTimes(2);
    expect(mockClient.storeEncryptedProofBundle.mock.invocationCallOrder[1]).toBeLessThan(
      mockClient.enqueuePayrollAuthorization.mock.invocationCallOrder[0],
    );
    expect(mockClient.enqueuePayrollAuthorization.mock.invocationCallOrder[0]).toBeLessThan(
      input.submitPayroll.mock.invocationCallOrder[0],
    );
    expect(mockClient.checkDeploymentReadiness).not.toHaveBeenCalled();
    expect(mockClient.enqueueProofVerification).not.toHaveBeenCalled();
    expect(mockClient.createPayrollRun).toHaveBeenCalledWith(expect.objectContaining({
      id: input.snapshotPlan.runId,
      cycleId: input.snapshotPlan.cycleId,
      revision: input.snapshotPlan.payrollRevision,
      obligationSnapshotPlanId: input.snapshotPlan.planId,
    }));
    expect(input.submitPayroll).toHaveBeenCalledTimes(1);
    const action = input.submitPayroll.mock.calls[0][1];
    expect(action.type).toBe("invoke");
    expect(BigInt(action.contract)).toBe(BigInt(sealAddress));
    expect(action.calldata[0]).toBe("0x0");
    expect(input.persistPendingSubmission).toHaveBeenCalledWith(expect.objectContaining({
      version: 4,
      authorizationMode: "staged_vnext",
      snapshotProofBundleId: expect.any(String),
    }));
    expect(result).toMatchObject({
      runId: input.snapshotPlan.runId,
      version: 4,
      authorizationMode: "staged_vnext",
      transactionHash: "0xfeed",
      verificationQueued: true,
    });
  });

  it("resumes the exact encrypted snapshot run after proof storage failed without creating another payroll", async () => {
    const mockClient = client();
    const input = await snapshotExecutionInput(mockClient);
    const authorizeFxRoot = vi.fn().mockResolvedValue(undefined);
    mockClient.storeEncryptedProofBundle.mockRejectedValueOnce(
      new PayoApiError("Proof is bound to a different PAYO seal.", "PROOF_SEAL_MISMATCH", 400),
    );

    await expect(executeProofBoundPayroll({
      ...input,
      authorizeFxRoot,
      autonomousAgent: {
        capabilityId: generateUuidV7(now.getTime() + 50),
        policyAccountAddress: "0x456",
      },
    })).rejects.toMatchObject({ code: "PROOF_SEAL_MISMATCH" });

    const persisted = mockClient.createPayrollRun.mock.calls[0][0];
    mockClient.getPayrollRun.mockResolvedValue({
      run: {
        id: persisted.id,
        organizationId: persisted.organizationId,
        state: "calculated" as const,
        agreementRoot: persisted.agreementRoot,
        manifestRoot: persisted.manifestRoot,
        policyRoot: persisted.policyRoot,
        fxRoot: persisted.fxRoot,
        runNullifier: persisted.runNullifier,
        obligationSnapshotPlanId: persisted.obligationSnapshotPlanId ?? null,
        transactionHash: null,
        envelope: persisted.envelope,
      },
    });
    mockClient.getPayrollFxCatalog.mockClear();
    mockClient.createPayrollRun.mockClear();
    mockClient.transitionPayrollRun.mockClear();

    await expect(executeProofBoundPayroll({
      ...input,
      authorizeFxRoot,
      autonomousAgent: {
        capabilityId: generateUuidV7(now.getTime() + 50),
        policyAccountAddress: "0x456",
      },
    })).resolves.toMatchObject({
      mode: "autonomous_bounded",
      runId: input.snapshotPlan.runId,
      activationState: "active",
    });

    expect(mockClient.getPayrollFxCatalog).not.toHaveBeenCalled();
    expect(authorizeFxRoot).toHaveBeenCalledTimes(1);
    expect(mockClient.createPayrollRun).not.toHaveBeenCalled();
    expect(mockClient.transitionPayrollRun).not.toHaveBeenCalled();
    expect(mockClient.storeEncryptedProofBundle).toHaveBeenCalledTimes(2);
    expect(mockClient.provisionDirectPrivacyAccount).toHaveBeenCalledOnce();
    expect(mockClient.stageDirectPrivacyRunWitness).toHaveBeenCalledOnce();
  });

  it("links the exact MCP execution before opening Ready for human approval", async () => {
    const mockClient = client();
    const input = await snapshotExecutionInput(mockClient);
    const capabilityId = generateUuidV7(now.getTime() + 30);
    const executionId = generateUuidV7(now.getTime() + 31);
    mockClient.linkAgentExecutionApproval.mockImplementationOnce((approval: {
      capabilityId: string;
      executionId: string;
      settlementId: string;
    }) => Promise.resolve({ execution: {
      ...approval,
      runId: input.snapshotPlan.runId,
      state: "approval_pending" as const,
      requiresApproval: true,
    } }));

    await executeProofBoundPayroll({
      ...input,
      humanAgentApproval: { capabilityId, executionId },
    });

    expect(mockClient.linkAgentExecutionApproval).toHaveBeenCalledWith({
      capabilityId,
      executionId,
      settlementId: expect.any(String),
    });
    expect(mockClient.linkAgentExecutionApproval.mock.invocationCallOrder[0]).toBeLessThan(
      input.submitPayroll.mock.invocationCallOrder[0],
    );
  });

  it("cancels both durable sides and never opens Ready when agent linking fails", async () => {
    const mockClient = client();
    const input = await snapshotExecutionInput(mockClient);
    const capabilityId = generateUuidV7(now.getTime() + 32);
    const executionId = generateUuidV7(now.getTime() + 33);
    mockClient.linkAgentExecutionApproval.mockRejectedValue(new Error("approval binding rejected"));

    await expect(executeProofBoundPayroll({
      ...input,
      humanAgentApproval: { capabilityId, executionId },
    })).rejects.toThrow("could not prepare approval and proof delivery");

    expect(input.submitPayroll).not.toHaveBeenCalled();
    expect(mockClient.cancelSettlementApproval).toHaveBeenCalledOnce();
    expect(mockClient.cancelAgentExecutionApproval).toHaveBeenCalledWith({ capabilityId, executionId });
  });

  it("fails closed without a Ready request when staged payroll authorization dies", async () => {
    const mockClient = client();
    const input = await snapshotExecutionInput(mockClient);
    mockClient.enqueuePayrollAuthorization.mockImplementationOnce(async ({ runId }: { runId: string }) => ({
      authorization: {
        ...(await mockClient.getPayrollAuthorization(runId)).authorization,
        state: "dead" as const,
        transactionHash: null,
        authorizedAt: null,
        lastErrorCode: "PROOF_REJECTED",
        lastErrorMessage: "Snapshot proof rejected.",
      },
    }));

    await expect(executeProofBoundPayroll(input)).rejects.toThrow(
      "Payroll proof authorization failed: Snapshot proof rejected.",
    );
    expect(input.submitPayroll).not.toHaveBeenCalled();
    expect(mockClient.createSettlementIntent).not.toHaveBeenCalled();
    expect(input.persistPendingSubmission).not.toHaveBeenCalled();
  });

  it("rejects an advanced payroll that omits its registered pre-payday snapshot", async () => {
    const mockClient = client();
    const input = await snapshotExecutionInput(mockClient);
    const { snapshotPlan, proveSnapshot, ...withoutSnapshot } = input;
    expect(snapshotPlan).toBeDefined();
    expect(proveSnapshot).toBeTypeOf("function");

    await expect(executeProofBoundPayroll(withoutSnapshot)).rejects.toThrow(
      /requires an exact registered pre-payday snapshot/i,
    );
    expect(input.prove).not.toHaveBeenCalled();
    expect(input.submitPayroll).not.toHaveBeenCalled();
    expect(mockClient.createPayrollRun).not.toHaveBeenCalled();
  });
});
