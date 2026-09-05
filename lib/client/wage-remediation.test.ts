import { describe, expect, it, vi } from "vitest";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  generateVaultPrincipal,
} from "@/lib/crypto/vault";
import { buildFxSnapshot } from "@/lib/domain/fx";
import { claimCapabilityCommitmentV2 } from "@/lib/domain/exception-protocol";
import { generateUuidV7 } from "@/lib/domain/records";
import type { WageRemediationSummary } from "@/lib/domain/wage-remediation";
import { workerClaimPrivateSchema, type WorkerClaimSummary } from "@/lib/domain/worker-claim";
import {
  buildObligationSnapshotPlanInputs,
  buildWageClaimV2Inputs,
} from "@/lib/proof/exception-input-builder";
import {
  buildPayrollAgreementSnapshot,
  PAYO_NET_INVOICE_POLICY,
  type PayrollIntegrityLineInput,
} from "@/lib/proof/input-builder";
import {
  minimumWageRemediationAmount,
  openAcceptedWorkerClaimV2,
  prepareStoredWageRemediationV2,
  prepareWageRemediationV2,
  proveAndAuthorizeWageRemediationV2,
} from "./wage-remediation";
import { executeAuthorizedRemediationPayment } from "./remediation-payment";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import { WAGE_REMEDIATION_VNEXT_CIRCUIT_SHA256 } from "@/lib/proof/protocol";
import { mockExceptionBookProof } from "@/lib/proof/vesting-transition-test-support";

const organizationId = "0198ddf0-9c00-7000-8000-0000000000b1";
const owner = generateVaultPrincipal("owner:wage-remediation-v7-test");
const claimant = generateVaultPrincipal("worker:wage-remediation-v7-test");
const outsider = generateVaultPrincipal("outsider:wage-remediation-v7-test");
const capabilitySecret = `0x${"91".repeat(32)}`;

function payrollLine(): PayrollIntegrityLineInput {
  return {
    agreementId: "remediation-usdc",
    recipientAddress: "0x456",
    recipientSalt: `0x${"11".repeat(32)}`,
    agreementSalt: `0x${"22".repeat(32)}`,
    lineSalt: `0x${"33".repeat(32)}`,
    token: "USDC",
    earningsAtomic: ["1000000"],
    deductionsAtomic: [],
    policyId: PAYO_NET_INVOICE_POLICY.id,
    scheduleCommitment: `0x${"44".repeat(32)}`,
    dueAt: 1_000n,
    validUntil: 2_000n,
    classification: { declared: 2, score: 2, employeeThreshold: 5 },
    fxFloorAtomic: "0",
    referenceCurrency: "USD",
  };
}

async function acceptedClaim() {
  const line = payrollLine();
  const payroll = await buildPayrollAgreementSnapshot({
    organizationSecret: `0x${"55".repeat(32)}`,
    cycleId: "wage-remediation-client",
    revision: 1,
    policies: [PAYO_NET_INVOICE_POLICY],
    lines: [line],
  });
  const snapshot = await buildObligationSnapshotPlanInputs({
    ownerAddress: "0xabc",
    payroll,
    claimCapabilityCommitments: {
      [line.agreementId]: claimCapabilityCommitmentV2(capabilitySecret),
    },
    graceEndsAt: 1_100n,
    claimEndsAt: 2_000n,
  });
  const claim = await buildWageClaimV2Inputs({
    chainId: "0x1",
    sealAddress: "0x12345",
    snapshot,
    agreementId: line.agreementId,
    claimCapabilitySecret: capabilitySecret,
    claimKind: "missing_obligation",
    evidence: { source: "unsettled_period" },
    validityStart: 1_150n,
    validityExpiry: 1_200n,
  });
  const now = new Date("2026-08-29T03:00:00.000Z");
  const privateClaim = workerClaimPrivateSchema.parse({
    format: "payo-worker-wage-claim-v2",
    schemaVersion: 2,
    id: generateUuidV7(now.getTime()),
    claimAccessGrantId: generateUuidV7(now.getTime() + 1),
    snapshotPlanId: generateUuidV7(now.getTime() + 2),
    organizationId,
    runId: generateUuidV7(now.getTime() + 3),
    agreementId: line.agreementId,
    claimKind: "missing_obligation",
    claimFact: claim.claimFact,
    claimFactCommitment: claim.claimFactCommitment,
    proofBundleId: generateUuidV7(now.getTime() + 4),
    claimantPrincipal: {
      principalId: claimant.principalId,
      publicKey: claimant.publicKey,
    },
    remediationWitness: {
      snapshot: snapshot.snapshot,
      recipientAddress: line.recipientAddress,
      recipientSalt: line.recipientSalt,
      agreement: claim.target.agreement,
      agreementMembership: claim.target.agreementMembership,
    },
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  });
  return { privateClaim, now };
}

function remediationFxSnapshot(input: {
  now: Date;
  priceAtomic: string;
}) {
  const observedAt = new Date(input.now.getTime() - 10_000).toISOString();
  return buildFxSnapshot({
    baseToken: "USDC",
    referenceCurrency: "USD",
    feedId: "pragma:USDC/USD:remediation",
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 300,
    minimumSources: 3,
    quotes: ["a", "b", "c"].map((source) => ({
      source: "pragma-usdc-" + source,
      priceAtomic: input.priceAtomic,
      observedAt,
    })),
    now: input.now,
  });
}

async function acceptedFxClaim() {
  const line: PayrollIntegrityLineInput = {
    ...payrollLine(),
    agreementId: "remediation-fx-usdc",
    fxFloorAtomic: "1500000",
  };
  const payroll = await buildPayrollAgreementSnapshot({
    organizationSecret: `0x${"56".repeat(32)}`,
    cycleId: "wage-remediation-fx-client",
    revision: 1,
    policies: [PAYO_NET_INVOICE_POLICY],
    lines: [line],
  });
  const snapshot = await buildObligationSnapshotPlanInputs({
    ownerAddress: "0xabc",
    payroll,
    claimCapabilityCommitments: {
      [line.agreementId]: claimCapabilityCommitmentV2(capabilitySecret),
    },
    graceEndsAt: 1_100n,
    claimEndsAt: 2_000n,
  });
  const statementFx = remediationFxSnapshot({
    now: new Date(1_150_000),
    priceAtomic: "600000",
  });
  const claim = await buildWageClaimV2Inputs({
    chainId: "0x1",
    sealAddress: "0x12345",
    snapshot,
    agreementId: line.agreementId,
    claimCapabilitySecret: capabilitySecret,
    claimKind: "below_committed_floor",
    evidence: {
      source: "employer_statement",
      observedAt: 1_150n,
      availabilityCommitment: `0x${"77".repeat(32)}`,
      target: {
        kind: "line",
        deductionsAtomic: [],
        lineSalt: `0x${"66".repeat(32)}`,
        classificationTreatment: 2,
        finalIncludedMask: 0,
        referenceValueAtomic: "600000",
      },
      fxSnapshots: [statementFx],
    },
    validityStart: 1_150n,
    validityExpiry: 1_200n,
  });
  const now = new Date("2026-08-29T03:00:00.000Z");
  const privateClaim = workerClaimPrivateSchema.parse({
    format: "payo-worker-wage-claim-v2",
    schemaVersion: 2,
    id: generateUuidV7(now.getTime() + 20),
    claimAccessGrantId: generateUuidV7(now.getTime() + 21),
    snapshotPlanId: generateUuidV7(now.getTime() + 22),
    organizationId,
    runId: generateUuidV7(now.getTime() + 23),
    agreementId: line.agreementId,
    claimKind: "below_committed_floor",
    claimFact: claim.claimFact,
    claimFactCommitment: claim.claimFactCommitment,
    proofBundleId: generateUuidV7(now.getTime() + 24),
    claimantPrincipal: {
      principalId: claimant.principalId,
      publicKey: claimant.publicKey,
    },
    remediationWitness: {
      snapshot: snapshot.snapshot,
      recipientAddress: line.recipientAddress,
      recipientSalt: line.recipientSalt,
      agreement: claim.target.agreement,
      agreementMembership: claim.target.agreementMembership,
    },
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  });
  return { privateClaim, now };
}

function preparedRemediationSummary(input: {
  prepared: Awaited<ReturnType<typeof prepareWageRemediationV2>>;
  now: Date;
}): WageRemediationSummary {
  const { prepared, now } = input;
  return {
    id: prepared.create.id,
    workerClaimId: prepared.create.workerClaimId,
    organizationId: prepared.create.organizationId,
    runId: prepared.create.runId,
    claimantPrincipalId: claimant.principalId,
    proofBundleId: prepared.create.proofBundleId,
    claimSubjectNullifier: prepared.create.claimSubjectNullifier,
    claimFactCommitment: prepared.create.claimFactCommitment,
    remediationSubjectNullifier: prepared.create.remediationSubjectNullifier,
    remediationFactCommitment: prepared.create.remediationFactCommitment,
    actionCommitment: prepared.create.actionCommitment,
    fxRoot: prepared.create.fxRoot,
    validityExpiresAt: new Date(
      Number(prepared.create.validityExpiry) * 1_000,
    ).toISOString(),
    state: "prepared",
    settlementId: null,
    authorizedAt: null,
    paymentConfirmedAt: null,
    reconciledAt: null,
    lastErrorCode: null,
    lastErrorMessage: null,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
    envelope: prepared.create.envelope,
  };
}

describe("durable Remediation v7 client binding", () => {
  it("binds one exact accepted claim, recipient, token and amount", async () => {
    const { privateClaim, now } = await acceptedClaim();
    const validityStart = BigInt(Math.floor(now.getTime() / 1_000));
    const prepared = await prepareWageRemediationV2({
      acceptedClaim: privateClaim,
      claimState: "accepted",
      organizationId,
      runId: privateClaim.runId,
      chainId: "0x1",
      sealAddress: "0x12345",
      amountAtomic: "1000000",
      token: "USDC",
      principal: owner,
      remediationSecret: `0x${"92".repeat(32)}`,
      actionSalt: `0x${"93".repeat(32)}`,
      validityStart,
      validityExpiry: validityStart + 1_800n,
      now,
    });
    expect(prepared.build.publicInputs).toMatchObject({
      proofVersion: "7",
      parentFactCommitmentHigh: expect.any(String),
      manifestRootHigh: expect.any(String),
    });
    expect(prepared.privateRecord).toMatchObject({
      claimFactCommitment: privateClaim.claimFactCommitment,
      token: "USDC",
      tokenDecimals: 6,
      amountAtomic: "1000000",
      referenceValueAtomic: "1000000",
    });
    expect(prepared.create.actionCommitment)
      .toBe(prepared.build.actionCommitment);
    expect(decryptVaultRecord(prepared.create.envelope, claimant))
      .toEqual(prepared.privateRecord);
    expect(decryptVaultRecord(prepared.create.envelope, owner))
      .toEqual(prepared.privateRecord);
    expect(() => decryptVaultRecord(prepared.create.envelope, outsider))
      .toThrow(/not authorized/i);
  });

  it("rejects a changed recipient and an underfunded remediation", async () => {
    const { privateClaim, now } = await acceptedClaim();
    const validityStart = BigInt(Math.floor(now.getTime() / 1_000));
    await expect(prepareWageRemediationV2({
      acceptedClaim: {
        ...privateClaim,
        remediationWitness: {
          ...privateClaim.remediationWitness,
          recipientAddress: "0x999",
        },
      },
      claimState: "accepted",
      organizationId,
      runId: privateClaim.runId,
      chainId: "0x1",
      sealAddress: "0x12345",
      amountAtomic: "1000000",
      token: "USDC",
      principal: owner,
      validityStart,
      validityExpiry: validityStart + 1_800n,
      now,
    })).rejects.toThrow(/recipient address/i);

    await expect(prepareWageRemediationV2({
      acceptedClaim: privateClaim,
      claimState: "accepted",
      organizationId,
      runId: privateClaim.runId,
      chainId: "0x1",
      sealAddress: "0x12345",
      amountAtomic: "999999",
      token: "USDC",
      principal: owner,
      validityStart,
      validityExpiry: validityStart + 1_800n,
      now,
    })).rejects.toThrow(/below/i);
  });

  it("opens only the accepted employer copy and proves Remediation v7 before relayer authorization", async () => {
    const { privateClaim, now } = await acceptedClaim();
    const claimEnvelope = encryptVaultRecord(privateClaim, {
      schemaVersion: 1,
      organizationId,
      recordType: "wage-claim-v2",
      recordId: privateClaim.id,
      revision: 1,
    }, [claimant, owner]);
    const summary: WorkerClaimSummary = {
      id: privateClaim.id,
      claimAccessGrantId: privateClaim.claimAccessGrantId,
      organizationId,
      runId: privateClaim.runId,
      claimantPrincipalId: claimant.principalId,
      proofBundleId: privateClaim.proofBundleId,
      claimSubjectNullifier: privateClaim.claimFact.claimSubjectNullifier,
      claimFactCommitment: privateClaim.claimFactCommitment,
      state: "accepted",
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      envelope: claimEnvelope,
    };
    expect(openAcceptedWorkerClaimV2({ claim: summary, principal: owner }))
      .toEqual(privateClaim);
    expect(() => openAcceptedWorkerClaimV2({ claim: summary, principal: claimant }))
      .toThrow(/employer PAYO identity/i);

    const start = BigInt(Math.floor(now.getTime() / 1_000));
    const prepared = await prepareWageRemediationV2({
      acceptedClaim: privateClaim,
      claimState: "accepted",
      organizationId,
      runId: privateClaim.runId,
      chainId: "0x1",
      sealAddress: "0x12345",
      amountAtomic: "1000000",
      token: "USDC",
      principal: owner,
      remediationSecret: `0x${"92".repeat(32)}`,
      actionSalt: `0x${"93".repeat(32)}`,
      validityStart: start,
      validityExpiry: start + 1_800n,
      now,
    });
    const proofCalldata = Array.from({ length: 35 }, (_, index) =>
      `0x${(index + 1).toString(16)}`);
    const proof = {
      version: 2 as const,
      type: "exception-proof-complete" as const,
      requestId: generateUuidV7(),
      profile: "wage_remediation_v7" as const,
      scheme: "ultra_keccak_zk_honk" as const,
      circuitSha256: WAGE_REMEDIATION_VNEXT_CIRCUIT_SHA256,
      provingTimeMs: 101,
      proof: {
        proof: Uint8Array.of(1, 2, 3),
        proofCalldata,
        calldataHash: hashProofCalldata(proofCalldata),
        publicInputs: prepared.build.publicInputs,
      },
      vestingBook: mockExceptionBookProof({
        source: prepared.build.publicInputs,
        entryKind: "remediation",
        bookSealAddress: "0x456",
        sourceSealAddress: "0x12345",
        ownerAddress: prepared.bookOwnerAddress,
        runNullifier: prepared.privateRecord.claimFact.runNullifier,
        payment: { token: prepared.privateRecord.token, amountAtomic: prepared.privateRecord.amountAtomic },
      }),
    };
    const order: string[] = [];
    const client = {
      createWageRemediation: vi.fn().mockImplementation(async (create) => {
        order.push("remediation");
        return { remediation: { id: create.id, proofBundleId: create.proofBundleId } };
      }),
      proveExceptionRemotely: vi.fn().mockImplementation(async () => {
        order.push("prove");
        return proof;
      }),
      storeEncryptedProofBundle: vi.fn().mockImplementation(async () => {
        order.push("proof");
        return { proofBundle: {} };
      }),
      enqueueExceptionAuthorization: vi.fn().mockImplementation(async () => {
        order.push("authorize");
        return { authorization: { state: "pending" } };
      }),
    };
    const result = await proveAndAuthorizeWageRemediationV2({
      client: client as never,
      prepared,
      principal: owner,
      proverBaseUrl: "https://prover.invalid",
      bookSealAddress: "0x456",
    });
    expect(order).toEqual(["remediation", "prove", "proof", "authorize"]);
    expect(result.proofBundle.proofVersion).toBe("7");
    expect(decryptVaultRecord(result.proofBundle.envelope, claimant))
      .toMatchObject({ profile: "wage_remediation_v7" });
    expect(client.enqueueExceptionAuthorization).toHaveBeenCalledWith({
      proofBundleId: prepared.create.proofBundleId,
      request: {
        proofCalldata,
        vestingBook: expect.objectContaining({ entryKind: "remediation" }),
      },
    });
  });

  it("creates the durable v7 payment intent before one exact Ready transfer", async () => {
    const { privateClaim, now } = await acceptedClaim();
    const start = BigInt(Math.floor(now.getTime() / 1_000));
    const prepared = await prepareWageRemediationV2({
      acceptedClaim: privateClaim,
      claimState: "accepted",
      organizationId,
      runId: privateClaim.runId,
      chainId: "0x1",
      sealAddress: "0x12345",
      amountAtomic: "1000000",
      token: "USDC",
      principal: owner,
      remediationSecret: `0x${"94".repeat(32)}`,
      actionSalt: `0x${"95".repeat(32)}`,
      validityStart: start,
      validityExpiry: start + 1_800n,
      now,
    });
    const proofCalldata = Array.from({ length: 35 }, (_, index) =>
      `0x${(index + 1).toString(16)}`);
    const proof = {
      version: 2 as const,
      type: "exception-proof-complete" as const,
      requestId: generateUuidV7(),
      profile: "wage_remediation_v7" as const,
      scheme: "ultra_keccak_zk_honk" as const,
      circuitSha256: WAGE_REMEDIATION_VNEXT_CIRCUIT_SHA256,
      provingTimeMs: 101,
      proof: {
        proof: Uint8Array.of(1),
        proofCalldata,
        calldataHash: hashProofCalldata(proofCalldata),
        publicInputs: prepared.build.publicInputs,
      },
      vestingBook: mockExceptionBookProof({
        source: prepared.build.publicInputs,
        entryKind: "remediation",
        bookSealAddress: "0x456",
        sourceSealAddress: "0x12345",
        ownerAddress: prepared.bookOwnerAddress,
        runNullifier: prepared.privateRecord.claimFact.runNullifier,
        payment: { token: prepared.privateRecord.token, amountAtomic: prepared.privateRecord.amountAtomic },
      }),
    };
    const proofResult = await proveAndAuthorizeWageRemediationV2({
      client: {
        createWageRemediation: vi.fn().mockResolvedValue({
          remediation: { id: prepared.create.id, proofBundleId: prepared.create.proofBundleId },
        }),
        proveExceptionRemotely: vi.fn().mockResolvedValue(proof),
        storeEncryptedProofBundle: vi.fn().mockResolvedValue({ proofBundle: {} }),
        enqueueExceptionAuthorization: vi.fn().mockResolvedValue({ authorization: { state: "complete" } }),
      } as never,
      prepared,
      principal: owner,
      proverBaseUrl: "https://prover.invalid",
      bookSealAddress: "0x456",
    });
    const summary = {
      id: prepared.create.id,
      workerClaimId: prepared.create.workerClaimId,
      organizationId,
      runId: prepared.create.runId,
      claimantPrincipalId: claimant.principalId,
      proofBundleId: prepared.create.proofBundleId,
      claimSubjectNullifier: prepared.create.claimSubjectNullifier,
      claimFactCommitment: prepared.create.claimFactCommitment,
      remediationSubjectNullifier: prepared.create.remediationSubjectNullifier,
      remediationFactCommitment: prepared.create.remediationFactCommitment,
      actionCommitment: prepared.create.actionCommitment,
      fxRoot: prepared.create.fxRoot,
      validityExpiresAt: new Date(Number(prepared.create.validityExpiry) * 1_000).toISOString(),
      state: "authorized" as const,
      settlementId: null,
      authorizedAt: now.toISOString(),
      paymentConfirmedAt: null,
      reconciledAt: null,
      lastErrorCode: null,
      lastErrorMessage: null,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      envelope: prepared.create.envelope,
    };
    const metadata = {
      schemaVersion: 2 as const,
      envelopeRecordId: proofResult.proofBundle.id,
      envelopeRevision: proofResult.proofBundle.revision,
      proofType: proofResult.proofBundle.proofType,
      subjectRecordId: proofResult.proofBundle.subjectRecordId,
      proofVersion: proofResult.proofBundle.proofVersion,
      circuitSha256: proofResult.proofBundle.circuitSha256,
      verificationKeySha256: proofResult.proofBundle.verificationKeySha256,
      publicInputsHash: proofResult.proofBundle.publicInputsHash,
      publicInputs: proofResult.proofBundle.publicInputs,
      proofCalldataHash: proofResult.proofBundle.proofCalldataHash,
    };
    const order: string[] = [];
    const client = {
      getWageRemediation: vi.fn().mockResolvedValue({ remediation: summary }),
      getEncryptedProofBundle: vi.fn().mockResolvedValue({ proofBundle: {
        id: proofResult.proofBundle.id,
        organizationId,
        runId: summary.runId,
        proofType: "wage_remediation",
        proofVersion: "7",
        subjectRecordId: summary.id,
        proofPackage: metadata,
        verificationState: "onchain_verified",
        verificationTransactionHash: "0xc700",
        createdAt: now.toISOString(),
        revision: 1,
        envelope: proofResult.proofBundle.envelope,
      } }),
      createSettlementIntent: vi.fn().mockImplementation(async (intent) => {
        order.push("intent");
        return { settlement: { id: intent.id } };
      }),
      getSettlement: vi.fn().mockResolvedValue({ settlement: {} }),
      recordSettlementSubmission: vi.fn().mockImplementation(async () => {
        order.push("record");
        return { settlement: {} };
      }),
      cancelSettlementApproval: vi.fn(),
    };
    const prepareSubmit = vi.fn().mockImplementation(async (_workflow, recipients, action) => {
      order.push("preflight");
      expect(recipients).toEqual([{ address: prepared.privateRecord.recipientAddress, amount: "1", token: "USDC" }]);
      expect(action).toHaveLength(2);
      expect(action[0].calldata).toHaveLength(7);
      expect(action[0].calldata[0]).toBe("0x3");
      expect(BigInt(action[1].contract)).toBe(0x456n);
      return async () => {
        order.push("wallet");
        return "0xfeed";
      };
    });
    const date = vi.spyOn(Date, "now").mockReturnValue(now.getTime());
    try {
      const rejectedIntent = vi.fn();
      await expect(executeAuthorizedRemediationPayment({
        client: {
          ...client,
          createSettlementIntent: rejectedIntent,
        } as never,
        remediation: summary,
        principal: owner,
        sealAddress: "0x12345",
        bookSealAddress: "0x456",
        chainId: "0x1",
        prepareSubmit: vi.fn().mockRejectedValue(new Error(
          "The shielded USDC treasury does not cover this wage remediation.",
        )),
      })).rejects.toThrow(/does not cover this wage remediation/i);
      expect(rejectedIntent).not.toHaveBeenCalled();
      expect(order).toEqual([]);

      await expect(executeAuthorizedRemediationPayment({
        client: client as never,
        remediation: summary,
        principal: owner,
        sealAddress: "0x12345",
        bookSealAddress: "0x456",
        chainId: "0x1",
        prepareSubmit,
      })).resolves.toMatchObject({ transactionHash: "0xfeed", replayed: false });
    } finally {
      date.mockRestore();
    }
    expect(order).toEqual(["preflight", "intent", "wallet", "record"]);
    expect(client.createSettlementIntent).toHaveBeenCalledOnce();
    expect(prepareSubmit).toHaveBeenCalledOnce();
  });

  it("resumes the exact FX-floor action and rejects altered durable evidence", async () => {
    const { privateClaim, now } = await acceptedFxClaim();
    expect(privateClaim.claimFact).toMatchObject({
      claimKind: "below_committed_floor",
      shortfallAtomic: "900000",
      shortfallUnit: "usd_6",
      obligationToken: "USDC",
      evidenceSource: "employer_statement",
    });
    expect(() => minimumWageRemediationAmount({
      acceptedClaim: privateClaim,
    })).toThrow(/fresh FX snapshot/i);

    const freshFx = remediationFxSnapshot({ now, priceAtomic: "600000" });
    const amountAtomic = minimumWageRemediationAmount({
      acceptedClaim: privateClaim,
      fxSnapshot: freshFx,
    });
    expect(amountAtomic).toBe("1500000");
    const validityStart = BigInt(Math.floor(now.getTime() / 1_000));
    const prepared = await prepareWageRemediationV2({
      acceptedClaim: privateClaim,
      claimState: "accepted",
      organizationId,
      runId: privateClaim.runId,
      chainId: "0x1",
      sealAddress: "0x12345",
      amountAtomic,
      token: "USDC",
      fxSnapshots: [freshFx],
      selectedFxIndex: 0,
      principal: owner,
      remediationSecret: `0x${"96".repeat(32)}`,
      actionSalt: `0x${"97".repeat(32)}`,
      validityStart,
      validityExpiry: validityStart + 1_800n,
      now,
    });
    const summary = preparedRemediationSummary({ prepared, now });
    const resumed = await prepareStoredWageRemediationV2({
      remediation: summary,
      acceptedClaim: privateClaim,
      chainId: "0x1",
      sealAddress: "0x12345",
      principal: owner,
      now,
    });
    expect(resumed.create).toEqual(prepared.create);
    expect(resumed.privateRecord).toEqual(prepared.privateRecord);
    expect(resumed.build).toMatchObject({
      actionCommitment: prepared.build.actionCommitment,
      remediationFactCommitment: prepared.build.remediationFactCommitment,
      fxRoot: prepared.build.fxRoot,
      referenceValueAtomic: "900000",
    });

    await expect(prepareStoredWageRemediationV2({
      remediation: {
        ...summary,
        actionCommitment: `0x${"aa".repeat(32)}`,
      },
      acceptedClaim: privateClaim,
      chainId: "0x1",
      sealAddress: "0x12345",
      principal: owner,
      now,
    })).rejects.toThrow(/durable bindings/i);

    const alteredFx = remediationFxSnapshot({ now, priceAtomic: "700000" });
    const alteredPrivate = {
      ...prepared.privateRecord,
      fxEvidence: { snapshots: [alteredFx], selectedFxIndex: 0 },
    };
    const alteredEnvelope = encryptVaultRecord(alteredPrivate, {
      schemaVersion: 1,
      organizationId,
      recordType: "wage-remediation-v2",
      recordId: prepared.create.id,
      revision: 1,
    }, [claimant, owner]);
    await expect(prepareStoredWageRemediationV2({
      remediation: { ...summary, envelope: alteredEnvelope },
      acceptedClaim: privateClaim,
      chainId: "0x1",
      sealAddress: "0x12345",
      principal: owner,
      now,
    })).rejects.toThrow(/immutable private action/i);

    await expect(prepareStoredWageRemediationV2({
      remediation: summary,
      acceptedClaim: privateClaim,
      chainId: "0x1",
      sealAddress: "0x12345",
      principal: owner,
      now: new Date(
        (Number(prepared.create.validityExpiry) - 119) * 1_000,
      ),
    })).rejects.toThrow(/proof window expired/i);
  });
});
