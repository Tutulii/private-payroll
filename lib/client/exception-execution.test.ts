import { describe, expect, it, vi } from "vitest";
import { encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { buildFxSnapshot } from "@/lib/domain/fx";
import {
  WAGE_CLAIM_CIRCUIT_SHA256,
  WAGE_REMEDIATION_CIRCUIT_SHA256,
  type ProofWorkerSuccess,
} from "@/lib/proof/protocol";
import {
  buildPayrollIntegrityInputsFromSerialized,
  PAYO_NET_INVOICE_POLICY,
  serializePayrollIntegrityBuildRequest,
} from "@/lib/proof/input-builder";
import { buildWageClaimInputs, buildWageRemediationInputs } from "@/lib/proof/wage-claim-input";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import type { PayoClient } from "./payo-client";
import {
  executeProofBoundWageClaim,
  executeProofBoundWageRemediation,
  resumeProofBoundWageClaim,
} from "./exception-execution";
import { prepareEncryptedPayrollIntegrityBundle } from "./proof-bundle";

const organizationId = "0198f300-0000-7000-8000-000000000001";
const runId = "0198f300-0000-7000-8000-000000000002";
const agreementId = "0198f300-0000-7000-8000-000000000003";
const claimId = "0198f300-0000-7000-8000-000000000004";
const now = new Date("2026-08-26T04:00:00.000Z");
const nowUnix = BigInt(Math.floor(now.getTime() / 1_000));

function sourceRequest() {
  return serializePayrollIntegrityBuildRequest({
    chainId: "0x1",
    sealAddress: "0x12345",
    organizationSecret: `0x${"31".repeat(32)}`,
    cycleId: "claim-execution-source",
    revision: 1,
    validityStart: nowUnix - 3_600n,
    validityExpiry: nowUnix - 3_000n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: [buildFxSnapshot({
      baseToken: "USDC",
      referenceCurrency: "USD",
      quoteDecimals: 6,
      haircutBps: 0,
      maximumAgeSeconds: 300,
      minimumSources: 3,
      aggregatedSourceCount: 5,
      quotes: [{ source: "pragma-usdc", priceAtomic: "1000000", observedAt: now.toISOString() }],
      now,
    })],
    lines: [{
      agreementId,
      recipientAddress: "0x456",
      recipientSalt: `0x${"32".repeat(32)}`,
      agreementSalt: `0x${"33".repeat(32)}`,
      lineSalt: `0x${"34".repeat(32)}`,
      token: "USDC",
      earningsAtomic: ["500"],
      deductionsAtomic: [],
      policyId: PAYO_NET_INVOICE_POLICY.id,
      scheduleCommitment: `0x${"35".repeat(32)}`,
      dueAt: nowUnix - 86_400n,
      validUntil: nowUnix + 86_400n,
      classification: { declared: 2, score: 2, employeeThreshold: 5 },
      fxFloorAtomic: "0",
      referenceCurrency: "USD",
    }],
  });
}

function payrollProofRecoveryClient(principal: ReturnType<typeof generateVaultPrincipal>) {
  const proofBundleId = "0198f300-0000-7000-8000-000000000009";
  const settlementId = "0198f300-0000-7000-8000-000000000010";
  const envelope = encryptVaultRecord(
    {
      shards: [
        { shardIndex: 0, proofCalldata: ["0x1"], publicInputs: { validityExpiry: String(Math.floor(Date.now() / 1_000) + 3_600) } },
        { shardIndex: 1, proofCalldata: ["0x2"], publicInputs: { validityExpiry: String(Math.floor(Date.now() / 1_000) + 3_600) } },
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
  );
  return {
    payrollRecoveryEnvelope: envelope,
    getSealedPayrollRecovery: vi.fn().mockResolvedValue({
      recovery: {
        recoveryKind: "verification",
        runId,
        proofBundleId,
        settlementId,
        transactionHash: "0xabc",
        blockNumber: "1",
      },
    }),
    getEncryptedRecord: vi.fn().mockResolvedValue({ record: { envelope, revision: 1 } }),
    enqueueProofVerification: vi.fn().mockResolvedValue({ proofVerification: { state: "complete" } }),
    getProofVerification: vi.fn().mockResolvedValue({ proofVerification: { state: "complete" } }),
  };
}

describe("proof-bound wage-claim execution", () => {
  it("fails closed when an expired payday FX root cannot be renewed", async () => {
    const principal = generateVaultPrincipal("worker:expired-claim-test");
    const buildInput = sourceRequest();
    const payroll = await buildPayrollIntegrityInputsFromSerialized(buildInput);
    const runEnvelope = encryptVaultRecord(
      { claimProofSource: { buildInput } },
      {
        schemaVersion: 1,
        organizationId,
        recordType: "payroll-run",
        recordId: runId,
        revision: 1,
      },
      [principal],
    );
    const prove = vi.fn();
    const client = {
      ...payrollProofRecoveryClient(principal),
      getPayrollRun: vi.fn().mockResolvedValue({
        run: {
          id: runId,
          organizationId,
          state: "confirmed",
          agreementRoot: payroll.agreementRoot,
          manifestRoot: payroll.manifestRoot,
          policyRoot: payroll.policyRoot,
          fxRoot: payroll.fxRoot,
          runNullifier: payroll.runNullifier,
          envelope: runEnvelope,
        },
      }),
      checkDeploymentReadiness: vi.fn().mockResolvedValue({
        readiness: {
          ready: false,
          checks: [{ code: "fx_root", ready: false, message: "FX root is inactive." }],
        },
      }),
      renewHistoricalFxRoot: vi.fn().mockResolvedValue({ transactionHash: "0xabc" }),
    } as unknown as PayoClient;

    await expect(executeProofBoundWageClaim({
      client,
      organizationId,
      principal,
      chainId: "0x1",
      sealAddress: "0x12345",
      claim: {
        schemaVersion: 1,
        id: claimId,
        organizationId,
        revision: 1,
        createdAt: now.toISOString(),
        updatedAt: now.toISOString(),
        agreementId,
        runId,
        claimSalt: `0x${"36".repeat(32)}`,
        claimKind: "missing_obligation",
        state: "draft",
      },
      submitException: vi.fn(),
      prove,
      now: () => now,
    })).rejects.toThrow("PAYO exception deployment is not ready");
    expect(client.renewHistoricalFxRoot).toHaveBeenCalledWith({
      organizationId,
      runId,
      workflowType: "wage_claim",
    });
    expect(prove).not.toHaveBeenCalled();
  });

  it("proves, encrypts, seals, records, and queues an invoke-only claim", async () => {
    const principal = generateVaultPrincipal("worker:claim-test");
    const buildInput = sourceRequest();
    const payroll = await buildPayrollIntegrityInputsFromSerialized(buildInput);
    const claimSalt = `0x${"36".repeat(32)}` as const;
    const claimInput = await buildWageClaimInputs({
      payroll,
      agreementId,
      claimKind: "missing_obligation",
      claimSalt,
      validityStart: nowUnix - 30n,
      validityExpiry: nowUnix + 3_570n,
    });
    const proofCalldata = ["0x1", "0x2", "0x3"];
    const proof: ProofWorkerSuccess = {
      version: 1,
      type: "proof-complete",
      requestId: "claim-proof-test",
      scheme: "ultra_keccak_zk_honk",
      circuitSha256: WAGE_CLAIM_CIRCUIT_SHA256,
      provingTimeMs: 100,
      shards: [0, 1].map((shardIndex) => ({
        shardIndex: shardIndex as 0 | 1,
        proof: new Uint8Array([1, shardIndex + 1]),
        proofCalldata,
        calldataHash: hashProofCalldata(proofCalldata),
        publicInputs: claimInput.publicInputs[shardIndex],
      })) as ProofWorkerSuccess["shards"],
    };
    const runEnvelope = encryptVaultRecord(
      { claimProofSource: { buildInput } },
      {
        schemaVersion: 1,
        organizationId,
        recordType: "payroll-run",
        recordId: runId,
        revision: 1,
      },
      [principal],
    );
    const storeEncryptedRecord = vi.fn().mockResolvedValue({ record: {} });
    const createSettlementIntent = vi.fn().mockResolvedValue({ settlement: { id: "stored" } });
    const recordSettlementSubmission = vi.fn().mockResolvedValue({ settlement: {} });
    const enqueueProofVerification = vi.fn().mockResolvedValue({ job: {} });
    const client = {
      ...payrollProofRecoveryClient(principal),
      getPayrollRun: vi.fn().mockResolvedValue({
        run: {
          id: runId,
          organizationId,
          state: "confirmed",
          agreementRoot: payroll.agreementRoot,
          manifestRoot: payroll.manifestRoot,
          policyRoot: payroll.policyRoot,
          fxRoot: payroll.fxRoot,
          runNullifier: payroll.runNullifier,
          envelope: runEnvelope,
        },
      }),
      checkDeploymentReadiness: vi.fn().mockResolvedValue({ readiness: { ready: true, checks: [] } }),
      storeEncryptedProofBundle: vi.fn().mockResolvedValue({ proofBundle: {} }),
      storeEncryptedRecord,
      createSettlementIntent,
      recordSettlementSubmission,
      enqueueProofVerification,
    } as unknown as PayoClient;
    const submitException = vi.fn().mockImplementation(async (workflow, recipients, action) => {
      expect(workflow).toBe("wage_claim");
      expect(recipients).toEqual([]);
      expect(BigInt(action.calldata[0])).toBe(2n);
      return "0xc1a1";
    });
    const pending = vi.fn();

    const result = await executeProofBoundWageClaim({
      client,
      organizationId,
      principal,
      chainId: "0x1",
      sealAddress: "0x12345",
      claim: {
        schemaVersion: 1,
        id: claimId,
        organizationId,
        revision: 1,
        createdAt: now.toISOString(),
        updatedAt: now.toISOString(),
        agreementId,
        runId,
        claimSalt,
        claimKind: "missing_obligation",
        state: "draft",
      },
      submitException,
      persistPendingSubmission: pending,
      prove: vi.fn().mockResolvedValue(proof),
      now: () => now,
    });

    expect(result).toMatchObject({ workflowType: "wage_claim", transactionHash: "0xc1a1", verificationQueued: true });
    expect(createSettlementIntent).toHaveBeenCalledWith(expect.objectContaining({
      workflowType: "wage_claim",
      subjectRecordId: claimId,
    }));
    expect(recordSettlementSubmission).toHaveBeenCalledWith(result.settlementId, "0xc1a1");
    expect(enqueueProofVerification).toHaveBeenCalledWith(expect.objectContaining({ proofBundleId: result.proofBundleId }));
    expect(storeEncryptedRecord).toHaveBeenCalledTimes(2);
    expect(pending).toHaveBeenLastCalledWith(null);
  });

  it("renews the payday root and atomically refreshes an expired unsigned claim proof", async () => {
    const principal = generateVaultPrincipal("worker:claim-resume-refresh");
    const buildInput = sourceRequest();
    const payroll = await buildPayrollIntegrityInputsFromSerialized(buildInput);
    const claimSalt = `0x${"51".repeat(32)}` as const;
    const oldClaimInput = await buildWageClaimInputs({
      payroll,
      agreementId,
      claimKind: "missing_obligation",
      claimSalt,
      validityStart: nowUnix - 4_000n,
      validityExpiry: nowUnix - 1_000n,
    });
    const refreshedClaimInput = await buildWageClaimInputs({
      payroll,
      agreementId,
      claimKind: "missing_obligation",
      claimSalt,
      validityStart: nowUnix - 30n,
      validityExpiry: nowUnix + 3_570n,
    });
    const proof = (claimInput: typeof oldClaimInput, calldata: string[]): ProofWorkerSuccess => ({
      version: 1,
      type: "proof-complete",
      requestId: "claim-refresh-proof",
      scheme: "ultra_keccak_zk_honk",
      circuitSha256: WAGE_CLAIM_CIRCUIT_SHA256,
      provingTimeMs: 100,
      shards: [0, 1].map((shardIndex) => ({
        shardIndex: shardIndex as 0 | 1,
        proof: new Uint8Array([3, shardIndex + 1]),
        proofCalldata: calldata,
        calldataHash: hashProofCalldata(calldata),
        publicInputs: claimInput.publicInputs[shardIndex],
      })) as ProofWorkerSuccess["shards"],
    });
    const oldProof = proof(oldClaimInput, ["0x11", "0x12", "0x13"]);
    const refreshedProof = proof(refreshedClaimInput, ["0x21", "0x22", "0x23"]);
    const proofBundleId = "0198f300-0000-7000-8000-000000000005";
    const settlementId = "0198f300-0000-7000-8000-000000000006";
    const oldBundle = prepareEncryptedPayrollIntegrityBundle({
      id: proofBundleId,
      organizationId,
      runId,
      revision: 1,
      proof: oldProof,
      subjectRecordId: claimId,
      principals: [principal],
    });
    const runEnvelope = encryptVaultRecord(
      { claimProofSource: { buildInput } },
      {
        schemaVersion: 1,
        organizationId,
        recordType: "payroll-run",
        recordId: runId,
        revision: 1,
      },
      [principal],
    );
    const readiness = vi.fn()
      .mockResolvedValueOnce({
        readiness: { ready: false, checks: [{ code: "fx_root", ready: false, message: "expired" }] },
      })
      .mockResolvedValue({ readiness: { ready: true, checks: [] } });
    const storeEncryptedProofBundle = vi.fn().mockResolvedValue({ proofBundle: {} });
    const renewHistoricalFxRoot = vi.fn().mockResolvedValue({ transactionHash: "0xf001" });
    const payrollRecovery = payrollProofRecoveryClient(principal);
    const client = {
      getSealedPayrollRecovery: payrollRecovery.getSealedPayrollRecovery,
      getProofVerification: payrollRecovery.getProofVerification,
      getSettlement: vi.fn().mockResolvedValue({
        settlement: {
          organizationId,
          runId,
          workflowType: "wage_claim",
          subjectRecordId: claimId,
          tokenTotalsCommitment: `0x${"52".repeat(32)}`,
          transactionHash: null,
          state: "approval_pending",
        },
      }),
      getEncryptedRecord: vi.fn()
        .mockResolvedValueOnce({ record: { envelope: oldBundle.envelope, revision: 1 } })
        .mockResolvedValueOnce({ record: { envelope: payrollRecovery.payrollRecoveryEnvelope, revision: 1 } }),
      getPayrollRun: vi.fn().mockResolvedValue({
        run: {
          id: runId,
          organizationId,
          state: "confirmed",
          agreementRoot: payroll.agreementRoot,
          manifestRoot: payroll.manifestRoot,
          policyRoot: payroll.policyRoot,
          fxRoot: payroll.fxRoot,
          runNullifier: payroll.runNullifier,
          envelope: runEnvelope,
        },
      }),
      checkDeploymentReadiness: readiness,
      renewHistoricalFxRoot,
      storeEncryptedProofBundle,
      recordSettlementSubmission: vi.fn().mockResolvedValue({ settlement: {} }),
      enqueueProofVerification: vi.fn().mockResolvedValue({ proofVerification: {} }),
      storeEncryptedRecord: vi.fn().mockResolvedValue({ record: {} }),
    } as unknown as PayoClient;
    const pending = {
      version: 1 as const,
      workflowType: "wage_claim" as const,
      organizationId,
      runId,
      subjectRecordId: claimId,
      proofBundleId,
      settlementId,
      walletRequestId: "0198f300-0000-7000-8000-000000000007",
      idempotencyKey: "claim-refresh-approval",
      tokenTotalsCommitment: `0x${"52".repeat(32)}` as const,
      proofShards: [oldProof.shards[0].proofCalldata, oldProof.shards[1].proofCalldata] as [string[], string[]],
      createdAt: now.toISOString(),
    };
    const persist = vi.fn();
    const result = await resumeProofBoundWageClaim({
      client,
      organizationId,
      principal,
      chainId: "0x1",
      sealAddress: "0x12345",
      claim: {
        schemaVersion: 1,
        id: claimId,
        organizationId,
        revision: 2,
        createdAt: now.toISOString(),
        updatedAt: now.toISOString(),
        agreementId,
        runId,
        claimSalt,
        claimKind: "missing_obligation",
        claimNullifier: oldClaimInput.claimNullifier,
        shortfallAtomic: oldClaimInput.shortfallAtomic,
        token: oldClaimInput.token,
        proofBundleId,
        state: "proven",
      },
      pendingSubmission: pending,
      submitException: vi.fn().mockResolvedValue("0xc1a2"),
      persistPendingSubmission: persist,
      prove: vi.fn().mockResolvedValue(refreshedProof),
      now: () => now,
    });
    expect(renewHistoricalFxRoot).toHaveBeenCalledWith({
      organizationId,
      runId,
      workflowType: "wage_claim",
    });
    expect(storeEncryptedProofBundle).toHaveBeenCalledWith(expect.objectContaining({
      id: proofBundleId,
      revision: 2,
    }));
    expect(result).toMatchObject({ transactionHash: "0xc1a2" });
    expect(result.proofShards[0]).toEqual(refreshedProof.shards[0].proofCalldata);
    expect(persist).toHaveBeenLastCalledWith(null);
  });

  it("binds one private remediation transfer to the accepted claim and v4 proof", async () => {
    const principal = generateVaultPrincipal("employer:remediation-test");
    const buildInput = sourceRequest();
    const payroll = await buildPayrollIntegrityInputsFromSerialized(buildInput);
    const claimSalt = `0x${"41".repeat(32)}` as const;
    const remediationSalt = `0x${"42".repeat(32)}` as const;
    const claimInput = await buildWageClaimInputs({
      payroll,
      agreementId,
      claimKind: "missing_obligation",
      claimSalt,
      validityStart: nowUnix - 30n,
      validityExpiry: nowUnix + 3_570n,
    });
    const remediationInput = await buildWageRemediationInputs({
      claim: claimInput,
      amountAtomic: claimInput.shortfallAtomic,
      token: claimInput.token,
      remediationSalt,
      validityStart: nowUnix - 30n,
      validityExpiry: nowUnix + 3_570n,
    });
    const proofCalldata = ["0x4", "0x5", "0x6"];
    const proof: ProofWorkerSuccess = {
      version: 1,
      type: "proof-complete",
      requestId: "remediation-proof-test",
      scheme: "ultra_keccak_zk_honk",
      circuitSha256: WAGE_REMEDIATION_CIRCUIT_SHA256,
      provingTimeMs: 110,
      shards: [0, 1].map((shardIndex) => ({
        shardIndex: shardIndex as 0 | 1,
        proof: new Uint8Array([2, shardIndex + 1]),
        proofCalldata,
        calldataHash: hashProofCalldata(proofCalldata),
        publicInputs: remediationInput.publicInputs[shardIndex],
      })) as ProofWorkerSuccess["shards"],
    };
    const runEnvelope = encryptVaultRecord(
      { claimProofSource: { buildInput } },
      {
        schemaVersion: 1,
        organizationId,
        recordType: "payroll-run",
        recordId: runId,
        revision: 1,
      },
      [principal],
    );
    const storeEncryptedRecord = vi.fn().mockResolvedValue({ record: {} });
    const createSettlementIntent = vi.fn().mockResolvedValue({ settlement: { id: "stored" } });
    const client = {
      getPayrollRun: vi.fn().mockResolvedValue({
        run: {
          id: runId,
          organizationId,
          state: "disputed",
          agreementRoot: payroll.agreementRoot,
          manifestRoot: payroll.manifestRoot,
          policyRoot: payroll.policyRoot,
          fxRoot: payroll.fxRoot,
          runNullifier: payroll.runNullifier,
          envelope: runEnvelope,
        },
      }),
      checkDeploymentReadiness: vi.fn().mockResolvedValue({ readiness: { ready: true, checks: [] } }),
      storeEncryptedProofBundle: vi.fn().mockResolvedValue({ proofBundle: {} }),
      storeEncryptedRecord,
      createSettlementIntent,
      recordSettlementSubmission: vi.fn().mockResolvedValue({ settlement: {} }),
      enqueueProofVerification: vi.fn().mockResolvedValue({ job: {} }),
    } as unknown as PayoClient;
    const claim = {
      schemaVersion: 1 as const,
      id: claimId,
      organizationId,
      revision: 3,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      agreementId,
      runId,
      claimNullifier: claimInput.claimNullifier,
      claimSalt,
      claimKind: "missing_obligation" as const,
      shortfallAtomic: claimInput.shortfallAtomic,
      token: claimInput.token,
      proofBundleId: "0198f300-0000-7000-8000-000000000005",
      settlementId: "0198f300-0000-7000-8000-000000000006",
      state: "submitted" as const,
    };
    const remediationId = "0198f300-0000-7000-8000-000000000007";
    const submitException = vi.fn().mockImplementation(async (workflow, recipients, action) => {
      expect(workflow).toBe("wage_remediation");
      expect(recipients).toEqual([{ address: "0x456", amount: "0.0005", token: "USDC" }]);
      expect(BigInt(action.calldata[0])).toBe(3n);
      return "0xc2a2";
    });

    const result = await executeProofBoundWageRemediation({
      client,
      organizationId,
      principal,
      chainId: "0x1",
      sealAddress: "0x12345",
      claim,
      remediation: {
        schemaVersion: 1,
        id: remediationId,
        organizationId,
        revision: 1,
        createdAt: now.toISOString(),
        updatedAt: now.toISOString(),
        claimId,
        runId,
        agreementId,
        claimNullifier: claimInput.claimNullifier,
        amountAtomic: claimInput.shortfallAtomic,
        token: claimInput.token,
        remediationSalt,
        state: "draft",
      },
      submitException,
      prove: vi.fn().mockResolvedValue(proof),
      now: () => now,
    });

    expect(result).toMatchObject({ workflowType: "wage_remediation", transactionHash: "0xc2a2" });
    expect(createSettlementIntent).toHaveBeenCalledWith(expect.objectContaining({
      workflowType: "wage_remediation",
      subjectRecordId: remediationId,
    }));
    expect(storeEncryptedRecord).toHaveBeenCalledTimes(2);
  });
});
