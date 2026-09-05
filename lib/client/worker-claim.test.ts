import { describe, expect, it, vi } from "vitest";
import { referenceClassificationAnswers } from "@/lib/domain/classification";
import { claimCapabilityCommitmentV2 } from "@/lib/domain/exception-protocol";
import { deriveClaimCapabilitySecret } from "@/lib/crypto/claim-capability";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  generateVaultPrincipal,
} from "@/lib/crypto/vault";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
  type ExceptionProofWorkerSuccess,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import { mockExceptionBookProof } from "@/lib/proof/vesting-transition-test-support";
import { buildAdvancedPaymentPlanDraft } from "./advanced-agreement-draft";
import { storeEncryptedAdvancedAgreement } from "./agreement-directory";
import { prepareObligationSnapshotPlan } from "./obligation-snapshot-plan";
import { prepareEncryptedPayee } from "./payee-directory";
import {
  prepareStoredWorkerClaimV2,
  prepareWorkerClaimV2,
  proveAndSubmitWorkerClaimV2,
} from "./worker-claim";

const organizationId = "0198ddf0-9c00-7000-8000-000000000031";
const preparedAt = new Date("2026-08-24T12:00:00.000Z");
const claimAt = new Date("2026-08-24T12:26:00.000Z");
const employer = generateVaultPrincipal("employer:worker-claim-test");
const worker = generateVaultPrincipal("worker:worker-claim-test");
const organizationSecret = `0x${"44".repeat(32)}`;

async function fixture() {
  const capability = claimCapabilityCommitmentV2(
    deriveClaimCapabilitySecret(worker),
  );
  const payee = prepareEncryptedPayee({
    organizationId,
    displayName: "Protected worker",
    principalKind: "human",
    recipientAddress: "0x456",
    tokenPreference: "USDC",
    jurisdictionCode: "US",
    claimIdentity: {
      principalId: worker.principalId,
      publicKey: worker.publicKey,
      claimCapabilityCommitment: capability,
    },
    principal: employer,
    now: preparedAt,
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
      nextDueAt: "2026-08-24T12:10:00.000Z",
    }),
    fixedAmount: "2",
    policyId: "payo-net-invoice-no-withholding-v1",
    policyVersion: 1,
    principal: employer,
    now: preparedAt,
  });
  const prepared = await prepareObligationSnapshotPlan({
    organizationId,
    organizationSecret,
    ownerAddress: "0xabc",
    obligations: [{ agreement, payee }],
    principal: employer,
    now: preparedAt,
  });
  const seconds = (value: string) =>
    new Date(Number(value) * 1_000).toISOString();
  const grant = {
    id: prepared.claimAccess[0]!.record.grantId,
    claimantPrincipalId: worker.principalId,
    revokedAt: null,
    plan: {
      id: prepared.create.id,
      runId: prepared.create.runId,
      organizationId,
      cycleId: prepared.create.cycleId,
      revision: prepared.create.payrollRevision,
      ownerAddress: prepared.create.ownerAddress,
      agreementRoot: prepared.create.snapshot.baseAgreementRoot,
      claimRoot: prepared.create.snapshot.obligationRoot,
      policyRoot: prepared.create.snapshot.policyRoot,
      runNullifier: prepared.create.snapshot.runNullifier,
      snapshotFact: prepared.create.snapshotCommitment,
      dueAt: seconds(prepared.create.snapshot.dueAt),
      graceEndsAt: seconds(prepared.create.snapshot.graceEndsAt),
      claimEndsAt: seconds(prepared.create.snapshot.claimEndsAt),
      state: "registered" as const,
      registrationTransactionHash: "0x123",
      registeredAt: preparedAt.toISOString(),
      consumedAt: null,
      createdAt: preparedAt.toISOString(),
      updatedAt: preparedAt.toISOString(),
    },
    envelope: prepared.claimAccess[0]!.envelope,
  };
  return { prepared, grant };
}

function proofFor(
  prepared: Awaited<ReturnType<typeof prepareWorkerClaimV2>>,
): ExceptionProofWorkerSuccess {
  const proofCalldata = Array.from({ length: 35 }, (_, index) =>
    `0x${(index + 1).toString(16)}`,
  );
  return {
    version: 2,
    type: "exception-proof-complete",
    requestId: generateUuidV7(),
    profile: "wage_claim_v6",
    scheme: "ultra_keccak_zk_honk",
    circuitSha256: WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
    provingTimeMs: 123,
    proof: {
      proof: Uint8Array.of(1, 2, 3),
      proofCalldata,
      calldataHash: hashProofCalldata(proofCalldata),
      publicInputs: prepared.build.publicInputs,
    },
    vestingBook: mockExceptionBookProof({
      source: prepared.build.publicInputs,
      entryKind: "claim",
      bookSealAddress: "0x456",
      sourceSealAddress: "0x123",
      ownerAddress: prepared.opened.access.snapshot.ownerAddress,
      runNullifier: prepared.build.claimFact.runNullifier,
    }),
  };
}

describe("worker Claim v6 product binding", () => {
  it("opens only the worker packet and binds a missing claim to exact remediation data", async () => {
    const { grant } = await fixture();
    const result = await prepareWorkerClaimV2({
      grant,
      claimKind: "missing_obligation",
      chainId: "0x1",
      sealAddress: "0x123",
      principal: worker,
      now: claimAt,
    });

    expect(result.build.publicInputs.proofVersion).toBe("6");
    expect(result.evidence).toEqual({ source: "unsettled_period" });
    expect(result.privateRecord).toMatchObject({
      claimKind: "missing_obligation",
      claimFactCommitment: result.build.claimFactCommitment,
      remediationWitness: {
        recipientAddress: result.opened.access.witness.calculated.recipientAddress,
        recipientSalt: result.opened.access.recipientSalt,
      },
    });
    expect(decryptVaultRecord(result.create.envelope, worker))
      .toEqual(result.privateRecord);
    expect(decryptVaultRecord(result.create.envelope, employer))
      .toEqual(result.privateRecord);
    expect(() => decryptVaultRecord(
      result.create.envelope,
      generateVaultPrincipal("outsider:worker-claim-test"),
    )).toThrow(/not authorized/i);
    expect(new Set(result.create.envelope.wrappedKeys.map(({ principalId }) => principalId)))
      .toEqual(new Set([worker.principalId, employer.principalId]));
  });


  it("resumes a persisted pre-proof claim without changing its encrypted identity", async () => {
    const { grant } = await fixture();
    const prepared = await prepareWorkerClaimV2({
      grant,
      claimKind: "missing_obligation",
      chainId: "0x1",
      sealAddress: "0x123",
      principal: worker,
      now: claimAt,
    });
    const summary = {
      id: prepared.create.id,
      claimAccessGrantId: prepared.create.claimAccessGrantId,
      organizationId: prepared.create.organizationId,
      runId: prepared.create.runId,
      claimantPrincipalId: worker.principalId,
      proofBundleId: prepared.create.proofBundleId,
      claimSubjectNullifier: prepared.create.claimSubjectNullifier,
      claimFactCommitment: prepared.create.claimFactCommitment,
      state: "prepared" as const,
      createdAt: claimAt.toISOString(),
      updatedAt: claimAt.toISOString(),
      envelope: prepared.create.envelope,
    };
    const resumed = await prepareStoredWorkerClaimV2({
      claim: summary,
      grant,
      chainId: "0x1",
      sealAddress: "0x123",
      principal: worker,
      now: claimAt,
    });
    expect(resumed.create).toEqual(prepared.create);
    expect(resumed.privateRecord).toEqual(prepared.privateRecord);
    expect(resumed.build.claimFactCommitment).toBe(summary.claimFactCommitment);
  });

  it("persists before proving, stores the exact encrypted proof and enqueues Claim v6 once", async () => {
    const { grant } = await fixture();
    const prepared = await prepareWorkerClaimV2({
      grant,
      claimKind: "missing_obligation",
      chainId: "0x1",
      sealAddress: "0x123",
      principal: worker,
      now: claimAt,
    });
    const proof = proofFor(prepared);
    const order: string[] = [];
    const client = {
      createWorkerClaim: vi.fn().mockImplementation(async (claim) => {
        order.push("claim");
        return { claim: { id: claim.id, proofBundleId: claim.proofBundleId } };
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
        return { authorization: { state: "queued" } };
      }),
    };
    const stages: string[] = [];
    const result = await proveAndSubmitWorkerClaimV2({
      client: client as never,
      prepared,
      principal: worker,
      proverBaseUrl: "https://prover.invalid",
      bookSealAddress: "0x456",
      onStage: (stage) => stages.push(stage),
    });

    expect(order).toEqual(["claim", "prove", "proof", "authorize"]);
    expect(stages).toEqual([
      "persisting_claim",
      "proving",
      "persisting_proof",
      "authorizing",
    ]);
    expect(client.proveExceptionRemotely).toHaveBeenCalledWith(expect.objectContaining({
      claimAccessGrantId: grant.id,
      principal: worker,
    }));
    expect(client.enqueueExceptionAuthorization).toHaveBeenCalledWith({
      proofBundleId: prepared.create.proofBundleId,
      request: {
        proofCalldata: proof.proof.proofCalldata,
        vestingBook: expect.objectContaining({ entryKind: "claim" }),
      },
    });
    expect(decryptVaultRecord(result.proofBundle.envelope, worker))
      .toMatchObject({ profile: "wage_claim_v6" });
    expect(decryptVaultRecord(result.proofBundle.envelope, employer))
      .toMatchObject({ profile: "wage_claim_v6" });
  });

  it("fails closed for legacy packets, false claim types and the wrong worker", async () => {
    const { prepared, grant } = await fixture();
    const { recipientSalt: removedRecipientSalt, ...legacyAccess } = prepared.claimAccess[0]!.record;
    expect(removedRecipientSalt).toMatch(/^0x[0-9a-f]{64}$/);
    const legacyEnvelope = encryptVaultRecord(legacyAccess, {
      schemaVersion: 1,
      organizationId,
      recordType: "obligation-claim-access",
      recordId: grant.id,
      revision: 1,
    }, [worker]);
    await expect(prepareWorkerClaimV2({
      grant: { ...grant, envelope: legacyEnvelope },
      claimKind: "missing_obligation",
      chainId: "0x1",
      sealAddress: "0x123",
      principal: worker,
      now: claimAt,
    })).rejects.toThrow(/newly protected payday/i);
    await expect(prepareWorkerClaimV2({
      grant,
      claimKind: "below_committed_floor",
      chainId: "0x1",
      sealAddress: "0x123",
      principal: worker,
      now: claimAt,
    })).rejects.toThrow(/registered FX statement evidence/i);
    await expect(prepareWorkerClaimV2({
      grant,
      claimKind: "missing_obligation",
      chainId: "0x1",
      sealAddress: "0x123",
      principal: employer,
      now: claimAt,
    })).rejects.toThrow(/invalid or revoked/i);
  });
});
