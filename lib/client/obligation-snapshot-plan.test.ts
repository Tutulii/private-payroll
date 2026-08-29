import { describe, expect, it, vi } from "vitest";
import { referenceClassificationAnswers } from "@/lib/domain/classification";
import { claimCapabilityCommitmentV2 } from "@/lib/domain/exception-protocol";
import { deriveClaimCapabilitySecret } from "@/lib/crypto/claim-capability";
import { generateUuidV7 } from "@/lib/domain/records";
import { decryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { storeEncryptedAdvancedAgreement } from "./agreement-directory";
import { buildAdvancedPaymentPlanDraft } from "./advanced-agreement-draft";
import { prepareEncryptedPayee } from "./payee-directory";
import {
  createDurableObligationSnapshotPlan,
  deriveObligationSnapshotCycleId,
  loadRegisteredObligationSnapshotPlan,
  openObligationClaimAccess,
  openObligationSnapshotPlan,
  prepareObligationSnapshotPlan,
  registerDurableObligationSnapshotPlan,
} from "./obligation-snapshot-plan";
import { PayoApiError } from "./payo-client";

const organizationId = "0198ddf0-9c00-7000-8000-000000000001";
const now = new Date("2026-08-24T12:00:00.000Z");
const principal = generateVaultPrincipal("owner:snapshot-test");
const organizationSecret = `0x${"44".repeat(32)}`;

async function obligation(withClaimIdentity = true) {
  const claimant = generateVaultPrincipal(generateUuidV7(now.getTime() - 2));
  const claimCapabilityCommitment = claimCapabilityCommitmentV2(deriveClaimCapabilitySecret(claimant));
  const payee = prepareEncryptedPayee({
    organizationId,
    displayName: "Snapshot worker",
    principalKind: "human",
    recipientAddress: "0x456",
    tokenPreference: "USDC",
    jurisdictionCode: "US",
    ...(withClaimIdentity ? {
      claimIdentity: {
        principalId: claimant.principalId,
        publicKey: claimant.publicKey,
        claimCapabilityCommitment,
      },
    } : {}),
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
      nextDueAt: "2026-08-24T12:10:00.000Z",
    }),
    fixedAmount: "2",
    policyId: "payo-net-invoice-no-withholding-v1",
    policyVersion: 1,
    principal,
    now,
  });
  return { agreement, payee, claimant };
}

describe("pre-payday obligation snapshot plan", () => {
  it("encrypts a complete worker-owned claim witness and reserves the future run", async () => {
    const selected = await obligation();
    const prepared = await prepareObligationSnapshotPlan({
      organizationId,
      organizationSecret,
      ownerAddress: "0xabc",
      obligations: [selected],
      principal,
      now,
    });
    expect(prepared.create.id).not.toBe(prepared.create.runId);
    expect(prepared.create.snapshot.dueAt).toBe(String(now.getTime() / 1_000 + 600));
    expect(prepared.create.snapshot.availabilityCommitment)
      .toBe(prepared.create.snapshot.obligationRoot);
    expect(prepared.privatePlan.claimWitness.lines).toHaveLength(1);
    expect(prepared.privatePlan.claimWitness.lines[0]).toMatchObject({
      agreementId: selected.agreement.agreement.id,
      expectedNetAtomic: "2000000",
    });
    expect(prepared.privatePlan.agreementBindings[0].claimCapabilityCommitment)
      .toBe(selected.payee.claimCapabilityCommitment);
    const decrypted = decryptVaultRecord(prepared.create.envelope, principal);
    expect(decrypted).toEqual(prepared.privatePlan);
    expect(prepared.create.claimAccessGrants).toHaveLength(1);
    expect(prepared.claimAccess[0].record.recipientSalt)
      .toBe(selected.agreement.recipientSalt);
    expect(decryptVaultRecord(prepared.claimAccess[0].envelope, selected.claimant))
      .toEqual(prepared.claimAccess[0].record);
    expect(() => decryptVaultRecord(prepared.claimAccess[0].envelope, principal))
      .toThrow(/not authorized/i);
    const seconds = (value: string) => new Date(Number(value) * 1_000).toISOString();
    const grant = {
      id: prepared.claimAccess[0].record.grantId,
      claimantPrincipalId: selected.claimant.principalId,
      revokedAt: null,
      plan: {
        id: prepared.create.id,
        runId: prepared.create.runId,
        organizationId,
        cycleId: prepared.create.cycleId,
        revision: prepared.create.payrollRevision,
        ownerAddress: prepared.create.ownerAddress,
        agreementRoot: prepared.create.snapshot.baseAgreementRoot as `0x${string}`,
        claimRoot: prepared.create.snapshot.obligationRoot,
        policyRoot: prepared.create.snapshot.policyRoot,
        runNullifier: prepared.create.snapshot.runNullifier,
        snapshotFact: prepared.create.snapshotCommitment,
        dueAt: seconds(prepared.create.snapshot.dueAt),
        graceEndsAt: seconds(prepared.create.snapshot.graceEndsAt),
        claimEndsAt: seconds(prepared.create.snapshot.claimEndsAt),
        state: "registered" as const,
        registrationTransactionHash: "0x123",
        registeredAt: now.toISOString(),
        consumedAt: null,
        createdAt: now.toISOString(),
        updatedAt: now.toISOString(),
      },
      envelope: prepared.claimAccess[0].envelope,
    };
    await expect(openObligationClaimAccess({ grant, principal: selected.claimant }))
      .resolves.toMatchObject({
        access: { grantId: grant.id, runId: prepared.create.runId },
        claimCapabilitySecret: deriveClaimCapabilitySecret(selected.claimant),
      });
    await expect(openObligationClaimAccess({
      grant: { ...grant, plan: { ...grant.plan, claimRoot: `0x${"ef".repeat(32)}` } },
      principal: selected.claimant,
    })).rejects.toThrow(/immutable public snapshot/i);
  });

  it("persists before any wallet request and rejects missing identity or late preparation", async () => {
    const selected = await obligation();
    const createObligationSnapshotPlan = vi.fn().mockImplementation((create) => Promise.resolve({
      plan: { id: create.id, runId: create.runId, replayed: false },
    }));
    const durable = await createDurableObligationSnapshotPlan({
      client: { createObligationSnapshotPlan } as never,
      organizationId,
      organizationSecret,
      ownerAddress: "0xabc",
      obligations: [selected],
      principal,
      now,
    });
    expect(createObligationSnapshotPlan).toHaveBeenCalledOnce();
    expect(durable.stored.id).toBe(durable.create.id);

    await expect(prepareObligationSnapshotPlan({
      organizationId,
      organizationSecret,
      ownerAddress: "0xabc",
      obligations: [await obligation(false)],
      principal,
      now,
    })).rejects.toThrow(/claim identity/i);
    await expect(prepareObligationSnapshotPlan({
      organizationId,
      organizationSecret,
      ownerAddress: "0xabc",
      obligations: [selected],
      principal,
      now: new Date("2026-08-24T12:09:00.000Z"),
    })).rejects.toThrow(/two minutes before payday/i);
  });

  it("uses the concrete proof schedule in the cycle identity", async () => {
    const selected = await obligation();
    const first = deriveObligationSnapshotCycleId(organizationId, [selected]);
    const reordered = deriveObligationSnapshotCycleId(organizationId, [selected]);
    const advanced = deriveObligationSnapshotCycleId(organizationId, [{
      ...selected,
      agreement: {
        ...selected.agreement,
        revision: selected.agreement.revision + 1,
        proofScheduleCommitment: `0x${"ab".repeat(32)}`,
      },
    }]);
    expect(first).toBe(reordered);
    expect(advanced).not.toBe(first);
  });

  it("opens only an exact public, encrypted-directory and Ready-owner binding", async () => {
    const selected = await obligation();
    const prepared = await prepareObligationSnapshotPlan({
      organizationId,
      organizationSecret,
      ownerAddress: "0xabc",
      obligations: [selected],
      principal,
      now,
    });
    const iso = (seconds: string) => new Date(Number(seconds) * 1_000).toISOString();
    const plan = {
      id: prepared.create.id,
      runId: prepared.create.runId,
      organizationId,
      cycleId: prepared.create.cycleId,
      revision: prepared.create.payrollRevision,
      ownerAddress: prepared.create.ownerAddress,
      agreementRoot: prepared.create.snapshot.baseAgreementRoot as `0x${string}`,
      claimRoot: prepared.create.snapshot.obligationRoot,
      policyRoot: prepared.create.snapshot.policyRoot,
      runNullifier: prepared.create.snapshot.runNullifier,
      snapshotFact: prepared.create.snapshotCommitment,
      dueAt: iso(prepared.create.snapshot.dueAt),
      graceEndsAt: iso(prepared.create.snapshot.graceEndsAt),
      claimEndsAt: iso(prepared.create.snapshot.claimEndsAt),
      state: "registered" as const,
      registrationTransactionHash: "0x123",
      registeredAt: now.toISOString(),
      consumedAt: null,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      envelope: prepared.create.envelope,
    };
    expect(openObligationSnapshotPlan({
      plan,
      principal,
      organizationId,
      ownerAddress: "0xabc",
      obligations: [selected],
    })).toEqual(prepared.privatePlan);
    expect(() => openObligationSnapshotPlan({
      plan: { ...plan, claimRoot: `0x${"ee".repeat(32)}` },
      principal,
      organizationId,
      ownerAddress: "0xabc",
      obligations: [selected],
    })).toThrow(/does not match/i);
    expect(() => openObligationSnapshotPlan({
      plan,
      principal,
      organizationId,
      ownerAddress: "0xdef",
      obligations: [selected],
    })).toThrow(/does not match/i);

    const findRegisteredObligationSnapshotPlan = vi.fn().mockResolvedValue({ plan });
    await expect(loadRegisteredObligationSnapshotPlan({
      client: { findRegisteredObligationSnapshotPlan } as never,
      principal,
      organizationId,
      ownerAddress: "0xabc",
      agreementRoot: prepared.create.snapshot.baseAgreementRoot as `0x${string}`,
      obligations: [selected],
    })).resolves.toEqual(prepared.privatePlan);
    expect(findRegisteredObligationSnapshotPlan).toHaveBeenCalledWith({
      organizationId,
      cycleId: prepared.create.cycleId,
      agreementRoot: prepared.create.snapshot.baseAgreementRoot,
    });
  });

  it("recovers canonical registration before opening Ready and submits only once", async () => {
    const selected = await obligation();
    const prepared = await prepareObligationSnapshotPlan({
      organizationId,
      organizationSecret,
      ownerAddress: "0xabc",
      obligations: [selected],
      principal,
      now,
    });
    const order: string[] = [];
    const reconcileObligationSnapshotPlan = vi.fn()
      .mockRejectedValueOnce(new PayoApiError("absent", "SNAPSHOT_NOT_REGISTERED", 409))
      .mockResolvedValueOnce({ plan: { ...prepared.create, state: "registered" }, blockNumber: 10 });
    const result = await registerDurableObligationSnapshotPlan({
      client: {
        reconcileObligationSnapshotPlan,
        recordObligationSnapshotSubmission: vi.fn().mockImplementation(async () => {
          order.push("record");
          return { plan: {} };
        }),
      } as never,
      plan: {
        id: prepared.create.id,
        state: "prepared",
        registrationTransactionHash: null,
        snapshot: prepared.create.snapshot,
        snapshotCommitment: prepared.create.snapshotCommitment,
      },
      ensureAgreementRoot: vi.fn().mockImplementation(async () => { order.push("root"); }),
      registerSnapshot: vi.fn().mockImplementation(async () => {
        order.push("wallet");
        return "0x123";
      }),
    });
    expect(order).toEqual(["root", "wallet", "record"]);
    expect(reconcileObligationSnapshotPlan).toHaveBeenCalledTimes(2);
    expect(result).toMatchObject({ recovered: false, transactionHash: "0x123" });

    const registerSnapshot = vi.fn();
    const recovered = await registerDurableObligationSnapshotPlan({
      client: {
        reconcileObligationSnapshotPlan: vi.fn().mockResolvedValue({
          plan: { ...prepared.create, state: "registered" },
          blockNumber: 11,
        }),
        recordObligationSnapshotSubmission: vi.fn(),
      } as never,
      plan: {
        id: prepared.create.id,
        state: "prepared",
        registrationTransactionHash: null,
        snapshot: prepared.create.snapshot,
        snapshotCommitment: prepared.create.snapshotCommitment,
      },
      ensureAgreementRoot: vi.fn(),
      registerSnapshot,
    });
    expect(recovered.recovered).toBe(true);
    expect(registerSnapshot).not.toHaveBeenCalled();
  });

  it("never resubmits a transaction already recorded for reconciliation", async () => {
    const selected = await obligation();
    const prepared = await prepareObligationSnapshotPlan({
      organizationId,
      organizationSecret,
      ownerAddress: "0xabc",
      obligations: [selected],
      principal,
      now,
    });
    const registerSnapshot = vi.fn();
    await expect(registerDurableObligationSnapshotPlan({
      client: {
        reconcileObligationSnapshotPlan: vi.fn().mockRejectedValue(
          new PayoApiError("absent", "SNAPSHOT_NOT_REGISTERED", 409),
        ),
        recordObligationSnapshotSubmission: vi.fn(),
      } as never,
      plan: {
        id: prepared.create.id,
        state: "submitted",
        registrationTransactionHash: "0x123",
        snapshot: prepared.create.snapshot,
        snapshotCommitment: prepared.create.snapshotCommitment,
      },
      ensureAgreementRoot: vi.fn(),
      registerSnapshot,
    })).rejects.toThrow(/do not submit it again/i);
    expect(registerSnapshot).not.toHaveBeenCalled();
  });
});
