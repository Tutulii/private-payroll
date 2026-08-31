import { describe, expect, it, vi } from "vitest";
import { decryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { hashCapability, verifySignedCapability } from "@/lib/domain/capability";
import {
  issueEncryptedAgentCapability,
  prepareEncryptedAgentCapability,
  revokeEncryptedAgentCapability,
} from "./agent-capabilities";

const organizationId = "0198ddf0-9c00-7000-8000-000000000001";
const principalId = "0198ddf0-9c00-7000-8000-000000000002";
const organizationSecret = `0x${"44".repeat(32)}`;
const now = new Date("2026-08-24T12:00:00.000Z");
const expiresAt = new Date("2026-09-24T12:00:00.000Z");
const principal = generateVaultPrincipal("did:privy:admin");

function input() {
  return {
    organizationId,
    organizationSecret,
    principalId,
    recipientAddresses: ["0x123"],
    limits: [{
      token: "STRK" as const,
      maxPerPaymentAtomic: "1000000000000000000",
      maxPerPeriodAtomic: "4000000000000000000",
      approvalThresholdAtomic: "1000000000000000000",
    }],
    vaultPrincipal: principal,
    expiresAt,
    now,
  };
}

describe("encrypted agent capability lifecycle", () => {
  it("signs locally and stores the complete capability only inside one vault envelope", () => {
    const prepared = prepareEncryptedAgentCapability(input());
    const decrypted = decryptVaultRecord(prepared.envelope, principal);
    expect(decrypted).toEqual(prepared.record);
    expect(verifySignedCapability(prepared.record.signedCapability)).toEqual(
      prepared.record.signedCapability,
    );
    expect(prepared.envelope.aad).toMatchObject({
      organizationId,
      recordType: "agent-capability",
      recordId: prepared.record.id,
      revision: 1,
    });
    expect(JSON.stringify(prepared.envelope)).not.toContain("0x123");
    expect("encryptedEnvelope" in prepared.record).toBe(false);
  });

  it("atomically submits the signed enforcement policy with its encrypted revision", async () => {
    const registerEncryptedAgentCapability = vi.fn().mockImplementation(async (request) => ({
      capability: {
        id: request.recordId,
        capabilityHash: hashCapability(request.signedCapability.capability),
        expiresAt: expiresAt.toISOString(),
        replayed: false,
      },
    }));
    const record = await issueEncryptedAgentCapability({
      ...input(),
      client: { registerEncryptedAgentCapability } as never,
    });
    expect(registerEncryptedAgentCapability).toHaveBeenCalledTimes(1);
    const request = registerEncryptedAgentCapability.mock.calls[0][0];
    expect(request.recordId).toBe(record.id);
    expect(request.revision).toBe(1);
    expect(request.envelope.aad.recordType).toBe("agent-capability");
  });

  it("requires an explicit opt-in before issuing a bounded-autonomy policy", () => {
    expect(prepareEncryptedAgentCapability(input()).signedCapability.capability.executionMode)
      .toBe("request_approval");
    const prepared = prepareEncryptedAgentCapability({
      ...input(),
      executionMode: "autonomous_bounded",
      maxCallCount: 1,
    });
    expect(prepared.signedCapability.capability).toMatchObject({
      executionMode: "autonomous_bounded",
      maxCallCount: 1,
      usedCallCount: 0,
    });
  });

  it("writes revocation as the next authenticated encrypted revision", async () => {
    const prepared = prepareEncryptedAgentCapability(input());
    const revoke = vi.fn().mockResolvedValue({
      capability: { id: prepared.record.id, revokedAt: now.toISOString(), replayed: false },
    });
    const revoked = await revokeEncryptedAgentCapability({
      client: { revokeEncryptedAgentCapability: revoke } as never,
      record: prepared.record,
      principal,
      now: new Date("2026-08-25T12:00:00.000Z"),
    });
    expect(revoked.revision).toBe(2);
    expect(revoked.revokedAt).toBe("2026-08-25T12:00:00.000Z");
    const request = revoke.mock.calls[0][0];
    expect(request.revision).toBe(2);
    expect(decryptVaultRecord(request.envelope, principal)).toEqual(revoked);
  });
});
