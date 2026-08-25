import { describe, expect, it, vi } from "vitest";
import { encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { generateUuidV7, settlementRecordSchema } from "@/lib/domain/records";
import { commitTokenTotals } from "@/lib/domain/settlement";
import { createEncryptedSettlementReceipt } from "./settlement-receipts";

const organizationId = "018f1000-0000-7000-8000-000000000001";
const runId = "018f1000-0000-7000-8000-000000000002";
const settlementId = "018f1000-0000-7000-8000-000000000003";
const timestamp = "2026-08-24T12:00:00.000Z";

function fixture(state = "confirmed") {
  const principal = generateVaultPrincipal("admin:test");
  const tokenTotals = { STRK: "1000000000000000000", USDC: "2500000" };
  const tokenTotalsCommitment = commitTokenTotals({ organizationId, runId, totals: tokenTotals });
  const record = settlementRecordSchema.parse({
    schemaVersion: 1,
    id: settlementId,
    organizationId,
    revision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    runId,
    walletRequestId: generateUuidV7(),
    idempotencyKey: "settlement-receipt-test-key",
    tokenTotals,
    tokenTotalsCommitment,
    transactionHash: "0xabc",
    state,
    submittedAt: timestamp,
    confirmedAt: state === "confirmed" ? timestamp : undefined,
    noteEvidenceState: "unavailable",
  });
  const envelope = encryptVaultRecord(record, {
    schemaVersion: 1,
    organizationId,
    recordType: "settlement",
    recordId: settlementId,
    revision: 1,
  }, [principal]);
  const createReceipt = vi.fn().mockResolvedValue({ receipt: {} });
  const client = {
    getSettlement: vi.fn().mockResolvedValue({ settlement: {
      id: settlementId,
      runId,
      state,
      transactionHash: "0xabc",
      tokenTotalsCommitment,
      confirmationDepth: 3,
      blockNumber: "100",
    } }),
    getEncryptedRecord: vi.fn().mockResolvedValue({ record: { envelope } }),
    createReceipt,
  };
  return { principal, tokenTotals, client, createReceipt };
}

describe("encrypted settlement receipts", () => {
  it("binds private totals to public chain evidence without uploading plaintext", async () => {
    const { principal, tokenTotals, client, createReceipt } = fixture();
    const result = await createEncryptedSettlementReceipt({
      client: client as never,
      organizationId,
      settlementId,
      issuerPrincipal: principal,
      now: new Date(timestamp),
    });
    expect(result.record.evidence).toMatchObject({ tokenTotals, transactionHash: "0xabc", confirmationDepth: 3 });
    expect(result.record.packageCommitment).toMatch(/^0x[0-9a-f]{64}$/);
    const request = createReceipt.mock.calls[0][0];
    expect(request.scope).toBe("employer");
    expect(JSON.stringify(request.envelope)).not.toContain(tokenTotals.STRK);
    expect(JSON.stringify(request.envelope)).not.toContain(tokenTotals.USDC);
  });

  it("refuses receipts for unconfirmed settlements", async () => {
    const { principal, client, createReceipt } = fixture("submitted");
    await expect(createEncryptedSettlementReceipt({
      client: client as never,
      organizationId,
      settlementId,
      issuerPrincipal: principal,
    })).rejects.toThrow(/only after Starknet confirms/i);
    expect(createReceipt).not.toHaveBeenCalled();
  });
});
