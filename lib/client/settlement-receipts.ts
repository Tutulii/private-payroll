import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  decryptVaultRecord,
  type EncryptedVaultRecord,
  type VaultPrincipal,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import {
  generateUuidV7,
  receiptRecordSchema,
  settlementRecordSchema,
} from "@/lib/domain/records";
import type { PayoClient } from "./payo-client";
import { prepareCanonicalEncryptedRecord } from "./encrypted-records";

type PublicSettlement = {
  id?: unknown;
  runId?: unknown;
  state?: unknown;
  transactionHash?: unknown;
  tokenTotalsCommitment?: unknown;
  confirmationDepth?: unknown;
  blockNumber?: unknown;
};

function canonicalPublicSettlement(input: PublicSettlement) {
  if (
    typeof input.id !== "string"
    || typeof input.runId !== "string"
    || typeof input.state !== "string"
    || typeof input.transactionHash !== "string"
    || typeof input.tokenTotalsCommitment !== "string"
    || !Number.isInteger(input.confirmationDepth)
    || (input.blockNumber !== null && input.blockNumber !== undefined && typeof input.blockNumber !== "string")
  ) {
    throw new Error("PAYO returned incomplete settlement evidence.");
  }
  return {
    id: input.id,
    runId: input.runId,
    state: input.state,
    transactionHash: input.transactionHash,
    tokenTotalsCommitment: input.tokenTotalsCommitment,
    confirmationDepth: input.confirmationDepth as number,
    blockNumber: input.blockNumber as string | null | undefined,
  };
}

export async function createEncryptedSettlementReceipt(input: {
  client: Pick<PayoClient, "getSettlement" | "getEncryptedRecord" | "createReceipt">;
  organizationId: string;
  settlementId: string;
  issuerPrincipal: VaultPrincipalKeyPair;
  scope?: "employer" | "worker" | "auditor" | "tax";
  granteePrincipal?: VaultPrincipal;
  granteePrincipalId?: string;
  expiresAt?: string;
  now?: Date;
}): Promise<{
  record: ReturnType<typeof receiptRecordSchema.parse>;
  envelope: EncryptedVaultRecord;
}> {
  const [publicResponse, encryptedResponse] = await Promise.all([
    input.client.getSettlement(input.settlementId),
    input.client.getEncryptedRecord({
      organizationId: input.organizationId,
      recordId: input.settlementId,
    }),
  ]);
  const settlement = canonicalPublicSettlement(publicResponse.settlement as PublicSettlement);
  const encrypted = encryptedResponse.record as { envelope?: EncryptedVaultRecord };
  if (!encrypted.envelope) throw new Error("The encrypted settlement record is missing.");
  const privateSettlement = settlementRecordSchema.parse(
    decryptVaultRecord(encrypted.envelope, input.issuerPrincipal),
  );
  if (
    privateSettlement.organizationId !== input.organizationId
    || privateSettlement.id !== input.settlementId
    || settlement.id !== privateSettlement.id
    || settlement.runId !== privateSettlement.runId
    || BigInt(settlement.transactionHash) !== BigInt(privateSettlement.transactionHash ?? "0x0")
    || BigInt(settlement.tokenTotalsCommitment) !== BigInt(privateSettlement.tokenTotalsCommitment)
  ) {
    throw new Error("Public and encrypted settlement evidence do not match.");
  }
  if (!["confirmed", "finalized", "reconciled"].includes(settlement.state)) {
    throw new Error("A receipt can be issued only after Starknet confirms the settlement.");
  }
  const now = input.now ?? new Date();
  const timestamp = now.toISOString();
  const id = generateUuidV7(now.getTime());
  const granteePrincipalId = input.granteePrincipalId ?? input.organizationId;
  const evidence = {
    settlementState: settlement.state,
    transactionHash: settlement.transactionHash,
    tokenTotals: privateSettlement.tokenTotals,
    tokenTotalsCommitment: privateSettlement.tokenTotalsCommitment,
    confirmationDepth: settlement.confirmationDepth,
    ...(settlement.blockNumber ? { blockNumber: settlement.blockNumber } : {}),
    issuedAt: timestamp,
  };
  const packageCommitment = hashCanonicalJson({
    domain: "PAYO_SETTLEMENT_RECEIPT_V1",
    organizationId: input.organizationId,
    runId: settlement.runId,
    settlementId: settlement.id,
    scope: input.scope ?? "employer",
    granteePrincipalId,
    evidence,
  });
  const record = receiptRecordSchema.parse({
    schemaVersion: 1,
    id,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    runId: settlement.runId,
    settlementId: settlement.id,
    scope: input.scope ?? "employer",
    granteePrincipalId,
    packageCommitment,
    evidence,
    ...(input.expiresAt ? { expiresAt: new Date(input.expiresAt).toISOString() } : {}),
  });
  const recipients: VaultPrincipal[] = [input.issuerPrincipal];
  if (
    input.granteePrincipal
    && input.granteePrincipal.principalId !== input.issuerPrincipal.principalId
  ) recipients.push(input.granteePrincipal);
  const prepared = prepareCanonicalEncryptedRecord({
    organizationId: input.organizationId,
    recordType: "receipt",
    record,
    principals: recipients,
  });
  await input.client.createReceipt({
    id: record.id,
    organizationId: input.organizationId,
    runId: record.runId,
    settlementId: record.settlementId,
    scope: record.scope,
    granteePrincipalId: record.granteePrincipalId,
    packageCommitment: record.packageCommitment,
    ...(record.expiresAt ? { expiresAt: record.expiresAt } : {}),
    envelope: prepared.envelope,
  });
  return { record, envelope: prepared.envelope };
}
