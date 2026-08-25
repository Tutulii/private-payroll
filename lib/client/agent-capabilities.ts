import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, normalizedHexBytes, toHex, utf8 } from "@/lib/crypto/encoding";
import type { VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import {
  agentCapabilitySchema,
  hashCapability,
  signCapability,
  verifySignedCapability,
  type AgentAction,
} from "@/lib/domain/capability";
import { agentCapabilityRecordSchema, generateUuidV7 } from "@/lib/domain/records";
import type { PayrollTokenSymbol } from "@/app/starknet/tokens";
import { loadCanonicalEncryptedRecords, prepareCanonicalEncryptedRecord } from "./encrypted-records";
import type { PayoClient } from "./payo-client";

export type AgentCapabilityDirectoryRecord = ReturnType<typeof agentCapabilityRecordSchema.parse>;

const DEFAULT_AGENT_ACTIONS: AgentAction[] = [
  "list_due_obligations",
  "draft_run",
  "validate_run",
  "request_execution",
  "get_run_status",
  "get_receipt",
];

function deriveIssuerSecret(organizationSecret: string): Uint8Array {
  return sha256(concatBytes(
    utf8("PAYO_AGENT_CAPABILITY_ISSUER_V1"),
    normalizedHexBytes(organizationSecret, 32),
  ));
}

function randomNonce(): string {
  return toHex(crypto.getRandomValues(new Uint8Array(32)));
}

export function prepareEncryptedAgentCapability(input: {
  organizationId: string;
  organizationSecret: string;
  principalId: string;
  recipientAddresses: readonly string[];
  limits: readonly {
    token: PayrollTokenSymbol;
    maxPerPaymentAtomic: string;
    maxPerPeriodAtomic: string;
    approvalThresholdAtomic: string;
  }[];
  vaultPrincipal: VaultPrincipalKeyPair;
  purposeCodes?: readonly string[];
  validAfter?: Date;
  expiresAt: Date;
  now?: Date;
}) {
  const now = input.now ?? new Date();
  const validAfter = input.validAfter ?? now;
  if (input.recipientAddresses.length < 1) throw new Error("A capability requires at least one committed recipient.");
  if (input.limits.length < 1) throw new Error("A capability requires at least one token limit.");
  const id = generateUuidV7(now.getTime());
  const periodStartsAt = validAfter.toISOString();
  const periodEndsAt = input.expiresAt.toISOString();
  const capability = agentCapabilitySchema.parse({
    capabilityVersion: "payo-agent-capability-v1",
    id,
    organizationId: input.organizationId,
    principalId: input.principalId,
    allowedActions: DEFAULT_AGENT_ACTIONS,
    allowedTokens: input.limits.map(({ token }) => token),
    recipientScope: { mode: "allowlist", addresses: [...new Set(input.recipientAddresses)] },
    purposeCodes: input.purposeCodes ?? ["private_payroll"],
    limits: input.limits.map((limit) => ({
      ...limit,
      spentThisPeriodAtomic: "0",
      periodStartsAt,
      periodEndsAt,
    })),
    executionMode: "request_approval",
    validAfter: validAfter.toISOString(),
    expiresAt: input.expiresAt.toISOString(),
    nonce: randomNonce(),
  });
  const signedCapability = signCapability(capability, deriveIssuerSecret(input.organizationSecret));
  verifySignedCapability(signedCapability);
  const timestamp = now.toISOString();
  const record = agentCapabilityRecordSchema.parse({
    schemaVersion: 1,
    id,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
    principalId: input.principalId,
    signedCapability,
    capabilityHash: hashCapability(capability),
  });
  const prepared = prepareCanonicalEncryptedRecord({
    organizationId: input.organizationId,
    recordType: "agent-capability",
    record,
    principals: [input.vaultPrincipal],
  });
  return { ...prepared, signedCapability };
}

export async function issueEncryptedAgentCapability(input: Parameters<typeof prepareEncryptedAgentCapability>[0] & {
  client: Pick<PayoClient, "registerEncryptedAgentCapability">;
}): Promise<AgentCapabilityDirectoryRecord> {
  const prepared = prepareEncryptedAgentCapability(input);
  const response = await input.client.registerEncryptedAgentCapability({
    signedCapability: prepared.signedCapability,
    recordId: prepared.record.id,
    revision: 1,
    envelope: prepared.envelope,
  });
  if (response.capability.id !== prepared.record.id) {
    throw new Error("PAYO returned a different capability identity.");
  }
  if (BigInt(response.capability.capabilityHash) !== BigInt(prepared.record.capabilityHash)) {
    throw new Error("PAYO returned a different capability commitment.");
  }
  return prepared.record;
}

export async function loadEncryptedAgentCapabilities(input: {
  client: Pick<PayoClient, "listEncryptedRecords" | "getEncryptedRecord">;
  organizationId: string;
  principal: VaultPrincipalKeyPair;
}): Promise<AgentCapabilityDirectoryRecord[]> {
  return loadCanonicalEncryptedRecords({ ...input, recordType: "agent-capability" });
}

export async function revokeEncryptedAgentCapability(input: {
  client: Pick<PayoClient, "revokeEncryptedAgentCapability">;
  record: AgentCapabilityDirectoryRecord;
  principal: VaultPrincipalKeyPair;
  now?: Date;
}): Promise<AgentCapabilityDirectoryRecord> {
  if (input.record.revokedAt) return input.record;
  const now = input.now ?? new Date();
  const record = agentCapabilityRecordSchema.parse({
    ...input.record,
    revision: input.record.revision + 1,
    updatedAt: now.toISOString(),
    revokedAt: now.toISOString(),
  });
  const prepared = prepareCanonicalEncryptedRecord({
    organizationId: record.organizationId,
    recordType: "agent-capability",
    record,
    principals: [input.principal],
  });
  await input.client.revokeEncryptedAgentCapability({
    capabilityId: record.id,
    organizationId: record.organizationId,
    revision: record.revision,
    envelope: prepared.envelope,
  });
  return record;
}
