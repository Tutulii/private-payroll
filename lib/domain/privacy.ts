import { z } from "zod";
import { commitmentSchema, uuidV7Schema } from "./records";
import { payrollRunStateSchema } from "./payroll";

export type DataVisibility = "public" | "operational" | "encrypted" | "never_store";

export const PAYO_DATA_CLASSIFICATION = {
  chainId: "public",
  contractAddress: "public",
  transactionHash: "public",
  proofVersion: "public",
  commitmentRoots: "public",
  runNullifier: "public",
  proofStatus: "public",
  organizationId: "operational",
  recordId: "operational",
  revision: "operational",
  dueAt: "operational",
  workflowState: "operational",
  encryptedPayloadSize: "operational",
  workerIdentity: "encrypted",
  recipientAddress: "encrypted",
  salary: "encrypted",
  deductions: "encrypted",
  benefits: "encrypted",
  severance: "encrypted",
  tokenPreference: "encrypted",
  agreementType: "encrypted",
  jurisdiction: "encrypted",
  classificationEvidence: "encrypted",
  schedule: "encrypted",
  vesting: "encrypted",
  recoveryPhrase: "never_store",
  walletPrivateKey: "never_store",
  readyViewingKey: "never_store",
} as const satisfies Record<string, DataVisibility>;

export const payrollRunOperationalViewSchema = z.object({
  id: uuidV7Schema,
  organizationId: uuidV7Schema,
  cycleId: z.string().min(1).max(160),
  revision: z.number().int().positive(),
  state: payrollRunStateSchema,
  dueAt: z.string().datetime(),
  agreementRoot: commitmentSchema.nullable(),
  manifestRoot: commitmentSchema.nullable(),
  runNullifier: commitmentSchema.nullable(),
  transactionHash: z.string().regex(/^0x[0-9a-fA-F]+$/).nullable(),
  updatedAt: z.string().datetime(),
}).strict();

const forbiddenMetadataKeys = new Set([
  "amount",
  "benefits",
  "classification",
  "deductions",
  "email",
  "jurisdiction",
  "legalname",
  "name",
  "recipient",
  "recipientaddress",
  "salary",
  "severance",
  "tokenpreference",
  "viewingkey",
  "readyviewingkey",
  "privatekey",
  "walletprivatekey",
  "recoveryphrase",
]);

export function assertOperationalMetadataSafe(value: unknown, path = "metadata"): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertOperationalMetadataSafe(entry, `${path}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, entry] of Object.entries(value)) {
    const normalized = key.toLowerCase().replaceAll(/[^a-z]/g, "");
    if (forbiddenMetadataKeys.has(normalized)) {
      throw new Error(`Sensitive field is forbidden in operational metadata: ${path}.${key}.`);
    }
    assertOperationalMetadataSafe(entry, `${path}.${key}`);
  }
}
