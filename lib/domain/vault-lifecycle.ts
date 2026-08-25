import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { uuidV7Schema } from "./records";

export const rotatedVaultRecordSchema = z.object({
  recordId: uuidV7Schema,
  recordType: z.string().min(1).max(64),
  revision: z.number().int().positive(),
  envelope: encryptedVaultRecordSchema,
}).strict();

export const rotatedVaultGrantSchema = z.object({
  grantId: uuidV7Schema,
  granteePrincipalId: z.string().min(1).max(160),
  envelope: encryptedVaultRecordSchema,
}).strict();

export const vaultRotationRequestSchema = z.object({
  expectedKeyVersion: z.number().int().positive(),
  recoveryPackageHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  encryptedProfile: encryptedVaultRecordSchema,
  records: z.array(rotatedVaultRecordSchema).max(10_000),
  grants: z.array(rotatedVaultGrantSchema).max(100),
  revokePrincipalIds: z.array(z.string().min(1).max(160)).max(99),
}).strict();

export type VaultRotationRequest = z.infer<typeof vaultRotationRequestSchema>;
