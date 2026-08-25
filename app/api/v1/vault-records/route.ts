import { z } from "zod";
import { encryptedVaultRecordSchema } from "@/lib/crypto/vault";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  ENCRYPTED_RECORD_TYPES,
  getEncryptedVaultRecord,
  listEncryptedVaultRecords,
  storeEncryptedVaultRevision,
  storeEncryptedVaultRevisions,
} from "@/lib/persistence/vault-repository";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const encryptedRecordTypeSchema = z.enum(ENCRYPTED_RECORD_TYPES);
const encryptedRecordItemSchema = z.object({
  recordId: uuidV7Schema,
  recordType: encryptedRecordTypeSchema,
  revision: z.number().int().positive(),
  envelope: encryptedVaultRecordSchema,
}).strict();
const createEncryptedRecordSchema = encryptedRecordItemSchema.extend({
  organizationId: uuidV7Schema,
}).strict();
const createEncryptedRecordBatchSchema = z.object({
  organizationId: uuidV7Schema,
  records: z.array(encryptedRecordItemSchema).min(1).max(100),
}).strict();

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const search = new URL(request.url).searchParams;
    const organizationId = uuidV7Schema.parse(search.get("organizationId"));
    const recordId = search.get("recordId");
    const recordType = search.get("recordType");
    const revisionValue = search.get("revision");
    const revision = revisionValue === null ? undefined : Number(revisionValue);
    if (revision !== undefined && (!Number.isInteger(revision) || revision <= 0)) {
      throw new ApiError(400, "revision must be a positive integer.", "REVISION_INVALID");
    }
    if (recordId) {
      return Response.json({
        record: await getEncryptedVaultRecord({
          organizationId,
          recordId: uuidV7Schema.parse(recordId),
          revision,
          principal,
        }),
      });
    }
    return Response.json({
      records: await listEncryptedVaultRecords({
        organizationId,
        recordType: recordType ? encryptedRecordTypeSchema.parse(recordType) : undefined,
        principal,
      }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const body = await readJson(request);
    const batch = createEncryptedRecordBatchSchema.safeParse(body);
    if (batch.success) {
      const records = await storeEncryptedVaultRevisions({ ...batch.data, principal });
      return Response.json({ records }, { status: records.every(({ replayed }) => replayed) ? 200 : 201 });
    }
    const input = createEncryptedRecordSchema.parse(body);
    const record = await storeEncryptedVaultRevision({ ...input, principal });
    return Response.json({ record }, { status: record.replayed ? 200 : 201 });
  } catch (error) {
    return apiFailure(error);
  }
}
