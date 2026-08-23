import { strToU8, unzipSync, zipSync } from "fflate";
import { sha256 } from "@noble/hashes/sha2.js";
import { z } from "zod";
import { stableJson, toHex, utf8 } from "@/lib/crypto/encoding";
import { atomicAmountSchema, payrollTokenSchema, proofPackageSchema } from "@/lib/domain/payroll";

const journalEntrySchema = z.object({
  date: z.string().date(),
  accountCode: z.string().min(1).max(80),
  debitAtomic: atomicAmountSchema,
  creditAtomic: atomicAmountSchema,
  token: payrollTokenSchema,
  memo: z.string().max(240),
}).strict().refine(
  (entry) => (BigInt(entry.debitAtomic) === 0n) !== (BigInt(entry.creditAtomic) === 0n),
  "A journal line must contain either a debit or a credit.",
);

export const complianceExportSchema = z.object({
  exportVersion: z.literal("payo-compliance-export-v1"),
  scope: z.enum(["employer", "auditor", "worker"]),
  organizationId: z.string().min(8).max(128),
  runId: z.string().min(8).max(128),
  journal: z.array(journalEntrySchema).min(2),
  proofPackage: proofPackageSchema,
  verification: z.object({
    verified: z.boolean(),
    verifierAddress: z.string().regex(/^0x[0-9a-fA-F]+$/),
    proofVersion: z.string().min(1).max(64),
    checkedAt: z.string().datetime(),
  }).strict(),
  starknetReceipt: z.record(z.string(), z.unknown()),
  disclosure: z.record(z.string(), z.unknown()).optional(),
}).strict().superRefine((input, context) => {
  if (
    input.proofPackage.organizationId !== input.organizationId ||
    input.proofPackage.runId !== input.runId
  ) {
    context.addIssue({ code: "custom", path: ["proofPackage"], message: "Proof package scope mismatch." });
  }
  const totals = new Map<string, { debit: bigint; credit: bigint }>();
  for (const entry of input.journal) {
    const total = totals.get(entry.token) ?? { debit: 0n, credit: 0n };
    total.debit += BigInt(entry.debitAtomic);
    total.credit += BigInt(entry.creditAtomic);
    totals.set(entry.token, total);
  }
  for (const [token, total] of totals) {
    if (total.debit !== total.credit) {
      context.addIssue({ code: "custom", path: ["journal"], message: `${token} journal is not balanced.` });
    }
  }
});
export type ComplianceExport = z.infer<typeof complianceExportSchema>;

function csvCell(value: string): string {
  const safe = /^[=+\-@]/.test(value) ? `'${value}` : value;
  return /[",\r\n]/.test(safe) ? `"${safe.replaceAll('"', '""')}"` : safe;
}

function journalCsv(journal: ComplianceExport["journal"]): string {
  const rows = journal.map((entry) => [
    entry.date,
    entry.accountCode,
    entry.debitAtomic,
    entry.creditAtomic,
    entry.token,
    entry.memo,
  ].map(csvCell).join(","));
  return ["date,account_code,debit_atomic,credit_atomic,token,memo", ...rows].join("\n");
}

export function createComplianceExportZip(input: ComplianceExport): Uint8Array {
  const parsed = complianceExportSchema.parse(input);
  const files: Record<string, string> = {
    "journal.csv": journalCsv(parsed.journal),
    "proof.json": `${stableJson(parsed.proofPackage)}\n`,
    "verification.json": `${stableJson(parsed.verification)}\n`,
    "starknet-receipt.json": `${stableJson(parsed.starknetReceipt)}\n`,
  };
  if (parsed.disclosure) files["disclosure.json"] = `${stableJson(parsed.disclosure)}\n`;

  const manifest = {
    exportVersion: parsed.exportVersion,
    scope: parsed.scope,
    organizationId: parsed.organizationId,
    runId: parsed.runId,
    createdAt: parsed.verification.checkedAt,
    content: Object.keys(files).sort().map((name) => ({
      name,
      sha256: toHex(sha256(utf8(files[name]))),
    })),
  };
  files["manifest.json"] = `${stableJson(manifest)}\n`;
  return zipSync(
    Object.fromEntries(Object.entries(files).map(([name, contents]) => [name, strToU8(contents)])),
    { level: 6 },
  );
}

export function inspectComplianceExportZip(archive: Uint8Array): Record<string, Uint8Array> {
  return unzipSync(archive);
}
