import { z } from "zod";
import { hashTextCommitment } from "@/lib/crypto/commitments";

export const payrollTokenSchema = z.enum(["STRK", "USDC"]);
export type PayrollTokenSymbol = z.infer<typeof payrollTokenSchema>;

export const PAYO_MAX_U128 = (1n << 128n) - 1n;
const PAYO_MAX_U128_DECIMAL = PAYO_MAX_U128.toString();

export const atomicAmountSchema = z
  .string()
  .regex(/^(0|[1-9]\d*)$/, "Amounts must be unsigned base-10 atomic-unit strings.")
  .refine(
    (value) => value.length < PAYO_MAX_U128_DECIMAL.length
      || (value.length === PAYO_MAX_U128_DECIMAL.length && value <= PAYO_MAX_U128_DECIMAL),
    "Amount exceeds PayrollIntegrity's u128 range.",
  );

export const moneySchema = z.object({
  token: payrollTokenSchema,
  atomic: atomicAmountSchema,
});
export type Money = z.infer<typeof moneySchema>;

export const payrollRunStates = [
  "draft",
  "calculated",
  "proven",
  "approval_pending",
  "submitted",
  "confirmed",
  "reconciled",
  "cancelled",
  "failed",
  "disputed",
] as const;

export const payrollRunStateSchema = z.enum(payrollRunStates);
export type PayrollRunState = z.infer<typeof payrollRunStateSchema>;

export const PAYROLL_STATE_TRANSITIONS: Readonly<
  Record<PayrollRunState, readonly PayrollRunState[]>
> = {
  draft: ["calculated", "cancelled"],
  calculated: ["proven", "draft"],
  proven: ["approval_pending", "calculated", "cancelled"],
  approval_pending: ["submitted", "cancelled"],
  submitted: ["confirmed", "failed"],
  confirmed: ["reconciled", "disputed"],
  reconciled: [],
  cancelled: [],
  failed: ["approval_pending"],
  disputed: ["reconciled"],
};

export function assertPayrollTransition(from: PayrollRunState, to: PayrollRunState): void {
  if (!PAYROLL_STATE_TRANSITIONS[from].includes(to)) {
    throw new Error(`Invalid payroll transition: ${from} -> ${to}.`);
  }
}

export const privatePayrollLineSchema = z.object({
  agreementId: z.string().min(1).max(160),
  recipientAddress: z.string().regex(/^0x[0-9a-fA-F]+$/, "Expected a Starknet address."),
  token: payrollTokenSchema,
  earningsAtomic: z.array(atomicAmountSchema).min(1).max(8),
  deductionsAtomic: z.array(atomicAmountSchema).max(8),
  committedPolicyId: z.string().min(1).max(160),
  scheduleCommitment: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  salt: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
});
export type PrivatePayrollLine = z.infer<typeof privatePayrollLineSchema>;

export type CalculatedPayrollLine = PrivatePayrollLine & {
  grossAtomic: string;
  deductionsTotalAtomic: string;
  netAtomic: string;
};

function sumAtomic(values: readonly string[]): bigint {
  return values.reduce((total, value) => total + BigInt(atomicAmountSchema.parse(value)), 0n);
}

export function comparePayrollAgreementIds(left: string, right: string): number {
  const leftCommitment = hashTextCommitment("PAYO_AGREEMENT_ID_V1", left);
  const rightCommitment = hashTextCommitment("PAYO_AGREEMENT_ID_V1", right);
  for (let index = 0; index < leftCommitment.length; index += 1) {
    if (leftCommitment[index] !== rightCommitment[index]) {
      return leftCommitment[index] - rightCommitment[index];
    }
  }
  return 0;
}

export function calculatePayrollLine(input: PrivatePayrollLine): CalculatedPayrollLine {
  const line = privatePayrollLineSchema.parse(input);
  const gross = sumAtomic(line.earningsAtomic);
  const deductions = sumAtomic(line.deductionsAtomic);
  if (gross <= 0n) throw new Error("Gross pay must be greater than zero.");
  if (gross > PAYO_MAX_U128 || deductions > PAYO_MAX_U128) {
    throw new Error("Payroll totals exceed PayrollIntegrity's u128 range.");
  }
  if (deductions > gross) throw new Error("Deductions cannot exceed gross pay.");

  return {
    ...line,
    grossAtomic: gross.toString(),
    deductionsTotalAtomic: deductions.toString(),
    netAtomic: (gross - deductions).toString(),
  };
}

export function calculatePayrollManifest(lines: readonly PrivatePayrollLine[]) {
  if (lines.length === 0 || lines.length > 50) {
    throw new Error("A payroll run must contain between 1 and 50 lines.");
  }

  const calculated = lines.map(calculatePayrollLine);
  const agreementIds = new Set<string>();
  const recipients = new Set<string>();
  const totals: Record<PayrollTokenSymbol, bigint> = { STRK: 0n, USDC: 0n };

  for (const line of calculated) {
    if (agreementIds.has(line.agreementId)) {
      throw new Error(`Duplicate agreement in payroll run: ${line.agreementId}.`);
    }
    agreementIds.add(line.agreementId);

    const payoutKey = `${line.recipientAddress.toLowerCase()}:${line.token}`;
    if (recipients.has(payoutKey)) {
      throw new Error(`Duplicate recipient/token pair in payroll run: ${payoutKey}.`);
    }
    recipients.add(payoutKey);
    totals[line.token] += BigInt(line.netAtomic);
  }

  return {
    lines: calculated.sort((a, b) => comparePayrollAgreementIds(a.agreementId, b.agreementId)),
    totals: {
      STRK: totals.STRK.toString(),
      USDC: totals.USDC.toString(),
    },
  };
}

export const encryptedRunCreateSchema = z.object({
  id: z.string().min(8).max(128),
  organizationId: z.string().min(8).max(128),
  cycleId: z.string().min(1).max(160),
  revision: z.number().int().positive(),
  dueAt: z.string().datetime(),
  ciphertext: z.string().min(24),
  envelope: z.record(z.string(), z.unknown()),
  agreementRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  manifestRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  policyRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  fxRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  runNullifier: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  obligationSnapshotPlanId: z.string().uuid().optional(),
  lineRecords: z.array(z.object({
    id: z.string().min(8).max(128),
    revision: z.literal(1),
    envelope: z.record(z.string(), z.unknown()),
  }).strict()).min(1).max(50),
}).strict();
export type EncryptedRunCreate = z.infer<typeof encryptedRunCreateSchema>;

export const proofPackageSchema = z.object({
  packageVersion: z.literal("payo-proof-package-v1"),
  runId: z.string().min(8).max(128),
  organizationId: z.string().min(8).max(128),
  proofType: z.enum(["payroll_integrity", "wage_claim", "wage_remediation", "settlement_match", "scoped_disclosure"]),
  proofVersion: z.string().min(1).max(64),
  verifier: z.object({
    chainId: z.string().min(1),
    contractAddress: z.string().regex(/^0x[0-9a-fA-F]+$/),
    classHash: z.string().regex(/^0x[0-9a-fA-F]+$/).optional(),
  }),
  publicInputs: z.record(z.string(), z.string()),
  proof: z.string().min(1),
  transactionHash: z.string().regex(/^0x[0-9a-fA-F]+$/).optional(),
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime().optional(),
}).strict();
export type ProofPackage = z.infer<typeof proofPackageSchema>;

export function buildProofPackage(input: Omit<ProofPackage, "packageVersion" | "createdAt">): ProofPackage {
  return proofPackageSchema.parse({
    ...input,
    packageVersion: "payo-proof-package-v1",
    createdAt: new Date().toISOString(),
  });
}
