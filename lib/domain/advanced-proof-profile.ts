import { z } from "zod";
import { commitmentSchema, uuidV7Schema } from "./records";

export const advancedProofProfileSchema = z.enum([
  "statutory_correct",
  "fx_floor",
  "classification_consistency",
  "offboarding_correct",
]);
export type AdvancedProofProfile = z.infer<typeof advancedProofProfileSchema>;

export const verifierBackedProfileSchema = z.object({
  profileVersion: z.literal("payo-advanced-proof-profile-v1"),
  profile: advancedProofProfileSchema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  proofBundleId: uuidV7Schema,
  proofVersion: z.string().regex(/^[1-9]\d{0,9}$/),
  circuitSha256: commitmentSchema,
  verificationKeySha256: commitmentSchema,
  publicInputsHash: commitmentSchema,
  agreementRoot: commitmentSchema,
  manifestRoot: commitmentSchema,
  policyRoot: commitmentSchema,
  fxRoot: commitmentSchema,
  runNullifier: commitmentSchema,
  coveredLineCount: z.number().int().positive().max(50),
  verificationState: z.literal("onchain_verified"),
  verifiedAt: z.string().datetime(),
}).strict();
export type VerifierBackedProfile = z.infer<typeof verifierBackedProfileSchema>;

export type AdvancedProfileLine = {
  fxFloorAtomic?: string;
  finalPay?: { requiredMask: number; includedMask: number };
};

/**
 * PayrollIntegrity enforces statutory policy arithmetic and classification on
 * every active line. FXFloor and OffboardingCorrect are issued only when at
 * least one non-trivial line activates those assertions. These records contain
 * no line index, salary, identity, or jurisdiction and must stay encrypted.
 */
export function buildVerifierBackedProfiles(input: {
  organizationId: string;
  runId: string;
  proofBundleId: string;
  proofVersion: string;
  circuitSha256: string;
  verificationKeySha256: string;
  publicInputsHash: string;
  agreementRoot: string;
  manifestRoot: string;
  policyRoot: string;
  fxRoot: string;
  runNullifier: string;
  verificationState: "unverified" | "locally_verified" | "onchain_verified" | "rejected";
  lines: readonly AdvancedProfileLine[];
  verifiedAt?: Date;
}): VerifierBackedProfile[] {
  if (input.verificationState !== "onchain_verified") {
    throw new Error("Advanced proof profiles require an on-chain verified PayrollIntegrity bundle.");
  }
  if (input.lines.length < 1 || input.lines.length > 50) {
    throw new Error("Advanced proof profiles require 1–50 private payroll lines.");
  }
  const profiles: Array<{ profile: AdvancedProofProfile; coveredLineCount: number }> = [
    { profile: "statutory_correct", coveredLineCount: input.lines.length },
    { profile: "classification_consistency", coveredLineCount: input.lines.length },
  ];
  const fxLines = input.lines.filter((line) => BigInt(line.fxFloorAtomic ?? "0") > 0n).length;
  if (fxLines > 0) profiles.push({ profile: "fx_floor", coveredLineCount: fxLines });
  const finalPayLines = input.lines.filter((line) => line.finalPay !== undefined).length;
  if (finalPayLines > 0) {
    for (const line of input.lines) {
      if (line.finalPay && line.finalPay.requiredMask !== line.finalPay.includedMask) {
        throw new Error("Offboarding profile input contains an incomplete final-pay mask.");
      }
    }
    profiles.push({ profile: "offboarding_correct", coveredLineCount: finalPayLines });
  }
  const verifiedAt = (input.verifiedAt ?? new Date()).toISOString();
  return profiles.map(({ profile, coveredLineCount }) => verifierBackedProfileSchema.parse({
    profileVersion: "payo-advanced-proof-profile-v1",
    profile,
    organizationId: input.organizationId,
    runId: input.runId,
    proofBundleId: input.proofBundleId,
    proofVersion: input.proofVersion,
    circuitSha256: input.circuitSha256,
    verificationKeySha256: input.verificationKeySha256,
    publicInputsHash: input.publicInputsHash,
    agreementRoot: input.agreementRoot,
    manifestRoot: input.manifestRoot,
    policyRoot: input.policyRoot,
    fxRoot: input.fxRoot,
    runNullifier: input.runNullifier,
    coveredLineCount,
    verificationState: input.verificationState,
    verifiedAt,
  }));
}

