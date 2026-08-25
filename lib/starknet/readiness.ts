import { z } from "zod";

const commitmentSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);

export const payoReadinessRequestSchema = z.object({
  chainId: z.string().regex(/^(?:0x[0-9a-fA-F]+|[1-9]\d*)$/),
  sealAddress: z.string().regex(/^0x[0-9a-fA-F]+$/),
  proofVersion: z.number().int().positive().max(0xffff_ffff),
  agreementRoot: commitmentSchema,
  policyRoot: commitmentSchema,
  fxRoot: commitmentSchema,
}).strict();

export type PayoReadinessRequest = z.infer<typeof payoReadinessRequestSchema>;

export type PayoReadinessCheck = {
  code:
    | "chain"
    | "seal"
    | "pool"
    | "policy_root"
    | "fx_root"
    | "agreement_root"
    | "verifier";
  ready: boolean;
  message: string;
};

export type PayoReadinessResult = {
  ready: boolean;
  blockNumber: number;
  chainId: string;
  sealAddress: string;
  poolAddress: string;
  catalogRegistryAddress: string;
  obligationRegistryAddress: string;
  verifierAddress: string | null;
  checks: PayoReadinessCheck[];
};
