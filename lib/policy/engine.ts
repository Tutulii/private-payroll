import { z } from "zod";
import { hashTextCommitment } from "@/lib/crypto/commitments";
import { stableJson, toHex } from "@/lib/crypto/encoding";
import { atomicAmountSchema } from "@/lib/domain/payroll";

const registerSchema = z.string().regex(/^[a-z][a-z0-9_]{0,47}$/);

const instructionSchema = z.discriminatedUnion("op", [
  z.object({ op: z.literal("CONST"), out: registerSchema, value: atomicAmountSchema }).strict(),
  z.object({ op: z.literal("INPUT"), out: registerSchema, key: registerSchema }).strict(),
  z.object({ op: z.literal("ADD"), out: registerSchema, left: registerSchema, right: registerSchema }).strict(),
  z.object({ op: z.literal("SUB"), out: registerSchema, left: registerSchema, right: registerSchema }).strict(),
  z.object({
    op: z.literal("MUL_DIV"),
    out: registerSchema,
    value: registerSchema,
    numerator: atomicAmountSchema,
    denominator: atomicAmountSchema,
  }).strict(),
  z.object({ op: z.literal("MIN"), out: registerSchema, left: registerSchema, right: registerSchema }).strict(),
  z.object({ op: z.literal("MAX"), out: registerSchema, left: registerSchema, right: registerSchema }).strict(),
  z.object({
    op: z.literal("BRACKET"),
    out: registerSchema,
    input: registerSchema,
    brackets: z.array(z.object({
      upperAtomic: atomicAmountSchema.optional(),
      rateBps: z.number().int().min(0).max(10_000),
    }).strict()).min(1).max(8),
  }).strict(),
]);
export type PolicyInstruction = z.infer<typeof instructionSchema>;

export const policyPackSchema = z.object({
  packVersion: z.literal("payo-policy-pack-v1"),
  id: z.string().min(1).max(160),
  revision: z.number().int().positive(),
  jurisdictionCode: z.string().regex(/^[A-Z]{2}(-[A-Z0-9]{1,3})?$/),
  appliesTo: z.array(z.enum(["employee", "contractor", "agent_service"])).min(1),
  effectiveFrom: z.string().date(),
  effectiveUntil: z.string().date(),
  sourceUri: z.string().url(),
  legalReviewRequired: z.literal(true),
  instructions: z.array(instructionSchema).min(1).max(32),
  outputs: z.record(z.string(), registerSchema),
}).strict().superRefine((pack, context) => {
  if (pack.effectiveUntil < pack.effectiveFrom) {
    context.addIssue({ code: "custom", path: ["effectiveUntil"], message: "Invalid policy window." });
  }
  const outputs = new Set<string>();
  for (const [index, instruction] of pack.instructions.entries()) {
    if (outputs.has(instruction.out)) {
      context.addIssue({ code: "custom", path: ["instructions", index, "out"], message: "Register is assigned twice." });
    }
    outputs.add(instruction.out);
  }
  for (const register of Object.values(pack.outputs)) {
    if (!outputs.has(register)) {
      context.addIssue({ code: "custom", path: ["outputs"], message: `Unknown output register: ${register}.` });
    }
  }
});
export type PolicyPack = z.infer<typeof policyPackSchema>;

function load(registers: Map<string, bigint>, name: string): bigint {
  const value = registers.get(name);
  if (value === undefined) throw new Error(`Policy reads an unset register: ${name}.`);
  return value;
}

function progressiveBracket(value: bigint, brackets: Extract<PolicyInstruction, { op: "BRACKET" }>["brackets"]): bigint {
  let previousUpper = 0n;
  let result = 0n;
  let openEndedSeen = false;
  for (const [index, bracket] of brackets.entries()) {
    if (openEndedSeen) throw new Error("An open-ended bracket must be last.");
    const upper = bracket.upperAtomic === undefined ? null : BigInt(bracket.upperAtomic);
    if (upper !== null && upper <= previousUpper) throw new Error("Policy brackets must increase.");
    const bandEnd = upper === null || value < upper ? value : upper;
    const taxable = bandEnd > previousUpper ? bandEnd - previousUpper : 0n;
    result += taxable * BigInt(bracket.rateBps) / 10_000n;
    if (upper === null) openEndedSeen = true;
    else previousUpper = upper;
    if (bandEnd === value) {
      if (index < brackets.length - 1 && brackets[index + 1].upperAtomic === undefined) {
        // The remaining open bracket is valid but contributes zero.
      }
      break;
    }
  }
  if (!openEndedSeen && value > previousUpper) throw new Error("Policy brackets do not cover the input.");
  return result;
}

export function evaluatePolicyPack(
  packInput: PolicyPack,
  inputs: Readonly<Record<string, string>>,
): Record<string, string> {
  const pack = policyPackSchema.parse(packInput);
  const registers = new Map<string, bigint>();
  for (const instruction of pack.instructions) {
    let value: bigint;
    switch (instruction.op) {
      case "CONST": value = BigInt(instruction.value); break;
      case "INPUT": {
        const input = inputs[instruction.key];
        if (input === undefined) throw new Error(`Policy input is missing: ${instruction.key}.`);
        value = BigInt(atomicAmountSchema.parse(input));
        break;
      }
      case "ADD": value = load(registers, instruction.left) + load(registers, instruction.right); break;
      case "SUB": {
        const left = load(registers, instruction.left);
        const right = load(registers, instruction.right);
        if (right > left) throw new Error(`Policy subtraction underflow at ${instruction.out}.`);
        value = left - right;
        break;
      }
      case "MUL_DIV": {
        const denominator = BigInt(instruction.denominator);
        if (denominator === 0n) throw new Error(`Policy division by zero at ${instruction.out}.`);
        value = load(registers, instruction.value) * BigInt(instruction.numerator) / denominator;
        break;
      }
      case "MIN": {
        const left = load(registers, instruction.left);
        const right = load(registers, instruction.right);
        value = left < right ? left : right;
        break;
      }
      case "MAX": {
        const left = load(registers, instruction.left);
        const right = load(registers, instruction.right);
        value = left > right ? left : right;
        break;
      }
      case "BRACKET": value = progressiveBracket(load(registers, instruction.input), instruction.brackets); break;
    }
    registers.set(instruction.out, value);
  }
  return Object.fromEntries(
    Object.entries(pack.outputs).map(([name, register]) => [name, load(registers, register).toString()]),
  );
}

export function policyPackCommitment(pack: PolicyPack): `0x${string}` {
  const parsed = policyPackSchema.parse(pack);
  return toHex(hashTextCommitment("PAYO_POLICY_PACK_V1", stableJson(parsed)));
}

/** Demonstration data only. It is intentionally not represented as current tax advice. */
export const DEMO_PROGRESSIVE_POLICY: PolicyPack = {
  packVersion: "payo-policy-pack-v1",
  id: "demo-progressive-reference-v1",
  revision: 1,
  jurisdictionCode: "US",
  appliesTo: ["employee"],
  effectiveFrom: "2026-01-01",
  effectiveUntil: "2026-12-31",
  sourceUri: "https://example.invalid/payo/reference-policy",
  legalReviewRequired: true,
  instructions: [
    { op: "INPUT", out: "taxable", key: "taxable_gross" },
    { op: "BRACKET", out: "withholding", input: "taxable", brackets: [
      { upperAtomic: "1000", rateBps: 1000 },
      { upperAtomic: "5000", rateBps: 2000 },
      { rateBps: 3000 },
    ] },
  ],
  outputs: { statutoryWithholding: "withholding" },
};
