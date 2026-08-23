import { z } from "zod";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { hashTextCommitment } from "@/lib/crypto/commitments";
import { concatBytes, encodeU32, encodeUint, normalizedHexBytes, stableJson, toHex, utf8 } from "@/lib/crypto/encoding";
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

export const PAYO_MAX_POLICY_STEPS = 16;

export type CompiledPolicyProgram = {
  metadataCommitment: `0x${string}`;
  instructionCount: number;
  opcodes: readonly number[];
  left: readonly number[];
  right: readonly number[];
  immediate: readonly string[];
  numerator: readonly string[];
  denominator: readonly string[];
  outputRegister: number;
};

type CompiledStep = {
  opcode: number;
  left?: number;
  right?: number;
  immediate?: bigint;
  numerator?: bigint;
  denominator?: bigint;
};

function policyMetadataCommitment(pack: PolicyPack): `0x${string}` {
  return toHex(hashTextCommitment("PAYO_POLICY_METADATA_V1", stableJson(pack)));
}

function assertU64(value: bigint, label: string): bigint {
  if (value < 0n || value >= 1n << 64n) throw new Error(`${label} does not fit in u64.`);
  return value;
}

/** Deterministically lowers the public policy DSL into the exact bounded Noir VM. */
export function compilePolicyPack(packInput: PolicyPack): CompiledPolicyProgram {
  const pack = policyPackSchema.parse(packInput);
  const steps: CompiledStep[] = [];
  const registers = new Map<string, number>();
  const emit = (step: CompiledStep): number => {
    if (steps.length >= PAYO_MAX_POLICY_STEPS) {
      throw new Error(`Compiled policy exceeds ${PAYO_MAX_POLICY_STEPS} Noir steps.`);
    }
    steps.push(step);
    return steps.length - 1;
  };
  const resolve = (name: string): number => {
    const register = registers.get(name);
    if (register === undefined) throw new Error(`Policy reads an unset register: ${name}.`);
    return register;
  };

  for (const instruction of pack.instructions) {
    let output: number;
    switch (instruction.op) {
      case "CONST":
        output = emit({ opcode: 1, immediate: BigInt(instruction.value) });
        break;
      case "INPUT": {
        if (instruction.key === "gross" || instruction.key === "taxable_gross") {
          output = emit({ opcode: 2 });
          break;
        }
        const earning = /^earning_([0-7])$/.exec(instruction.key);
        if (!earning) throw new Error(`Unsupported circuit policy input: ${instruction.key}.`);
        output = emit({ opcode: 3, left: Number(earning[1]) });
        break;
      }
      case "ADD":
        output = emit({ opcode: 4, left: resolve(instruction.left), right: resolve(instruction.right) });
        break;
      case "SUB":
        output = emit({ opcode: 5, left: resolve(instruction.left), right: resolve(instruction.right) });
        break;
      case "MUL_DIV": {
        const denominator = assertU64(BigInt(instruction.denominator), "Policy denominator");
        if (denominator === 0n) throw new Error(`Policy division by zero at ${instruction.out}.`);
        output = emit({
          opcode: 6,
          left: resolve(instruction.value),
          numerator: assertU64(BigInt(instruction.numerator), "Policy numerator"),
          denominator,
        });
        break;
      }
      case "MIN":
        output = emit({ opcode: 7, left: resolve(instruction.left), right: resolve(instruction.right) });
        break;
      case "MAX":
        output = emit({ opcode: 8, left: resolve(instruction.left), right: resolve(instruction.right) });
        break;
      case "BRACKET": {
        const input = resolve(instruction.input);
        let previousUpper = 0n;
        let runningTotal: number | undefined;
        let openEndedSeen = false;
        for (const bracket of instruction.brackets) {
          if (openEndedSeen) throw new Error("An open-ended bracket must be last.");
          const upper = bracket.upperAtomic === undefined ? undefined : BigInt(bracket.upperAtomic);
          if (upper !== undefined && upper <= previousUpper) throw new Error("Policy brackets must increase.");
          let bandEnd = input;
          if (upper !== undefined) {
            const upperRegister = emit({ opcode: 1, immediate: upper });
            bandEnd = emit({ opcode: 7, left: input, right: upperRegister });
          } else {
            openEndedSeen = true;
          }
          let taxable = bandEnd;
          if (previousUpper > 0n) {
            const lowerRegister = emit({ opcode: 1, immediate: previousUpper });
            const flooredEnd = emit({ opcode: 8, left: bandEnd, right: lowerRegister });
            taxable = emit({ opcode: 5, left: flooredEnd, right: lowerRegister });
          }
          const bandTax = emit({
            opcode: 6,
            left: taxable,
            numerator: BigInt(bracket.rateBps),
            denominator: 10_000n,
          });
          runningTotal = runningTotal === undefined
            ? bandTax
            : emit({ opcode: 4, left: runningTotal, right: bandTax });
          if (upper !== undefined) previousUpper = upper;
        }
        if (!openEndedSeen) throw new Error("Policy brackets must end with an open band.");
        output = runningTotal!;
        break;
      }
    }
    registers.set(instruction.out, output);
  }

  const statutoryOutput = pack.outputs.statutoryWithholding
    ?? pack.outputs.statutoryDeduction
    ?? Object.values(pack.outputs)[0];
  if (!statutoryOutput) throw new Error("Policy has no circuit output.");
  const outputRegister = resolve(statutoryOutput);
  const padded = Array.from({ length: PAYO_MAX_POLICY_STEPS }, (_, index) => steps[index]);
  return {
    metadataCommitment: policyMetadataCommitment(pack),
    instructionCount: steps.length,
    opcodes: padded.map((step) => step?.opcode ?? 0),
    left: padded.map((step) => step?.left ?? 0),
    right: padded.map((step) => step?.right ?? 0),
    immediate: padded.map((step) => (step?.immediate ?? 0n).toString()),
    numerator: padded.map((step) => (step?.numerator ?? 0n).toString()),
    denominator: padded.map((step) => (step?.denominator ?? 0n).toString()),
    outputRegister,
  };
}

export function compiledPolicyProgramCommitment(program: CompiledPolicyProgram): `0x${string}` {
  if (program.instructionCount < 1 || program.instructionCount > PAYO_MAX_POLICY_STEPS) {
    throw new Error("Invalid compiled policy instruction count.");
  }
  const chunks: Uint8Array[] = [
    utf8("PAYO_POLICY_PROGRAM_V1"),
    normalizedHexBytes(program.metadataCommitment, 32),
    encodeU32(program.instructionCount),
    Uint8Array.of(program.outputRegister),
  ];
  for (let index = 0; index < PAYO_MAX_POLICY_STEPS; index += 1) {
    chunks.push(
      Uint8Array.of(program.opcodes[index], program.left[index], program.right[index]),
      encodeUint(BigInt(program.immediate[index]), 16),
      encodeUint(BigInt(program.numerator[index]), 8),
      encodeUint(BigInt(program.denominator[index]), 8),
    );
  }
  return toHex(keccak_256(concatBytes(...chunks)));
}

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
  return compiledPolicyProgramCommitment(compilePolicyPack(pack));
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
