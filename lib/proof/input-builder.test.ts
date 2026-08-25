import { readFileSync } from "node:fs";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { describe, expect, it } from "vitest";
import { buildFxSnapshot } from "@/lib/domain/fx";
import {
  buildPayrollIntegrityInputs,
  PAYO_NET_INVOICE_POLICY,
  type PayrollIntegrityLineInput,
} from "./input-builder";

const salts = {
  recipient: `0x${"11".repeat(32)}` as const,
  agreement: `0x${"22".repeat(32)}` as const,
  line: `0x${"33".repeat(32)}` as const,
  schedule: `0x${"44".repeat(32)}` as const,
};

function snapshot(token: "STRK" | "USDC", priceAtomic: string) {
  return buildFxSnapshot({
    baseToken: token,
    referenceCurrency: "USD",
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 30,
    minimumSources: 3,
    feedId: `pragma:${token}/USD:median`,
    quotes: ["a", "b", "c"].map((source, index) => ({
      source: `pragma-${token.toLowerCase()}-${source}`,
      priceAtomic,
      observedAt: `1970-01-01T00:16:${40 + index}.000Z`,
    })),
    now: new Date(1_010_000),
  });
}

function line(input: {
  agreementId: string;
  recipientAddress: string;
  token: "STRK" | "USDC";
  amount: string;
  saltByte: string;
}): PayrollIntegrityLineInput {
  return {
    agreementId: input.agreementId,
    recipientAddress: input.recipientAddress,
    recipientSalt: `0x${input.saltByte.repeat(32)}`,
    agreementSalt: salts.agreement,
    lineSalt: salts.line,
    token: input.token,
    earningsAtomic: [input.amount],
    deductionsAtomic: [],
    policyId: PAYO_NET_INVOICE_POLICY.id,
    scheduleCommitment: salts.schedule,
    dueAt: 1_000n,
    validUntil: 2_000n,
    classification: { declared: 2, score: 2, employeeThreshold: 5 },
    fxFloorAtomic: "0",
    referenceCurrency: "USD",
  };
}

describe("production PayrollIntegrity input builder", () => {
  it("builds and executes both mixed-token proof shards against the pinned circuit", async () => {
    const result = await buildPayrollIntegrityInputs({
      chainId: "0x1",
      sealAddress: "0x12345",
      organizationSecret: `0x${"55".repeat(32)}`,
      cycleId: "production-builder-mixed-token",
      revision: 1,
      validityStart: 1_010n,
      validityExpiry: 2_000n,
      policies: [PAYO_NET_INVOICE_POLICY],
      fxSnapshots: [snapshot("STRK", "150000"), snapshot("USDC", "1000000")],
      lines: [
        line({ agreementId: "invoice-strk", recipientAddress: "0x111", token: "STRK", amount: "1000000000000000000", saltByte: "66" }),
        line({ agreementId: "invoice-usdc", recipientAddress: "0x222", token: "USDC", amount: "1000000", saltByte: "77" }),
      ],
    });
    expect(result.agreementRoot).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.manifestRoot).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.publicInputs[0]).toMatchObject({
      agreementRootHigh: result.witness.circuitInputs[0].agreement_root_high,
      manifestRootLow: result.witness.circuitInputs[0].manifest_root_low,
      shardIndex: "0",
    });
    expect(result.publicInputs[1].shardIndex).toBe("1");

    const circuit = JSON.parse(readFileSync(
      new URL("../../public/circuits/payroll_integrity-v1.json", import.meta.url),
      "utf8",
    )) as CompiledCircuit;
    const noir = new Noir(circuit);
    for (const input of result.witness.circuitInputs) {
      const { witness } = await noir.execute(input);
      expect(witness.byteLength).toBeGreaterThan(0);
      witness.fill(0);
    }
  }, 120_000);

  it("rejects policy, FX, classification, and duplicate agreement inconsistencies before proving", async () => {
    const base = line({
      agreementId: "duplicate",
      recipientAddress: "0x111",
      token: "USDC",
      amount: "1000000",
      saltByte: "66",
    });
    await expect(buildPayrollIntegrityInputs({
      chainId: "0x1",
      sealAddress: "0x12345",
      organizationSecret: `0x${"55".repeat(32)}`,
      cycleId: "negative-builder",
      revision: 1,
      validityStart: 1_010n,
      validityExpiry: 2_000n,
      policies: [PAYO_NET_INVOICE_POLICY],
      fxSnapshots: [snapshot("USDC", "1000000")],
      lines: [base, { ...base, recipientAddress: "0x222" }],
    })).rejects.toThrow("identifiers must be unique");

    await expect(buildPayrollIntegrityInputs({
      chainId: "0x1",
      sealAddress: "0x12345",
      organizationSecret: `0x${"55".repeat(32)}`,
      cycleId: "negative-classification",
      revision: 1,
      validityStart: 1_010n,
      validityExpiry: 2_000n,
      policies: [PAYO_NET_INVOICE_POLICY],
      fxSnapshots: [snapshot("USDC", "1000000")],
      lines: [{ ...base, classification: { declared: 1, score: 2, employeeThreshold: 5 } }],
    })).rejects.toThrow("classification facts");
  });
});
