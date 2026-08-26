import { readFileSync } from "node:fs";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { describe, expect, it } from "vitest";
import { buildFxSnapshot } from "@/lib/domain/fx";
import {
  buildPayrollIntegrityInputs,
  PAYO_NET_INVOICE_POLICY,
  type PayrollIntegrityLineInput,
} from "./input-builder";
import { buildWageClaimInputs, buildWageRemediationInputs } from "./wage-claim-input";

const claimCircuit = JSON.parse(readFileSync(
  new URL("../../public/circuits/wage_claim-v3.json", import.meta.url), "utf8",
)) as CompiledCircuit;
const remediationCircuit = JSON.parse(readFileSync(
  new URL("../../public/circuits/wage_remediation-v4.json", import.meta.url), "utf8",
)) as CompiledCircuit;

function snapshot() {
  return buildFxSnapshot({
    baseToken: "USDC",
    referenceCurrency: "USD",
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 300,
    minimumSources: 3,
    aggregatedSourceCount: 5,
    quotes: [{ source: "pragma-usdc", priceAtomic: "1000000", observedAt: "1970-01-01T00:16:30.000Z" }],
    now: new Date("1970-01-01T00:16:40.000Z"),
  });
}

function line(overrides: Partial<PayrollIntegrityLineInput> = {}): PayrollIntegrityLineInput {
  return {
    agreementId: "claim-agreement",
    recipientAddress: "0x456",
    recipientSalt: `0x${"21".repeat(32)}`,
    agreementSalt: `0x${"22".repeat(32)}`,
    lineSalt: `0x${"23".repeat(32)}`,
    token: "USDC",
    earningsAtomic: ["100"],
    deductionsAtomic: [],
    policyId: PAYO_NET_INVOICE_POLICY.id,
    scheduleCommitment: `0x${"24".repeat(32)}`,
    dueAt: 1_000n,
    validUntil: 2_000n,
    classification: { declared: 2, score: 2, employeeThreshold: 5 },
    fxFloorAtomic: "0",
    referenceCurrency: "USD",
    ...overrides,
  };
}

async function payroll(payrollLine: PayrollIntegrityLineInput) {
  return buildPayrollIntegrityInputs({
    chainId: "0x1",
    sealAddress: "0x12345",
    organizationSecret: `0x${"25".repeat(32)}`,
    cycleId: "private-wage-claim",
    revision: 1,
    validityStart: 1_000n,
    validityExpiry: 2_000n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: [snapshot()],
    lines: [payrollLine],
  });
}

async function executeBoth(circuit: CompiledCircuit, inputs: readonly [object, object]) {
  const noir = new Noir(circuit);
  for (const input of inputs) {
    const { witness } = await noir.execute(input as never);
    expect(witness.byteLength).toBeGreaterThan(0);
    witness.fill(0);
  }
}

describe("private claim and remediation proof inputs", () => {
  it("proves a missing due obligation and an exact supplemental remediation", async () => {
    const claim = await buildWageClaimInputs({
      payroll: await payroll(line()),
      agreementId: "claim-agreement",
      claimKind: "missing_obligation",
      claimSalt: `0x${"26".repeat(32)}`,
      validityStart: 1_500n,
      validityExpiry: 2_000n,
    });
    expect(claim.shortfallAtomic).toBe("100");
    await executeBoth(claimCircuit, claim.witness.circuitInputs);
    const remediation = await buildWageRemediationInputs({
      claim,
      amountAtomic: "100",
      token: "USDC",
      remediationSalt: `0x${"27".repeat(32)}`,
      validityStart: 1_600n,
      validityExpiry: 2_000n,
    });
    await executeBoth(remediationCircuit, remediation.witness.circuitInputs);
    await expect(buildWageRemediationInputs({
      claim,
      amountAtomic: "99",
      token: "USDC",
      remediationSalt: `0x${"27".repeat(32)}`,
      validityStart: 1_600n,
      validityExpiry: 2_000n,
    })).rejects.toThrow(/below the proved private shortfall/);
  }, 120_000);

  it("proves a below-floor manifest without revealing the floor", async () => {
    const claim = await buildWageClaimInputs({
      payroll: await payroll(line({ fxFloorAtomic: "100" })),
      agreementId: "claim-agreement",
      claimKind: "below_committed_floor",
      disputedReferenceValueAtomic: "60",
      claimSalt: `0x${"28".repeat(32)}`,
      validityStart: 1_500n,
      validityExpiry: 2_000n,
    });
    expect(claim.shortfallAtomic).toBe("40");
    await executeBoth(claimCircuit, claim.witness.circuitInputs);
  }, 120_000);

  it("proves an incomplete final-pay manifest and rejects a complete mask", async () => {
    const base = await payroll(line({
      earningsAtomic: ["70", "30"],
      finalPay: { requiredMask: 3, includedMask: 3, componentsAtomic: ["70", "30", "0", "0", "0"] },
    }));
    const claim = await buildWageClaimInputs({
      payroll: base,
      agreementId: "claim-agreement",
      claimKind: "incomplete_final_pay",
      disputedFinalIncludedMask: 1,
      claimSalt: `0x${"29".repeat(32)}`,
      validityStart: 1_500n,
      validityExpiry: 2_000n,
    });
    expect(claim.shortfallAtomic).toBe("30");
    await executeBoth(claimCircuit, claim.witness.circuitInputs);
    await expect(buildWageClaimInputs({
      payroll: base,
      agreementId: "claim-agreement",
      claimKind: "incomplete_final_pay",
      disputedFinalIncludedMask: 3,
      claimSalt: `0x${"29".repeat(32)}`,
      validityStart: 1_500n,
      validityExpiry: 2_000n,
    })).rejects.toThrow(/omit at least one/);
  }, 120_000);
});
