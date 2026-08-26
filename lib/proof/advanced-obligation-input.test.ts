import { readFileSync } from "node:fs";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { describe, expect, it } from "vitest";
import { buildFxSnapshot } from "@/lib/domain/fx";
import type { EmploymentAgreement } from "@/lib/domain/obligations";
import { advancedPlanProofCommitment } from "./advanced-plan-commitment";
import { buildAdvancedObligationInputs } from "./advanced-obligation-input";
import { buildPayrollIntegrityInputs, PAYO_NET_INVOICE_POLICY } from "./input-builder";

const ZERO_CATALOG = `0x${"11".repeat(32)}`;

function checkpointAgreement(): Extract<EmploymentAgreement, { agreementVersion: "payo-agreement-v2" }> {
  return {
    agreementVersion: "payo-agreement-v2",
    id: "advanced-checkpoint-1",
    organizationId: "organization-advanced",
    principalKind: "human",
    classification: "contractor",
    classificationFactsCommitment: `0x${"12".repeat(32)}`,
    jurisdictionCode: "US",
    settlementToken: "USDC",
    earningsAtomic: ["500"],
    schedule: {
      kind: "stream",
      startsAt: "1970-01-01T00:00:00.000Z",
      endsAt: "1970-01-01T00:33:20.000Z",
      totalAtomic: "1000",
      claimedAtomic: "0",
    },
    statutoryPolicy: {
      catalogRoot: ZERO_CATALOG,
      policyId: PAYO_NET_INVOICE_POLICY.id,
      policyVersion: PAYO_NET_INVOICE_POLICY.revision,
    },
    paymentPlan: {
      planVersion: "payo-payment-plan-v1",
      kind: "checkpoint_stream",
      startsAt: "1970-01-01T00:00:00.000Z",
      endsAt: "1970-01-01T00:33:20.000Z",
      totalAtomic: "1000",
      settledAtomic: "0",
      minimumCheckpointSeconds: 300,
      checkpoint: {
        sequence: 1,
        checkpointAt: "1970-01-01T00:16:40.000Z",
        cumulativeEntitlementAtomic: "500",
        attestationCommitment: `0x${"13".repeat(32)}`,
      },
    },
    planSalt: `0x${"14".repeat(32)}`,
  };
}

describe("advanced obligation proof input", () => {
  it("executes both linked v2 shards against the pinned circuit", async () => {
    const agreement = checkpointAgreement();
    const scheduleCommitment = await advancedPlanProofCommitment(agreement);
    const snapshot = buildFxSnapshot({
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
    const payroll = await buildPayrollIntegrityInputs({
      chainId: "0x1",
      sealAddress: "0x12345",
      organizationSecret: `0x${"15".repeat(32)}`,
      cycleId: "advanced-checkpoint-proof",
      revision: 1,
      validityStart: 1_000n,
      validityExpiry: 2_000n,
      policies: [PAYO_NET_INVOICE_POLICY],
      fxSnapshots: [snapshot],
      lines: [{
        agreementId: agreement.id,
        recipientAddress: "0x456",
        recipientSalt: `0x${"16".repeat(32)}`,
        agreementSalt: `0x${"17".repeat(32)}`,
        lineSalt: `0x${"18".repeat(32)}`,
        token: "USDC",
        earningsAtomic: agreement.earningsAtomic,
        deductionsAtomic: [],
        policyId: PAYO_NET_INVOICE_POLICY.id,
        scheduleCommitment,
        dueAt: 1_000n,
        validUntil: 2_000n,
        classification: { declared: 2, score: 2, employeeThreshold: 5 },
        fxFloorAtomic: "0",
        referenceCurrency: "USD",
      }],
    });
    const advanced = buildAdvancedObligationInputs({ payroll, agreements: [agreement] });
    const circuit = JSON.parse(readFileSync(
      new URL("../../public/circuits/advanced_obligation-v2.json", import.meta.url),
      "utf8",
    )) as CompiledCircuit;
    const noir = new Noir(circuit);
    for (const input of advanced.witness.circuitInputs) {
      const { witness } = await noir.execute(input);
      expect(witness.byteLength).toBeGreaterThan(0);
      witness.fill(0);
    }
  }, 120_000);

  it("rejects an advanced witness that does not cover every proved line", async () => {
    const agreement = checkpointAgreement();
    const fakePayroll = { calculatedLines: [{ agreementId: agreement.id }] } as never;
    expect(() => buildAdvancedObligationInputs({ payroll: fakePayroll, agreements: [] }))
      .toThrow(/cover the proved payroll manifest/);
  });
});
