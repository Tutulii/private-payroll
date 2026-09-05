import { readFileSync } from "node:fs";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { describe, expect, it } from "vitest";
import { buildFxSnapshot } from "@/lib/domain/fx";
import type { EmploymentAgreement } from "@/lib/domain/obligations";
import { advancedPlanProofCommitment } from "./advanced-plan-commitment";
import { buildPayrollIntegrityInputs, PAYO_NET_INVOICE_POLICY } from "./input-builder";
import {
  buildPayrollBookEntryInputs,
  buildVestingTransitionInputs,
} from "./vesting-transition-input";

const hex = (byte: string): `0x${string}` => `0x${byte.repeat(64)}`;

function vestingAgreement(): Extract<EmploymentAgreement, { agreementVersion: "payo-agreement-v2" }> {
  return {
    agreementVersion: "payo-agreement-v2",
    id: "private-vesting-transition-1",
    organizationId: "organization-vesting",
    principalKind: "human",
    classification: "contractor",
    classificationFactsCommitment: hex("1"),
    jurisdictionCode: "US",
    settlementToken: "STRK",
    earningsAtomic: ["500"],
    schedule: {
      kind: "vesting",
      startsAt: "1970-01-01T00:01:40.000Z",
      cliffAt: "1970-01-01T00:03:20.000Z",
      endsAt: "1970-01-01T00:18:20.000Z",
      totalAtomic: "1000",
      releasedAtomic: "0",
    },
    statutoryPolicy: {
      catalogRoot: hex("2"),
      policyId: PAYO_NET_INVOICE_POLICY.id,
      policyVersion: PAYO_NET_INVOICE_POLICY.revision,
    },
    paymentPlan: {
      planVersion: "payo-payment-plan-v1",
      kind: "private_vesting",
      startsAt: "1970-01-01T00:01:40.000Z",
      cliffAt: "1970-01-01T00:03:20.000Z",
      releaseAt: "1970-01-01T00:10:00.000Z",
      endsAt: "1970-01-01T00:18:20.000Z",
      totalAtomic: "1000",
      releasedAtomic: "0",
      releaseSequence: 0,
    },
    planSalt: hex("3"),
  };
}

async function fixture(mode: "vesting" | "ordinary" = "vesting") {
  const agreement = vestingAgreement();
  const scheduleCommitment = await advancedPlanProofCommitment(agreement);
  const fx = buildFxSnapshot({
    baseToken: "STRK",
    referenceCurrency: "USD",
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 300,
    minimumSources: 3,
    aggregatedSourceCount: 3,
    quotes: [{ source: "pragma-strk", priceAtomic: "100000", observedAt: "1970-01-01T00:09:50.000Z" }],
    now: new Date("1970-01-01T00:10:00.000Z"),
  });
  const payroll = await buildPayrollIntegrityInputs({
    chainId: "0x534e5f4d41494e",
    sealAddress: "0x456",
    organizationSecret: hex("4"),
    cycleId: "vesting-transition-1",
    revision: 1,
    validityStart: 600n,
    validityExpiry: 900n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: [fx],
    lines: [{
      agreementId: agreement.id,
      recipientAddress: "0x789",
      recipientSalt: hex("5"),
      agreementSalt: hex("6"),
      lineSalt: hex("7"),
      token: "STRK",
      earningsAtomic: agreement.earningsAtomic,
      deductionsAtomic: [],
      policyId: PAYO_NET_INVOICE_POLICY.id,
      scheduleCommitment,
      dueAt: 600n,
      validUntil: 900n,
      classification: { declared: 2, score: 2, employeeThreshold: 5 },
      fxFloorAtomic: "0",
      referenceCurrency: "USD",
    }],
  });
  if (mode === "ordinary") {
    return buildPayrollBookEntryInputs({
      payroll,
      ownerAddress: "0x123",
      periodStart: 1n,
      periodEnd: 1_000n,
      totalsSalt: hex("a"),
    });
  }
  return buildVestingTransitionInputs({
    payroll,
    agreement,
    ownerAddress: "0x123",
    periodStart: 1n,
    periodEnd: 1_000n,
    previousStateSalt: hex("8"),
    nextStateSalt: hex("9"),
    totalsSalt: hex("a"),
  });
}

describe("Advanced v3 vesting transition inputs", () => {
  it("executes both ordered shards with TypeScript commitments", async () => {
    const build = await fixture();
    const circuit = JSON.parse(readFileSync(
      new URL("../../circuits/vesting_transition/target/payo_vesting_transition.json", import.meta.url),
      "utf8",
    )) as CompiledCircuit;
    const noir = new Noir(circuit);
    for (const input of build.circuitInputs) {
      const { witness } = await noir.execute(input);
      expect(witness.byteLength).toBeGreaterThan(0);
      witness.fill(0);
    }
    expect(build.publicInputs.map(({ shardIndex }) => shardIndex)).toEqual(["0", "1"]);
    expect(build.previousStateCommitment).toBe(`0x${"00".repeat(32)}`);
  }, 120_000);

  it("executes an ordinary payroll-book entry with zero vesting state", async () => {
    const build = await fixture("ordinary");
    const circuit = JSON.parse(readFileSync(
      new URL("../../circuits/vesting_transition/target/payo_vesting_transition.json", import.meta.url),
      "utf8",
    )) as CompiledCircuit;
    const noir = new Noir(circuit);
    for (const input of build.circuitInputs) {
      const { witness } = await noir.execute(input);
      expect(witness.byteLength).toBeGreaterThan(0);
      witness.fill(0);
    }
    expect(build.entryKind).toBe("ordinary");
    expect(build.publicInputs.map(({ entryKind }) => entryKind)).toEqual(["0", "0"]);
    expect(build.scheduleId).toBe(`0x${"00".repeat(32)}`);
    await expect(noir.execute({ ...build.circuitInputs[0], schedule_id_low: "1" }))
      .rejects.toThrow(/ordinary book entry has vesting schedule/);
  }, 120_000);

  it("fails closed when a stale state or changed book entry reaches the circuit", async () => {
    const build = await fixture();
    const circuit = JSON.parse(readFileSync(
      new URL("../../circuits/vesting_transition/target/payo_vesting_transition.json", import.meta.url),
      "utf8",
    )) as CompiledCircuit;
    const noir = new Noir(circuit);
    await expect(noir.execute({ ...build.circuitInputs[0], previous_state_low: "1" }))
      .rejects.toThrow(/genesis vesting state/);
    await expect(noir.execute({ ...build.circuitInputs[0], book_entry_low: "1" }))
      .rejects.toThrow(/root low limb mismatch/);
  }, 120_000);
});
