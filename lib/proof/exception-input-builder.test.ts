import { readFileSync } from "node:fs";
import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";
import { describe, expect, it } from "vitest";
import { buildFxSnapshot } from "@/lib/domain/fx";
import { claimCapabilityCommitmentV2 } from "@/lib/domain/exception-protocol";
import {
  buildPayrollIntegrityInputs,
  buildPayrollAgreementSnapshot,
  PAYO_NET_INVOICE_POLICY,
  type PayrollIntegrityLineInput,
} from "./input-builder";
import {
  buildObligationSnapshotLinkInputs,
  buildObligationSnapshotPlanInputs,
  buildWageClaimV2Inputs,
  buildWageRemediationV2Inputs,
} from "./exception-input-builder";

const capabilitySecret = `0x${"91".repeat(32)}`;
const capabilityCommitment = claimCapabilityCommitmentV2(capabilitySecret);
const chainId = "0x1";
const sealAddress = "0x12345";

async function executeCircuit(filename: string, input: InputMap) {
  const circuit = JSON.parse(readFileSync(
    new URL(`../../public/circuits/${filename}`, import.meta.url),
    "utf8",
  )) as CompiledCircuit;
  const { witness } = await new Noir(circuit).execute(input);
  expect(witness.byteLength).toBeGreaterThan(0);
  witness.fill(0);
}

function fxSnapshot(token: "STRK" | "USDC", priceAtomic: string, observedAtSeconds: number) {
  const observedAt = new Date(observedAtSeconds * 1_000).toISOString();
  return buildFxSnapshot({
    baseToken: token,
    referenceCurrency: "USD",
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 300,
    minimumSources: 3,
    feedId: `pragma:${token}/USD:${observedAtSeconds}`,
    quotes: ["a", "b", "c"].map((source) => ({
      source: `pragma-${token.toLowerCase()}-${source}`,
      priceAtomic,
      observedAt,
    })),
    now: new Date((observedAtSeconds + 1) * 1_000),
  });
}

function line(input: {
  agreementId: string;
  token: "STRK" | "USDC";
  amount: string;
  fxFloorAtomic?: string;
  finalPay?: PayrollIntegrityLineInput["finalPay"];
}): PayrollIntegrityLineInput {
  return {
    agreementId: input.agreementId,
    recipientAddress: "0x456",
    recipientSalt: `0x${"11".repeat(32)}`,
    agreementSalt: `0x${"22".repeat(32)}`,
    lineSalt: `0x${"33".repeat(32)}`,
    token: input.token,
    earningsAtomic: [input.amount],
    deductionsAtomic: [],
    policyId: PAYO_NET_INVOICE_POLICY.id,
    scheduleCommitment: `0x${"44".repeat(32)}`,
    dueAt: 1_000n,
    validUntil: 2_000n,
    classification: { declared: 2, score: 2, employeeThreshold: 5 },
    finalPay: input.finalPay,
    fxFloorAtomic: input.fxFloorAtomic ?? "0",
    referenceCurrency: "USD",
  };
}

async function snapshotFor(payrollLine: PayrollIntegrityLineInput, payrollFx: ReturnType<typeof fxSnapshot>) {
  const payroll = await buildPayrollIntegrityInputs({
    chainId,
    sealAddress,
    organizationSecret: `0x${"55".repeat(32)}`,
    cycleId: `claim-${payrollLine.agreementId}`,
    revision: 1,
    validityStart: 1_000n,
    validityExpiry: 1_100n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: [payrollFx],
    lines: [payrollLine],
  });
  return buildObligationSnapshotLinkInputs({
    chainId,
    sealAddress,
    ownerAddress: "0xabc",
    payroll,
    claimCapabilityCommitments: { [payrollLine.agreementId]: capabilityCommitment },
    graceEndsAt: 1_100n,
    claimEndsAt: 1_500n,
    validityStart: 999n,
    validityExpiry: 1_000n,
  });
}

describe("vNext exception proof input builders", () => {
  it("freezes the snapshot before payday and proves the identical fact after payday", async () => {
    const payrollLine = line({
      agreementId: "prepayday-usdc",
      token: "USDC",
      amount: "1000000",
    });
    const immutablePayroll = await buildPayrollAgreementSnapshot({
      organizationSecret: `0x${"55".repeat(32)}`,
      cycleId: "prepayday-cycle",
      revision: 1,
      policies: [PAYO_NET_INVOICE_POLICY],
      lines: [payrollLine],
    });
    const planned = await buildObligationSnapshotPlanInputs({
      ownerAddress: "0xabc",
      payroll: immutablePayroll,
      claimCapabilityCommitments: { [payrollLine.agreementId]: capabilityCommitment },
      graceEndsAt: 1_100n,
      claimEndsAt: 1_500n,
    });
    const livePayroll = await buildPayrollIntegrityInputs({
      chainId,
      sealAddress,
      organizationSecret: `0x${"55".repeat(32)}`,
      cycleId: "prepayday-cycle",
      revision: 1,
      validityStart: 1_150n,
      validityExpiry: 1_200n,
      policies: [PAYO_NET_INVOICE_POLICY],
      fxSnapshots: [fxSnapshot("USDC", "1000000", 1_140)],
      lines: [payrollLine],
    });
    const proved = await buildObligationSnapshotLinkInputs({
      chainId,
      sealAddress,
      ownerAddress: "0xabc",
      payroll: livePayroll,
      claimCapabilityCommitments: { [payrollLine.agreementId]: capabilityCommitment },
      graceEndsAt: 1_100n,
      claimEndsAt: 1_500n,
      validityStart: 1_150n,
      validityExpiry: 1_200n,
    });
    expect(livePayroll.agreementRoot).toBe(immutablePayroll.agreementRoot);
    expect(proved.snapshotCommitment).toBe(planned.snapshotCommitment);
    expect(proved.claimRoot).toBe(planned.claimRoot);
    await executeCircuit("obligation_snapshot_link-v5.json", proved.circuitInputs);
  });

  it("builds a deterministic worker-controlled omission claim and linked remediation", async () => {
    const snapshot = await snapshotFor(
      line({ agreementId: "missing-usdc", token: "USDC", amount: "1000000" }),
      fxSnapshot("USDC", "1000000", 990),
    );
    expect(snapshot.publicInputs.proofVersion).toBe("5");
    await executeCircuit("obligation_snapshot_link-v5.json", snapshot.circuitInputs);

    const claim = await buildWageClaimV2Inputs({
      chainId,
      sealAddress,
      snapshot,
      agreementId: "missing-usdc",
      claimCapabilitySecret: capabilitySecret,
      claimKind: "missing_obligation",
      evidence: { source: "unsettled_period" },
      validityStart: 1_150n,
      validityExpiry: 1_200n,
    });
    expect(claim.publicInputs).toMatchObject({ proofVersion: "6", manifestRootHigh: "0" });
    expect(claim.claimFact).toMatchObject({
      claimKind: "missing_obligation",
      shortfallAtomic: "1000000",
      shortfallUnit: "usdc_atomic",
      evidenceSource: "unsettled_period",
    });
    await executeCircuit("wage_claim-v6.json", claim.circuitInputs);

    const remediation = await buildWageRemediationV2Inputs({
      chainId,
      sealAddress,
      claim,
      remediationSecret: `0x${"92".repeat(32)}`,
      actionSalt: `0x${"93".repeat(32)}`,
      amountAtomic: "1000000",
      token: "USDC",
      validityStart: 1_201n,
      validityExpiry: 1_250n,
    });
    expect(remediation.publicInputs.proofVersion).toBe("7");
    expect(remediation.publicInputs.parentNullifierHigh).toBe(claim.publicInputs.subjectNullifierHigh);
    expect(remediation.remediationSubjectNullifier).not.toBe(claim.claimSubjectNullifier);
    await executeCircuit("wage_remediation-v7.json", remediation.circuitInputs);

    await expect(buildWageClaimV2Inputs({
      chainId,
      sealAddress,
      snapshot,
      agreementId: "missing-usdc",
      claimCapabilitySecret: `0x${"99".repeat(32)}`,
      claimKind: "missing_obligation",
      evidence: { source: "unsettled_period" },
      validityStart: 1_150n,
      validityExpiry: 1_200n,
    })).rejects.toThrow(/does not control/i);
    await expect(buildWageRemediationV2Inputs({
      chainId,
      sealAddress,
      claim,
      remediationSecret: `0x${"92".repeat(32)}`,
      actionSalt: `0x${"93".repeat(32)}`,
      amountAtomic: "999999",
      token: "USDC",
      validityStart: 1_201n,
      validityExpiry: 1_250n,
    })).rejects.toThrow(/below/i);
  });

  it("accepts an FX-floor claim only against an anchored failing statement", async () => {
    const snapshot = await snapshotFor(
      line({
        agreementId: "fx-strk",
        token: "STRK",
        amount: "1000000000000000000",
        fxFloorAtomic: "1500000",
      }),
      fxSnapshot("STRK", "2000000", 990),
    );
    const lowFx = fxSnapshot("STRK", "1000000", 1_140);
    const claim = await buildWageClaimV2Inputs({
      chainId,
      sealAddress,
      snapshot,
      agreementId: "fx-strk",
      claimCapabilitySecret: capabilitySecret,
      claimKind: "below_committed_floor",
      evidence: {
        source: "employer_statement",
        observedAt: 1_150n,
        availabilityCommitment: `0x${"77".repeat(32)}`,
        target: {
          kind: "line",
          deductionsAtomic: [],
          lineSalt: `0x${"66".repeat(32)}`,
          classificationTreatment: 2,
          finalIncludedMask: 0,
          referenceValueAtomic: "1000000",
        },
        fxSnapshots: [lowFx],
      },
      validityStart: 1_150n,
      validityExpiry: 1_200n,
    });
    expect(claim.claimFact).toMatchObject({
      claimKind: "below_committed_floor",
      shortfallAtomic: "500000",
      shortfallUnit: "usd_6",
      evidenceSource: "employer_statement",
    });
    expect(claim.statementCommitment).not.toBe(`0x${"00".repeat(32)}`);
    await executeCircuit("wage_claim-v6.json", claim.circuitInputs);

    const manifestRoot = `0x${(
      (BigInt(claim.publicInputs.manifestRootHigh) << 128n)
      | BigInt(claim.publicInputs.manifestRootLow)
    ).toString(16).padStart(64, "0")}`;
    const manifestSiblings = claim.circuitInputs.manifest_siblings as string[];
    const manifestPathBits = claim.circuitInputs.manifest_path_bits as boolean[];
    const wrongSlotPath = [...manifestPathBits];
    wrongSlotPath[0] = !wrongSlotPath[0];
    await expect(buildWageClaimV2Inputs({
      chainId,
      sealAddress,
      snapshot,
      agreementId: "fx-strk",
      claimCapabilitySecret: capabilitySecret,
      claimKind: "below_committed_floor",
      evidence: {
        source: "employer_statement",
        observedAt: 1_150n,
        availabilityCommitment: `0x${"77".repeat(32)}`,
        target: {
          kind: "line",
          deductionsAtomic: [],
          lineSalt: `0x${"66".repeat(32)}`,
          classificationTreatment: 2,
          finalIncludedMask: 0,
          referenceValueAtomic: "1000000",
          manifestRoot,
          manifestMembership: {
            siblings: manifestSiblings,
            pathBits: wrongSlotPath,
          },
        },
        fxSnapshots: [lowFx],
      },
      validityStart: 1_150n,
      validityExpiry: 1_200n,
    })).rejects.toThrow(/different payroll slot/i);
    await expect(buildWageClaimV2Inputs({
      chainId,
      sealAddress,
      snapshot,
      agreementId: "fx-strk",
      claimCapabilitySecret: capabilitySecret,
      claimKind: "below_committed_floor",
      evidence: {
        source: "employer_statement",
        observedAt: 1_150n,
        availabilityCommitment: `0x${"77".repeat(32)}`,
        target: {
          kind: "line",
          deductionsAtomic: [],
          lineSalt: `0x${"67".repeat(32)}`,
          classificationTreatment: 2,
          finalIncludedMask: 0,
          referenceValueAtomic: "1000000",
          manifestRoot,
          manifestMembership: {
            siblings: manifestSiblings,
            pathBits: manifestPathBits,
          },
        },
        fxSnapshots: [lowFx],
      },
      validityStart: 1_150n,
      validityExpiry: 1_200n,
    })).rejects.toThrow(/does not open the registered manifest root/i);

    await expect(buildWageClaimV2Inputs({
      chainId,
      sealAddress,
      snapshot,
      agreementId: "fx-strk",
      claimCapabilitySecret: capabilitySecret,
      claimKind: "below_committed_floor",
      evidence: { source: "unsettled_period" },
      validityStart: 1_150n,
      validityExpiry: 1_200n,
    })).rejects.toThrow(/require an immutable/i);
  });

  it("derives incomplete final pay from the committed component mask", async () => {
    const snapshot = await snapshotFor(
      line({
        agreementId: "final-usdc",
        token: "USDC",
        amount: "1000000",
        finalPay: {
          requiredMask: 3,
          includedMask: 3,
          componentsAtomic: ["800000", "200000"],
        },
      }),
      fxSnapshot("USDC", "1000000", 990),
    );
    const claim = await buildWageClaimV2Inputs({
      chainId,
      sealAddress,
      snapshot,
      agreementId: "final-usdc",
      claimCapabilitySecret: capabilitySecret,
      claimKind: "incomplete_final_pay",
      evidence: {
        source: "employer_statement",
        observedAt: 1_150n,
        availabilityCommitment: `0x${"76".repeat(32)}`,
        target: {
          kind: "line",
          deductionsAtomic: [],
          lineSalt: `0x${"65".repeat(32)}`,
          classificationTreatment: 2,
          finalIncludedMask: 1,
          referenceValueAtomic: "0",
        },
      },
      validityStart: 1_150n,
      validityExpiry: 1_200n,
    });
    expect(claim.claimFact).toMatchObject({
      claimKind: "incomplete_final_pay",
      shortfallAtomic: "200000",
      shortfallUnit: "usdc_atomic",
    });
    await executeCircuit("wage_claim-v6.json", claim.circuitInputs);
  });
});
