import { readFileSync } from "node:fs";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { describe, expect, it } from "vitest";
import {
  claimFactCommitmentV2,
  remediationFactCommitmentV2,
  remediationSubjectNullifierV2,
  type ExceptionPublicInputsV2,
} from "@/lib/domain/exception-protocol";
import { splitHashToU128 } from "@/lib/crypto/commitments";
import { createProofCommitter } from "./commitments";
import { buildExceptionPayrollBookEntryInputs } from "./vesting-transition-input";

const hex = (byte: string): `0x${string}` => `0x${byte.repeat(32)}`;

function split(value: string) {
  const limbs = splitHashToU128(value);
  return { high: limbs.high.toString(), low: limbs.low.toString() };
}

function source(input: {
  version: "6" | "7";
  manifestRoot: string;
  subject: string;
  parent: string;
  fact: string;
  parentFact: string;
}): ExceptionPublicInputsV2 {
  const agreement = split(hex("21"));
  const manifest = split(input.manifestRoot);
  const policy = split(hex("22"));
  const zero = split(hex("00"));
  const subject = split(input.subject);
  const parent = split(input.parent);
  const fact = split(input.fact);
  const parentFact = split(input.parentFact);
  return {
    chainId: "1",
    sealAddress: "0x999",
    proofVersion: input.version,
    schemaVersion: "2",
    agreementRootHigh: agreement.high,
    agreementRootLow: agreement.low,
    manifestRootHigh: manifest.high,
    manifestRootLow: manifest.low,
    policyRootHigh: policy.high,
    policyRootLow: policy.low,
    fxRootHigh: zero.high,
    fxRootLow: zero.low,
    subjectNullifierHigh: subject.high,
    subjectNullifierLow: subject.low,
    parentNullifierHigh: parent.high,
    parentNullifierLow: parent.low,
    factCommitmentHigh: fact.high,
    factCommitmentLow: fact.low,
    parentFactCommitmentHigh: parentFact.high,
    parentFactCommitmentLow: parentFact.low,
    validityStart: "600",
    validityExpiry: "900",
    shardIndex: "0",
  };
}

const claimFact = {
  claimSubjectNullifier: hex("11"),
  runNullifier: hex("12"),
  snapshotCommitment: hex("13"),
  statementCommitment: hex("00"),
  manifestRoot: hex("00"),
  agreementLeaf: hex("14"),
  targetIndex: 0,
  claimKind: "missing_obligation" as const,
  shortfallAtomic: "100",
  shortfallUnit: "strk_atomic" as const,
  obligationToken: "STRK" as const,
  evidenceSource: "unsettled_period" as const,
};

function circuit() {
  return new Noir(JSON.parse(readFileSync(
    new URL("../../public/circuits/vesting_transition-v3.json", import.meta.url),
    "utf8",
  )) as CompiledCircuit);
}

describe("universal claim and remediation book proof", () => {
  it("binds a zero-value Claim v6 fact into both ordered book shards", async () => {
    const fact = claimFactCommitmentV2(claimFact);
    const build = await buildExceptionPayrollBookEntryInputs({
      source: source({
        version: "6",
        manifestRoot: claimFact.manifestRoot,
        subject: claimFact.claimSubjectNullifier,
        parent: claimFact.runNullifier,
        fact,
        parentFact: claimFact.snapshotCommitment,
      }),
      entryKind: "claim",
      bookSealAddress: "0x456",
      sourceSealAddress: "0x999",
      ownerAddress: "0x123",
      runNullifier: claimFact.runNullifier,
      periodStart: 1n,
      periodEnd: 1_000n,
      totalsSalt: hex("31"),
      claimFact,
    });
    const noir = circuit();
    for (const input of build.circuitInputs) {
      const { witness } = await noir.execute(input);
      witness.fill(0);
    }
    expect(build.entryKind).toBe("claim");
    expect(build.bookEntry.totalsDisclosure).toBe("hidden");
    expect(build.totalsOpening.totals.STRK.netAtomic).toBe("0");

    const changed = structuredClone(build.circuitInputs[0]);
    (changed.exception_entry as Record<string, unknown>).shortfall_atomic = "99";
    await expect(noir.execute(changed)).rejects.toThrow(/claim fact mismatch/);
  }, 120_000);

  it("binds Remediation v7 to its exact private token, amount and action", async () => {
    const claimCommitment = claimFactCommitmentV2(claimFact);
    const remediation = {
      remediationSecret: hex("15"),
      recipientCommitment: hex("16"),
      amountAtomic: "100",
      referenceValueAtomic: "100",
      actionSalt: hex("17"),
    };
    const subject = remediationSubjectNullifierV2({
      claimSubjectNullifier: claimFact.claimSubjectNullifier,
      remediationSecret: remediation.remediationSecret,
    });
    const committer = await createProofCommitter();
    const action = committer.proofRemediationActionCommitment({
      claimSubjectNullifier: claimFact.claimSubjectNullifier,
      recipientCommitment: remediation.recipientCommitment,
      token: 0,
      amountAtomic: remediation.amountAtomic,
      salt: remediation.actionSalt,
    });
    const fact = remediationFactCommitmentV2({
      remediationSubjectNullifier: subject,
      claimSubjectNullifier: claimFact.claimSubjectNullifier,
      claimFactCommitment: claimCommitment,
      recipientCommitment: remediation.recipientCommitment,
      token: "STRK",
      amountAtomic: remediation.amountAtomic,
      referenceValueAtomic: remediation.referenceValueAtomic,
      referenceUnit: claimFact.shortfallUnit,
      fxRoot: hex("00"),
    });
    const build = await buildExceptionPayrollBookEntryInputs({
      source: source({
        version: "7",
        manifestRoot: action,
        subject,
        parent: claimFact.claimSubjectNullifier,
        fact,
        parentFact: claimCommitment,
      }),
      entryKind: "remediation",
      bookSealAddress: "0x456",
      sourceSealAddress: "0x999",
      ownerAddress: "0x123",
      runNullifier: claimFact.runNullifier,
      periodStart: 1n,
      periodEnd: 1_000n,
      totalsSalt: hex("32"),
      totalsDisclosure: "hidden",
      claimFact,
      remediation,
    });
    const noir = circuit();
    for (const input of build.circuitInputs) {
      const { witness } = await noir.execute(input);
      witness.fill(0);
    }
    expect(build.entryKind).toBe("remediation");
    expect(build.totalsOpening.totals.STRK.netAtomic).toBe("100");

    const changed = structuredClone(build.circuitInputs[0]);
    (changed.exception_entry as Record<string, unknown>).remediation_amount_atomic = "99";
    await expect(noir.execute(changed)).rejects.toThrow(/remediation action mismatch/);
  }, 120_000);
});
