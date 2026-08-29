import { describe, expect, it } from "vitest";
import {
  PAYO_EXCEPTION_PUBLIC_INPUT_COUNT,
  claimCapabilityCommitmentV2,
  claimFactCommitmentV2,
  claimSubjectNullifierV2,
  exceptionClaimFactSchema,
  mapExceptionPublicInputsV2,
  obligationSnapshotCommitmentV2,
  payrollStatementCommitmentV2,
  remediationFactCommitmentV2,
  remediationSubjectNullifierV2,
} from "./exception-protocol";

const hex = (byte: string) => `0x${byte.repeat(32)}`;

describe("PAYO exception protocol v2", () => {
  const snapshot = {
    schemaVersion: 2 as const,
    runNullifier: hex("11"),
    baseAgreementRoot: hex("21"),
    obligationRoot: hex("22"),
    policyRoot: hex("33"),
    ownerAddress: "0x1234",
    dueAt: "100",
    graceEndsAt: "200",
    claimEndsAt: "500",
    availabilityCommitment: hex("44"),
  };

  it("commits the snapshot and statement canonically", () => {
    const snapshotCommitment = obligationSnapshotCommitmentV2(snapshot);
    const statementCommitment = payrollStatementCommitmentV2({
      schemaVersion: 2,
      runNullifier: snapshot.runNullifier,
      snapshotCommitment,
      manifestRoot: hex("55"),
      fxRoot: hex("66"),
      availabilityCommitment: hex("77"),
      observedAt: "210",
      source: "employer_statement",
    });
    expect(snapshotCommitment).toBe("0xf75739a62e3338d68af1c30c98d7029bd32ba29fc61fb9aefdb560d5d6ac8ac4");
    expect(statementCommitment).toBe("0xa7968d6d92db5ff5e29c8cda2ec1cf714de4885e67b1d353a7428a0a46b5a86b");
    expect(statementCommitment).not.toBe(snapshotCommitment);
  });

  it("binds claimant capability, exact claim fact and remediation", () => {
    const capabilitySecret = hex("88");
    const capability = claimCapabilityCommitmentV2(capabilitySecret);
    const subject = claimSubjectNullifierV2({
      claimCapabilitySecret: capabilitySecret,
      runNullifier: snapshot.runNullifier,
      agreementLeaf: hex("99"),
      claimKind: "below_committed_floor",
    });
    const snapshotCommitment = obligationSnapshotCommitmentV2(snapshot);
    const claimFact = claimFactCommitmentV2({
      claimSubjectNullifier: subject,
      runNullifier: snapshot.runNullifier,
      snapshotCommitment,
      statementCommitment: hex("aa"),
      manifestRoot: hex("bb"),
      agreementLeaf: hex("99"),
      targetIndex: 4,
      claimKind: "below_committed_floor",
      shortfallAtomic: "250000",
      shortfallUnit: "usd_6",
      obligationToken: "STRK",
      evidenceSource: "employer_statement",
    });
    const remediationSecret = hex("cc");
    const remediationSubject = remediationSubjectNullifierV2({
      claimSubjectNullifier: subject,
      remediationSecret,
    });
    const remediationFact = remediationFactCommitmentV2({
      remediationSubjectNullifier: remediationSubject,
      claimSubjectNullifier: subject,
      claimFactCommitment: claimFact,
      recipientCommitment: hex("dd"),
      token: "STRK",
      amountAtomic: "1000000000000000000",
      referenceValueAtomic: "300000",
      referenceUnit: "usd_6",
      fxRoot: hex("66"),
    });
    expect(capability).toBe("0x17e2a10450e47c5a34a1ef9c3e42b67dd936cb0224c8e574c4b0aee3edbe6062");
    expect(subject).toBe("0xff1d73feb9ab45e78c03fd6deba118c17681c574d0aa474a663683590c74609a");
    expect(claimFact).toBe("0xa6ed511782bfe75f9faa7c42c55e1670f9098bcf08ce97b7cb088c0b4a92c2ac");
    expect(remediationSubject).toBe("0x78b13525f3b40079e59fc98daaf2215cfeb32afed8e350681214da9312109e7d");
    expect(remediationFact).toBe("0xd65c00b4c1991ccb248de82827784c7f54fcf52b48f21a180e0518dbed96f625");
    expect(claimSubjectNullifierV2({
      claimCapabilitySecret: capabilitySecret,
      runNullifier: snapshot.runNullifier,
      agreementLeaf: hex("99"),
      claimKind: "missing_obligation",
    })).not.toBe(subject);
    expect(remediationFactCommitmentV2({
      remediationSubjectNullifier: remediationSubject,
      claimSubjectNullifier: subject,
      claimFactCommitment: claimFact,
      recipientCommitment: hex("dd"),
      token: "STRK",
      amountAtomic: "1000000000000000001",
      referenceValueAtomic: "300000",
      referenceUnit: "usd_6",
      fxRoot: hex("66"),
    })).not.toBe(remediationFact);
  });

  it("rejects dimensionally invalid shortfalls", () => {
    expect(() => exceptionClaimFactSchema.parse({
      claimSubjectNullifier: hex("01"),
      runNullifier: hex("02"),
      snapshotCommitment: hex("03"),
      statementCommitment: hex("04"),
      manifestRoot: hex("05"),
      agreementLeaf: hex("06"),
      targetIndex: 0,
      claimKind: "below_committed_floor",
      shortfallAtomic: "1",
      shortfallUnit: "strk_atomic",
      obligationToken: "STRK",
      evidenceSource: "employer_statement",
    })).toThrow(/reference-currency/);
    expect(() => exceptionClaimFactSchema.parse({
      claimSubjectNullifier: hex("01"),
      runNullifier: hex("02"),
      snapshotCommitment: hex("03"),
      statementCommitment: hex("04"),
      manifestRoot: hex("05"),
      agreementLeaf: hex("06"),
      targetIndex: 0,
      claimKind: "missing_obligation",
      shortfallAtomic: "1",
      shortfallUnit: "strk_atomic",
      obligationToken: "STRK",
      evidenceSource: "payo_run",
    })).toThrow(/verified native PAYO run/);
  });

  it("maps the exact 23-field public-input ABI", () => {
    const values = Array.from({ length: PAYO_EXCEPTION_PUBLIC_INPUT_COUNT }, (_, index) => String(index));
    expect(PAYO_EXCEPTION_PUBLIC_INPUT_COUNT).toBe(23);
    expect(mapExceptionPublicInputsV2(values)).toMatchObject({
      chainId: "0",
      parentFactCommitmentLow: "19",
      validityStart: "20",
      validityExpiry: "21",
      shardIndex: "22",
    });
    expect(() => mapExceptionPublicInputsV2(values.slice(1))).toThrow(/Expected 23/);
  });
});
