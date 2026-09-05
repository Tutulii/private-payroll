import { describe, expect, it } from "vitest";
import { splitHashToU128 } from "@/lib/crypto/commitments";
import {
  claimFactCommitmentV2,
  remediationFactCommitmentV2,
  remediationSubjectNullifierV2,
  type ExceptionPublicInputsV2,
} from "@/lib/domain/exception-protocol";
import {
  VESTING_TRANSITION_CIRCUIT_SHA256,
  VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
  type ExceptionCircuitProof,
  type VestingBookProof,
} from "@/lib/proof/protocol";
import { createProofCommitter } from "@/lib/proof/commitments";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import { buildExceptionPayrollBookEntryInputs } from "@/lib/proof/vesting-transition-input";
import {
  buildBeginExceptionBookAuthorizationCall,
  buildExceptionBookAction,
  buildFinalizeClaimBookEntryCall,
} from "./payo-vesting-book";

const hex = (byte: string): `0x${string}` => `0x${byte.repeat(32)}`;
const BOOK_SEAL = "0x456";
const EXCEPTION_SEAL = "0x999";
const OWNER = "0x123";

function split(value: string) {
  const valueLimbs = splitHashToU128(value);
  return { high: valueLimbs.high.toString(), low: valueLimbs.low.toString() };
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
  const subjectValue = split(input.subject);
  const parent = split(input.parent);
  const fact = split(input.fact);
  const parentFact = split(input.parentFact);
  return {
    chainId: "1",
    sealAddress: EXCEPTION_SEAL,
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
    subjectNullifierHigh: subjectValue.high,
    subjectNullifierLow: subjectValue.low,
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

function sourceProof(publicInputs: ExceptionPublicInputsV2): ExceptionCircuitProof {
  const proofCalldata = ["0x111"];
  return {
    proof: new Uint8Array(),
    proofCalldata,
    calldataHash: hashProofCalldata(proofCalldata),
    publicInputs,
  };
}

function bookProof(
  build: Awaited<ReturnType<typeof buildExceptionPayrollBookEntryInputs>>,
): VestingBookProof {
  return {
    proofVersion: 3,
    entryKind: build.entryKind,
    circuitSha256: VESTING_TRANSITION_CIRCUIT_SHA256,
    verificationKeySha256: VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
    provingTimeMs: 1,
    scheduleId: build.scheduleId,
    previousStateCommitment: build.previousStateCommitment,
    nextStateCommitment: build.nextStateCommitment,
    releaseNullifier: build.releaseNullifier,
    bookEntry: build.bookEntry,
    bookEntryCommitment: build.bookEntryCommitment,
    shards: build.publicInputs.map((publicInputs, shardIndex) => {
      const proofCalldata = [`0x${(shardIndex + 2).toString(16)}`];
      return {
        shardIndex: shardIndex as 0 | 1,
        proof: new Uint8Array(),
        proofCalldata,
        calldataHash: hashProofCalldata(proofCalldata),
        publicInputs,
      };
    }) as VestingBookProof["shards"],
  };
}

async function claimFixture() {
  const fact = claimFactCommitmentV2(claimFact);
  const publicInputs = source({
    version: "6",
    manifestRoot: claimFact.manifestRoot,
    subject: claimFact.claimSubjectNullifier,
    parent: claimFact.runNullifier,
    fact,
    parentFact: claimFact.snapshotCommitment,
  });
  const build = await buildExceptionPayrollBookEntryInputs({
    source: publicInputs,
    entryKind: "claim",
    bookSealAddress: BOOK_SEAL,
    sourceSealAddress: EXCEPTION_SEAL,
    ownerAddress: OWNER,
    runNullifier: claimFact.runNullifier,
    periodStart: 1n,
    periodEnd: 1_000n,
    totalsSalt: hex("31"),
    claimFact,
  });
  return { sourceProof: sourceProof(publicInputs), vestingBook: bookProof(build) };
}

async function remediationFixture() {
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
  const publicInputs = source({
    version: "7",
    manifestRoot: action,
    subject,
    parent: claimFact.claimSubjectNullifier,
    fact,
    parentFact: claimCommitment,
  });
  const build = await buildExceptionPayrollBookEntryInputs({
    source: publicInputs,
    entryKind: "remediation",
    bookSealAddress: BOOK_SEAL,
    sourceSealAddress: EXCEPTION_SEAL,
    ownerAddress: OWNER,
    runNullifier: claimFact.runNullifier,
    periodStart: 1n,
    periodEnd: 1_000n,
    totalsSalt: hex("32"),
    claimFact,
    remediation,
  });
  return { sourceProof: sourceProof(publicInputs), vestingBook: bookProof(build) };
}

describe("exception-backed universal payroll-book calls", () => {
  it("builds Claim v6 authorization and finalization calls from one exact proof pair", async () => {
    const fixture = await claimFixture();
    const begin = buildBeginExceptionBookAuthorizationCall({
      sealAddress: BOOK_SEAL,
      exceptionSealAddress: EXCEPTION_SEAL,
      chainId: "0x1",
      ...fixture,
    });
    const finalize = buildFinalizeClaimBookEntryCall({
      sealAddress: BOOK_SEAL,
      exceptionSealAddress: EXCEPTION_SEAL,
      chainId: "0x1",
      ...fixture,
    });
    expect(begin.entrypoint).toBe("begin_exception_book_authorization");
    expect(BigInt(begin.contractAddress)).toBe(BigInt(BOOK_SEAL));
    expect(finalize.entrypoint).toBe("finalize_claim_book_entry");
    expect(BigInt(finalize.contractAddress)).toBe(BigInt(BOOK_SEAL));
    expect(Array.isArray(finalize.calldata)).toBe(true);
    const finalizeCalldata = finalize.calldata as string[];
    expect(finalizeCalldata.slice(0, 2).map(BigInt)).toEqual([
      BigInt(fixture.sourceProof.publicInputs.subjectNullifierHigh),
      BigInt(fixture.sourceProof.publicInputs.subjectNullifierLow),
    ]);
  });

  it("builds the remediation callback and rejects a mutated source fact", async () => {
    const fixture = await remediationFixture();
    const action = buildExceptionBookAction({
      sealAddress: BOOK_SEAL,
      exceptionSealAddress: EXCEPTION_SEAL,
      chainId: "0x1",
      ...fixture,
    });
    expect(action.type).toBe("invoke");
    expect(BigInt(action.contract)).toBe(BigInt(BOOK_SEAL));
    expect(action.calldata.slice(2, 4).map(BigInt)).toEqual([0n, 0n]);

    const changed = structuredClone(fixture);
    changed.sourceProof.publicInputs.factCommitmentLow = (
      BigInt(changed.sourceProof.publicInputs.factCommitmentLow) + 1n
    ).toString();
    expect(() => buildExceptionBookAction({
      sealAddress: BOOK_SEAL,
      exceptionSealAddress: EXCEPTION_SEAL,
      chainId: "0x1",
      ...changed,
    })).toThrow("source fact low");
  });
});
