import { describe, expect, it } from "vitest";
import type { ExceptionCircuitProof, PayrollIntegrityShardProof } from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import { obligationSnapshotCommitmentV2, payrollStatementCommitmentV2 } from "@/lib/domain/exception-protocol";
import {
  buildAuthorizeClaimCall,
  buildAuthorizedExceptionAction,
  buildAuthorizedPayrollAction,
  buildBeginPayrollAuthorizationCall,
  buildRegisterEmployerStatementCall,
  buildRegisterObligationSnapshotCall,
  buildVerifyPayrollAuthorizationProofCall,
} from "./payo-exception-seal";

const SEAL = "0x123";
const CHAIN = "0x534e5f4d41494e";

function payrollShard(shardIndex: 0 | 1): PayrollIntegrityShardProof {
  const proofCalldata = ["0x1", "0x2"];
  return {
    shardIndex,
    proof: new Uint8Array([1]),
    proofCalldata,
    calldataHash: hashProofCalldata(proofCalldata),
    publicInputs: {
      chainId: CHAIN,
      sealAddress: SEAL,
      proofVersion: "2",
      schemaVersion: "1",
      agreementRootHigh: "3",
      agreementRootLow: "4",
      manifestRootHigh: "5",
      manifestRootLow: "6",
      policyRootHigh: "7",
      policyRootLow: "8",
      fxRootHigh: "9",
      fxRootLow: "10",
      runNullifierHigh: "11",
      runNullifierLow: "12",
      validityStart: "1000",
      validityExpiry: "1100",
      shardIndex: String(shardIndex),
    },
  };
}

function exceptionProof(version: 5 | 6 | 7): ExceptionCircuitProof {
  const proofCalldata = ["0x3", "0x4"];
  return {
    proof: new Uint8Array([2]),
    proofCalldata,
    calldataHash: hashProofCalldata(proofCalldata),
    publicInputs: {
      chainId: CHAIN,
      sealAddress: SEAL,
      proofVersion: String(version),
      schemaVersion: "2",
      agreementRootHigh: "3",
      agreementRootLow: "4",
      manifestRootHigh: "5",
      manifestRootLow: "6",
      policyRootHigh: "7",
      policyRootLow: "8",
      fxRootHigh: "9",
      fxRootLow: "10",
      subjectNullifierHigh: "11",
      subjectNullifierLow: "12",
      parentNullifierHigh: "13",
      parentNullifierLow: "14",
      factCommitmentHigh: "15",
      factCommitmentLow: "16",
      parentFactCommitmentHigh: "17",
      parentFactCommitmentLow: "18",
      validityStart: "900",
      validityExpiry: "1000",
      shardIndex: "0",
    },
  };
}

function commitment(high: string, low: string): `0x${string}` {
  return `0x${((BigInt(high) << 128n) | BigInt(low)).toString(16).padStart(64, "0")}`;
}

describe("vNext exception seal calldata", () => {
  it("builds one compact begin call containing only proof commitments", () => {
    const call = buildBeginPayrollAuthorizationCall({
      sealAddress: SEAL,
      chainId: CHAIN,
      payrollShards: [payrollShard(0), payrollShard(1)],
      snapshotProof: exceptionProof(5),
    });
    const calldata = call.calldata as string[];
    expect(call.entrypoint).toBe("begin_payroll_authorization");
    expect(calldata).toHaveLength(14 + 21 + 3);
    expect(calldata.at(-3)).toBe(hashProofCalldata(["0x1", "0x2"]));
    expect(calldata.at(-1)).toBe(hashProofCalldata(["0x3", "0x4"]));
  });

  it("submits each committed proof in a separate calldata-safe call", () => {
    const call = buildVerifyPayrollAuthorizationProofCall({
      sealAddress: SEAL,
      runNullifierHigh: "11",
      runNullifierLow: "12",
      proofKind: 2,
      proofCalldata: ["0x3", "0x4"],
    });
    expect(call).toMatchObject({
      entrypoint: "verify_payroll_authorization_proof",
      calldata: ["0xb", "0xc", "0x2", "0x2", "0x3", "0x4"],
    });
  });

  it("registers exactly the pre-payday snapshot committed by proof v5", () => {
    const proof = exceptionProof(5);
    proof.publicInputs.fxRootHigh = "0";
    proof.publicInputs.fxRootLow = "0";
    proof.publicInputs.parentNullifierHigh = "0";
    proof.publicInputs.parentNullifierLow = "0";
    proof.publicInputs.parentFactCommitmentHigh = "0";
    proof.publicInputs.parentFactCommitmentLow = "0";
    const ownerAddress = "0xabc";
    const snapshot = {
      schemaVersion: 2 as const,
      runNullifier: commitment("11", "12"),
      baseAgreementRoot: commitment("3", "4"),
      obligationRoot: commitment("5", "6"),
      policyRoot: commitment("7", "8"),
      ownerAddress: `0x${ownerAddress.slice(2).padStart(64, "0")}`,
      dueAt: "2000",
      graceEndsAt: "2100",
      claimEndsAt: "3000",
      availabilityCommitment: commitment("5", "6"),
    };
    const snapshotCommitment = obligationSnapshotCommitmentV2(snapshot);
    const fact = BigInt(snapshotCommitment);
    proof.publicInputs.factCommitmentHigh = (fact >> 128n).toString();
    proof.publicInputs.factCommitmentLow = (fact & ((1n << 128n) - 1n)).toString();
    const call = buildRegisterObligationSnapshotCall({
      sealAddress: SEAL,
      ownerAddress,
      snapshotCommitment,
      proofPublicInputs: proof.publicInputs,
      snapshot,
    });
    expect(call).toMatchObject({
      entrypoint: "register_obligation_snapshot",
      calldata: [
        "0xb", "0xc", "0x3", "0x4", "0x5", "0x6", "0x7", "0x8",
        "0x7d0", "0x834", "0xbb8",
        `0x${(fact >> 128n).toString(16)}`,
        `0x${(fact & ((1n << 128n) - 1n)).toString(16)}`,
      ],
    });
  });

  it("registers a self-authenticating snapshot before its later proof exists", () => {
    const snapshot = {
      schemaVersion: 2 as const,
      runNullifier: commitment("11", "12"),
      baseAgreementRoot: commitment("3", "4"),
      obligationRoot: commitment("5", "6"),
      policyRoot: commitment("7", "8"),
      ownerAddress: `0x${"abc".padStart(64, "0")}`,
      dueAt: "2000",
      graceEndsAt: "2100",
      claimEndsAt: "3000",
      availabilityCommitment: commitment("5", "6"),
    };
    const snapshotCommitment = obligationSnapshotCommitmentV2(snapshot);
    const call = buildRegisterObligationSnapshotCall({
      sealAddress: SEAL,
      ownerAddress: "0xabc",
      snapshot,
      snapshotCommitment,
    });
    expect(call.entrypoint).toBe("register_obligation_snapshot");
    expect(call.calldata).toHaveLength(13);
    expect(() => buildRegisterObligationSnapshotCall({
      sealAddress: SEAL,
      ownerAddress: "0xabc",
      snapshot,
      snapshotCommitment: `0x${"99".repeat(32)}`,
    })).toThrow(/commitment does not match/);
  });

  it("registers an exact employer-authored statement fact", () => {
    const statement = {
      schemaVersion: 2 as const,
      runNullifier: commitment("11", "12"),
      snapshotCommitment: commitment("13", "14"),
      manifestRoot: commitment("5", "6"),
      fxRoot: commitment("9", "10"),
      availabilityCommitment: commitment("21", "22"),
      observedAt: "2200",
      source: "employer_statement" as const,
    };
    const statementCommitment = payrollStatementCommitmentV2(statement);
    const fact = BigInt(statementCommitment);
    expect(buildRegisterEmployerStatementCall({
      sealAddress: SEAL,
      statement,
      statementCommitment,
    })).toMatchObject({
      entrypoint: "register_employer_statement",
      calldata: [
        "0xb", "0xc", "0x5", "0x6", "0x9", "0xa",
        "0x15", "0x16", "0x898",
        `0x${(fact >> 128n).toString(16)}`,
        `0x${(fact & ((1n << 128n) - 1n)).toString(16)}`,
      ],
    });
    expect(() => buildRegisterEmployerStatementCall({
      sealAddress: SEAL,
      statement,
      statementCommitment: `0x${"99".repeat(32)}`,
    })).toThrow(/commitment does not match/);
  });

  it("binds one v6 proof directly to authorize_claim", () => {
    const call = buildAuthorizeClaimCall({
      sealAddress: SEAL,
      chainId: CHAIN,
      proof: exceptionProof(6),
    });
    expect(call.entrypoint).toBe("authorize_claim");
    expect(call.calldata).toHaveLength(21 + 1 + 2);
  });

  it("builds the exact remediation authorization consumption action", () => {
    const action = buildAuthorizedExceptionAction({
      sealAddress: SEAL,
      mode: 3,
      publicInputs: exceptionProof(7).publicInputs,
    });
    expect(action).toEqual({
      type: "invoke",
      contract: "0x" + SEAL.slice(2).padStart(64, "0"),
      calldata: ["0x3", "0xb", "0xc", "0xf", "0x10", "0x5", "0x6"],
    });
  });

  it("consumes a payroll authorization with the snapshot fact and payroll manifest", () => {
    const snapshot = exceptionProof(5).publicInputs;
    const action = buildAuthorizedPayrollAction({
      sealAddress: SEAL,
      payrollPublicInputs: payrollShard(0).publicInputs,
      snapshotPublicInputs: snapshot,
    });
    expect(action).toEqual({
      type: "invoke",
      contract: "0x" + SEAL.slice(2).padStart(64, "0"),
      calldata: ["0x0", "0xb", "0xc", "0xf", "0x10", "0x5", "0x6"],
    });
  });

  it("rejects a proof whose committed Poseidon hash changed", () => {
    const proof = exceptionProof(6);
    proof.proofCalldata[0] = "0x9";
    expect(() => buildAuthorizeClaimCall({ sealAddress: SEAL, chainId: CHAIN, proof }))
      .toThrow(/hash does not match/);
  });
});
