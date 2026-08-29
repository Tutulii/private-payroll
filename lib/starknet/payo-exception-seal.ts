import {
  num,
  validateAndParseAddress,
  type Call,
  type STRK20_INVOKE_ACTION,
} from "starknet";
import {
  obligationSnapshotCommitmentV2,
  payrollStatementCommitmentV2,
  type ExceptionPublicInputsV2,
  type ObligationSnapshotV2,
  type PayrollStatementV2,
} from "@/lib/domain/exception-protocol";
import type {
  ExceptionCircuitProof,
  PayrollIntegrityPublicInputs,
  PayrollIntegrityShardProof,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";

const U8_LIMIT = 1n << 8n;
const U32_LIMIT = 1n << 32n;
const U64_LIMIT = 1n << 64n;
const U128_LIMIT = 1n << 128n;

function bounded(value: string | number | bigint, label: string, limit: bigint): bigint {
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(`${label} is not an integer.`);
  }
  if (parsed < 0n || parsed >= limit) throw new Error(`${label} is outside its canonical range.`);
  return parsed;
}

function address(value: string, label: string): string {
  try {
    return validateAndParseAddress(value);
  } catch {
    throw new Error(`${label} is not a canonical Starknet address.`);
  }
}

function commitmentLimbs(value: string, label: string): readonly [bigint, bigint] {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`${label} is not a 32-byte commitment.`);
  const parsed = BigInt(value);
  return [parsed >> 128n, parsed & (U128_LIMIT - 1n)] as const;
}

function sameLimbs(value: string, high: string, low: string): boolean {
  const [expectedHigh, expectedLow] = commitmentLimbs(value, "Commitment");
  return expectedHigh === BigInt(high) && expectedLow === BigInt(low);
}

function payrollState(inputs: PayrollIntegrityPublicInputs): string[] {
  if (bounded(inputs.proofVersion, "Payroll proof version", U32_LIMIT) !== 2n) {
    throw new Error("The vNext exception seal requires PayrollIntegrity proof version 2.");
  }
  if (bounded(inputs.schemaVersion, "Payroll schema version", U32_LIMIT) !== 1n) {
    throw new Error("The vNext exception seal requires payroll schema version 1.");
  }
  return [
    inputs.proofVersion,
    inputs.schemaVersion,
    inputs.agreementRootHigh,
    inputs.agreementRootLow,
    inputs.manifestRootHigh,
    inputs.manifestRootLow,
    inputs.policyRootHigh,
    inputs.policyRootLow,
    inputs.fxRootHigh,
    inputs.fxRootLow,
    inputs.runNullifierHigh,
    inputs.runNullifierLow,
    inputs.validityStart,
    inputs.validityExpiry,
  ].map((value, index) => num.toHex(bounded(
    value,
    `Payroll state field ${index}`,
    index < 2 ? U32_LIMIT : index >= 12 ? U64_LIMIT : U128_LIMIT,
  )));
}

function exceptionState(inputs: ExceptionPublicInputsV2): string[] {
  const fields: Array<[string, bigint]> = [
    [inputs.proofVersion, U32_LIMIT],
    [inputs.schemaVersion, U32_LIMIT],
    [inputs.agreementRootHigh, U128_LIMIT],
    [inputs.agreementRootLow, U128_LIMIT],
    [inputs.manifestRootHigh, U128_LIMIT],
    [inputs.manifestRootLow, U128_LIMIT],
    [inputs.policyRootHigh, U128_LIMIT],
    [inputs.policyRootLow, U128_LIMIT],
    [inputs.fxRootHigh, U128_LIMIT],
    [inputs.fxRootLow, U128_LIMIT],
    [inputs.subjectNullifierHigh, U128_LIMIT],
    [inputs.subjectNullifierLow, U128_LIMIT],
    [inputs.parentNullifierHigh, U128_LIMIT],
    [inputs.parentNullifierLow, U128_LIMIT],
    [inputs.factCommitmentHigh, U128_LIMIT],
    [inputs.factCommitmentLow, U128_LIMIT],
    [inputs.parentFactCommitmentHigh, U128_LIMIT],
    [inputs.parentFactCommitmentLow, U128_LIMIT],
    [inputs.validityStart, U64_LIMIT],
    [inputs.validityExpiry, U64_LIMIT],
    [inputs.shardIndex, U8_LIMIT],
  ];
  return fields.map(([value, limit], index) =>
    num.toHex(bounded(value, `Exception state field ${index}`, limit)));
}

function assertDeploymentBinding(input: {
  sealAddress: string;
  chainId: string;
  publicInputs: Pick<ExceptionPublicInputsV2, "sealAddress" | "chainId">;
}): string {
  const seal = address(input.sealAddress, "PAYO exception seal address");
  if (BigInt(input.publicInputs.sealAddress) !== BigInt(seal)) {
    throw new Error("The exception proof is bound to a different PAYO seal.");
  }
  if (BigInt(input.publicInputs.chainId) !== BigInt(input.chainId)) {
    throw new Error("The exception proof is bound to a different Starknet chain.");
  }
  return seal;
}

function assertProof(proof: ExceptionCircuitProof, version: 5 | 6 | 7): string {
  if (BigInt(proof.publicInputs.proofVersion) !== BigInt(version)) {
    throw new Error(`Expected exception proof version ${version}.`);
  }
  if (BigInt(proof.publicInputs.schemaVersion) !== 2n || BigInt(proof.publicInputs.shardIndex) !== 0n) {
    throw new Error("The exception proof does not use the canonical vNext public-input ABI.");
  }
  if (!proof.proofCalldata.length) throw new Error("The exception proof calldata is empty.");
  const calculated = hashProofCalldata(proof.proofCalldata);
  if (BigInt(calculated) !== BigInt(proof.calldataHash)) {
    throw new Error("The exception proof calldata hash does not match.");
  }
  return calculated;
}

export function buildBeginPayrollAuthorizationCall(input: {
  sealAddress: string;
  chainId: string;
  payrollShards: readonly [PayrollIntegrityShardProof, PayrollIntegrityShardProof];
  snapshotProof: ExceptionCircuitProof;
}): Call {
  const [shardZero, shardOne] = input.payrollShards;
  if (shardZero.shardIndex !== 0 || shardOne.shardIndex !== 1) {
    throw new Error("Payroll proof shards must be ordered 0 then 1.");
  }
  const zeroState = payrollState(shardZero.publicInputs);
  const oneState = payrollState(shardOne.publicInputs);
  if (JSON.stringify(zeroState) !== JSON.stringify(oneState)) {
    throw new Error("Payroll proof shards do not share one authorization state.");
  }
  const seal = assertDeploymentBinding({
    sealAddress: input.sealAddress,
    chainId: input.chainId,
    publicInputs: input.snapshotProof.publicInputs,
  });
  if (
    BigInt(shardZero.publicInputs.chainId) !== BigInt(input.chainId)
    || BigInt(shardZero.publicInputs.sealAddress) !== BigInt(seal)
  ) throw new Error("Payroll proof shards are bound to a different deployment.");
  const snapshotHash = assertProof(input.snapshotProof, 5);
  const shardZeroHash = hashProofCalldata(shardZero.proofCalldata);
  const shardOneHash = hashProofCalldata(shardOne.proofCalldata);
  if (
    BigInt(shardZeroHash) !== BigInt(shardZero.calldataHash)
    || BigInt(shardOneHash) !== BigInt(shardOne.calldataHash)
  ) throw new Error("A payroll shard calldata hash does not match.");
  return {
    contractAddress: seal,
    entrypoint: "begin_payroll_authorization",
    calldata: [
      ...zeroState,
      ...exceptionState(input.snapshotProof.publicInputs),
      num.toHex(BigInt(shardZeroHash)),
      num.toHex(BigInt(shardOneHash)),
      num.toHex(BigInt(snapshotHash)),
    ],
  };
}

export function buildRegisterObligationSnapshotCall(input: {
  sealAddress: string;
  ownerAddress: string;
  snapshot: ObligationSnapshotV2;
  snapshotCommitment: string;
  proofPublicInputs?: ExceptionPublicInputsV2;
}): Call {
  const seal = address(input.sealAddress, "PAYO exception seal address");
  const owner = address(input.ownerAddress, "Snapshot owner address");
  const snapshot = input.snapshot;
  if (BigInt(snapshot.ownerAddress) !== BigInt(owner)) {
    throw new Error("The connected account is not the committed snapshot owner.");
  }
  if (BigInt(snapshot.availabilityCommitment) !== BigInt(snapshot.obligationRoot)) {
    throw new Error("The active PAYO seal requires full obligation-root availability.");
  }
  const expectedCommitment = obligationSnapshotCommitmentV2(snapshot);
  if (BigInt(expectedCommitment) !== BigInt(input.snapshotCommitment)) {
    throw new Error("The obligation snapshot commitment does not match its immutable fields.");
  }
  const publicInputs = input.proofPublicInputs;
  if (publicInputs) {
    if (
      BigInt(publicInputs.proofVersion) !== 5n
      || BigInt(publicInputs.schemaVersion) !== 2n
      || BigInt(publicInputs.shardIndex) !== 0n
      || BigInt(publicInputs.sealAddress) !== BigInt(seal)
    ) throw new Error("The obligation snapshot proof uses the wrong deployment ABI.");
    if (
      !sameLimbs(snapshot.runNullifier, publicInputs.subjectNullifierHigh, publicInputs.subjectNullifierLow)
      || BigInt(publicInputs.parentNullifierHigh) !== 0n
      || BigInt(publicInputs.parentNullifierLow) !== 0n
      || !sameLimbs(snapshot.baseAgreementRoot, publicInputs.agreementRootHigh, publicInputs.agreementRootLow)
      || !sameLimbs(snapshot.obligationRoot, publicInputs.manifestRootHigh, publicInputs.manifestRootLow)
      || !sameLimbs(snapshot.policyRoot, publicInputs.policyRootHigh, publicInputs.policyRootLow)
      || BigInt(publicInputs.fxRootHigh) !== 0n
      || BigInt(publicInputs.fxRootLow) !== 0n
      || !sameLimbs(input.snapshotCommitment, publicInputs.factCommitmentHigh, publicInputs.factCommitmentLow)
      || BigInt(publicInputs.parentFactCommitmentHigh) !== 0n
      || BigInt(publicInputs.parentFactCommitmentLow) !== 0n
    ) throw new Error("The obligation snapshot registration does not match its proof bindings.");
  }
  const run = commitmentLimbs(snapshot.runNullifier, "Snapshot run nullifier");
  const agreement = commitmentLimbs(snapshot.baseAgreementRoot, "Snapshot agreement root");
  const claim = commitmentLimbs(snapshot.obligationRoot, "Snapshot obligation root");
  const policy = commitmentLimbs(snapshot.policyRoot, "Snapshot policy root");
  const fact = commitmentLimbs(input.snapshotCommitment, "Snapshot fact commitment");
  return {
    contractAddress: seal,
    entrypoint: "register_obligation_snapshot",
    calldata: [
      ...run,
      ...agreement,
      ...claim,
      ...policy,
      bounded(snapshot.dueAt, "Snapshot payday", U64_LIMIT),
      bounded(snapshot.graceEndsAt, "Snapshot grace deadline", U64_LIMIT),
      bounded(snapshot.claimEndsAt, "Snapshot claim deadline", U64_LIMIT),
      ...fact,
    ].map((value) => num.toHex(value)),
  };
}

export function buildRegisterEmployerStatementCall(input: {
  sealAddress: string;
  statement: PayrollStatementV2;
  statementCommitment: string;
}): Call {
  const seal = address(input.sealAddress, "PAYO exception seal address");
  if (input.statement.source !== "employer_statement") {
    throw new Error("This entrypoint accepts only an employer-authored statement.");
  }
  const expectedCommitment = payrollStatementCommitmentV2(input.statement);
  if (BigInt(expectedCommitment) !== BigInt(input.statementCommitment)) {
    throw new Error("The employer statement commitment does not match its immutable fields.");
  }
  const run = commitmentLimbs(input.statement.runNullifier, "Statement run nullifier");
  const manifest = commitmentLimbs(input.statement.manifestRoot, "Statement manifest root");
  const fx = commitmentLimbs(input.statement.fxRoot, "Statement FX root");
  const availability = commitmentLimbs(
    input.statement.availabilityCommitment,
    "Statement availability commitment",
  );
  const fact = commitmentLimbs(input.statementCommitment, "Statement fact commitment");
  return {
    contractAddress: seal,
    entrypoint: "register_employer_statement",
    calldata: [
      ...run,
      ...manifest,
      ...fx,
      ...availability,
      bounded(input.statement.observedAt, "Statement observation time", U64_LIMIT),
      ...fact,
    ].map((value) => num.toHex(value)),
  };
}

export function buildVerifyPayrollAuthorizationProofCall(input: {
  sealAddress: string;
  runNullifierHigh: string;
  runNullifierLow: string;
  proofKind: 0 | 1 | 2;
  proofCalldata: readonly string[];
}): Call {
  const seal = address(input.sealAddress, "PAYO exception seal address");
  if (!input.proofCalldata.length) throw new Error("Authorization proof calldata is empty.");
  return {
    contractAddress: seal,
    entrypoint: "verify_payroll_authorization_proof",
    calldata: [
      num.toHex(bounded(input.runNullifierHigh, "Run nullifier high", U128_LIMIT)),
      num.toHex(bounded(input.runNullifierLow, "Run nullifier low", U128_LIMIT)),
      num.toHex(bounded(input.proofKind, "Proof kind", U8_LIMIT)),
      num.toHex(input.proofCalldata.length),
      ...input.proofCalldata,
    ],
  };
}

function buildExceptionAuthorizationCall(input: {
  sealAddress: string;
  chainId: string;
  proof: ExceptionCircuitProof;
  version: 6 | 7;
  entrypoint: "authorize_claim" | "authorize_remediation";
}): Call {
  const seal = assertDeploymentBinding({
    sealAddress: input.sealAddress,
    chainId: input.chainId,
    publicInputs: input.proof.publicInputs,
  });
  assertProof(input.proof, input.version);
  return {
    contractAddress: seal,
    entrypoint: input.entrypoint,
    calldata: [
      ...exceptionState(input.proof.publicInputs),
      num.toHex(input.proof.proofCalldata.length),
      ...input.proof.proofCalldata,
    ],
  };
}

export function buildAuthorizeClaimCall(input: {
  sealAddress: string;
  chainId: string;
  proof: ExceptionCircuitProof;
}): Call {
  return buildExceptionAuthorizationCall({ ...input, version: 6, entrypoint: "authorize_claim" });
}

export function buildAuthorizeRemediationCall(input: {
  sealAddress: string;
  chainId: string;
  proof: ExceptionCircuitProof;
}): Call {
  return buildExceptionAuthorizationCall({ ...input, version: 7, entrypoint: "authorize_remediation" });
}

export function buildAuthorizedExceptionAction(input: {
  sealAddress: string;
  mode: 0 | 3;
  publicInputs: ExceptionPublicInputsV2;
}): STRK20_INVOKE_ACTION {
  const seal = address(input.sealAddress, "PAYO exception seal address");
  return {
    type: "invoke",
    contract: seal,
    calldata: [
      num.toHex(input.mode),
      num.toHex(bounded(input.publicInputs.subjectNullifierHigh, "Subject high", U128_LIMIT)),
      num.toHex(bounded(input.publicInputs.subjectNullifierLow, "Subject low", U128_LIMIT)),
      num.toHex(bounded(input.publicInputs.factCommitmentHigh, "Fact high", U128_LIMIT)),
      num.toHex(bounded(input.publicInputs.factCommitmentLow, "Fact low", U128_LIMIT)),
      num.toHex(bounded(input.publicInputs.manifestRootHigh, "Action high", U128_LIMIT)),
      num.toHex(bounded(input.publicInputs.manifestRootLow, "Action low", U128_LIMIT)),
    ],
  };
}

export function buildAuthorizedPayrollAction(input: {
  sealAddress: string;
  payrollPublicInputs: PayrollIntegrityPublicInputs;
  snapshotPublicInputs: ExceptionPublicInputsV2;
}): STRK20_INVOKE_ACTION {
  const seal = address(input.sealAddress, "PAYO exception seal address");
  const payroll = input.payrollPublicInputs;
  const snapshot = input.snapshotPublicInputs;
  if (
    BigInt(payroll.proofVersion) !== 2n
    || BigInt(payroll.schemaVersion) !== 1n
    || BigInt(snapshot.proofVersion) !== 5n
    || BigInt(snapshot.schemaVersion) !== 2n
  ) throw new Error("The authorized payroll action requires PayrollIntegrity v2 and snapshot v5.");
  if (
    BigInt(payroll.runNullifierHigh) !== BigInt(snapshot.subjectNullifierHigh)
    || BigInt(payroll.runNullifierLow) !== BigInt(snapshot.subjectNullifierLow)
    || BigInt(payroll.agreementRootHigh) !== BigInt(snapshot.agreementRootHigh)
    || BigInt(payroll.agreementRootLow) !== BigInt(snapshot.agreementRootLow)
    || BigInt(payroll.policyRootHigh) !== BigInt(snapshot.policyRootHigh)
    || BigInt(payroll.policyRootLow) !== BigInt(snapshot.policyRootLow)
  ) throw new Error("The authorized payroll and pre-payday snapshot do not share one immutable run.");
  return {
    type: "invoke",
    contract: seal,
    calldata: [
      "0x0",
      num.toHex(bounded(payroll.runNullifierHigh, "Run high", U128_LIMIT)),
      num.toHex(bounded(payroll.runNullifierLow, "Run low", U128_LIMIT)),
      num.toHex(bounded(snapshot.factCommitmentHigh, "Snapshot fact high", U128_LIMIT)),
      num.toHex(bounded(snapshot.factCommitmentLow, "Snapshot fact low", U128_LIMIT)),
      num.toHex(bounded(payroll.manifestRootHigh, "Payroll action high", U128_LIMIT)),
      num.toHex(bounded(payroll.manifestRootLow, "Payroll action low", U128_LIMIT)),
    ],
  };
}
