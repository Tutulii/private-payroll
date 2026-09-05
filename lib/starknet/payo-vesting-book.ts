import {
  num,
  validateAndParseAddress,
  type Call,
  type STRK20_INVOKE_ACTION,
} from "starknet";
import { universalPayrollBookEntryCommitment } from "@/lib/domain/universal-payroll-book";
import type {
  ExceptionCircuitProof,
  PayrollIntegrityPublicInputs,
  PayrollIntegrityShardProof,
  VestingBookProof,
  VestingTransitionShardProof,
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

function limbs(value: string, label: string): readonly [bigint, bigint] {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`${label} is not a 32-byte commitment.`);
  const parsed = BigInt(value);
  return [parsed >> 128n, parsed & (U128_LIMIT - 1n)] as const;
}

function sameCommitment(value: string, high: string, low: string): boolean {
  const [expectedHigh, expectedLow] = limbs(value, "Commitment");
  return expectedHigh === BigInt(high) && expectedLow === BigInt(low);
}

function checkedHash(
  proof: Pick<PayrollIntegrityShardProof | VestingTransitionShardProof, "proofCalldata" | "calldataHash" | "shardIndex">,
  label: string,
): string {
  if (!proof.proofCalldata.length) throw new Error(`${label} proof calldata is empty.`);
  const calculated = hashProofCalldata(proof.proofCalldata);
  if (BigInt(calculated) !== BigInt(proof.calldataHash)) {
    throw new Error(`${label} shard ${proof.shardIndex} calldata hash does not match.`);
  }
  return calculated;
}

export function serializeVestingPayrollProofState(input: PayrollIntegrityPublicInputs): string[] {
  const fields: Array<[string, bigint]> = [
    [input.proofVersion, U32_LIMIT],
    [input.schemaVersion, U32_LIMIT],
    [input.agreementRootHigh, U128_LIMIT],
    [input.agreementRootLow, U128_LIMIT],
    [input.manifestRootHigh, U128_LIMIT],
    [input.manifestRootLow, U128_LIMIT],
    [input.policyRootHigh, U128_LIMIT],
    [input.policyRootLow, U128_LIMIT],
    [input.fxRootHigh, U128_LIMIT],
    [input.fxRootLow, U128_LIMIT],
    [input.runNullifierHigh, U128_LIMIT],
    [input.runNullifierLow, U128_LIMIT],
    [input.validityStart, U64_LIMIT],
    [input.validityExpiry, U64_LIMIT],
  ];
  if (BigInt(input.proofVersion) !== 2n || BigInt(input.schemaVersion) !== 1n) {
    throw new Error("The vesting/book seal requires Advanced PayrollIntegrity v2.");
  }
  return fields.map(([value, limit], index) =>
    num.toHex(bounded(value, `Payroll state field ${index}`, limit)));
}

export function serializeVestingTransitionProofState(proof: VestingBookProof): string[] {
  const input = proof.shards[0].publicInputs;
  const fields: Array<[string, bigint]> = [
    [input.proofVersion, U32_LIMIT],
    [input.schemaVersion, U32_LIMIT],
    [input.entryKind, U8_LIMIT],
    [input.agreementRootHigh, U128_LIMIT],
    [input.agreementRootLow, U128_LIMIT],
    [input.manifestRootHigh, U128_LIMIT],
    [input.manifestRootLow, U128_LIMIT],
    [input.policyRootHigh, U128_LIMIT],
    [input.policyRootLow, U128_LIMIT],
    [input.fxRootHigh, U128_LIMIT],
    [input.fxRootLow, U128_LIMIT],
    [input.runNullifierHigh, U128_LIMIT],
    [input.runNullifierLow, U128_LIMIT],
    [input.subjectNullifierHigh, U128_LIMIT],
    [input.subjectNullifierLow, U128_LIMIT],
    [input.parentFactHigh, U128_LIMIT],
    [input.parentFactLow, U128_LIMIT],
    [input.factHigh, U128_LIMIT],
    [input.factLow, U128_LIMIT],
    [input.ownerAddress, 1n << 251n],
    [input.sourceSealAddress, 1n << 251n],
    [input.sourceProofVersion, U32_LIMIT],
    [input.attestationRootHigh, U128_LIMIT],
    [input.attestationRootLow, U128_LIMIT],
    [input.shard0ContributorCount, U32_LIMIT],
    [input.shard1ContributorCount, U32_LIMIT],
    [input.totalsDisclosed, U8_LIMIT],
    [input.totalsCommitmentHigh, U128_LIMIT],
    [input.totalsCommitmentLow, U128_LIMIT],
    [input.shard0StrkGross, U128_LIMIT],
    [input.shard0StrkDeductions, U128_LIMIT],
    [input.shard0StrkNet, U128_LIMIT],
    [input.shard0UsdcGross, U128_LIMIT],
    [input.shard0UsdcDeductions, U128_LIMIT],
    [input.shard0UsdcNet, U128_LIMIT],
    [input.shard1StrkGross, U128_LIMIT],
    [input.shard1StrkDeductions, U128_LIMIT],
    [input.shard1StrkNet, U128_LIMIT],
    [input.shard1UsdcGross, U128_LIMIT],
    [input.shard1UsdcDeductions, U128_LIMIT],
    [input.shard1UsdcNet, U128_LIMIT],
    [input.scheduleIdHigh, U128_LIMIT],
    [input.scheduleIdLow, U128_LIMIT],
    [input.previousStateHigh, U128_LIMIT],
    [input.previousStateLow, U128_LIMIT],
    [input.nextStateHigh, U128_LIMIT],
    [input.nextStateLow, U128_LIMIT],
    [input.releaseNullifierHigh, U128_LIMIT],
    [input.releaseNullifierLow, U128_LIMIT],
    [input.bookEntryHigh, U128_LIMIT],
    [input.bookEntryLow, U128_LIMIT],
    [input.periodStart, U64_LIMIT],
    [input.periodEnd, U64_LIMIT],
    [input.validityStart, U64_LIMIT],
    [input.validityExpiry, U64_LIMIT],
  ];
  return fields.map(([value, limit], index) =>
    num.toHex(bounded(value, `Vesting state field ${index}`, limit)));
}

function assertLinkedProofs(input: {
  sealAddress: string;
  chainId: string;
  payrollShards: readonly [PayrollIntegrityShardProof, PayrollIntegrityShardProof];
  vestingBook: VestingBookProof;
}): { seal: string; payrollState: string[]; transitionState: string[]; hashes: [string, string, string, string] } {
  const seal = address(input.sealAddress, "PAYO vesting/book seal address");
  const [payrollZero, payrollOne] = input.payrollShards;
  const [transitionZero, transitionOne] = input.vestingBook.shards;
  if (payrollZero.shardIndex !== 0 || payrollOne.shardIndex !== 1
    || transitionZero.shardIndex !== 0 || transitionOne.shardIndex !== 1) {
    throw new Error("Payroll and vesting proof shards must be ordered 0 then 1.");
  }
  const payroll = serializeVestingPayrollProofState(payrollZero.publicInputs);
  if (JSON.stringify(payroll) !== JSON.stringify(serializeVestingPayrollProofState(payrollOne.publicInputs))) {
    throw new Error("Payroll proof shards do not share one state.");
  }
  const transition = serializeVestingTransitionProofState(input.vestingBook);
  const otherTransition = serializeVestingTransitionProofState({
    ...input.vestingBook,
    shards: [transitionOne, transitionZero],
  });
  if (JSON.stringify(transition) !== JSON.stringify(otherTransition)) {
    throw new Error("Vesting proof shards do not share one state.");
  }
  const publicInputs = transitionZero.publicInputs;
  if (BigInt(payrollZero.publicInputs.chainId) !== BigInt(input.chainId)
    || BigInt(publicInputs.chainId) !== BigInt(input.chainId)) {
    throw new Error("The linked proofs are bound to a different Starknet chain.");
  }
  const expectedPayrollSeal = input.vestingBook.entryKind === "agent"
    ? publicInputs.sourceSealAddress
    : seal;
  if (BigInt(payrollZero.publicInputs.sealAddress) !== BigInt(expectedPayrollSeal)
    || BigInt(publicInputs.sealAddress) !== BigInt(seal)
    || BigInt(publicInputs.sourceSealAddress) !== BigInt(expectedPayrollSeal)) {
    throw new Error("The linked proofs are bound to a different PAYO source or payroll-book seal.");
  }
  const linked: Array<[string, string, string]> = [
    [payrollZero.publicInputs.agreementRootHigh, publicInputs.agreementRootHigh, "agreement root high"],
    [payrollZero.publicInputs.agreementRootLow, publicInputs.agreementRootLow, "agreement root low"],
    [payrollZero.publicInputs.manifestRootHigh, publicInputs.manifestRootHigh, "manifest root high"],
    [payrollZero.publicInputs.manifestRootLow, publicInputs.manifestRootLow, "manifest root low"],
    [payrollZero.publicInputs.policyRootHigh, publicInputs.policyRootHigh, "policy root high"],
    [payrollZero.publicInputs.policyRootLow, publicInputs.policyRootLow, "policy root low"],
    [payrollZero.publicInputs.fxRootHigh, publicInputs.fxRootHigh, "FX root high"],
    [payrollZero.publicInputs.fxRootLow, publicInputs.fxRootLow, "FX root low"],
    [payrollZero.publicInputs.runNullifierHigh, publicInputs.runNullifierHigh, "run nullifier high"],
    [payrollZero.publicInputs.runNullifierLow, publicInputs.runNullifierLow, "run nullifier low"],
    [payrollZero.publicInputs.validityStart, publicInputs.validityStart, "validity start"],
    [payrollZero.publicInputs.validityExpiry, publicInputs.validityExpiry, "validity expiry"],
  ];
  const mismatch = linked.find(([left, right]) => BigInt(left) !== BigInt(right));
  if (mismatch) throw new Error(`The v3 proof changed its v2 ${mismatch[2]} binding.`);
  if (input.vestingBook.proofVersion !== 3
    || BigInt(publicInputs.proofVersion) !== 3n
    || BigInt(publicInputs.schemaVersion) !== 1n) {
    throw new Error("The state/book proof does not use the v3 ABI.");
  }
  const expectedKinds = { ordinary: 0n, vesting: 1n, agent: 2n, claim: 3n, remediation: 4n } as const;
  if (BigInt(publicInputs.entryKind) !== expectedKinds[input.vestingBook.entryKind]) {
    throw new Error("The state/book proof entry kind is inconsistent.");
  }
  if (BigInt(publicInputs.ownerAddress) === 0n) throw new Error("The payroll-book owner is zero.");
  if (BigInt(publicInputs.periodEnd) <= BigInt(publicInputs.periodStart)
    || BigInt(publicInputs.validityStart) < BigInt(publicInputs.periodStart)
    || BigInt(publicInputs.validityStart) >= BigInt(publicInputs.periodEnd)) {
    throw new Error("The state/book proof uses an invalid reporting period.");
  }

  const entry = input.vestingBook.bookEntry;
  const contributorCount = BigInt(publicInputs.shard0ContributorCount)
    + BigInt(publicInputs.shard1ContributorCount);
  const combined = (high: string, low: string) => (BigInt(high) << 128n) | BigInt(low);
  const publicTotals = {
    STRK: {
      grossAtomic: (BigInt(publicInputs.shard0StrkGross) + BigInt(publicInputs.shard1StrkGross)).toString(),
      deductionsAtomic: (BigInt(publicInputs.shard0StrkDeductions) + BigInt(publicInputs.shard1StrkDeductions)).toString(),
      netAtomic: (BigInt(publicInputs.shard0StrkNet) + BigInt(publicInputs.shard1StrkNet)).toString(),
    },
    USDC: {
      grossAtomic: (BigInt(publicInputs.shard0UsdcGross) + BigInt(publicInputs.shard1UsdcGross)).toString(),
      deductionsAtomic: (BigInt(publicInputs.shard0UsdcDeductions) + BigInt(publicInputs.shard1UsdcDeductions)).toString(),
      netAtomic: (BigInt(publicInputs.shard0UsdcNet) + BigInt(publicInputs.shard1UsdcNet)).toString(),
    },
  };
  if (entry.entryKind !== input.vestingBook.entryKind
    || BigInt(entry.chainId) !== BigInt(input.chainId)
    || BigInt(entry.sealAddress) !== BigInt(seal)
    || BigInt(entry.sourceSealAddress) !== BigInt(publicInputs.sourceSealAddress)
    || BigInt(entry.ownerAddress) !== BigInt(publicInputs.ownerAddress)
    || BigInt(entry.agreementRoot) !== combined(publicInputs.agreementRootHigh, publicInputs.agreementRootLow)
    || BigInt(entry.manifestRoot) !== combined(publicInputs.manifestRootHigh, publicInputs.manifestRootLow)
    || BigInt(entry.policyRoot) !== combined(publicInputs.policyRootHigh, publicInputs.policyRootLow)
    || BigInt(entry.fxRoot) !== combined(publicInputs.fxRootHigh, publicInputs.fxRootLow)
    || BigInt(entry.runNullifier) !== combined(publicInputs.runNullifierHigh, publicInputs.runNullifierLow)
    || BigInt(entry.subjectNullifier) !== combined(publicInputs.subjectNullifierHigh, publicInputs.subjectNullifierLow)
    || BigInt(entry.parentFactCommitment) !== combined(publicInputs.parentFactHigh, publicInputs.parentFactLow)
    || BigInt(entry.factCommitment) !== combined(publicInputs.factHigh, publicInputs.factLow)
    || BigInt(entry.sourceProofVersion) !== BigInt(publicInputs.sourceProofVersion)
    || BigInt(entry.attestationRoot) !== combined(publicInputs.attestationRootHigh, publicInputs.attestationRootLow)
    || BigInt(entry.totalsCommitment) !== combined(publicInputs.totalsCommitmentHigh, publicInputs.totalsCommitmentLow)
    || BigInt(entry.contributorCount) !== contributorCount
    || entry.totalsDisclosure !== (BigInt(publicInputs.totalsDisclosed) === 1n ? "public" : "hidden")
    || JSON.stringify(entry.totals) !== JSON.stringify(publicTotals)
    || BigInt(entry.vestingScheduleId) !== combined(publicInputs.scheduleIdHigh, publicInputs.scheduleIdLow)
    || BigInt(entry.vestingStateCommitment) !== combined(publicInputs.nextStateHigh, publicInputs.nextStateLow)
    || BigInt(entry.periodStart) !== BigInt(publicInputs.periodStart)
    || BigInt(entry.periodEnd) !== BigInt(publicInputs.periodEnd)) {
    throw new Error("The disclosed payroll-book entry differs from the v3 public state.");
  }
  const entryCommitment = universalPayrollBookEntryCommitment(entry);
  if (BigInt(entryCommitment) !== BigInt(input.vestingBook.bookEntryCommitment)
    || !sameCommitment(entryCommitment, publicInputs.bookEntryHigh, publicInputs.bookEntryLow)
    || !sameCommitment(input.vestingBook.scheduleId, publicInputs.scheduleIdHigh, publicInputs.scheduleIdLow)
    || !sameCommitment(input.vestingBook.previousStateCommitment, publicInputs.previousStateHigh, publicInputs.previousStateLow)
    || !sameCommitment(input.vestingBook.nextStateCommitment, publicInputs.nextStateHigh, publicInputs.nextStateLow)
    || !sameCommitment(input.vestingBook.releaseNullifier, publicInputs.releaseNullifierHigh, publicInputs.releaseNullifierLow)) {
    throw new Error("The v3 proof metadata differs from its public commitments.");
  }
  return {
    seal,
    payrollState: payroll,
    transitionState: transition,
    hashes: [
      checkedHash(payrollZero, "Payroll"),
      checkedHash(payrollOne, "Payroll"),
      checkedHash(transitionZero, "Vesting"),
      checkedHash(transitionOne, "Vesting"),
    ],
  };
}

export function buildBeginVestingAuthorizationCall(input: {
  sealAddress: string;
  chainId: string;
  payrollShards: readonly [PayrollIntegrityShardProof, PayrollIntegrityShardProof];
  vestingBook: VestingBookProof;
}): Call {
  const checked = assertLinkedProofs(input);
  return {
    contractAddress: checked.seal,
    entrypoint: "begin_vesting_authorization",
    calldata: [
      ...checked.payrollState,
      ...checked.transitionState,
      ...checked.hashes.map((value) => num.toHex(BigInt(value))),
    ],
  };
}

export function buildVerifyVestingAuthorizationProofCall(input: {
  sealAddress: string;
  runNullifierHigh: string;
  runNullifierLow: string;
  proofKind: 0 | 1 | 2 | 3;
  proofCalldata: readonly string[];
}): Call {
  const seal = address(input.sealAddress, "PAYO vesting/book seal address");
  if (!input.proofCalldata.length) throw new Error("Vesting authorization proof calldata is empty.");
  return {
    contractAddress: seal,
    entrypoint: "verify_vesting_authorization_proof",
    calldata: [
      num.toHex(bounded(input.runNullifierHigh, "Run nullifier high", U128_LIMIT)),
      num.toHex(bounded(input.runNullifierLow, "Run nullifier low", U128_LIMIT)),
      num.toHex(bounded(input.proofKind, "Proof kind", U8_LIMIT)),
      num.toHex(input.proofCalldata.length),
      ...input.proofCalldata,
    ],
  };
}

export function buildVestingBookAction(input: {
  sealAddress: string;
  chainId: string;
  payrollShards: readonly [PayrollIntegrityShardProof, PayrollIntegrityShardProof];
  vestingBook: VestingBookProof;
}): STRK20_INVOKE_ACTION {
  const checked = assertLinkedProofs(input);
  const state = input.vestingBook.shards[0].publicInputs;
  return {
    type: "invoke",
    contract: checked.seal,
    calldata: [
      state.runNullifierHigh,
      state.runNullifierLow,
      state.releaseNullifierHigh,
      state.releaseNullifierLow,
      state.bookEntryHigh,
      state.bookEntryLow,
    ].map((value) => num.toHex(BigInt(value))),
  };
}


function assertExceptionBookProof(input: {
  sealAddress: string;
  exceptionSealAddress: string;
  chainId: string;
  sourceProof: ExceptionCircuitProof;
  vestingBook: VestingBookProof;
}): {
  seal: string;
  transitionState: string[];
  hashes: [string, string];
  subject: [string, string];
} {
  const seal = address(input.sealAddress, "PAYO vesting/book seal address");
  const sourceSeal = address(input.exceptionSealAddress, "PAYO exception seal address");
  const [first, second] = input.vestingBook.shards;
  if (first.shardIndex !== 0 || second.shardIndex !== 1
    || BigInt(first.publicInputs.shardIndex) !== 0n
    || BigInt(second.publicInputs.shardIndex) !== 1n) {
    throw new Error("Exception book proof shards must be ordered 0 then 1.");
  }
  const transitionState = serializeVestingTransitionProofState(input.vestingBook);
  const otherState = serializeVestingTransitionProofState({
    ...input.vestingBook,
    shards: [second, first],
  });
  if (JSON.stringify(transitionState) !== JSON.stringify(otherState)) {
    throw new Error("Exception book proof shards do not share one state.");
  }
  const state = first.publicInputs;
  const sourceState = input.sourceProof.publicInputs;
  const expectedKind = input.vestingBook.entryKind === "claim" ? 3n
    : input.vestingBook.entryKind === "remediation" ? 4n : -1n;
  const expectedSourceVersion = expectedKind === 3n ? 6n : 7n;
  if (expectedKind < 0n || BigInt(state.entryKind) !== expectedKind
    || BigInt(state.proofVersion) !== 3n || BigInt(state.schemaVersion) !== 1n) {
    throw new Error("Exception book proof has the wrong entry kind or ABI.");
  }
  if (BigInt(state.chainId) !== BigInt(input.chainId)
    || BigInt(state.sealAddress) !== BigInt(seal)
    || BigInt(sourceState.chainId) !== BigInt(input.chainId)
    || BigInt(sourceState.sealAddress) !== BigInt(sourceSeal)) {
    throw new Error("Exception book proof is bound to another deployment.");
  }
  if (BigInt(sourceState.proofVersion) !== expectedSourceVersion
    || BigInt(sourceState.schemaVersion) !== 2n
    || BigInt(sourceState.shardIndex) !== 0n
    || BigInt(state.sourceProofVersion) !== expectedSourceVersion
    || BigInt(state.sourceSealAddress) !== BigInt(sourceSeal)) {
    throw new Error("Exception book proof has the wrong source proof binding.");
  }
  const linked: Array<[string, string, string]> = [
    [state.agreementRootHigh, sourceState.agreementRootHigh, "agreement root high"],
    [state.agreementRootLow, sourceState.agreementRootLow, "agreement root low"],
    [state.manifestRootHigh, sourceState.manifestRootHigh, "manifest root high"],
    [state.manifestRootLow, sourceState.manifestRootLow, "manifest root low"],
    [state.policyRootHigh, sourceState.policyRootHigh, "policy root high"],
    [state.policyRootLow, sourceState.policyRootLow, "policy root low"],
    [state.fxRootHigh, sourceState.fxRootHigh, "FX root high"],
    [state.fxRootLow, sourceState.fxRootLow, "FX root low"],
    [state.subjectNullifierHigh, sourceState.subjectNullifierHigh, "subject high"],
    [state.subjectNullifierLow, sourceState.subjectNullifierLow, "subject low"],
    [state.parentFactHigh, sourceState.parentFactCommitmentHigh, "parent fact high"],
    [state.parentFactLow, sourceState.parentFactCommitmentLow, "parent fact low"],
    [state.factHigh, sourceState.factCommitmentHigh, "fact high"],
    [state.factLow, sourceState.factCommitmentLow, "fact low"],
    [state.validityStart, sourceState.validityStart, "validity start"],
    [state.validityExpiry, sourceState.validityExpiry, "validity expiry"],
  ];
  const mismatch = linked.find(([left, right]) => BigInt(left) !== BigInt(right));
  if (mismatch) throw new Error(`The exception book proof changed its source ${mismatch[2]}.`);
  if (expectedKind === 3n && (
    BigInt(state.runNullifierHigh) !== BigInt(sourceState.parentNullifierHigh)
    || BigInt(state.runNullifierLow) !== BigInt(sourceState.parentNullifierLow)
  )) throw new Error("Claim book proof changed its source run nullifier.");
  if (BigInt(state.ownerAddress) === 0n
    || BigInt(state.periodEnd) <= BigInt(state.periodStart)
    || BigInt(state.validityStart) < BigInt(state.periodStart)
    || BigInt(state.validityStart) >= BigInt(state.periodEnd)) {
    throw new Error("Exception book proof has an invalid owner or period.");
  }
  if (BigInt(state.attestationRootHigh) !== 0n || BigInt(state.attestationRootLow) !== 0n
    || BigInt(state.scheduleIdHigh) !== 0n || BigInt(state.scheduleIdLow) !== 0n
    || BigInt(state.previousStateHigh) !== 0n || BigInt(state.previousStateLow) !== 0n
    || BigInt(state.nextStateHigh) !== 0n || BigInt(state.nextStateLow) !== 0n
    || BigInt(state.releaseNullifierHigh) !== 0n || BigInt(state.releaseNullifierLow) !== 0n) {
    throw new Error("Exception entries cannot carry vesting or attestation state.");
  }
  const joined = (high: string, low: string) => (BigInt(high) << 128n) | BigInt(low);
  const publicTotals = {
    STRK: {
      grossAtomic: (BigInt(state.shard0StrkGross) + BigInt(state.shard1StrkGross)).toString(),
      deductionsAtomic: (BigInt(state.shard0StrkDeductions) + BigInt(state.shard1StrkDeductions)).toString(),
      netAtomic: (BigInt(state.shard0StrkNet) + BigInt(state.shard1StrkNet)).toString(),
    },
    USDC: {
      grossAtomic: (BigInt(state.shard0UsdcGross) + BigInt(state.shard1UsdcGross)).toString(),
      deductionsAtomic: (BigInt(state.shard0UsdcDeductions) + BigInt(state.shard1UsdcDeductions)).toString(),
      netAtomic: (BigInt(state.shard0UsdcNet) + BigInt(state.shard1UsdcNet)).toString(),
    },
  };
  const entry = input.vestingBook.bookEntry;
  if (entry.entryKind !== input.vestingBook.entryKind
    || BigInt(entry.chainId) !== BigInt(input.chainId)
    || BigInt(entry.sealAddress) !== BigInt(seal)
    || BigInt(entry.sourceSealAddress) !== BigInt(sourceSeal)
    || BigInt(entry.ownerAddress) !== BigInt(state.ownerAddress)
    || BigInt(entry.agreementRoot) !== joined(state.agreementRootHigh, state.agreementRootLow)
    || BigInt(entry.manifestRoot) !== joined(state.manifestRootHigh, state.manifestRootLow)
    || BigInt(entry.policyRoot) !== joined(state.policyRootHigh, state.policyRootLow)
    || BigInt(entry.fxRoot) !== joined(state.fxRootHigh, state.fxRootLow)
    || BigInt(entry.runNullifier) !== joined(state.runNullifierHigh, state.runNullifierLow)
    || BigInt(entry.subjectNullifier) !== joined(state.subjectNullifierHigh, state.subjectNullifierLow)
    || BigInt(entry.parentFactCommitment) !== joined(state.parentFactHigh, state.parentFactLow)
    || BigInt(entry.factCommitment) !== joined(state.factHigh, state.factLow)
    || BigInt(entry.sourceProofVersion) !== expectedSourceVersion
    || entry.contributorCount !== Number(BigInt(state.shard0ContributorCount) + BigInt(state.shard1ContributorCount))
    || entry.totalsDisclosure !== (BigInt(state.totalsDisclosed) === 1n ? "public" : "hidden")
    || JSON.stringify(entry.totals) !== JSON.stringify(publicTotals)
    || BigInt(entry.totalsCommitment) !== joined(state.totalsCommitmentHigh, state.totalsCommitmentLow)) {
    throw new Error("The exception book entry differs from the v3 public state.");
  }
  const commitment = universalPayrollBookEntryCommitment(entry);
  if (BigInt(commitment) !== BigInt(input.vestingBook.bookEntryCommitment)
    || !sameCommitment(commitment, state.bookEntryHigh, state.bookEntryLow)
    || BigInt(input.vestingBook.scheduleId) !== 0n
    || BigInt(input.vestingBook.previousStateCommitment) !== 0n
    || BigInt(input.vestingBook.nextStateCommitment) !== 0n
    || BigInt(input.vestingBook.releaseNullifier) !== 0n) {
    throw new Error("The exception book metadata differs from its v3 commitments.");
  }
  if (!input.sourceProof.proofCalldata.length
    || BigInt(hashProofCalldata(input.sourceProof.proofCalldata)) !== BigInt(input.sourceProof.calldataHash)) {
    throw new Error("The source exception proof calldata hash does not match.");
  }
  return {
    seal,
    transitionState,
    hashes: [checkedHash(first, "Exception book"), checkedHash(second, "Exception book")],
    subject: [state.subjectNullifierHigh, state.subjectNullifierLow],
  };
}

export function buildBeginExceptionBookAuthorizationCall(input: {
  sealAddress: string;
  exceptionSealAddress: string;
  chainId: string;
  sourceProof: ExceptionCircuitProof;
  vestingBook: VestingBookProof;
}): Call {
  const checked = assertExceptionBookProof(input);
  return {
    contractAddress: checked.seal,
    entrypoint: "begin_exception_book_authorization",
    calldata: [
      ...checked.transitionState,
      ...checked.hashes.map((value) => num.toHex(BigInt(value))),
    ],
  };
}

export function buildFinalizeClaimBookEntryCall(input: {
  sealAddress: string;
  exceptionSealAddress: string;
  chainId: string;
  sourceProof: ExceptionCircuitProof;
  vestingBook: VestingBookProof;
}): Call {
  if (input.vestingBook.entryKind !== "claim") {
    throw new Error("Only a Claim v6 book entry uses explicit finalization.");
  }
  const checked = assertExceptionBookProof(input);
  const state = input.vestingBook.shards[0].publicInputs;
  return {
    contractAddress: checked.seal,
    entrypoint: "finalize_claim_book_entry",
    calldata: [
      ...checked.subject,
      state.bookEntryHigh,
      state.bookEntryLow,
    ].map((value) => num.toHex(BigInt(value))),
  };
}

export function buildExceptionBookAction(input: {
  sealAddress: string;
  exceptionSealAddress: string;
  chainId: string;
  sourceProof: ExceptionCircuitProof;
  vestingBook: VestingBookProof;
}): STRK20_INVOKE_ACTION {
  if (input.vestingBook.entryKind !== "remediation") {
    throw new Error("Only a Remediation v7 payment uses the private book callback.");
  }
  const checked = assertExceptionBookProof(input);
  const state = input.vestingBook.shards[0].publicInputs;
  return {
    type: "invoke",
    contract: checked.seal,
    calldata: [
      ...checked.subject,
      state.releaseNullifierHigh,
      state.releaseNullifierLow,
      state.bookEntryHigh,
      state.bookEntryLow,
    ].map((value) => num.toHex(BigInt(value))),
  };
}
