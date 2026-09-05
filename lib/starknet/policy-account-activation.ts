import { num } from "starknet";
import type { DirectPrivacyAccountConfig } from "@/lib/domain/direct-privacy";

const STARK_FIELD_PRIME = (1n << 251n) + 17n * (1n << 192n) + 1n;
const U128_MASK = (1n << 128n) - 1n;
const U32_MAX = (1n << 32n) - 1n;
const U64_MAX = (1n << 64n) - 1n;

function integer(value: string, label: string, maximum = STARK_FIELD_PRIME - 1n): bigint {
  let parsed: bigint;
  try { parsed = BigInt(value); } catch { throw new Error(`${label} is not an integer felt.`); }
  if (parsed < 0n || parsed > maximum) throw new Error(`${label} is outside its Cairo range.`);
  return parsed;
}

function felt(value: string, label: string): `0x${string}` {
  return num.toHex(integer(value, label)) as `0x${string}`;
}

function equal(left: string | number | bigint, right: string | number | bigint): boolean {
  try { return BigInt(left) === BigInt(right); } catch { return false; }
}

function splitRoot(root: string): readonly [bigint, bigint] {
  if (!/^0x[0-9a-fA-F]{64}$/.test(root)) throw new Error("The payroll policy root is not 32 bytes.");
  const value = BigInt(root);
  return [value >> 128n, value & U128_MASK];
}

export type PolicyAccountState = {
  configured: boolean;
  revoked: boolean;
  sessionPublicKey: `0x${string}`;
  poolAddress: `0x${string}`;
  sealAddress: `0x${string}`;
  bookSealAddress: `0x${string}`;
  sealMode: 0 | 1 | 2;
  proofVersion: number;
  schemaVersion: number;
  payrollPolicyRootHigh: bigint;
  payrollPolicyRootLow: bigint;
  tokenSetCommitment: `0x${string}`;
  recipientSetCommitment: `0x${string}`;
  purposeCommitment: `0x${string}`;
  amountLimitCommitment: `0x${string}`;
  authorizedRunsRoot: `0x${string}`;
  validAfterUnix: bigint;
  validBeforeUnix: bigint;
  periodSeconds: bigint;
  maxCallsPerPeriod: number;
  maxCallCount: number;
  periodStartedAtUnix: bigint;
  periodCallCount: number;
  usedCallCount: number;
};

/** Decodes the Cairo `PolicyState` return without trusting an ABI supplied by the account. */
export function decodePolicyAccountState(values: readonly string[]): PolicyAccountState {
  if (values.length !== 24) throw new Error("The policy account returned an unexpected PolicyState shape.");
  const boolean = (index: number, label: string): boolean => {
    const value = integer(values[index], label, 1n);
    return value === 1n;
  };
  const number = (index: number, label: string, maximum: bigint): number =>
    Number(integer(values[index], label, maximum));
  const sealMode = number(6, "Policy seal mode", 2n);
  return {
    configured: boolean(0, "Policy configured flag"),
    revoked: boolean(1, "Policy revoked flag"),
    sessionPublicKey: felt(values[2], "Policy session public key"),
    poolAddress: felt(values[3], "Policy pool address"),
    sealAddress: felt(values[4], "Policy seal address"),
    bookSealAddress: felt(values[5], "Policy book seal address"),
    sealMode: sealMode as 0 | 1 | 2,
    proofVersion: number(7, "Policy proof version", U32_MAX),
    schemaVersion: number(8, "Policy schema version", U32_MAX),
    payrollPolicyRootHigh: integer(values[9], "Policy root high limb", U128_MASK),
    payrollPolicyRootLow: integer(values[10], "Policy root low limb", U128_MASK),
    tokenSetCommitment: felt(values[11], "Policy token commitment"),
    recipientSetCommitment: felt(values[12], "Policy recipient commitment"),
    purposeCommitment: felt(values[13], "Policy purpose commitment"),
    amountLimitCommitment: felt(values[14], "Policy amount commitment"),
    authorizedRunsRoot: felt(values[15], "Policy authorized-runs root"),
    validAfterUnix: integer(values[16], "Policy valid-after", U64_MAX),
    validBeforeUnix: integer(values[17], "Policy valid-before", U64_MAX),
    periodSeconds: integer(values[18], "Policy period", U64_MAX),
    maxCallsPerPeriod: number(19, "Policy period call limit", U32_MAX),
    maxCallCount: number(20, "Policy total call limit", U32_MAX),
    periodStartedAtUnix: integer(values[21], "Policy period start", U64_MAX),
    periodCallCount: number(22, "Policy period call count", U32_MAX),
    usedCallCount: number(23, "Policy used call count", U32_MAX),
  };
}

export type PolicyAccountActivationSnapshot = {
  chainId: `0x${string}`;
  classHash: `0x${string}`;
  blockNumber: bigint;
  blockHash: `0x${string}`;
  blockTimestamp: bigint;
  active: boolean;
  paused: boolean;
  policy: PolicyAccountState;
};

function assertSame(label: string, actual: string | number | bigint, expected: string | number | bigint): void {
  if (!equal(actual, expected)) throw new Error(`The on-chain ${label} does not match the pending PAYO account.`);
}

/** Fails closed unless one pinned on-chain snapshot exactly matches the generated policy. */
export function assertPolicyAccountActivation(input: {
  config: DirectPrivacyAccountConfig;
  snapshot: PolicyAccountActivationSnapshot;
  expectedClassHash: string;
}): void {
  const { config, snapshot, expectedClassHash } = input;
  const { policy } = snapshot;
  assertSame("chain ID", snapshot.chainId, config.chainId);
  assertSame("policy account class hash", snapshot.classHash, expectedClassHash);
  if (!policy.configured || policy.revoked || !snapshot.active || snapshot.paused) {
    throw new Error("The policy account is not configured, active and unpaused at the pinned block.");
  }
  assertSame("session public key", policy.sessionPublicKey, config.sessionPublicKey);
  assertSame("Privacy Pool", policy.poolAddress, config.poolAddress);
  assertSame("PAYO Seal", policy.sealAddress, config.sealAddress);
  assertSame("universal payroll-book seal", policy.bookSealAddress, config.bookSealAddress ?? "0x0");
  assertSame("seal mode", policy.sealMode, config.sealMode);
  assertSame("proof version", policy.proofVersion, config.proofVersion);
  assertSame("schema version", policy.schemaVersion, config.schemaVersion);
  const [rootHigh, rootLow] = splitRoot(config.payrollPolicyRoot);
  assertSame("payroll policy root high limb", policy.payrollPolicyRootHigh, rootHigh);
  assertSame("payroll policy root low limb", policy.payrollPolicyRootLow, rootLow);
  assertSame("token scope", policy.tokenSetCommitment, config.tokenSetCommitment);
  assertSame("recipient scope", policy.recipientSetCommitment, config.recipientSetCommitment);
  assertSame("purpose scope", policy.purposeCommitment, config.purposeCommitment);
  assertSame("amount scope", policy.amountLimitCommitment, config.amountLimitCommitment);
  assertSame("authorized-runs root", policy.authorizedRunsRoot, config.authorizedRunsRoot);
  assertSame("valid-after", policy.validAfterUnix, config.validAfterUnix);
  assertSame("valid-before", policy.validBeforeUnix, config.validBeforeUnix);
  assertSame("period", policy.periodSeconds, config.periodSeconds);
  assertSame("period call limit", policy.maxCallsPerPeriod, config.maxCallsPerPeriod);
  assertSame("total call limit", policy.maxCallCount, config.maxCallCount);
  assertSame("initial period start", policy.periodStartedAtUnix, config.validAfterUnix);
  if (policy.periodCallCount !== 0 || policy.usedCallCount !== 0) {
    throw new Error("PAYO will not activate a policy account that was used before verification.");
  }
  const validAfter = BigInt(config.validAfterUnix);
  const validBefore = BigInt(config.validBeforeUnix);
  if (!(validAfter < snapshot.blockTimestamp && snapshot.blockTimestamp < validBefore)) {
    throw new Error("The policy validity window is not active at the pinned block.");
  }
}
