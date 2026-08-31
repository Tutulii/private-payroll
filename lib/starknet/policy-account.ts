import { hash, num, shortString } from "starknet";
import {
  agentCapabilitySchema,
  type AgentCapability,
} from "@/lib/domain/capability";

const RUN_TREE_DEPTH = 8;
const RUN_TREE_CAPACITY = 1 << RUN_TREE_DEPTH;
const RUN_LEAF_DOMAIN = shortString.encodeShortString("PAYO_AGENT_RUN_V1");
const EMPTY_RUN_DOMAIN = shortString.encodeShortString("PAYO_AGENT_EMPTY_V1");
const TOKEN_SCOPE_DOMAIN = shortString.encodeShortString("PAYO_AGENT_TOKEN_V1");
const RECIPIENT_SCOPE_DOMAIN = shortString.encodeShortString("PAYO_AGENT_RCPT_V1");
const PURPOSE_SCOPE_DOMAIN = shortString.encodeShortString("PAYO_AGENT_PURP_V1");
const AMOUNT_SCOPE_DOMAIN = shortString.encodeShortString("PAYO_AGENT_AMT_V1");

export type PolicyScopeCommitments = {
  tokenSetCommitment: `0x${string}`;
  recipientSetCommitment: `0x${string}`;
  purposeCommitment: `0x${string}`;
  amountLimitCommitment: `0x${string}`;
};

export type PolicyRunBinding = {
  agreementRoot: `0x${string}`;
  manifestRoot: `0x${string}`;
  runNullifier: `0x${string}`;
};

export type PolicyLeafContext = PolicyScopeCommitments & {
  policyId: string;
  sealMode: 0 | 1;
  proofVersion: number;
  schemaVersion: number;
  payrollPolicyRoot: `0x${string}`;
};

export type PolicyRunProof = PolicyRunBinding & {
  leaf: `0x${string}`;
  pathBits: number;
  siblings: `0x${string}`[];
};

function felt(value: string | number | bigint): `0x${string}` {
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= (1n << 251n) + 17n * (1n << 192n) + 1n) {
    throw new Error("Policy commitment input is not a canonical Starknet felt.");
  }
  return num.toHex(parsed) as `0x${string}`;
}

function poseidon(values: readonly (string | number | bigint)[]): `0x${string}` {
  return num.toHex(hash.computePoseidonHashOnElements([...values])) as `0x${string}`;
}

function timestampSeconds(value: string): bigint {
  const milliseconds = new Date(value).getTime();
  if (!Number.isSafeInteger(milliseconds)) throw new Error("Capability limit timestamp is invalid.");
  return BigInt(Math.floor(milliseconds / 1_000));
}

function splitRoot(value: `0x${string}`): readonly [bigint, bigint] {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error("Policy run roots must be 32-byte hex values.");
  const root = BigInt(value);
  return [root >> 128n, root & ((1n << 128n) - 1n)];
}

/**
 * Reproduces the exact scope commitments reviewed by the owner before
 * `configure_policy`. Autonomous policies deliberately forbid `any`
 * recipients, even though human-approval capabilities may use that mode.
 */
export function commitPolicyCapability(capabilityInput: AgentCapability): PolicyScopeCommitments {
  const capability = agentCapabilitySchema.parse(capabilityInput);
  if (capability.executionMode !== "autonomous_bounded") {
    throw new Error("Only an explicitly autonomous-bounded capability can configure a policy account.");
  }
  if (capability.recipientScope.mode !== "allowlist") {
    throw new Error("Autonomous policy accounts require an exact recipient allowlist.");
  }

  const tokens = [...capability.allowedTokens]
    .sort()
    .map((token) => BigInt(shortString.encodeShortString(token)));
  const recipients = capability.recipientScope.addresses
    .map((address) => BigInt(address))
    .sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
  const purposes = [...capability.purposeCodes]
    .sort()
    .map((purpose) => BigInt(hash.starknetKeccak(purpose)));
  const limits = [...capability.limits].sort((left, right) => left.token.localeCompare(right.token));
  const encodedLimits = limits.flatMap((limit) => [
    BigInt(shortString.encodeShortString(limit.token)),
    BigInt(limit.maxPerPaymentAtomic),
    BigInt(limit.maxPerPeriodAtomic),
    BigInt(limit.approvalThresholdAtomic),
    timestampSeconds(limit.periodStartsAt),
    timestampSeconds(limit.periodEndsAt),
  ]);

  return {
    tokenSetCommitment: poseidon([TOKEN_SCOPE_DOMAIN, tokens.length, ...tokens]),
    recipientSetCommitment: poseidon([RECIPIENT_SCOPE_DOMAIN, recipients.length, ...recipients]),
    purposeCommitment: poseidon([PURPOSE_SCOPE_DOMAIN, purposes.length, ...purposes]),
    amountLimitCommitment: poseidon([
      AMOUNT_SCOPE_DOMAIN,
      limits.length,
      capability.maxCallCount,
      ...encodedLimits,
    ]),
  };
}

/** Matches `PayoPolicyAccount::run_leaf` field-for-field. */
export function computePolicyRunLeaf(
  context: PolicyLeafContext,
  run: PolicyRunBinding,
): `0x${string}` {
  const [policyHigh, policyLow] = splitRoot(context.payrollPolicyRoot);
  const [agreementHigh, agreementLow] = splitRoot(run.agreementRoot);
  const [manifestHigh, manifestLow] = splitRoot(run.manifestRoot);
  const [nullifierHigh, nullifierLow] = splitRoot(run.runNullifier);
  if (!Number.isInteger(context.proofVersion) || context.proofVersion < 1) {
    throw new Error("Policy proof version must be a positive integer.");
  }
  if (!Number.isInteger(context.schemaVersion) || context.schemaVersion < 1) {
    throw new Error("Policy schema version must be a positive integer.");
  }
  return poseidon([
    RUN_LEAF_DOMAIN,
    felt(context.policyId),
    context.sealMode,
    context.proofVersion,
    context.schemaVersion,
    policyHigh,
    policyLow,
    context.tokenSetCommitment,
    context.recipientSetCommitment,
    context.purposeCommitment,
    context.amountLimitCommitment,
    agreementHigh,
    agreementLow,
    manifestHigh,
    manifestLow,
    nullifierHigh,
    nullifierLow,
  ]);
}

/**
 * Builds the contract's fixed depth-8 tree and returns one proof per run.
 * Input order is significant and must be persisted with the reviewed policy.
 */
export function buildAuthorizedPolicyRunTree(
  context: PolicyLeafContext,
  runs: readonly PolicyRunBinding[],
): { root: `0x${string}`; proofs: PolicyRunProof[] } {
  if (runs.length < 1 || runs.length > RUN_TREE_CAPACITY) {
    throw new Error(`A policy authorizes 1–${RUN_TREE_CAPACITY} exact runs.`);
  }
  const nullifiers = new Set<string>();
  const leaves = runs.map((run) => {
    const normalized = run.runNullifier.toLowerCase();
    if (nullifiers.has(normalized)) throw new Error("A policy cannot authorize the same run nullifier twice.");
    nullifiers.add(normalized);
    return computePolicyRunLeaf(context, run);
  });
  while (leaves.length < RUN_TREE_CAPACITY) {
    leaves.push(poseidon([EMPTY_RUN_DOMAIN, leaves.length]));
  }

  const levels: `0x${string}`[][] = [leaves];
  for (let depth = 0; depth < RUN_TREE_DEPTH; depth += 1) {
    const previous = levels[depth];
    const next: `0x${string}`[] = [];
    for (let index = 0; index < previous.length; index += 2) {
      next.push(poseidon([previous[index], previous[index + 1]]));
    }
    levels.push(next);
  }

  return {
    root: levels[RUN_TREE_DEPTH][0],
    proofs: runs.map((run, index) => {
      const siblings: `0x${string}`[] = [];
      let cursor = index;
      for (let depth = 0; depth < RUN_TREE_DEPTH; depth += 1) {
        siblings.push(levels[depth][cursor ^ 1]);
        cursor >>= 1;
      }
      return {
        ...run,
        leaf: levels[0][index],
        pathBits: index,
        siblings,
      };
    }),
  };
}

export function verifyPolicyRunProof(root: string, proof: PolicyRunProof): boolean {
  if (proof.siblings.length !== RUN_TREE_DEPTH || proof.pathBits < 0 || proof.pathBits >= RUN_TREE_CAPACITY) {
    return false;
  }
  let current = proof.leaf;
  let path = proof.pathBits;
  for (const sibling of proof.siblings) {
    current = (path & 1) === 0
      ? poseidon([current, sibling])
      : poseidon([sibling, current]);
    path >>= 1;
  }
  return BigInt(current) === BigInt(root);
}
