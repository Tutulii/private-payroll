import { validateAndParseAddress } from "starknet";
import type { AgentCapability } from "@/lib/domain/capability";
import type { DirectPrivacyAccountConfig } from "@/lib/domain/direct-privacy";
import type { DirectPrivacyDeploymentConfig } from "@/lib/server/direct-privacy-deployment";
import {
  buildAuthorizedPolicyRunTree,
  commitPolicyCapability,
} from "./policy-account";

const MAX_POLICY_LIFETIME_SECONDS = 366n * 24n * 60n * 60n;

export type DirectPrivacyProvisioningRun = {
  runId: string;
  runVersion: number;
  agreementRoot: `0x${string}`;
  manifestRoot: `0x${string}`;
  payrollPolicyRoot: `0x${string}`;
  runNullifier: `0x${string}`;
  proofVersion: 1 | 2;
};

export type DirectPrivacyProvisioningRequest = {
  policyAccountAddress: string;
  policyId: string;
  validForSeconds: number;
  periodSeconds: number;
  maxCallsPerPeriod: number;
  maxCallCount: number;
};

function unixSeconds(value: string, label: string): bigint {
  const milliseconds = new Date(value).getTime();
  if (!Number.isSafeInteger(milliseconds)) throw new Error(`${label} is invalid.`);
  return BigInt(Math.floor(milliseconds / 1_000));
}

function boundedInteger(value: number, label: string, maximum = 4_294_967_295): number {
  if (!Number.isInteger(value) || value <= 0 || value > maximum) {
    throw new Error(`${label} is outside the supported range.`);
  }
  return value;
}

function sameFelt(left: string, right: string): boolean {
  try { return BigInt(left) === BigInt(right); } catch { return false; }
}

function canonicalAddress(value: string): `0x${string}` {
  return `0x${BigInt(validateAndParseAddress(value)).toString(16)}`;
}

export function buildDirectPrivacyAccountProvisioningPlan(input: {
  capability: AgentCapability;
  runs: readonly DirectPrivacyProvisioningRun[];
  request: DirectPrivacyProvisioningRequest;
  deployment: DirectPrivacyDeploymentConfig;
  now: Date;
}): {
  config: Omit<DirectPrivacyAccountConfig, "version" | "sessionPublicKey" | "sdkVersion" | "sdkRevision">;
  authorizedRuns: Array<{
    runId: string;
    runVersion: number;
    agreementRoot: `0x${string}`;
    manifestRoot: `0x${string}`;
    runNullifier: `0x${string}`;
    pathBits: number;
    siblings: `0x${string}`[];
  }>;
} {
  if (input.runs.length < 1 || input.runs.length > 256) throw new Error("Select 1–256 exact payroll runs.");
  if (new Set(input.runs.map(({ runId }) => runId)).size !== input.runs.length) {
    throw new Error("A policy cannot authorize the same payroll run twice.");
  }
  const capability = input.capability;
  if (capability.executionMode !== "autonomous_bounded") {
    throw new Error("The capability is not bounded-autonomous.");
  }
  const now = BigInt(Math.floor(input.now.getTime() / 1_000));
  const capabilityValidAfter = unixSeconds(capability.validAfter, "Capability valid-after");
  const capabilityValidBefore = unixSeconds(capability.expiresAt, "Capability expiry");
  if (now <= capabilityValidAfter || now >= capabilityValidBefore) throw new Error("The capability is not currently active.");
  const validFor = BigInt(boundedInteger(input.request.validForSeconds, "Policy lifetime", Number(MAX_POLICY_LIFETIME_SECONDS)));
  const periodSeconds = BigInt(boundedInteger(input.request.periodSeconds, "Policy period", Number(MAX_POLICY_LIFETIME_SECONDS)));
  const remainingCalls = capability.maxCallCount - capability.usedCallCount;
  const maxCallCount = boundedInteger(input.request.maxCallCount, "Policy total call limit");
  const maxCallsPerPeriod = boundedInteger(input.request.maxCallsPerPeriod, "Policy period call limit");
  if (maxCallCount > remainingCalls || maxCallCount > input.runs.length || maxCallsPerPeriod > maxCallCount) {
    throw new Error("The policy call limits exceed the capability or authorized runs.");
  }
  const validAfter = now - 1n;
  const validBefore = now + validFor < capabilityValidBefore ? now + validFor : capabilityValidBefore;
  if (validAfter < capabilityValidAfter || validBefore <= now) {
    throw new Error("The policy validity cannot fit inside the capability window.");
  }
  const proofVersion = input.runs[0].proofVersion;
  const payrollPolicyRoot = input.runs[0].payrollPolicyRoot;
  if (input.runs.some((run) =>
    run.proofVersion !== proofVersion || !sameFelt(run.payrollPolicyRoot, payrollPolicyRoot))) {
    throw new Error("One policy account requires one proof version and payroll policy root.");
  }
  const scope = commitPolicyCapability(capability);
  const policyAccountAddress = canonicalAddress(input.request.policyAccountAddress);
  if (!sameFelt(policyAccountAddress, input.deployment.policyAccountAddress)) {
    throw new Error("The requested policy account is not the reviewed PAYO deployment.");
  }
  const policyId = canonicalAddress(input.request.policyId);
  const context = {
    policyId,
    sealMode: 0 as const,
    proofVersion,
    schemaVersion: 1,
    payrollPolicyRoot,
    ...scope,
  };
  const tree = buildAuthorizedPolicyRunTree(context, input.runs.map((run) => ({
    agreementRoot: run.agreementRoot,
    manifestRoot: run.manifestRoot,
    runNullifier: run.runNullifier,
  })));
  return {
    config: {
      chainId: input.deployment.chainId,
      policyAccountAddress,
      policyId,
      sealMode: 0,
      proofVersion,
      schemaVersion: 1,
      payrollPolicyRoot,
      ...scope,
      authorizedRunsRoot: tree.root,
      validAfterUnix: validAfter.toString(),
      validBeforeUnix: validBefore.toString(),
      periodSeconds: periodSeconds.toString(),
      maxCallsPerPeriod,
      maxCallCount,
      poolAddress: input.deployment.poolAddress,
      sealAddress: input.deployment.sealAddress,
      tokenAddresses: input.deployment.tokenAddresses,
    },
    authorizedRuns: input.runs.map((run, index) => ({
      runId: run.runId,
      runVersion: run.runVersion,
      agreementRoot: run.agreementRoot,
      manifestRoot: run.manifestRoot,
      runNullifier: run.runNullifier,
      pathBits: tree.proofs[index].pathBits,
      siblings: tree.proofs[index].siblings,
    })),
  };
}
