import "server-only";

import { ec, RpcProvider, type Call } from "starknet";
import {
  assertPolicyAccountActivation,
  decodePolicyAccountState,
  type PolicyAccountActivationSnapshot,
} from "@/lib/starknet/policy-account-activation";
import type { DirectPrivacyAccountConfig } from "@/lib/domain/direct-privacy";
import {
  activateDirectPrivacyAccount,
  getDirectPrivacyAccountActivationCandidate,
} from "@/lib/persistence/direct-privacy-repository";
import { ApiError, type AuthenticatedPrincipal } from "./auth";
import type { DirectPrivacyDeploymentConfig } from "./direct-privacy-deployment";
import { buildConfigurePolicyCall } from "@/lib/starknet/policy-account-configuration";

function booleanResult(values: readonly string[], label: string): boolean {
  if (values.length !== 1 || (BigInt(values[0]) !== 0n && BigInt(values[0]) !== 1n)) {
    throw new Error(`${label} returned an invalid Cairo boolean.`);
  }
  return BigInt(values[0]) === 1n;
}

function sameFelt(left: string, right: string): boolean {
  try { return BigInt(left) === BigInt(right); } catch { return false; }
}

export function derivePolicyOwnerPublicKey(privateKey: string): `0x${string}` {
  let scalar: bigint;
  try { scalar = BigInt(privateKey); } catch { throw new Error("The policy owner key is invalid."); }
  if (scalar <= 0n || scalar >= ec.starkCurve.CURVE.n) {
    throw new Error("The policy owner key is invalid.");
  }
  return `0x${BigInt(ec.starkCurve.getStarkKey(privateKey)).toString(16)}`;
}

function assertDirectPrivacyDeployment(
  config: DirectPrivacyAccountConfig,
  deployment: DirectPrivacyDeploymentConfig,
): void {
  if (
    !sameFelt(config.chainId, deployment.chainId)
    || !sameFelt(config.poolAddress, deployment.poolAddress)
    || !sameFelt(config.sealAddress, deployment.sealAddress)
    || !sameFelt(config.tokenAddresses.STRK, deployment.tokenAddresses.STRK)
    || !sameFelt(config.tokenAddresses.USDC, deployment.tokenAddresses.USDC)
  ) {
    throw new ApiError(409, "The pending policy targets a different PAYO deployment.", "DIRECT_POLICY_DEPLOYMENT_MISMATCH");
  }
}

export type DirectPrivacyActivationSnapshot = PolicyAccountActivationSnapshot & {
  registrationPublicKey?: `0x${string}`;
};

export async function readPolicyAccountActivationSnapshot(input: {
  provider: RpcProvider;
  policyAccountAddress: string;
  policyId: string;
  poolAddress?: string;
}): Promise<DirectPrivacyActivationSnapshot> {
  const block = await input.provider.getBlock("latest");
  const pinnedBlock = block.block_hash;
  const [chainId, classHash, state, active, paused, registration] = await Promise.all([
    input.provider.getChainId(),
    input.provider.getClassHashAt(input.policyAccountAddress, pinnedBlock),
    input.provider.callContract({
      contractAddress: input.policyAccountAddress,
      entrypoint: "get_policy",
      calldata: [input.policyId],
    }, pinnedBlock),
    input.provider.callContract({
      contractAddress: input.policyAccountAddress,
      entrypoint: "is_policy_active",
      calldata: [input.policyId],
    }, pinnedBlock),
    input.provider.callContract({
      contractAddress: input.policyAccountAddress,
      entrypoint: "is_policy_account_paused",
      calldata: [],
    }, pinnedBlock),
    input.poolAddress
      ? input.provider.callContract({
          contractAddress: input.poolAddress,
          entrypoint: "get_public_key",
          calldata: [input.policyAccountAddress],
        }, pinnedBlock)
      : Promise.resolve(undefined),
  ]);
  if (registration && registration.length !== 1) {
    throw new Error("STRK20 get_public_key returned an invalid value.");
  }
  return {
    chainId: chainId as `0x${string}`,
    classHash: classHash as `0x${string}`,
    blockNumber: BigInt(block.block_number),
    blockHash: block.block_hash as `0x${string}`,
    blockTimestamp: BigInt(block.timestamp),
    active: booleanResult(active, "is_policy_active"),
    paused: booleanResult(paused, "is_policy_account_paused"),
    policy: decodePolicyAccountState(state),
    registrationPublicKey: registration?.[0] as `0x${string}` | undefined,
  };
}

async function persistVerifiedActivation(input: {
  candidate: Awaited<ReturnType<typeof getDirectPrivacyAccountActivationCandidate>>;
  snapshot: DirectPrivacyActivationSnapshot;
  expectedClassHash: string;
  principal: AuthenticatedPrincipal;
  now?: Date;
}) {
  try {
    assertPolicyAccountActivation({
      config: input.candidate.config,
      snapshot: input.snapshot,
      expectedClassHash: input.expectedClassHash,
    });
  } catch (error) {
    throw new ApiError(
      409,
      error instanceof Error ? error.message : "Policy activation failed.",
      "DIRECT_POLICY_CHAIN_MISMATCH",
    );
  }
  if (!input.snapshot.registrationPublicKey) {
    throw new ApiError(
      409,
      "The STRK20 pool did not return a registration key for the policy account.",
      "DIRECT_TREASURY_NOT_REGISTERED",
    );
  }
  return activateDirectPrivacyAccount({
    accountId: input.candidate.id,
    configCommitment: input.candidate.configCommitment,
    snapshot: input.snapshot,
    registrationPublicKey: input.snapshot.registrationPublicKey,
    expectedClassHash: input.expectedClassHash,
    principal: input.principal,
    now: input.now,
  });
}

/**
 * Two-step activation: PAYO first generated the session key, the owner then
 * configured that exact key on-chain, and only this pinned verification can
 * make the backend account executable.
 */
export async function verifyAndActivateDirectPrivacyAccount(input: {
  accountId: string;
  principal: AuthenticatedPrincipal;
  provider: RpcProvider;
  deployment: DirectPrivacyDeploymentConfig;
  now?: Date;
}) {
  const candidate = await getDirectPrivacyAccountActivationCandidate({
    accountId: input.accountId,
    principal: input.principal,
  });
  assertDirectPrivacyDeployment(candidate.config, input.deployment);
  const snapshot = await readPolicyAccountActivationSnapshot({
    provider: input.provider,
    policyAccountAddress: candidate.config.policyAccountAddress,
    policyId: candidate.config.policyId,
    poolAddress: candidate.config.poolAddress,
  });
  return persistVerifiedActivation({
    candidate,
    snapshot,
    expectedClassHash: input.deployment.policyAccountClassHash,
    principal: input.principal,
    now: input.now,
  });
}

/**
 * Configures one exact owner-authorized policy and persists activation only
 * after a fresh pinned read-back. The injected submitter owns fee estimation,
 * nonce serialization and confirmation waiting; no private key is returned.
 */
export async function configureAndActivateDirectPrivacyAccount(input: {
  accountId: string;
  principal: AuthenticatedPrincipal;
  provider: RpcProvider;
  deployment: DirectPrivacyDeploymentConfig;
  ownerPublicKey: string;
  submitConfiguration: (call: Call) => Promise<string | undefined>;
  now?: Date;
}): Promise<{
  account: Awaited<ReturnType<typeof activateDirectPrivacyAccount>>;
  configurationTransactionHash?: string;
}> {
  const candidate = await getDirectPrivacyAccountActivationCandidate({
    accountId: input.accountId,
    principal: input.principal,
  });
  assertDirectPrivacyDeployment(candidate.config, input.deployment);
  const snapshot = await readPolicyAccountActivationSnapshot({
    provider: input.provider,
    policyAccountAddress: candidate.config.policyAccountAddress,
    policyId: candidate.config.policyId,
    poolAddress: candidate.config.poolAddress,
  });
  if (snapshot.policy.configured) {
    return {
      account: await persistVerifiedActivation({
        candidate,
        snapshot,
        expectedClassHash: input.deployment.policyAccountClassHash,
        principal: input.principal,
        now: input.now,
      }),
    };
  }
  if (
    !sameFelt(snapshot.chainId, candidate.config.chainId)
    || !sameFelt(snapshot.classHash, input.deployment.policyAccountClassHash)
    || snapshot.active
    || snapshot.paused
  ) {
    throw new ApiError(
      409,
      "The unconfigured policy account failed its pinned deployment checks.",
      "DIRECT_POLICY_ACCOUNT_NOT_CONFIGURABLE",
    );
  }
  const ownerResult = await input.provider.callContract({
    contractAddress: candidate.config.policyAccountAddress,
    entrypoint: "get_public_key",
    calldata: [],
  }, snapshot.blockHash);
  let configuredOwnerPublicKey: `0x${string}`;
  try {
    configuredOwnerPublicKey = `0x${BigInt(input.ownerPublicKey).toString(16)}`;
    if (BigInt(configuredOwnerPublicKey) <= 0n) throw new Error("invalid");
  } catch {
    throw new ApiError(
      503,
      "The isolated policy owner signer is not configured.",
      "DIRECT_POLICY_OWNER_NOT_CONFIGURED",
    );
  }
  if (
    ownerResult.length !== 1
    || !sameFelt(ownerResult[0], configuredOwnerPublicKey)
  ) {
    throw new ApiError(
      503,
      "The configured policy owner signer does not control the reviewed account.",
      "DIRECT_POLICY_OWNER_MISMATCH",
    );
  }
  const configurationTransactionHash = await input.submitConfiguration(
    buildConfigurePolicyCall(candidate.config),
  );
  const verified = await verifyAndActivateDirectPrivacyAccount({
    accountId: input.accountId,
    principal: input.principal,
    provider: input.provider,
    deployment: input.deployment,
    now: input.now,
  });
  return { account: verified, configurationTransactionHash };
}

export type DirectPrivacyActivationEstimate = {
  accountId: string;
  configCommitment: string;
  policyId: string;
  validBeforeUnix: string;
  maxCallsPerPeriod: number;
  maxCallCount: number;
  pinnedBlockNumber: string;
  pinnedBlockHash: string;
  estimatedFeeFri: string;
  replayed: boolean;
};

/**
 * Produces a read-only, exact-call fee review before the owner signer may
 * submit a policy. The later activation repeats every chain check and estimate.
 */
export async function estimateDirectPrivacyAccountActivation(input: {
  accountId: string;
  principal: AuthenticatedPrincipal;
  provider: RpcProvider;
  deployment: DirectPrivacyDeploymentConfig;
  ownerPublicKey: string;
  estimateConfiguration: (call: Call) => Promise<{
    blockNumber: number;
    blockHash: string;
    estimatedFeeFri: string;
    replayed: boolean;
  }>;
}): Promise<DirectPrivacyActivationEstimate> {
  const candidate = await getDirectPrivacyAccountActivationCandidate({
    accountId: input.accountId,
    principal: input.principal,
  });
  assertDirectPrivacyDeployment(candidate.config, input.deployment);
  const snapshot = await readPolicyAccountActivationSnapshot({
    provider: input.provider,
    policyAccountAddress: candidate.config.policyAccountAddress,
    policyId: candidate.config.policyId,
    poolAddress: candidate.config.poolAddress,
  });
  if (
    !sameFelt(snapshot.chainId, candidate.config.chainId)
    || !sameFelt(snapshot.classHash, input.deployment.policyAccountClassHash)
    || snapshot.paused
  ) {
    throw new ApiError(
      409,
      "The policy account failed its pinned activation-preview checks.",
      "DIRECT_POLICY_ACCOUNT_NOT_CONFIGURABLE",
    );
  }
  const ownerResult = await input.provider.callContract({
    contractAddress: candidate.config.policyAccountAddress,
    entrypoint: "get_public_key",
    calldata: [],
  }, snapshot.blockHash);
  if (ownerResult.length !== 1 || !sameFelt(ownerResult[0], input.ownerPublicKey)) {
    throw new ApiError(
      503,
      "The configured policy owner signer does not control the reviewed account.",
      "DIRECT_POLICY_OWNER_MISMATCH",
    );
  }
  if (!snapshot.registrationPublicKey || BigInt(snapshot.registrationPublicKey) === 0n) {
    throw new ApiError(
      409,
      "The STRK20 policy treasury is not registered.",
      "DIRECT_TREASURY_NOT_REGISTERED",
    );
  }
  if (snapshot.policy.configured) {
    try {
      assertPolicyAccountActivation({
        config: candidate.config,
        snapshot,
        expectedClassHash: input.deployment.policyAccountClassHash,
      });
    } catch (error) {
      throw new ApiError(
        409,
        error instanceof Error ? error.message : "The configured policy does not match PAYO's pending account.",
        "DIRECT_POLICY_CHAIN_MISMATCH",
      );
    }
    return {
      accountId: candidate.id,
      configCommitment: candidate.configCommitment,
      policyId: candidate.config.policyId,
      validBeforeUnix: candidate.config.validBeforeUnix,
      maxCallsPerPeriod: candidate.config.maxCallsPerPeriod,
      maxCallCount: candidate.config.maxCallCount,
      pinnedBlockNumber: snapshot.blockNumber.toString(),
      pinnedBlockHash: snapshot.blockHash,
      estimatedFeeFri: "0",
      replayed: true,
    };
  }
  const estimate = await input.estimateConfiguration(
    buildConfigurePolicyCall(candidate.config),
  );
  return {
    accountId: candidate.id,
    configCommitment: candidate.configCommitment,
    policyId: candidate.config.policyId,
    validBeforeUnix: candidate.config.validBeforeUnix,
    maxCallsPerPeriod: candidate.config.maxCallsPerPeriod,
    maxCallCount: candidate.config.maxCallCount,
    pinnedBlockNumber: estimate.blockNumber.toString(),
    pinnedBlockHash: estimate.blockHash,
    estimatedFeeFri: estimate.estimatedFeeFri,
    replayed: estimate.replayed,
  };
}
