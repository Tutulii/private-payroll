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

export async function readPolicyAccountActivationSnapshot(input: {
  provider: RpcProvider;
  policyAccountAddress: string;
  policyId: string;
}): Promise<PolicyAccountActivationSnapshot> {
  const block = await input.provider.getBlock("latest");
  const pinnedBlock = block.block_hash;
  const [chainId, classHash, state, active, paused] = await Promise.all([
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
  ]);
  return {
    chainId: chainId as `0x${string}`,
    classHash: classHash as `0x${string}`,
    blockNumber: BigInt(block.block_number),
    blockHash: block.block_hash as `0x${string}`,
    blockTimestamp: BigInt(block.timestamp),
    active: booleanResult(active, "is_policy_active"),
    paused: booleanResult(paused, "is_policy_account_paused"),
    policy: decodePolicyAccountState(state),
  };
}

async function persistVerifiedActivation(input: {
  candidate: Awaited<ReturnType<typeof getDirectPrivacyAccountActivationCandidate>>;
  snapshot: PolicyAccountActivationSnapshot;
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
  return activateDirectPrivacyAccount({
    accountId: input.candidate.id,
    configCommitment: input.candidate.configCommitment,
    snapshot: input.snapshot,
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
  ownerPrivateKey: string;
  submitConfiguration: (call: Call) => Promise<string>;
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
    configuredOwnerPublicKey = derivePolicyOwnerPublicKey(input.ownerPrivateKey);
  } catch {
    throw new ApiError(
      503,
      "The policy owner signer is not configured.",
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
