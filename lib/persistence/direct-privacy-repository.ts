import "server-only";

import { and, eq, inArray } from "drizzle-orm";
import { ec } from "starknet";
import {
  encryptedVaultRecordSchema,
  generateVaultPrincipal,
  type EncryptedVaultRecord,
} from "@/lib/crypto/vault";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  commitDirectPrivacyAccountConfig,
  commitDirectPrivacyRunMaterial,
  directPrivacyAccountConfigSchema,
  directPrivacyRunMaterialSchema,
  directPrivacyStateSchema,
  emptyDirectPrivacyState,
  type DirectPrivacyAccountConfig,
  type DirectPrivacyRunMaterial,
  type DirectPrivacySecrets,
  type DirectPrivacyState,
} from "@/lib/domain/direct-privacy";
import { commitAgentExecutionRequest } from "@/lib/domain/agent-execution";
import { agentExecutionRequestSchema, type AgentExecutionRequest } from "@/lib/domain/capability";
import { generateUuidV7 } from "@/lib/domain/records";
import { commitPolicyCapability, computePolicyRunLeaf, verifyPolicyRunProof, type PolicyRunProof } from "@/lib/starknet/policy-account";
import {
  buildDirectPrivacyAccountProvisioningPlan,
  type DirectPrivacyProvisioningRequest,
} from "@/lib/starknet/direct-privacy-account-plan";
import type { DirectPrivacyDeploymentConfig } from "@/lib/server/direct-privacy-deployment";
import {
  assertPolicyAccountActivation,
  type PolicyAccountActivationSnapshot,
} from "@/lib/starknet/policy-account-activation";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { decryptCapabilityPolicy } from "@/lib/server/capability-policy-crypto";
import {
  decryptDirectPrivacyPayload,
  encryptDirectPrivacyPayload,
} from "@/lib/server/direct-privacy-crypto";
import {
  PAYO_PRIVACY_SDK_REVISION,
  PAYO_PRIVACY_SDK_VERSION,
} from "@/lib/server/privacy-sdk-loader";
import type { LeasedAgentExecution } from "./agent-execution-worker-repository";
import { getDatabase } from "./db";
import { requireOrganizationRoleWith } from "./repository";
import {
  agentCapabilities,
  auditEvents,
  directPrivacyAccounts,
  directPrivacyAuthorizedRuns,
  directPrivacyRunMaterials,
  proofBundles,
  payrollRuns,
} from "./schema";

const ACCOUNT_LEASE_MS = 30 * 60_000;
const MAX_POLICY_WINDOW_SECONDS = 366n * 24n * 60n * 60n;

function sameFeltArray(left: unknown, right: readonly string[]): boolean {
  if (!Array.isArray(left) || left.length !== right.length) return false;
  try {
    return left.every((value, index) => typeof value === "string" && BigInt(value) === BigInt(right[index]));
  } catch {
    return false;
  }
}

function parseAuthorizedSiblings(value: unknown): `0x${string}`[] {
  if (
    !Array.isArray(value)
    || value.length !== 8
    || value.some((entry) => typeof entry !== "string" || !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})$/.test(entry))
  ) throw new Error("DIRECT_AUTHORIZED_RUN_PATH_INVALID");
  return value as `0x${string}`[];
}

function timestampSeconds(value: string): bigint {
  const milliseconds = new Date(value).getTime();
  if (!Number.isSafeInteger(milliseconds)) throw new Error("Capability timestamp is invalid.");
  return BigInt(Math.floor(milliseconds / 1_000));
}

function privateKey(): `0x${string}` {
  return `0x${Buffer.from(ec.starkCurve.utils.randomPrivateKey()).toString("hex")}`;
}

function viewingKey(): `0x${string}` {
  const limit = ec.starkCurve.CURVE.n / 2n;
  for (;;) {
    const candidate = privateKey();
    const scalar = BigInt(candidate);
    if (scalar > 0n && scalar <= limit) return `0x${scalar.toString(16)}`;
  }
}

function sessionPublicKey(secret: string): `0x${string}` {
  let scalar: bigint;
  try { scalar = BigInt(secret); } catch { throw new Error("The policy-account session key is invalid."); }
  if (scalar <= 0n || scalar >= ec.starkCurve.CURVE.n) {
    throw new Error("The policy-account session key is not a valid Stark private key.");
  }
  return `0x${BigInt(ec.starkCurve.getStarkKey(secret)).toString(16)}`;
}

export type DirectPrivacyAccountPublic = {
  id: string;
  config: DirectPrivacyAccountConfig;
  proofPrincipal: { principalId: string; publicKey: string };
  stateVersion: number;
  authorizedRunCount: number;
  activationState: "pending" | "active";
  activation: {
    blockNumber: string;
    blockHash: string;
    classHash: string;
    blockTimestamp: string;
    activatedAt: string;
  } | null;
};

export type DirectPrivacyAccountSummary = {
  id: string;
  capabilityId: string;
  config: DirectPrivacyAccountConfig;
  stateVersion: number;
  authorizedRunCount: number;
  activationState: "pending" | "active";
  activation: DirectPrivacyAccountPublic["activation"];
  activeExecutionId: string | null;
  activeLeaseExpiresAt: string | null;
  createdAt: string;
  updatedAt: string;
};

export type DirectPrivacyAuthorizedRunInput = {
  runId: string;
  runVersion: number;
  agreementRoot: `0x${string}`;
  manifestRoot: `0x${string}`;
  runNullifier: `0x${string}`;
  pathBits: number;
  siblings: `0x${string}`[];
};

export async function provisionDirectPrivacyAccount(input: {
  organizationId: string;
  capabilityId: string;
  authorizedRuns: readonly DirectPrivacyAuthorizedRunInput[];
  config: Omit<
    DirectPrivacyAccountConfig,
    "version" | "sessionPublicKey" | "sdkVersion" | "sdkRevision"
  >;
  principal: AuthenticatedPrincipal;
  /** Deterministic keys are accepted only by integration tests. */
  testSecrets?: Pick<DirectPrivacySecrets, "sessionPrivateKey" | "viewingKey" | "proofPrincipal">;
  now?: Date;
}): Promise<DirectPrivacyAccountPublic> {
  if (input.testSecrets && process.env.NODE_ENV !== "test") {
    throw new Error("Caller-provided direct privacy keys are test-only.");
  }
  const now = input.now ?? new Date();
  const id = generateUuidV7(now.getTime());
  const secrets: DirectPrivacySecrets = {
    version: "payo-direct-privacy-secrets-v1",
    sessionPrivateKey: input.testSecrets?.sessionPrivateKey ?? privateKey(),
    viewingKey: input.testSecrets?.viewingKey ?? viewingKey(),
    proofPrincipal: input.testSecrets?.proofPrincipal
      ?? generateVaultPrincipal(`agent-proof:${id}`),
  };
  const config = directPrivacyAccountConfigSchema.parse({
    ...input.config,
    version: "payo-direct-privacy-account-v1",
    sessionPublicKey: sessionPublicKey(secrets.sessionPrivateKey),
    sdkVersion: PAYO_PRIVACY_SDK_VERSION,
    sdkRevision: PAYO_PRIVACY_SDK_REVISION,
  });

  return getDatabase().transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, input.principal, ["admin"]);
    const [capability] = await transaction.select().from(agentCapabilities).where(and(
      eq(agentCapabilities.id, input.capabilityId),
      eq(agentCapabilities.organizationId, input.organizationId),
    )).limit(1).for("update");
    if (!capability) throw new ApiError(404, "Agent capability not found.", "CAPABILITY_NOT_FOUND");
    const signed = decryptCapabilityPolicy(capability.policy, {
      capabilityId: capability.id,
      organizationId: capability.organizationId,
      principalId: capability.principalId,
      capabilityHash: capability.capabilityHash,
    });
    if (signed.capability.executionMode !== "autonomous_bounded") {
      throw new ApiError(409, "Only bounded-autonomy capabilities can provision a policy account.", "CAPABILITY_NOT_AUTONOMOUS");
    }
    if (capability.revokedAt || capability.expiresAt <= now) {
      throw new ApiError(409, "The capability is inactive.", "CAPABILITY_INACTIVE");
    }
    const expectedScope = commitPolicyCapability(signed.capability);
    for (const key of [
      "tokenSetCommitment",
      "recipientSetCommitment",
      "purposeCommitment",
      "amountLimitCommitment",
    ] as const) {
      if (BigInt(config[key]) !== BigInt(expectedScope[key])) {
        throw new ApiError(409, "The policy account scope does not match the signed capability.", "DIRECT_POLICY_SCOPE_MISMATCH");
      }
    }
    const capabilityValidAfter = timestampSeconds(signed.capability.validAfter);
    const capabilityValidBefore = timestampSeconds(signed.capability.expiresAt);
    const configValidAfter = BigInt(config.validAfterUnix);
    const configValidBefore = BigInt(config.validBeforeUnix);
    const periodSeconds = BigInt(config.periodSeconds);
    const remainingCalls = signed.capability.maxCallCount - signed.capability.usedCallCount;
    if (
      configValidAfter < capabilityValidAfter
      || configValidBefore > capabilityValidBefore
      || configValidBefore <= configValidAfter
      || configValidBefore - configValidAfter > MAX_POLICY_WINDOW_SECONDS
      || periodSeconds <= 0n
      || periodSeconds > MAX_POLICY_WINDOW_SECONDS
      || config.maxCallCount > remainingCalls
      || config.maxCallCount > input.authorizedRuns.length
      || config.maxCallsPerPeriod > config.maxCallCount
    ) {
      throw new ApiError(409, "The on-chain policy would broaden or invalidate the signed capability.", "DIRECT_POLICY_LIMIT_MISMATCH");
    }
    if (!Array.isArray(input.authorizedRuns) || input.authorizedRuns.length < 1 || input.authorizedRuns.length > 256) {
      throw new ApiError(400, "Select 1–256 exact payroll runs for this policy.", "DIRECT_POLICY_RUNS_INVALID");
    }
    const runIds = input.authorizedRuns.map(({ runId }) => runId);
    if (new Set(runIds).size !== runIds.length) {
      throw new ApiError(409, "A policy cannot authorize the same run twice.", "DIRECT_POLICY_RUN_DUPLICATE");
    }
    const runRows = await transaction.select().from(payrollRuns).where(and(
      eq(payrollRuns.organizationId, input.organizationId),
      inArray(payrollRuns.id, runIds),
    )).for("update");
    const proofRows = await transaction.select().from(proofBundles).where(and(
      eq(proofBundles.organizationId, input.organizationId),
      eq(proofBundles.proofType, "payroll_integrity"),
      inArray(proofBundles.runId, runIds),
    )).for("update");
    const proofByRunId = new Map(proofRows
      .filter((bundle) => bundle.subjectRecordId === bundle.runId)
      .map((bundle) => [bundle.runId, bundle]));
    const rowsById = new Map(runRows.map((run) => [run.id, run]));
    const nullifiers = new Set<string>();
    const policyContext = {
      policyId: config.policyId,
      sealMode: config.sealMode,
      proofVersion: config.proofVersion,
      schemaVersion: config.schemaVersion,
      payrollPolicyRoot: config.payrollPolicyRoot,
      tokenSetCommitment: config.tokenSetCommitment,
      recipientSetCommitment: config.recipientSetCommitment,
      purposeCommitment: config.purposeCommitment,
      amountLimitCommitment: config.amountLimitCommitment,
    };
    const authorizedRuns = input.authorizedRuns.map((authorization) => {
      const run = rowsById.get(authorization.runId);
      const bundle = proofByRunId.get(authorization.runId);
      const normalizedNullifier = authorization.runNullifier.toLowerCase();
      if (
        !run
        || !bundle
        || !["locally_verified", "onchain_verified"].includes(bundle.verificationState)
        || Number(bundle.proofVersion) !== config.proofVersion
        || run.state !== "proven"
        || run.version !== authorization.runVersion
        || !run.agreementRoot
        || !run.manifestRoot
        || !run.policyRoot
        || !run.runNullifier
        || BigInt(run.agreementRoot) !== BigInt(authorization.agreementRoot)
        || BigInt(run.manifestRoot) !== BigInt(authorization.manifestRoot)
        || BigInt(run.policyRoot) !== BigInt(config.payrollPolicyRoot)
        || BigInt(run.runNullifier) !== BigInt(authorization.runNullifier)
        || nullifiers.has(normalizedNullifier)
      ) {
        throw new ApiError(409, "An authorized run does not match a current proven PostgreSQL payroll.", "DIRECT_POLICY_RUN_BINDING_INVALID");
      }
      nullifiers.add(normalizedNullifier);
      const binding = {
        agreementRoot: authorization.agreementRoot,
        manifestRoot: authorization.manifestRoot,
        runNullifier: authorization.runNullifier,
      };
      const proof: PolicyRunProof = {
        ...binding,
        leaf: computePolicyRunLeaf(policyContext, binding),
        pathBits: authorization.pathBits,
        siblings: [...authorization.siblings],
      };
      if (!verifyPolicyRunProof(config.authorizedRunsRoot, proof)) {
        throw new ApiError(409, "An authorized-run path does not match the reviewed policy root.", "DIRECT_POLICY_RUN_PROOF_INVALID");
      }
      return { authorization, proof };
    });
    const encryptedSecrets = encryptDirectPrivacyPayload(
      secrets,
      { accountId: id, organizationId: input.organizationId, capabilityId: input.capabilityId, purpose: "secrets" },
    );
    const stateVersion = 1;
    const encryptedState = encryptDirectPrivacyPayload(
      emptyDirectPrivacyState(),
      { accountId: id, organizationId: input.organizationId, capabilityId: input.capabilityId, purpose: "state", stateVersion },
    );
    try {
      await transaction.insert(directPrivacyAccounts).values({
        id,
        organizationId: input.organizationId,
        capabilityId: input.capabilityId,
        config,
        encryptedSecrets,
        encryptedState,
        stateVersion,
        activationState: "pending",
        createdAt: now,
        updatedAt: now,
      });
    } catch (error) {
      if (String(error).includes("direct_privacy_accounts_capability_id_unique")) {
        throw new ApiError(409, "This capability already has a direct private account.", "DIRECT_ACCOUNT_EXISTS");
      }
      throw error;
    }
    await transaction.insert(directPrivacyAuthorizedRuns).values(authorizedRuns.map(({ authorization, proof }, index) => ({
      id: generateUuidV7(now.getTime() + index + 1),
      accountId: id,
      organizationId: input.organizationId,
      runId: authorization.runId,
      runVersion: authorization.runVersion,
      agreementRoot: authorization.agreementRoot,
      manifestRoot: authorization.manifestRoot,
      runNullifier: authorization.runNullifier,
      leaf: proof.leaf,
      pathBits: proof.pathBits,
      siblings: proof.siblings,
      createdAt: now,
    })));
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: input.organizationId,
      actorId: input.principal.principalId,
      action: "direct_privacy_account.provisioned",
      subjectId: id,
      metadata: {
        capabilityId: input.capabilityId,
        policyAccountAddress: config.policyAccountAddress,
        sdkVersion: config.sdkVersion,
        sdkRevision: config.sdkRevision,
        activationState: "pending",
        authorizedRunCount: authorizedRuns.length,
      },
    });
    return {
      id,
      config,
      proofPrincipal: {
        principalId: secrets.proofPrincipal.principalId,
        publicKey: secrets.proofPrincipal.publicKey,
      },
      stateVersion,
      authorizedRunCount: authorizedRuns.length,
      activationState: "pending",
      activation: null,
    };
  });
}

export async function provisionDirectPrivacyAccountFromRuns(input: {
  organizationId: string;
  capabilityId: string;
  runIds: readonly string[];
  request: DirectPrivacyProvisioningRequest;
  deployment: DirectPrivacyDeploymentConfig;
  principal: AuthenticatedPrincipal;
  now?: Date;
}): Promise<DirectPrivacyAccountPublic> {
  const now = input.now ?? new Date();
  if (input.runIds.length < 1 || input.runIds.length > 256) {
    throw new ApiError(400, "Select 1–256 exact payroll runs.", "DIRECT_POLICY_RUNS_INVALID");
  }
  if (new Set(input.runIds).size !== input.runIds.length) {
    throw new ApiError(409, "A policy cannot authorize the same run twice.", "DIRECT_POLICY_RUN_DUPLICATE");
  }
  const source = await getDatabase().transaction(async (transaction) => {
    await requireOrganizationRoleWith(transaction, input.organizationId, input.principal, ["admin"]);
    const [capabilityRow] = await transaction.select().from(agentCapabilities).where(and(
      eq(agentCapabilities.id, input.capabilityId),
      eq(agentCapabilities.organizationId, input.organizationId),
    )).limit(1);
    if (!capabilityRow) throw new ApiError(404, "Agent capability not found.", "CAPABILITY_NOT_FOUND");
    if (capabilityRow.revokedAt || capabilityRow.expiresAt <= now) {
      throw new ApiError(409, "The capability is inactive.", "CAPABILITY_INACTIVE");
    }
    const signed = decryptCapabilityPolicy(capabilityRow.policy, {
      capabilityId: capabilityRow.id,
      organizationId: capabilityRow.organizationId,
      principalId: capabilityRow.principalId,
      capabilityHash: capabilityRow.capabilityHash,
    });
    const [runs, bundles] = await Promise.all([
      transaction.select().from(payrollRuns).where(and(
        eq(payrollRuns.organizationId, input.organizationId),
        inArray(payrollRuns.id, [...input.runIds]),
      )),
      transaction.select().from(proofBundles).where(and(
        eq(proofBundles.organizationId, input.organizationId),
        eq(proofBundles.proofType, "payroll_integrity"),
        inArray(proofBundles.runId, [...input.runIds]),
      )),
    ]);
    const runsById = new Map(runs.map((run) => [run.id, run]));
    const bundlesByRun = new Map(bundles
      .filter((bundle) => bundle.subjectRecordId === bundle.runId)
      .map((bundle) => [bundle.runId, bundle]));
    const provisioningRuns = input.runIds.map((runId) => {
      const run = runsById.get(runId);
      const bundle = bundlesByRun.get(runId);
      const proofVersion = Number(bundle?.proofVersion);
      if (
        !run
        || run.state !== "proven"
        || !run.agreementRoot
        || !run.manifestRoot
        || !run.policyRoot
        || !run.runNullifier
        || !bundle
        || !["locally_verified", "onchain_verified"].includes(bundle.verificationState)
        || (proofVersion !== 1 && proofVersion !== 2)
      ) {
        throw new ApiError(409, "Every autonomous run must be current, proven and locally verified.", "DIRECT_POLICY_RUN_NOT_READY");
      }
      return {
        runId: run.id,
        runVersion: run.version,
        agreementRoot: run.agreementRoot as `0x${string}`,
        manifestRoot: run.manifestRoot as `0x${string}`,
        payrollPolicyRoot: run.policyRoot as `0x${string}`,
        runNullifier: run.runNullifier as `0x${string}`,
        proofVersion: proofVersion as 1 | 2,
      };
    });
    return { capability: signed.capability, provisioningRuns };
  });
  let plan: ReturnType<typeof buildDirectPrivacyAccountProvisioningPlan>;
  try {
    plan = buildDirectPrivacyAccountProvisioningPlan({
      capability: source.capability,
      runs: source.provisioningRuns,
      request: input.request,
      deployment: input.deployment,
      now,
    });
  } catch (error) {
    throw new ApiError(409, error instanceof Error ? error.message : "Policy planning failed.", "DIRECT_POLICY_PLAN_INVALID");
  }
  return provisionDirectPrivacyAccount({
    organizationId: input.organizationId,
    capabilityId: input.capabilityId,
    authorizedRuns: plan.authorizedRuns,
    config: plan.config,
    principal: input.principal,
    now,
  });
}

export type DirectPrivacyAccountActivationCandidate = {
  id: string;
  config: DirectPrivacyAccountConfig;
  configCommitment: `0x${string}`;
  activationState: "pending" | "active";
  activation: DirectPrivacyAccountPublic["activation"];
};

function parseActivationState(value: string): "pending" | "active" {
  if (value !== "pending" && value !== "active") throw new Error("DIRECT_ACCOUNT_ACTIVATION_STATE_INVALID");
  return value;
}

function activationEvidence(account: {
  activationState: string;
  activationBlockNumber: bigint | null;
  activationBlockHash: string | null;
  activationClassHash: string | null;
  activationBlockTimestamp: bigint | null;
  activatedAt: Date | null;
}): DirectPrivacyAccountPublic["activation"] {
  if (account.activationState === "pending") return null;
  if (
    account.activationBlockNumber === null
    || !account.activationBlockHash
    || !account.activationClassHash
    || account.activationBlockTimestamp === null
    || !account.activatedAt
  ) throw new Error("DIRECT_ACCOUNT_ACTIVATION_EVIDENCE_MISSING");
  return {
    blockNumber: account.activationBlockNumber.toString(),
    blockHash: account.activationBlockHash,
    classHash: account.activationClassHash,
    blockTimestamp: account.activationBlockTimestamp.toString(),
    activatedAt: account.activatedAt.toISOString(),
  };
}

export async function getDirectPrivacyAccountActivationCandidate(input: {
  accountId: string;
  principal: AuthenticatedPrincipal;
}): Promise<DirectPrivacyAccountActivationCandidate> {
  return getDatabase().transaction(async (transaction) => {
    const [account] = await transaction.select().from(directPrivacyAccounts)
      .where(eq(directPrivacyAccounts.id, input.accountId)).limit(1);
    if (!account || account.revokedAt) {
      throw new ApiError(404, "Direct private account not found.", "DIRECT_ACCOUNT_NOT_FOUND");
    }
    await requireOrganizationRoleWith(transaction, account.organizationId, input.principal, ["admin"]);
    const config = directPrivacyAccountConfigSchema.parse(account.config);
    return {
      id: account.id,
      config,
      configCommitment: commitDirectPrivacyAccountConfig(config),
      activationState: parseActivationState(account.activationState),
      activation: activationEvidence(account),
    };
  });
}

export async function activateDirectPrivacyAccount(input: {
  accountId: string;
  configCommitment: string;
  snapshot: PolicyAccountActivationSnapshot;
  expectedClassHash: string;
  principal: AuthenticatedPrincipal;
  now?: Date;
}): Promise<DirectPrivacyAccountActivationCandidate> {
  const now = input.now ?? new Date();
  return getDatabase().transaction(async (transaction) => {
    const [account] = await transaction.select().from(directPrivacyAccounts)
      .where(eq(directPrivacyAccounts.id, input.accountId)).limit(1).for("update");
    if (!account || account.revokedAt) {
      throw new ApiError(404, "Direct private account not found.", "DIRECT_ACCOUNT_NOT_FOUND");
    }
    await requireOrganizationRoleWith(transaction, account.organizationId, input.principal, ["admin"]);
    const config = directPrivacyAccountConfigSchema.parse(account.config);
    const configCommitment = commitDirectPrivacyAccountConfig(config);
    if (configCommitment !== input.configCommitment) {
      throw new ApiError(409, "The pending policy configuration changed during verification.", "DIRECT_POLICY_ACTIVATION_RACE");
    }
    try {
      assertPolicyAccountActivation({ config, snapshot: input.snapshot, expectedClassHash: input.expectedClassHash });
    } catch (error) {
      throw new ApiError(409, error instanceof Error ? error.message : "Policy activation failed.", "DIRECT_POLICY_CHAIN_MISMATCH");
    }
    const [capability] = await transaction.select().from(agentCapabilities).where(and(
      eq(agentCapabilities.id, account.capabilityId),
      eq(agentCapabilities.organizationId, account.organizationId),
    )).limit(1).for("update");
    if (!capability || capability.revokedAt || capability.expiresAt <= now) {
      throw new ApiError(409, "The capability became inactive before activation.", "CAPABILITY_INACTIVE");
    }
    const activationState = parseActivationState(account.activationState);
    if (activationState === "active") {
      return {
        id: account.id,
        config,
        configCommitment,
        activationState,
        activation: activationEvidence(account),
      };
    }
    await transaction.update(directPrivacyAccounts).set({
      activationState: "active",
      activationBlockNumber: input.snapshot.blockNumber,
      activationBlockHash: input.snapshot.blockHash,
      activationClassHash: input.snapshot.classHash,
      activationBlockTimestamp: input.snapshot.blockTimestamp,
      activatedAt: now,
      updatedAt: now,
    }).where(and(
      eq(directPrivacyAccounts.id, account.id),
      eq(directPrivacyAccounts.activationState, "pending"),
    ));
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: account.organizationId,
      actorId: input.principal.principalId,
      action: "direct_privacy_account.activated",
      subjectId: account.id,
      metadata: {
        capabilityId: account.capabilityId,
        policyAccountAddress: config.policyAccountAddress,
        policyId: config.policyId,
        classHash: input.snapshot.classHash,
        blockNumber: input.snapshot.blockNumber.toString(),
        blockHash: input.snapshot.blockHash,
        configCommitment,
      },
    });
    return {
      id: account.id,
      config,
      configCommitment,
      activationState: "active",
      activation: {
        blockNumber: input.snapshot.blockNumber.toString(),
        blockHash: input.snapshot.blockHash,
        classHash: input.snapshot.classHash,
        blockTimestamp: input.snapshot.blockTimestamp.toString(),
        activatedAt: now.toISOString(),
      },
    };
  });
}

/**
 * Stages only executor-encrypted proof input for an exact owner-authorized run.
 * The future PaymentIntent is deliberately absent: it is created by the agent
 * and bound transactionally by requestAgentExecution.
 */
export async function stageDirectPrivacyRunWitness(input: {
  accountId: string;
  encryptedWitness: EncryptedVaultRecord;
  principal: AuthenticatedPrincipal;
  now?: Date;
}): Promise<{
  runId: string;
  runVersion: number;
  witnessCommitment: `0x${string}`;
  replayed: boolean;
}> {
  const encryptedWitness = encryptedVaultRecordSchema.parse(input.encryptedWitness);
  const runId = encryptedWitness.aad.recordId;
  const now = input.now ?? new Date();
  const witnessCommitment = hashCanonicalJson({
    domain: "PAYO_DIRECT_PRIVACY_STAGED_WITNESS_V1",
    encryptedWitness,
  });
  return getDatabase().transaction(async (transaction) => {
    const [account] = await transaction.select().from(directPrivacyAccounts)
      .where(eq(directPrivacyAccounts.id, input.accountId)).limit(1).for("update");
    if (!account || account.revokedAt) {
      throw new ApiError(404, "Direct private account not found.", "DIRECT_ACCOUNT_NOT_FOUND");
    }
    await requireOrganizationRoleWith(transaction, account.organizationId, input.principal, ["admin"]);
    const [authorization] = await transaction.select().from(directPrivacyAuthorizedRuns).where(and(
      eq(directPrivacyAuthorizedRuns.accountId, account.id),
      eq(directPrivacyAuthorizedRuns.runId, runId),
    )).limit(1).for("update");
    const [run] = await transaction.select().from(payrollRuns)
      .where(eq(payrollRuns.id, runId)).limit(1).for("update");
    if (
      !authorization
      || !run
      || run.organizationId !== account.organizationId
      || run.version !== authorization.runVersion
      || run.state !== "proven"
    ) {
      throw new ApiError(
        409,
        "The encrypted witness must target a current proven run in this policy.",
        "DIRECT_WITNESS_RUN_NOT_READY",
      );
    }
    const secrets = decryptDirectPrivacyPayload(account.encryptedSecrets, {
      accountId: account.id,
      organizationId: account.organizationId,
      capabilityId: account.capabilityId,
      purpose: "secrets",
    });
    if (
      encryptedWitness.aad.organizationId !== account.organizationId
      || encryptedWitness.aad.recordType !== "agent_payroll_witness"
      || encryptedWitness.aad.recordId !== run.id
      || encryptedWitness.aad.revision !== run.version
      || !encryptedWitness.wrappedKeys.some(
        ({ principalId }) => principalId === secrets.proofPrincipal.principalId,
      )
    ) {
      throw new ApiError(
        409,
        "The autonomous witness is not encrypted to this exact executor run.",
        "DIRECT_WITNESS_RECIPIENT_INVALID",
      );
    }
    if (authorization.encryptedWitness) {
      const current = encryptedVaultRecordSchema.parse(authorization.encryptedWitness);
      const currentCommitment = hashCanonicalJson({
        domain: "PAYO_DIRECT_PRIVACY_STAGED_WITNESS_V1",
        encryptedWitness: current,
      });
      if (currentCommitment !== witnessCommitment) {
        throw new ApiError(
          409,
          "A different encrypted witness is already staged for this authorized run.",
          "DIRECT_WITNESS_ALREADY_STAGED",
        );
      }
      return { runId, runVersion: run.version, witnessCommitment, replayed: true };
    }
    await transaction.update(directPrivacyAuthorizedRuns).set({
      encryptedWitness,
      witnessStagedAt: now,
    }).where(eq(directPrivacyAuthorizedRuns.id, authorization.id));
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: account.organizationId,
      actorId: input.principal.principalId,
      action: "direct_privacy_witness.staged",
      subjectId: authorization.id,
      metadata: {
        accountId: account.id,
        capabilityId: account.capabilityId,
        runId,
        runVersion: run.version,
        witnessCommitment,
      },
    });
    return { runId, runVersion: run.version, witnessCommitment, replayed: false };
  });
}

/**
 * Public product seam: callers provide only a structured request and an
 * encrypted witness. PAYO reloads every run/root/Merkle-path field itself.
 */
export async function stageAuthoritativeDirectPrivacyRun(input: {
  accountId: string;
  request: AgentExecutionRequest;
  encryptedWitness: EncryptedVaultRecord;
  principal: AuthenticatedPrincipal;
  now?: Date;
}): Promise<{ id: string; materialCommitment: `0x${string}` }> {
  const request = agentExecutionRequestSchema.parse(input.request);
  const encryptedWitness = encryptedVaultRecordSchema.parse(input.encryptedWitness);
  const source = await getDatabase().transaction(async (transaction) => {
    const [account] = await transaction.select().from(directPrivacyAccounts)
      .where(eq(directPrivacyAccounts.id, input.accountId)).limit(1);
    if (!account || account.revokedAt || account.activationState !== "active") {
      throw new ApiError(404, "Active direct private account not found.", "DIRECT_ACCOUNT_NOT_FOUND");
    }
    await requireOrganizationRoleWith(transaction, account.organizationId, input.principal, ["admin"]);
    const [authorization] = await transaction.select().from(directPrivacyAuthorizedRuns).where(and(
      eq(directPrivacyAuthorizedRuns.accountId, account.id),
      eq(directPrivacyAuthorizedRuns.runId, request.runId),
    )).limit(1);
    if (!authorization) {
      throw new ApiError(409, "This payroll run was not owner-authorized for the policy account.", "DIRECT_POLICY_RUN_UNAUTHORIZED");
    }
    return {
      organizationId: account.organizationId,
      capabilityId: account.capabilityId,
      runVersion: authorization.runVersion,
      agreementRoot: authorization.agreementRoot as `0x${string}`,
      manifestRoot: authorization.manifestRoot as `0x${string}`,
      runNullifier: authorization.runNullifier as `0x${string}`,
      pathBits: authorization.pathBits,
      siblings: parseAuthorizedSiblings(authorization.siblings),
    };
  });
  const material = directPrivacyRunMaterialSchema.parse({
    version: "payo-direct-privacy-run-v1",
    organizationId: source.organizationId,
    capabilityId: source.capabilityId,
    runId: request.runId,
    runVersion: source.runVersion,
    requestCommitment: commitAgentExecutionRequest(request),
    authoritativeRequest: request,
    encryptedWitness,
    policyRun: {
      agreementRoot: source.agreementRoot,
      manifestRoot: source.manifestRoot,
      runNullifier: source.runNullifier,
      pathBits: source.pathBits,
      siblings: source.siblings,
    },
  });
  return stageDirectPrivacyRunMaterial({
    accountId: input.accountId,
    material,
    principal: input.principal,
    now: input.now,
  });
}

export async function stageDirectPrivacyRunMaterial(input: {
  accountId: string;
  material: DirectPrivacyRunMaterial;
  principal: AuthenticatedPrincipal;
  now?: Date;
}): Promise<{ id: string; materialCommitment: `0x${string}` }> {
  const material = directPrivacyRunMaterialSchema.parse(input.material);
  const now = input.now ?? new Date();
  const materialCommitment = commitDirectPrivacyRunMaterial(material);
  return getDatabase().transaction(async (transaction) => {
    const [account] = await transaction.select().from(directPrivacyAccounts)
      .where(eq(directPrivacyAccounts.id, input.accountId)).limit(1).for("update");
    if (!account || account.revokedAt || account.activationState !== "active") {
      throw new ApiError(404, "Active direct private account not found.", "DIRECT_ACCOUNT_NOT_FOUND");
    }
    await requireOrganizationRoleWith(transaction, account.organizationId, input.principal, ["admin"]);
    const config = directPrivacyAccountConfigSchema.parse(account.config);
    const [run] = await transaction.select().from(payrollRuns).where(eq(payrollRuns.id, material.runId))
      .limit(1).for("update");
    if (
      !run
      || run.organizationId !== account.organizationId
      || material.organizationId !== account.organizationId
      || material.capabilityId !== account.capabilityId
      || material.runVersion !== run.version
    ) throw new ApiError(409, "Run material does not match the direct account and current run.", "DIRECT_MATERIAL_BINDING_INVALID");
    if (
      !run.agreementRoot
      || !run.manifestRoot
      || !run.policyRoot
      || !run.runNullifier
      || BigInt(run.agreementRoot) !== BigInt(material.policyRun.agreementRoot)
      || BigInt(run.manifestRoot) !== BigInt(material.policyRun.manifestRoot)
      || BigInt(run.policyRoot) !== BigInt(config.payrollPolicyRoot)
      || BigInt(run.runNullifier) !== BigInt(material.policyRun.runNullifier)
    ) throw new ApiError(409, "Run material roots do not match PostgreSQL.", "DIRECT_MATERIAL_ROOT_MISMATCH");
    const runProof = {
      ...material.policyRun,
      leaf: computePolicyRunLeaf({
        policyId: config.policyId,
        sealMode: config.sealMode,
        proofVersion: config.proofVersion,
        schemaVersion: config.schemaVersion,
        payrollPolicyRoot: config.payrollPolicyRoot,
        tokenSetCommitment: config.tokenSetCommitment,
        recipientSetCommitment: config.recipientSetCommitment,
        purposeCommitment: config.purposeCommitment,
        amountLimitCommitment: config.amountLimitCommitment,
      }, material.policyRun),
    };
    const [authorization] = await transaction.select().from(directPrivacyAuthorizedRuns).where(and(
      eq(directPrivacyAuthorizedRuns.accountId, account.id),
      eq(directPrivacyAuthorizedRuns.runId, run.id),
      eq(directPrivacyAuthorizedRuns.runVersion, run.version),
    )).limit(1).for("update");
    if (
      !authorization
      || BigInt(authorization.agreementRoot) !== BigInt(material.policyRun.agreementRoot)
      || BigInt(authorization.manifestRoot) !== BigInt(material.policyRun.manifestRoot)
      || BigInt(authorization.runNullifier) !== BigInt(material.policyRun.runNullifier)
      || BigInt(authorization.leaf) !== BigInt(runProof.leaf)
      || authorization.pathBits !== material.policyRun.pathBits
      || !sameFeltArray(authorization.siblings, material.policyRun.siblings)
    ) {
      throw new ApiError(409, "The staged run does not match its owner-reviewed authorization.", "DIRECT_POLICY_RUN_AUTHORIZATION_MISMATCH");
    }
    if (!verifyPolicyRunProof(config.authorizedRunsRoot, runProof)) {
      throw new ApiError(409, "The run is not in the owner-authorized policy tree.", "DIRECT_POLICY_RUN_UNAUTHORIZED");
    }
    const secrets = decryptDirectPrivacyPayload(
      account.encryptedSecrets,
      { accountId: account.id, organizationId: account.organizationId, capabilityId: account.capabilityId, purpose: "secrets" },
    );
    if (
      material.encryptedWitness.aad.organizationId !== account.organizationId
      || material.encryptedWitness.aad.recordType !== "agent_payroll_witness"
      || material.encryptedWitness.aad.recordId !== run.id
      || !material.encryptedWitness.wrappedKeys.some(
        ({ principalId }) => principalId === secrets.proofPrincipal.principalId,
      )
    ) throw new ApiError(409, "The autonomous witness is not encrypted to this executor.", "DIRECT_WITNESS_RECIPIENT_INVALID");
    const [existingMaterial] = await transaction.select().from(directPrivacyRunMaterials).where(and(
      eq(directPrivacyRunMaterials.accountId, account.id),
      eq(directPrivacyRunMaterials.runId, run.id),
      eq(directPrivacyRunMaterials.runVersion, run.version),
    )).limit(1).for("update");
    if (existingMaterial) {
      if (
        existingMaterial.materialCommitment !== materialCommitment
        || existingMaterial.requestCommitment !== material.requestCommitment
      ) {
        throw new ApiError(409, "Different run material was already staged for this authorized version.", "DIRECT_MATERIAL_ALREADY_STAGED");
      }
      return { id: existingMaterial.id, materialCommitment: materialCommitment as `0x${string}` };
    }
    const id = generateUuidV7(now.getTime());
    const encryptedMaterial = encryptDirectPrivacyPayload(material, {
      accountId: account.id,
      organizationId: account.organizationId,
      capabilityId: account.capabilityId,
      purpose: "run",
      runId: run.id,
      runVersion: run.version,
      materialCommitment,
    });
    await transaction.insert(directPrivacyRunMaterials).values({
      id,
      accountId: account.id,
      organizationId: account.organizationId,
      capabilityId: account.capabilityId,
      runId: run.id,
      runVersion: run.version,
      requestCommitment: material.requestCommitment,
      materialCommitment,
      encryptedMaterial,
      createdAt: now,
      updatedAt: now,
    });
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: account.organizationId,
      actorId: input.principal.principalId,
      action: "direct_privacy_run.staged",
      subjectId: id,
      metadata: { capabilityId: account.capabilityId, runId: run.id, materialCommitment },
    });
    return { id, materialCommitment };
  });
}

export type DirectPrivacyExecutionContext = {
  accountId: string;
  config: DirectPrivacyAccountConfig;
  secrets: DirectPrivacySecrets;
  state: DirectPrivacyState;
  stateVersion: number;
  material: DirectPrivacyRunMaterial;
  materialCommitment: string;
};

export async function leaseDirectPrivacyExecutionContext(
  job: LeasedAgentExecution,
  now = new Date(),
): Promise<DirectPrivacyExecutionContext> {
  return getDatabase().transaction(async (transaction) => {
    const [account] = await transaction.select().from(directPrivacyAccounts).where(
      eq(directPrivacyAccounts.capabilityId, job.capabilityId),
    ).limit(1).for("update");
    if (!account || account.revokedAt || account.activationState !== "active" || account.organizationId !== job.organizationId) {
      throw new Error("DIRECT_ACCOUNT_INACTIVE");
    }
    if (
      account.activeExecutionId
      && account.activeExecutionId !== job.id
      && account.activeLeaseExpiresAt
      && account.activeLeaseExpiresAt > now
    ) throw new Error("DIRECT_ACCOUNT_BUSY");
    const [materialRow] = await transaction.select().from(directPrivacyRunMaterials).where(and(
      eq(directPrivacyRunMaterials.accountId, account.id),
      eq(directPrivacyRunMaterials.runId, job.runId),
      eq(directPrivacyRunMaterials.runVersion, job.runVersion),
    )).limit(1).for("update");
    if (
      !materialRow
      || materialRow.organizationId !== job.organizationId
      || materialRow.capabilityId !== job.capabilityId
      || materialRow.requestCommitment !== job.requestCommitment
    ) throw new Error("DIRECT_MATERIAL_MISSING");
    const material = decryptDirectPrivacyPayload(materialRow.encryptedMaterial, {
      accountId: account.id,
      organizationId: account.organizationId,
      capabilityId: account.capabilityId,
      purpose: "run",
      runId: job.runId,
      runVersion: job.runVersion,
      materialCommitment: materialRow.materialCommitment,
    });
    if (
      material.requestCommitment !== job.requestCommitment
      || commitAgentExecutionRequest(material.authoritativeRequest) !== job.requestCommitment
      || commitAgentExecutionRequest(job.request) !== job.requestCommitment
    ) throw new Error("DIRECT_REQUEST_TAMPERED");
    const config = directPrivacyAccountConfigSchema.parse(account.config);
    const secrets = decryptDirectPrivacyPayload(account.encryptedSecrets, {
      accountId: account.id,
      organizationId: account.organizationId,
      capabilityId: account.capabilityId,
      purpose: "secrets",
    });
    const state = decryptDirectPrivacyPayload(account.encryptedState, {
      accountId: account.id,
      organizationId: account.organizationId,
      capabilityId: account.capabilityId,
      purpose: "state",
      stateVersion: account.stateVersion,
    });
    await transaction.update(directPrivacyAccounts).set({
      activeExecutionId: job.id,
      activeLeaseExpiresAt: new Date(now.getTime() + ACCOUNT_LEASE_MS),
      updatedAt: now,
    }).where(eq(directPrivacyAccounts.id, account.id));
    return {
      accountId: account.id,
      config,
      secrets,
      state,
      stateVersion: account.stateVersion,
      material,
      materialCommitment: materialRow.materialCommitment,
    };
  });
}

export async function saveDirectPrivacyState(input: {
  job: LeasedAgentExecution;
  accountId: string;
  expectedVersion: number;
  state: DirectPrivacyState;
  now?: Date;
}): Promise<number> {
  const state = directPrivacyStateSchema.parse(input.state);
  const now = input.now ?? new Date();
  return getDatabase().transaction(async (transaction) => {
    const [account] = await transaction.select().from(directPrivacyAccounts).where(
      eq(directPrivacyAccounts.id, input.accountId),
    ).limit(1).for("update");
    if (
      !account
      || account.activeExecutionId !== input.job.id
      || account.stateVersion !== input.expectedVersion
    ) throw new Error("DIRECT_STATE_VERSION_CONFLICT");
    const nextVersion = account.stateVersion + 1;
    const encryptedState = encryptDirectPrivacyPayload(state, {
      accountId: account.id,
      organizationId: account.organizationId,
      capabilityId: account.capabilityId,
      purpose: "state",
      stateVersion: nextVersion,
    });
    await transaction.update(directPrivacyAccounts).set({
      encryptedState,
      stateVersion: nextVersion,
      activeLeaseExpiresAt: new Date(now.getTime() + ACCOUNT_LEASE_MS),
      updatedAt: now,
    }).where(eq(directPrivacyAccounts.id, account.id));
    return nextVersion;
  });
}

export async function releaseDirectPrivacyExecution(
  job: Pick<LeasedAgentExecution, "id" | "capabilityId">,
  now = new Date(),
): Promise<void> {
  await getDatabase().update(directPrivacyAccounts).set({
    activeExecutionId: null,
    activeLeaseExpiresAt: null,
    updatedAt: now,
  }).where(and(
    eq(directPrivacyAccounts.capabilityId, job.capabilityId),
    eq(directPrivacyAccounts.activeExecutionId, job.id),
  ));
}
