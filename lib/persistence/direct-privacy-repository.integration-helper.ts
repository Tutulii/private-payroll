import { ed25519 } from "@noble/curves/ed25519.js";
import { expect, it } from "vitest";
import { encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import {
  hashCapability,
  signCapability,
  type AgentCapability,
  type AgentExecutionRequest,
} from "@/lib/domain/capability";
import { commitAgentExecutionRequest } from "@/lib/domain/agent-execution";
import { commitDirectPrivacyAccountConfig } from "@/lib/domain/direct-privacy";
import { generateUuidV7 } from "@/lib/domain/records";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { encryptCapabilityPolicy } from "@/lib/server/capability-policy-crypto";
import {
  getDirectPrivacyAccountPublic,
  listDirectPrivacyAccountsPublic,
} from "@/lib/server/direct-privacy-account-view";
import {
  buildAuthorizedPolicyRunTree,
  commitPolicyCapability,
} from "@/lib/starknet/policy-account";
import { requestAgentExecution } from "./agent-execution-repository";
import { leaseAgentExecutions } from "./agent-execution-worker-repository";
import {
  leaseDirectPrivacyExecutionContext,
  activateDirectPrivacyAccount,
  deriveDirectPrivacyViewingPublicKey,
  provisionDirectPrivacyAccount,
  provisionDirectPrivacyAccountFromRuns,
  releaseDirectPrivacyExecution,
  saveDirectPrivacyState,
  stageDirectPrivacyRunWitness,
  stageDirectPrivacyRunMaterial,
} from "./direct-privacy-repository";
import { getDatabase } from "./db";
import {
  agentCapabilities,
  directPrivacyAccounts,
  directPrivacyAuthorizedRuns,
  directPrivacyRunMaterials,
  directPrivacyTreasuries,
  organizationMembers,
  organizations,
  proofBundles,
  payrollRuns,
} from "./schema";

export const principal: AuthenticatedPrincipal = {
  principalId: "admin:direct-privacy",
  sessionId: "session:direct-privacy",
};
export const now = new Date("2026-08-30T11:00:00.000Z");
const root = (byte: string) => `0x${byte.repeat(64)}` as `0x${string}`;

export async function fixture(options: {
  activate?: boolean;
  authoritativeProvision?: boolean;
  proofVerificationState?: string;
  registrationPublicKey?: string;
  runNullifierByte?: string;
  organizationId?: string;
  policyId?: `0x${string}`;
  sessionKeyByte?: string;
} = {}) {
  const organizationId = options.organizationId ?? generateUuidV7();
  const runId = generateUuidV7();
  const runNullifier = root(options.runNullifierByte ?? "5");
  const policyId = options.policyId ?? "0x222";
  if (!options.organizationId) {
    await getDatabase().insert(organizations).values({
      id: organizationId,
      encryptedProfile: { ciphertext: "direct-privacy-test" },
      recoveryState: "package_downloaded",
    });
    await getDatabase().insert(organizationMembers).values({
      organizationId,
      principalId: principal.principalId,
      role: "admin",
      vaultPublicKey: "direct-privacy-public-key",
    });
  }
  await getDatabase().insert(payrollRuns).values({
    id: runId,
    organizationId,
    cycleId: `direct-cycle:${runId}`,
    revision: 1,
    state: "proven",
    dueAt: now,
    agreementRoot: root("1"),
    manifestRoot: root("2"),
    policyRoot: root("3"),
    fxRoot: root("4"),
    runNullifier,
  });
  await getDatabase().insert(proofBundles).values({
    id: generateUuidV7(),
    runId,
    organizationId,
    proofType: "payroll_integrity",
    proofVersion: "1",
    subjectRecordId: runId,
    proofPackage: {},
    proofHash: root("6"),
    verificationState: options.proofVerificationState ?? "locally_verified",
  });
  const capability: AgentCapability = {
    capabilityVersion: "payo-agent-capability-v1",
    id: generateUuidV7(),
    organizationId,
    principalId: principal.principalId,
    allowedActions: ["request_execution"],
    allowedTokens: ["STRK", "USDC"],
    recipientScope: { mode: "allowlist", addresses: ["0x456"] },
    purposeCodes: ["private_payroll"],
    limits: [
      {
        token: "STRK",
        maxPerPaymentAtomic: "1000",
        maxPerPeriodAtomic: "5000",
        spentThisPeriodAtomic: "0",
        periodStartsAt: "2026-08-30T00:00:00.000Z",
        periodEndsAt: "2026-08-31T00:00:00.000Z",
        approvalThresholdAtomic: "900",
      },
      {
        token: "USDC",
        maxPerPaymentAtomic: "1000",
        maxPerPeriodAtomic: "5000",
        spentThisPeriodAtomic: "0",
        periodStartsAt: "2026-08-30T00:00:00.000Z",
        periodEndsAt: "2026-08-31T00:00:00.000Z",
        approvalThresholdAtomic: "900",
      },
    ],
    executionMode: "autonomous_bounded",
    maxCallCount: 5,
    usedCallCount: 0,
    validAfter: "2026-08-30T00:00:00.000Z",
    expiresAt: "2026-08-31T00:00:00.000Z",
    nonce: `direct-privacy-capability:${runId}`,
  };
  const capabilityHash = hashCapability(capability);
  await getDatabase().insert(agentCapabilities).values({
    id: capability.id,
    organizationId,
    principalId: principal.principalId,
    capabilityHash,
    policy: encryptCapabilityPolicy(signCapability(capability, ed25519.keygen().secretKey), {
      capabilityId: capability.id,
      organizationId,
      principalId: principal.principalId,
      capabilityHash,
    }),
    expiresAt: new Date(capability.expiresAt),
  });
  const scope = commitPolicyCapability(capability);
  const policyContext = {
    policyId,
    sealMode: 0 as const,
    proofVersion: 1,
    schemaVersion: 1,
    payrollPolicyRoot: root("3"),
    ...scope,
  };
  const authorizedTree = buildAuthorizedPolicyRunTree(policyContext, [{
    agreementRoot: root("1"),
    manifestRoot: root("2"),
    runNullifier,
  }]);
  const authorizedProof = authorizedTree.proofs[0];
  const proofPrincipal = generateVaultPrincipal(`agent-proof:${runId}`);
  const account = options.authoritativeProvision
    ? await provisionDirectPrivacyAccountFromRuns({
        organizationId,
        capabilityId: capability.id,
        runIds: [runId],
        request: {
          policyAccountAddress: "0x111",
          policyId,
          validForSeconds: 3_600,
          periodSeconds: 3_600,
          maxCallsPerPeriod: 1,
          maxCallCount: 1,
        },
        deployment: {
          chainId: "0x534e5f5345504f4c4941",
          policyAccountClassHash: "0xabc",
          policyAccountAddress: "0x111",
          poolAddress: "0x333",
          sealAddress: "0x444",
          tokenAddresses: { STRK: "0x555", USDC: "0x666" },
        },
        principal,
        now,
      })
    : await provisionDirectPrivacyAccount({
        organizationId,
        capabilityId: capability.id,
        authorizedRuns: [{
          runId,
          runVersion: 1,
          agreementRoot: authorizedProof.agreementRoot,
          manifestRoot: authorizedProof.manifestRoot,
          runNullifier: authorizedProof.runNullifier,
          pathBits: authorizedProof.pathBits,
          siblings: authorizedProof.siblings,
        }],
        principal,
        config: {
          chainId: "0x534e5f5345504f4c4941",
          policyAccountAddress: "0x111",
          policyId,
          sealMode: 0,
          proofVersion: 1,
          schemaVersion: 1,
          payrollPolicyRoot: root("3"),
          ...scope,
          authorizedRunsRoot: authorizedTree.root,
          validAfterUnix: "1788048000",
          validBeforeUnix: "1788134400",
          periodSeconds: "86400",
          maxCallsPerPeriod: 1,
          maxCallCount: 1,
          poolAddress: "0x333",
          sealAddress: "0x444",
          tokenAddresses: { STRK: "0x555", USDC: "0x666" },
        },
        testSecrets: {
          sessionPrivateKey: `0x${(options.sessionKeyByte ?? "01").repeat(32)}`,
          viewingKey: "0x123",
          proofPrincipal,
        },
        now,
      });
  if (options.activate !== false) {
    const policyRootValue = BigInt(account.config.payrollPolicyRoot);
    await activateDirectPrivacyAccount({
      accountId: account.id,
      configCommitment: commitDirectPrivacyAccountConfig(account.config),
      expectedClassHash: "0xabc",
      registrationPublicKey: options.registrationPublicKey
        ?? deriveDirectPrivacyViewingPublicKey("0x123"),
      principal,
      now,
      snapshot: {
        chainId: account.config.chainId,
        classHash: "0xabc",
        blockNumber: 42n,
        blockHash: "0xdef",
        blockTimestamp: BigInt(Math.floor(now.getTime() / 1_000)),
        active: true,
        paused: false,
        policy: {
          configured: true,
          revoked: false,
          sessionPublicKey: account.config.sessionPublicKey,
          poolAddress: account.config.poolAddress,
          sealAddress: account.config.sealAddress,
          sealMode: account.config.sealMode,
          proofVersion: account.config.proofVersion,
          schemaVersion: account.config.schemaVersion,
          payrollPolicyRootHigh: policyRootValue >> 128n,
          payrollPolicyRootLow: policyRootValue & ((1n << 128n) - 1n),
          tokenSetCommitment: account.config.tokenSetCommitment,
          recipientSetCommitment: account.config.recipientSetCommitment,
          purposeCommitment: account.config.purposeCommitment,
          amountLimitCommitment: account.config.amountLimitCommitment,
          authorizedRunsRoot: account.config.authorizedRunsRoot,
          validAfterUnix: BigInt(account.config.validAfterUnix),
          validBeforeUnix: BigInt(account.config.validBeforeUnix),
          periodSeconds: BigInt(account.config.periodSeconds),
          maxCallsPerPeriod: account.config.maxCallsPerPeriod,
          maxCallCount: account.config.maxCallCount,
          periodStartedAtUnix: BigInt(account.config.validAfterUnix),
          periodCallCount: 0,
          usedCallCount: 0,
        },
      },
    });
  }
  const witnessPrincipal = options.authoritativeProvision ? account.proofPrincipal : proofPrincipal;
  const request: AgentExecutionRequest = {
    requestVersion: "payo-agent-execution-v1",
    runId,
    intents: [{
      intentVersion: "payo-payment-intent-v1",
      intentId: "direct-privacy-intent-0001",
      organizationId,
      runId,
      action: "request_execution",
      token: "STRK",
      recipientAddress: "0x456",
      amountAtomic: "100",
      purposeCode: "private_payroll",
      capabilityNonce: capability.nonce,
      createdAt: now.toISOString(),
      validUntil: "2026-08-30T11:05:00.000Z",
    }],
  };
  const requestCommitment = commitAgentExecutionRequest(request);
  const witness = encryptVaultRecord(
    { encryptedAutonomyWitness: true },
    {
      schemaVersion: 1,
      organizationId,
      recordType: "agent_payroll_witness",
      recordId: runId,
      revision: 1,
    },
    [witnessPrincipal],
  );
  const material = {
    version: "payo-direct-privacy-run-v1" as const,
    organizationId,
    capabilityId: capability.id,
    runId,
    runVersion: 1,
    requestCommitment,
    authoritativeRequest: request,
    encryptedWitness: witness,
    policyRun: {
      agreementRoot: root("1"),
      manifestRoot: root("2"),
      runNullifier,
      pathBits: authorizedProof.pathBits,
      siblings: authorizedProof.siblings,
    },
  };
  return { organizationId, runId, capability, account, request, material, proofPrincipal };
}

export function registerDirectPrivacyRepositoryIntegrationTests(): void {
  it("derives a pending account only from authoritative runs and verified proof bundles", async () => {
    const input = await fixture({ activate: false, authoritativeProvision: true });
    const viewed = await getDirectPrivacyAccountPublic({ accountId: input.account.id, principal });
    const listed = await listDirectPrivacyAccountsPublic({
      organizationId: input.organizationId,
      principal,
    });
    expect(viewed.proofPrincipal).toEqual(input.account.proofPrincipal);
    expect(listed).toEqual([expect.objectContaining({
      id: input.account.id,
      capabilityId: input.capability.id,
      activationState: "pending",
      authorizedRunCount: 1,
      activeExecutionId: null,
    })]);
    expect(JSON.stringify(listed)).not.toContain("sessionPrivateKey");
    expect(JSON.stringify(listed)).not.toContain("viewingKey");
    expect("secretKey" in viewed.proofPrincipal).toBe(false);
    expect(input.account).toMatchObject({
      activationState: "pending",
      authorizedRunCount: 1,
      config: {
        policyAccountAddress: "0x111",
        policyId: "0x222",
        proofVersion: 1,
        schemaVersion: 1,
        maxCallCount: 1,
      },
    });
    const [authorization] = await getDatabase().select().from(directPrivacyAuthorizedRuns);
    expect(authorization).toMatchObject({ runId: input.runId, runVersion: 1, pathBits: 0 });
    const [stored] = await getDatabase().select().from(directPrivacyAccounts);
    expect(stored.activationState).toBe("pending");
    expect(stored.activatedAt).toBeNull();
    await expect(listDirectPrivacyAccountsPublic({
      organizationId: input.organizationId,
      principal: { principalId: "admin:outsider", sessionId: "session:outsider" },
    })).rejects.toMatchObject({ code: "ORG_FORBIDDEN" });
  });

  it("rejects provisioning when the locked payroll proof is not verified", async () => {
    await expect(fixture({ proofVerificationState: "unverified" })).rejects.toMatchObject({
      code: "DIRECT_POLICY_RUN_BINDING_INVALID",
    });
    expect(await getDatabase().select().from(directPrivacyAccounts)).toHaveLength(0);
  });

  it("rejects activation when STRK20 has no matching treasury registration", async () => {
    await expect(fixture({ registrationPublicKey: "0x0" })).rejects.toMatchObject({
      code: "DIRECT_TREASURY_NOT_REGISTERED",
    });
    const [account] = await getDatabase().select().from(directPrivacyAccounts);
    const [treasury] = await getDatabase().select().from(directPrivacyTreasuries);
    expect(account.activationState).toBe("pending");
    expect(treasury.registrationState).toBe("pending");
  });

  it("prevents one policy-account treasury from crossing organization boundaries", async () => {
    await fixture();
    await expect(fixture({ runNullifierByte: "7" })).rejects.toMatchObject({
      code: "DIRECT_TREASURY_DEPLOYMENT_MISMATCH",
    });
  });

  it("serializes different capabilities through one durable treasury state", async () => {
    const first = await fixture({ runNullifierByte: "8" });
    const second = await fixture({
      organizationId: first.organizationId,
      runNullifierByte: "7",
      policyId: "0x223",
      sessionKeyByte: "02",
    });
    expect(await getDatabase().select().from(directPrivacyAccounts)).toHaveLength(2);
    expect(await getDatabase().select().from(directPrivacyTreasuries)).toHaveLength(1);
    for (const input of [first, second]) {
      await stageDirectPrivacyRunWitness({
        accountId: input.account.id,
        encryptedWitness: input.material.encryptedWitness,
        principal,
        now,
      });
    }
    await requestAgentExecution({
      capabilityId: first.capability.id,
      idempotencyKey: `global-treasury:first:${first.runId}`,
      request: first.request,
      principal,
      now,
    });
    const [firstJob] = await leaseAgentExecutions("global-treasury-worker-1", 1, now);
    const firstContext = await leaseDirectPrivacyExecutionContext(firstJob, now);
    await requestAgentExecution({
      capabilityId: second.capability.id,
      idempotencyKey: `global-treasury:second:${second.runId}`,
      request: second.request,
      principal,
      now,
    });
    const [secondJob] = await leaseAgentExecutions("global-treasury-worker-2", 1, now);
    await expect(leaseDirectPrivacyExecutionContext(secondJob, now))
      .rejects.toThrow("DIRECT_TREASURY_BUSY");
    await releaseDirectPrivacyExecution(firstJob, now);
    const secondContext = await leaseDirectPrivacyExecutionContext(secondJob, now);
    expect(secondContext.treasuryAddress).toBe(firstContext.treasuryAddress);
    expect(secondContext.viewingKey).toBe(firstContext.viewingKey);
    expect(secondContext.stateVersion).toBe(firstContext.stateVersion);
  });

  it("blocks staging until the exact on-chain policy account is activated", async () => {
    const input = await fixture({ activate: false });
    await expect(stageDirectPrivacyRunMaterial({
      accountId: input.account.id,
      material: input.material,
      principal,
      now,
    })).rejects.toMatchObject({ code: "DIRECT_ACCOUNT_NOT_FOUND" });
    const [stored] = await getDatabase().select().from(directPrivacyAccounts);
    expect(stored.activationState).toBe("pending");
    expect(stored.activatedAt).toBeNull();
  });
  it("stages an owner witness, binds the later agent request, then leases exact encrypted material", async () => {
    const input = await fixture();
    const storedAccount = (await getDatabase().select().from(directPrivacyAccounts))[0];
    const serializedAccount = JSON.stringify(storedAccount, (_key, value) => typeof value === "bigint" ? value.toString() : value);
    expect(serializedAccount).not.toContain(input.proofPrincipal.secretKey);
    expect(serializedAccount).not.toContain(`0x${"01".repeat(32)}`);
    expect(storedAccount.activationState).toBe("active");
    expect(storedAccount.activationClassHash).toBe("0xabc");
    expect(await getDatabase().select().from(directPrivacyAuthorizedRuns)).toHaveLength(1);

    const staged = await stageDirectPrivacyRunWitness({
      accountId: input.account.id,
      encryptedWitness: input.material.encryptedWitness,
      principal,
      now,
    });
    const replayedStage = await stageDirectPrivacyRunWitness({
      accountId: input.account.id,
      encryptedWitness: input.material.encryptedWitness,
      principal,
      now,
    });
    expect(staged).toMatchObject({ runId: input.runId, runVersion: 1, replayed: false });
    expect(replayedStage).toMatchObject({
      runId: input.runId,
      runVersion: 1,
      witnessCommitment: staged.witnessCommitment,
      replayed: true,
    });
    expect(await getDatabase().select().from(directPrivacyRunMaterials)).toHaveLength(0);

    const receipt = await requestAgentExecution({
      capabilityId: input.capability.id,
      idempotencyKey: `direct-execution:${input.runId}`,
      request: input.request,
      principal,
      now,
    });
    const [storedMaterial] = await getDatabase().select().from(directPrivacyRunMaterials);
    expect(storedMaterial).toMatchObject({
      capabilityId: input.capability.id,
      runId: input.runId,
      runVersion: 1,
      requestCommitment: commitAgentExecutionRequest(input.request),
    });
    expect(JSON.stringify(storedMaterial)).not.toContain("encryptedAutonomyWitness");
    const [job] = await leaseAgentExecutions("direct-privacy-worker", 1, now);
    expect(job.id).toBe(receipt.executionId);
    const context = await leaseDirectPrivacyExecutionContext(job, now);
    expect(context.materialCommitment).toBe(storedMaterial.materialCommitment);
    expect(context.material.authoritativeRequest).toEqual(input.request);
    expect(context.secrets.proofPrincipal).toEqual(input.proofPrincipal);

    await expect(leaseDirectPrivacyExecutionContext({ ...job, id: generateUuidV7() }, now))
      .rejects.toThrow("DIRECT_TREASURY_BUSY");
    const nextState = { ...context.state, pinnedBlock: { number: 20, hash: "0xabc" as const } };
    await expect(saveDirectPrivacyState({
      job,
      accountId: context.accountId,
      expectedVersion: context.stateVersion,
      state: nextState,
      now,
    })).resolves.toBe(context.stateVersion + 1);
    await expect(saveDirectPrivacyState({
      job,
      accountId: context.accountId,
      expectedVersion: context.stateVersion,
      state: nextState,
      now,
    })).rejects.toThrow("DIRECT_STATE_VERSION_CONFLICT");
  });

  it("rejects a staged witness with substituted authoritative roots", async () => {
    const input = await fixture();
    await expect(stageDirectPrivacyRunMaterial({
      accountId: input.account.id,
      material: {
        ...input.material,
        policyRun: { ...input.material.policyRun, manifestRoot: root("9") },
      },
      principal,
      now,
    })).rejects.toMatchObject({ code: "DIRECT_MATERIAL_ROOT_MISMATCH" });
    expect(await getDatabase().select().from(directPrivacyRunMaterials)).toHaveLength(0);
  });
}
