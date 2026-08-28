import type { STRK20_INVOKE_ACTION } from "starknet";
import { z } from "zod";
import { decryptVaultRecord, encryptVaultRecord, type EncryptedVaultRecord, type VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import {
  generateUuidV7,
  remediationRecordSchema,
  settlementRecordSchema,
  wageClaimRecordSchema,
} from "@/lib/domain/records";
import { commitPayoActionTokenTotals } from "@/lib/domain/settlement";
import { buildPayrollIntegrityInputsFromSerialized, type SerializedPayrollIntegrityBuildRequest } from "@/lib/proof/input-builder";
import { proveEncryptedPayroll, type ProofProgressListener } from "@/lib/proof/client";
import {
  PAYO_MAX_PROOF_CALLDATA_FELTS,
  type PayrollIntegrityPublicInputs,
  type PayrollIntegrityShardProof,
  type ProofWorkerSuccess,
} from "@/lib/proof/protocol";
import { buildWageClaimInputs, buildWageRemediationInputs } from "@/lib/proof/wage-claim-input";
import {
  buildPayoSealedAction,
  PAYO_PROOF_MODE_CLAIM,
  PAYO_PROOF_MODE_REMEDIATE,
} from "@/lib/starknet/payo-seal";
import { formatTokenAmount, PAYROLL_TOKENS } from "@/lib/starknet/tokens";
import { prepareEncryptedPayrollIntegrityBundle } from "./proof-bundle";
import type { PayoClient } from "./payo-client";
import { storeCanonicalEncryptedRecord } from "./encrypted-records";
import type { RemediationRecord, WageClaimRecord } from "./claim-workflows";
import { recoverConfirmedPayrollVerification, type PayrollExecutionStage } from "./payroll-execution";

type ProveException = (input: {
  encryptedWitness: Parameters<typeof proveEncryptedPayroll>[0]["encryptedWitness"];
  principal: VaultPrincipalKeyPair;
  onProgress?: ProofProgressListener;
}) => Promise<ProofWorkerSuccess>;

export type PendingExceptionSubmission = {
  version: 1;
  workflowType: "wage_claim" | "wage_remediation";
  organizationId: string;
  runId: string;
  subjectRecordId: string;
  proofBundleId: string;
  settlementId: string;
  walletRequestId: string;
  idempotencyKey: string;
  tokenTotalsCommitment: `0x${string}`;
  proofShards: [string[], string[]];
  transactionHash?: string;
  createdAt: string;
};

export type WageClaimExecutionResult = PendingExceptionSubmission & {
  transactionHash: string;
  verificationQueued: true;
};

const pendingExceptionSubmissionSchema = z.object({
  version: z.literal(1),
  workflowType: z.enum(["wage_claim", "wage_remediation"]),
  organizationId: z.string().min(1),
  runId: z.string().min(1),
  subjectRecordId: z.string().min(1),
  proofBundleId: z.string().min(1),
  settlementId: z.string().min(1),
  walletRequestId: z.string().min(1),
  idempotencyKey: z.string().min(1),
  tokenTotalsCommitment: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  proofShards: z.tuple([
    z.array(z.string().regex(/^0x[0-9a-fA-F]+$/)).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
    z.array(z.string().regex(/^0x[0-9a-fA-F]+$/)).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
  ]),
  transactionHash: z.string().regex(/^0x[0-9a-fA-F]{1,64}$/).optional(),
  createdAt: z.string().datetime(),
}).strict();

const payrollPublicInputsSchema = z.object({
  chainId: z.string(),
  sealAddress: z.string(),
  proofVersion: z.string(),
  schemaVersion: z.string(),
  agreementRootHigh: z.string(),
  agreementRootLow: z.string(),
  manifestRootHigh: z.string(),
  manifestRootLow: z.string(),
  policyRootHigh: z.string(),
  policyRootLow: z.string(),
  fxRootHigh: z.string(),
  fxRootLow: z.string(),
  runNullifierHigh: z.string(),
  runNullifierLow: z.string(),
  validityStart: z.string(),
  validityExpiry: z.string(),
  shardIndex: z.string(),
}).strict();

const resumableExceptionProofSchema = z.object({
  shards: z.tuple([
    z.object({
      shardIndex: z.literal(0),
      proofCalldata: z.array(z.string().regex(/^0x[0-9a-fA-F]+$/)).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
      calldataHash: z.string().regex(/^0x[0-9a-fA-F]+$/),
      publicInputs: payrollPublicInputsSchema,
    }).passthrough(),
    z.object({
      shardIndex: z.literal(1),
      proofCalldata: z.array(z.string().regex(/^0x[0-9a-fA-F]+$/)).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
      calldataHash: z.string().regex(/^0x[0-9a-fA-F]+$/),
      publicInputs: payrollPublicInputsSchema,
    }).passthrough(),
  ]),
}).passthrough();

export function parsePendingExceptionSubmission(value: unknown): PendingExceptionSubmission {
  return pendingExceptionSubmissionSchema.parse(value) as PendingExceptionSubmission;
}

/**
 * Rebuilds browser recovery state after Ready submitted successfully but the
 * tab closed or localStorage was cleared. The transaction hash and intent come
 * from the authenticated durable settlement; proof calldata remains available
 * only by decrypting the tenant's encrypted proof bundle in this browser.
 */
export async function rebuildPendingExceptionSubmission(input: {
  client: PayoClient;
  organizationId: string;
  principal: VaultPrincipalKeyPair;
  runId: string;
  workflowType: "wage_claim" | "wage_remediation";
  subjectRecordId: string;
  proofBundleId: string;
  settlementId: string;
  now?: Date;
}): Promise<PendingExceptionSubmission> {
  const [{ settlement }, proofResponse] = await Promise.all([
    input.client.getSettlement(input.settlementId),
    input.client.getEncryptedRecord({
      organizationId: input.organizationId,
      recordId: input.proofBundleId,
    }) as Promise<{ record?: { envelope?: EncryptedVaultRecord } }>,
  ]);
  if (
    settlement.organizationId !== input.organizationId
    || settlement.runId !== input.runId
    || settlement.workflowType !== input.workflowType
    || settlement.subjectRecordId !== input.subjectRecordId
    || !proofResponse.record?.envelope
  ) {
    throw new Error("The durable exception recovery records do not match.");
  }
  const proofPayload = resumableExceptionProofSchema.parse(
    decryptVaultRecord(proofResponse.record.envelope, input.principal),
  );
  const validityExpiry = BigInt(proofPayload.shards[0].publicInputs.validityExpiry);
  const nowUnix = BigInt(Math.floor((input.now ?? new Date()).getTime() / 1_000));
  if (settlement.transactionHash && validityExpiry <= nowUnix + 120n) {
    const verificationComplete = await input.client.getProofVerification(input.settlementId)
      .then(({ proofVerification }) => proofVerification?.state === "complete")
      .catch(() => false);
    if (!verificationComplete) {
      const replacement = input.workflowType === "wage_claim"
        ? "Draft a fresh claim from the same confirmed payday; a new payroll is not required."
        : "Draft a fresh remediation from the verified claim.";
      throw new Error(
        `This sealed ${input.workflowType === "wage_claim" ? "claim" : "remediation"} proof expired before on-chain verification could be queued. ${replacement}`,
      );
    }
  }
  return parsePendingExceptionSubmission({
    version: 1,
    workflowType: input.workflowType,
    organizationId: input.organizationId,
    runId: input.runId,
    subjectRecordId: input.subjectRecordId,
    proofBundleId: input.proofBundleId,
    settlementId: input.settlementId,
    walletRequestId: settlement.walletRequestId,
    idempotencyKey: settlement.idempotencyKey,
    tokenTotalsCommitment: settlement.tokenTotalsCommitment,
    proofShards: [proofPayload.shards[0].proofCalldata, proofPayload.shards[1].proofCalldata],
    transactionHash: settlement.transactionHash,
    createdAt: settlement.createdAt,
  });
}

function canonicalRoot(high: string, low: string): `0x${string}` {
  const upper = BigInt(high);
  const lower = BigInt(low);
  if (upper < 0n || upper >= 1n << 128n || lower < 0n || lower >= 1n << 128n) {
    throw new Error("The exception proof returned a non-canonical root.");
  }
  return `0x${((upper << 128n) | lower).toString(16).padStart(64, "0")}`;
}

function assertSameRoot(actual: string, expected: string | null, label: string): void {
  if (!expected || BigInt(actual) !== BigInt(expected)) {
    throw new Error(`The encrypted claim source does not match the durable ${label}.`);
  }
}

async function retryWrite<T>(operation: () => Promise<T>): Promise<T> {
  let failure: unknown;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      failure = error;
      if (attempt === 2) throw error;
      await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
    }
  }
  throw failure;
}

async function requireConfirmedPayrollProof(input: {
  client: PayoClient;
  organizationId: string;
  runId: string;
  principal: VaultPrincipalKeyPair;
  onStage?: (stage: PayrollExecutionStage) => void;
}): Promise<void> {
  input.onStage?.("verifying");
  const recovery = await recoverConfirmedPayrollVerification({
    client: input.client,
    organizationId: input.organizationId,
    runId: input.runId,
    principal: input.principal,
    onStage: input.onStage,
  });
  const deadline = Date.now() + 20 * 60_000;
  while (true) {
    const { proofVerification } = await input.client.getProofVerification(recovery.settlementId) as {
      proofVerification: {
        state?: string;
        lastErrorCode?: string | null;
        lastErrorMessage?: string | null;
      };
    };
    if (proofVerification.state === "complete") return;
    if (proofVerification.state === "dead") {
      throw new Error(
        proofVerification.lastErrorMessage
        ?? proofVerification.lastErrorCode
        ?? "The confirmed payroll proof could not be verified on-chain.",
      );
    }
    if (Date.now() >= deadline) {
      throw new Error("The confirmed payroll proof is still being verified on-chain. This claim is safe to retry.");
    }
    await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
}

async function requireExceptionDeploymentReady(input: {
  client: PayoClient;
  organizationId: string;
  runId: string;
  workflowType: "wage_claim" | "wage_remediation";
  claimId?: string;
  chainId: string;
  sealAddress: string;
  mode: 0 | 2 | 3;
  proofVersion: number;
  agreementRoot: string;
  policyRoot: string;
  fxRoot: string;
}): Promise<void> {
  const check = () => input.client.checkDeploymentReadiness({
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    mode: input.mode,
    proofVersion: input.proofVersion,
    agreementRoot: input.agreementRoot,
    policyRoot: input.policyRoot,
    fxRoot: input.fxRoot,
  });
  let { readiness } = await check();
  if (readiness.ready) return;
  const failures = readiness.checks.filter(({ ready }) => !ready);
  const fxFailure = failures.some(({ code }) => code === "fx_root");
  const nonFxFailures = failures.filter(({ code }) => code !== "fx_root");
  if (fxFailure && nonFxFailures.length === 0) {
    if (input.workflowType === "wage_remediation" && !input.claimId) {
      throw new Error("The selected wage claim is required to renew remediation FX authorization.");
    }
    await input.client.renewHistoricalFxRoot(input.workflowType === "wage_remediation"
      ? {
          organizationId: input.organizationId,
          runId: input.runId,
          workflowType: input.workflowType,
          claimId: input.claimId!,
        }
      : {
          organizationId: input.organizationId,
          runId: input.runId,
          workflowType: input.workflowType,
        });
    ({ readiness } = await check());
    if (readiness.ready) return;
  }
  throw new Error(
    "PAYO exception deployment is not ready: "
    + readiness.checks.filter(({ ready }) => !ready).map(({ message }) => message).join(" "),
  );
}

export async function executeProofBoundWageClaim(input: {
  client: PayoClient;
  organizationId: string;
  principal: VaultPrincipalKeyPair;
  chainId: string;
  sealAddress: string;
  claim: WageClaimRecord;
  submitException: (
    workflow: "wage_claim",
    recipients: [],
    action: STRK20_INVOKE_ACTION,
  ) => Promise<string>;
  onStage?: (stage: PayrollExecutionStage) => void;
  persistPendingSubmission?: (submission: PendingExceptionSubmission | null) => void;
  prove?: ProveException;
  now?: () => Date;
}): Promise<WageClaimExecutionResult> {
  const claim = wageClaimRecordSchema.parse(input.claim);
  if (claim.organizationId !== input.organizationId || claim.state !== "draft") {
    throw new Error("Only an encrypted draft from this organization can be proved as a wage claim.");
  }
  if (!input.sealAddress || BigInt(input.chainId) === 0n || BigInt(input.sealAddress) === 0n) {
    throw new Error("PAYO claim proving requires non-zero chain and seal bindings.");
  }

  input.onStage?.("loading");
  const { run } = await input.client.getPayrollRun(claim.runId);
  if (run.organizationId !== input.organizationId || run.state !== "confirmed") {
    throw new Error("A wage claim requires the confirmed payroll run from this encrypted workspace.");
  }
  const privateRun = decryptVaultRecord<{
    claimProofSource?: { buildInput?: SerializedPayrollIntegrityBuildRequest };
  }>(run.envelope, input.principal);
  if (!privateRun.claimProofSource?.buildInput) {
    throw new Error("This payroll predates the encrypted claim-proof source and cannot be claimed through this workflow.");
  }
  const payroll = await buildPayrollIntegrityInputsFromSerialized(privateRun.claimProofSource.buildInput);
  assertSameRoot(payroll.agreementRoot, run.agreementRoot, "agreement root");
  assertSameRoot(payroll.manifestRoot, run.manifestRoot, "manifest root");
  assertSameRoot(payroll.policyRoot, run.policyRoot, "policy root");
  assertSameRoot(payroll.fxRoot, run.fxRoot, "FX root");
  assertSameRoot(payroll.runNullifier, run.runNullifier, "run nullifier");

  // Renew only the exact FX root bound to the confirmed payday before
  // spending prover CPU, then repeat after proving to close the expiry race.
  await requireConfirmedPayrollProof({
    client: input.client,
    organizationId: input.organizationId,
    runId: claim.runId,
    principal: input.principal,
    onStage: input.onStage,
  });
  input.onStage?.("preflight");
  await requireExceptionDeploymentReady({
    client: input.client,
    organizationId: input.organizationId,
    runId: claim.runId,
    workflowType: "wage_claim",
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    mode: PAYO_PROOF_MODE_CLAIM,
    proofVersion: 3,
    agreementRoot: payroll.agreementRoot,
    policyRoot: payroll.policyRoot,
    fxRoot: payroll.fxRoot,
  });

  const now = input.now?.() ?? new Date();
  const nowUnix = BigInt(Math.floor(now.getTime() / 1_000));
  const validityStart = nowUnix - 30n;
  const validityExpiry = validityStart + 3_600n;
  const claimInput = await buildWageClaimInputs({
    payroll,
    agreementId: claim.agreementId,
    claimKind: claim.claimKind,
    claimSalt: claim.claimSalt as `0x${string}`,
    validityStart,
    validityExpiry,
    disputedReferenceValueAtomic: claim.disputedReferenceValueAtomic,
    disputedFinalIncludedMask: claim.disputedFinalIncludedMask,
  });
  const requestId = generateUuidV7();
  const encryptedWitness = encryptVaultRecord(
    { circuitProfile: "wage_claim", circuitInputs: claimInput.witness.circuitInputs },
    {
      schemaVersion: 1,
      organizationId: input.organizationId,
      recordType: "payroll-proof-request",
      recordId: requestId,
      revision: 1,
    },
    [input.principal],
  );
  const proof = await (input.prove ?? proveEncryptedPayroll)({
    encryptedWitness,
    principal: input.principal,
    onProgress: (stage) => input.onStage?.(stage),
  });
  const publicInputs = proof.shards[0].publicInputs;
  const agreementRoot = canonicalRoot(publicInputs.agreementRootHigh, publicInputs.agreementRootLow);
  const policyRoot = canonicalRoot(publicInputs.policyRootHigh, publicInputs.policyRootLow);
  const fxRoot = canonicalRoot(publicInputs.fxRootHigh, publicInputs.fxRootLow);
  const proofClaimNullifier = canonicalRoot(publicInputs.runNullifierHigh, publicInputs.runNullifierLow);
  assertSameRoot(agreementRoot, run.agreementRoot, "agreement root");
  assertSameRoot(policyRoot, run.policyRoot, "policy root");
  assertSameRoot(fxRoot, run.fxRoot, "FX root");
  if (BigInt(proofClaimNullifier) !== BigInt(claimInput.claimNullifier)) {
    throw new Error("The wage-claim proof returned a different claim nullifier.");
  }

  input.onStage?.("preflight");
  await requireExceptionDeploymentReady({
    client: input.client,
    organizationId: input.organizationId,
    runId: claim.runId,
    workflowType: "wage_claim",
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    mode: PAYO_PROOF_MODE_CLAIM,
    proofVersion: 3,
    agreementRoot,
    policyRoot,
    fxRoot,
  });

  input.onStage?.("persisting");
  const proofBundleId = generateUuidV7();
  await input.client.storeEncryptedProofBundle(prepareEncryptedPayrollIntegrityBundle({
    id: proofBundleId,
    organizationId: input.organizationId,
    runId: claim.runId,
    revision: 1,
    proof,
    subjectRecordId: claim.id,
    principals: [input.principal],
  }));
  const proofTimestamp = new Date().toISOString();
  const provenClaim = wageClaimRecordSchema.parse({
    ...claim,
    revision: claim.revision + 1,
    updatedAt: proofTimestamp,
    claimNullifier: claimInput.claimNullifier,
    shortfallAtomic: claimInput.shortfallAtomic,
    token: claimInput.token,
    proofBundleId,
    state: "proven",
  });
  await storeCanonicalEncryptedRecord({
    client: input.client,
    organizationId: input.organizationId,
    recordType: "wage-claim",
    record: provenClaim,
    principals: [input.principal],
  });

  const sealed = buildPayoSealedAction({
    sealAddress: input.sealAddress,
    chainId: input.chainId,
    shards: proof.shards,
    mode: PAYO_PROOF_MODE_CLAIM,
    nowUnixSeconds: nowUnix,
  });
  const settlementId = generateUuidV7();
  const walletRequestId = generateUuidV7();
  const idempotencyKey = `wage-claim:${claim.id}:${walletRequestId}`;
  const totals = { STRK: "0", USDC: "0" } as const;
  const tokenTotalsCommitment = commitPayoActionTokenTotals({
    organizationId: input.organizationId,
    runId: claim.runId,
    workflowType: "wage_claim",
    subjectRecordId: claim.id,
    totals,
  });
  const settlementTimestamp = new Date().toISOString();
  const settlementRecord = settlementRecordSchema.parse({
    schemaVersion: 1,
    id: settlementId,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: settlementTimestamp,
    updatedAt: settlementTimestamp,
    runId: claim.runId,
    workflowType: "wage_claim",
    subjectRecordId: claim.id,
    walletRequestId,
    idempotencyKey,
    tokenTotals: totals,
    tokenTotalsCommitment,
    state: "approval_pending",
    noteEvidenceState: "unavailable",
  });
  const settlementEnvelope = encryptVaultRecord(settlementRecord, {
    schemaVersion: 1,
    organizationId: input.organizationId,
    recordType: "settlement",
    recordId: settlementId,
    revision: 1,
  }, [input.principal]);
  const pending: PendingExceptionSubmission = {
    version: 1,
    workflowType: "wage_claim",
    organizationId: input.organizationId,
    runId: claim.runId,
    subjectRecordId: claim.id,
    proofBundleId,
    settlementId,
    walletRequestId,
    idempotencyKey,
    tokenTotalsCommitment,
    proofShards: [proof.shards[0].proofCalldata, proof.shards[1].proofCalldata],
    createdAt: settlementTimestamp,
  };
  input.onStage?.("recording");
  await retryWrite(() => input.client.createSettlementIntent({
    id: settlementId,
    organizationId: input.organizationId,
    runId: claim.runId,
    workflowType: "wage_claim",
    subjectRecordId: claim.id,
    walletRequestId,
    idempotencyKey,
    tokenTotalsCommitment,
    envelope: settlementEnvelope,
  }));
  input.persistPendingSubmission?.(pending);

  input.onStage?.("wallet");
  const transactionHash = await input.submitException("wage_claim", [], sealed.invokeAction);
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(transactionHash)) {
    throw new Error("Ready submitted the wage claim without returning a valid transaction hash.");
  }
  const submitted = { ...pending, transactionHash };
  input.persistPendingSubmission?.(submitted);
  input.onStage?.("recording");
  await retryWrite(() => input.client.recordSettlementSubmission(settlementId, transactionHash));
  await retryWrite(() => input.client.enqueueProofVerification({
    settlementId,
    proofBundleId,
    shards: pending.proofShards,
  }));
  await storeCanonicalEncryptedRecord({
    client: input.client,
    organizationId: input.organizationId,
    recordType: "wage-claim",
    record: {
      ...provenClaim,
      revision: provenClaim.revision + 1,
      updatedAt: new Date().toISOString(),
      settlementId,
      state: "submitted",
    },
    principals: [input.principal],
  });
  input.persistPendingSubmission?.(null);
  input.onStage?.("queued");
  return { ...submitted, verificationQueued: true };
}

export async function resumeProofBoundWageClaim(input: {
  client: PayoClient;
  organizationId: string;
  principal: VaultPrincipalKeyPair;
  chainId: string;
  sealAddress: string;
  claim: WageClaimRecord;
  pendingSubmission: PendingExceptionSubmission;
  submitException: (
    workflow: "wage_claim",
    recipients: [],
    action: STRK20_INVOKE_ACTION,
  ) => Promise<string>;
  onStage?: (stage: PayrollExecutionStage) => void;
  persistPendingSubmission?: (submission: PendingExceptionSubmission | null) => void;
  prove?: ProveException;
  now?: () => Date;
}): Promise<WageClaimExecutionResult> {
  const pending = parsePendingExceptionSubmission(input.pendingSubmission);
  const claim = wageClaimRecordSchema.parse(input.claim);
  if (
    pending.workflowType !== "wage_claim"
    || pending.organizationId !== input.organizationId
    || pending.subjectRecordId !== claim.id
    || pending.runId !== claim.runId
    || claim.organizationId !== input.organizationId
    || claim.state !== "proven"
    || claim.proofBundleId !== pending.proofBundleId
    || !claim.claimNullifier
  ) {
    throw new Error("The saved Ready approval does not match this proven wage claim.");
  }
  if (!input.sealAddress || BigInt(input.chainId) === 0n || BigInt(input.sealAddress) === 0n) {
    throw new Error("PAYO claim recovery requires non-zero chain and seal bindings.");
  }

  input.onStage?.("loading");
  const settlementResponse = await input.client.getSettlement(pending.settlementId);
  const settlement = settlementResponse.settlement as Record<string, unknown>;
  if (
    settlement.organizationId !== input.organizationId
    || settlement.runId !== pending.runId
    || settlement.workflowType !== "wage_claim"
    || settlement.subjectRecordId !== claim.id
    || settlement.tokenTotalsCommitment !== pending.tokenTotalsCommitment
  ) {
    throw new Error("The durable claim approval intent does not match the saved proof.");
  }
  const serverTransactionHash = typeof settlement.transactionHash === "string"
    ? settlement.transactionHash
    : undefined;
  if (!serverTransactionHash && settlement.state !== "approval_pending") {
    throw new Error("This claim approval can no longer be resumed because its settlement is " + String(settlement.state) + ".");
  }

  const proofResponse = await input.client.getEncryptedRecord({
    organizationId: input.organizationId,
    recordId: pending.proofBundleId,
  }) as { record?: { envelope?: EncryptedVaultRecord; revision?: number } };
  if (!proofResponse.record?.envelope) {
    throw new Error("The encrypted wage-claim proof is unavailable for Ready recovery.");
  }
  const proofPayload = resumableExceptionProofSchema.parse(
    decryptVaultRecord(proofResponse.record.envelope, input.principal),
  );
  const shards = proofPayload.shards.map((shard) => ({
    shardIndex: shard.shardIndex,
    proof: new Uint8Array(),
    proofCalldata: shard.proofCalldata,
    calldataHash: shard.calldataHash,
    publicInputs: shard.publicInputs as PayrollIntegrityPublicInputs,
  })) as [PayrollIntegrityShardProof, PayrollIntegrityShardProof];
  const proofCalldataChanged =
    JSON.stringify(shards[0].proofCalldata) !== JSON.stringify(pending.proofShards[0])
    || JSON.stringify(shards[1].proofCalldata) !== JSON.stringify(pending.proofShards[1]);
  if (proofCalldataChanged && pending.transactionHash) {
    throw new Error("A submitted claim cannot switch to refreshed proof calldata.");
  }
  const proofNullifier = canonicalRoot(
    shards[0].publicInputs.runNullifierHigh,
    shards[0].publicInputs.runNullifierLow,
  );
  if (BigInt(proofNullifier) !== BigInt(claim.claimNullifier)) {
    throw new Error("The saved proof is bound to a different wage claim.");
  }

  let activePending: PendingExceptionSubmission = proofCalldataChanged ? {
    ...pending,
    proofShards: [shards[0].proofCalldata, shards[1].proofCalldata],
  } : pending;
  if (proofCalldataChanged) input.persistPendingSubmission?.(activePending);
  let activeShards = shards;
  let transactionHash = serverTransactionHash ?? pending.transactionHash;
  if (!transactionHash) {
    const agreementRoot = canonicalRoot(shards[0].publicInputs.agreementRootHigh, shards[0].publicInputs.agreementRootLow);
    const policyRoot = canonicalRoot(shards[0].publicInputs.policyRootHigh, shards[0].publicInputs.policyRootLow);
    const fxRoot = canonicalRoot(shards[0].publicInputs.fxRootHigh, shards[0].publicInputs.fxRootLow);
    await requireConfirmedPayrollProof({
      client: input.client,
      organizationId: input.organizationId,
      runId: claim.runId,
      principal: input.principal,
      onStage: input.onStage,
    });
    input.onStage?.("preflight");
    await requireExceptionDeploymentReady({
      client: input.client,
      organizationId: input.organizationId,
      runId: claim.runId,
      workflowType: "wage_claim",
      chainId: input.chainId,
      sealAddress: input.sealAddress,
      mode: PAYO_PROOF_MODE_CLAIM,
      proofVersion: 3,
      agreementRoot,
      policyRoot,
      fxRoot,
    });

    const now = input.now?.() ?? new Date();
    const nowUnix = BigInt(Math.floor(now.getTime() / 1_000));
    const proofExpiry = BigInt(shards[0].publicInputs.validityExpiry);
    if (proofExpiry - nowUnix < 300n) {
      const proofRevision = proofResponse.record?.revision;
      if (!Number.isInteger(proofRevision) || !proofRevision || proofRevision < 1) {
        throw new Error("The encrypted wage-claim proof revision is unavailable for safe refresh.");
      }
      input.onStage?.("loading");
      const { run } = await input.client.getPayrollRun(claim.runId);
      if (run.organizationId !== input.organizationId || !["confirmed", "reconciled"].includes(run.state)) {
        throw new Error("The payroll is no longer eligible for claim-proof refresh.");
      }
      const privateRun = decryptVaultRecord<{
        claimProofSource?: { buildInput?: SerializedPayrollIntegrityBuildRequest };
      }>(run.envelope, input.principal);
      if (!privateRun.claimProofSource?.buildInput) {
        throw new Error("The encrypted claim-proof source is unavailable for safe refresh.");
      }
      const payroll = await buildPayrollIntegrityInputsFromSerialized(privateRun.claimProofSource.buildInput);
      assertSameRoot(payroll.agreementRoot, run.agreementRoot, "agreement root");
      assertSameRoot(payroll.manifestRoot, run.manifestRoot, "manifest root");
      assertSameRoot(payroll.policyRoot, run.policyRoot, "policy root");
      assertSameRoot(payroll.fxRoot, run.fxRoot, "FX root");
      assertSameRoot(payroll.runNullifier, run.runNullifier, "run nullifier");
      const validityStart = nowUnix - 30n;
      const validityExpiry = validityStart + 3_600n;
      const claimInput = await buildWageClaimInputs({
        payroll,
        agreementId: claim.agreementId,
        claimKind: claim.claimKind,
        claimSalt: claim.claimSalt as `0x${string}`,
        validityStart,
        validityExpiry,
        disputedReferenceValueAtomic: claim.disputedReferenceValueAtomic,
        disputedFinalIncludedMask: claim.disputedFinalIncludedMask,
      });
      if (BigInt(claimInput.claimNullifier) !== BigInt(claim.claimNullifier)) {
        throw new Error("The refreshed claim witness changed its claim nullifier.");
      }
      const requestId = generateUuidV7();
      const encryptedWitness = encryptVaultRecord(
        { circuitProfile: "wage_claim", circuitInputs: claimInput.witness.circuitInputs },
        {
          schemaVersion: 1,
          organizationId: input.organizationId,
          recordType: "payroll-proof-request",
          recordId: requestId,
          revision: 1,
        },
        [input.principal],
      );
      const refreshedProof = await (input.prove ?? proveEncryptedPayroll)({
        encryptedWitness,
        principal: input.principal,
        onProgress: (stage) => input.onStage?.(stage),
      });
      const refreshedNullifier = canonicalRoot(
        refreshedProof.shards[0].publicInputs.runNullifierHigh,
        refreshedProof.shards[0].publicInputs.runNullifierLow,
      );
      if (BigInt(refreshedNullifier) !== BigInt(claim.claimNullifier)) {
        throw new Error("The refreshed proof returned a different claim nullifier.");
      }
      input.onStage?.("persisting");
      await input.client.storeEncryptedProofBundle(prepareEncryptedPayrollIntegrityBundle({
        id: pending.proofBundleId,
        organizationId: input.organizationId,
        runId: claim.runId,
        revision: proofRevision + 1,
        proof: refreshedProof,
        subjectRecordId: claim.id,
        principals: [input.principal],
      }));
      activeShards = refreshedProof.shards;
      activePending = {
        ...pending,
        proofShards: [
          refreshedProof.shards[0].proofCalldata,
          refreshedProof.shards[1].proofCalldata,
        ],
      };
      input.persistPendingSubmission?.(activePending);
    }

    input.onStage?.("preflight");
    await requireExceptionDeploymentReady({
      client: input.client,
      organizationId: input.organizationId,
      runId: claim.runId,
      workflowType: "wage_claim",
      chainId: input.chainId,
      sealAddress: input.sealAddress,
      mode: PAYO_PROOF_MODE_CLAIM,
      proofVersion: 3,
      agreementRoot: canonicalRoot(activeShards[0].publicInputs.agreementRootHigh, activeShards[0].publicInputs.agreementRootLow),
      policyRoot: canonicalRoot(activeShards[0].publicInputs.policyRootHigh, activeShards[0].publicInputs.policyRootLow),
      fxRoot: canonicalRoot(activeShards[0].publicInputs.fxRootHigh, activeShards[0].publicInputs.fxRootLow),
    });
    const sealed = buildPayoSealedAction({
      sealAddress: input.sealAddress,
      chainId: input.chainId,
      shards: activeShards,
      mode: PAYO_PROOF_MODE_CLAIM,
      nowUnixSeconds: BigInt(Math.floor((input.now?.() ?? new Date()).getTime() / 1_000)),
    });
    input.onStage?.("wallet");
    transactionHash = await input.submitException("wage_claim", [], sealed.invokeAction);
    if (!/^0x[0-9a-fA-F]{1,64}$/.test(transactionHash)) {
      throw new Error("Ready submitted the wage claim without returning a valid transaction hash.");
    }
    input.persistPendingSubmission?.({ ...activePending, transactionHash });
  }
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(transactionHash)) {
    throw new Error("The recovered wage-claim transaction hash is invalid.");
  }

  input.onStage?.("recording");
  await retryWrite(() => input.client.recordSettlementSubmission(pending.settlementId, transactionHash!));
  await retryWrite(() => input.client.enqueueProofVerification({
    settlementId: pending.settlementId,
    proofBundleId: activePending.proofBundleId,
    shards: activePending.proofShards,
  }));
  await storeCanonicalEncryptedRecord({
    client: input.client,
    organizationId: input.organizationId,
    recordType: "wage-claim",
    record: {
      ...claim,
      revision: claim.revision + 1,
      updatedAt: new Date().toISOString(),
      settlementId: pending.settlementId,
      state: "submitted",
    },
    principals: [input.principal],
  });
  const submitted = { ...activePending, transactionHash };
  input.persistPendingSubmission?.(null);
  input.onStage?.("queued");
  return { ...submitted, verificationQueued: true };
}

export async function executeProofBoundWageRemediation(input: {
  client: PayoClient;
  organizationId: string;
  principal: VaultPrincipalKeyPair;
  chainId: string;
  sealAddress: string;
  claim: WageClaimRecord;
  remediation: RemediationRecord;
  submitException: (
    workflow: "wage_remediation",
    recipients: Array<{ address: string; amount: string; token: "STRK" | "USDC" }>,
    action: STRK20_INVOKE_ACTION,
  ) => Promise<string>;
  onStage?: (stage: PayrollExecutionStage) => void;
  persistPendingSubmission?: (submission: PendingExceptionSubmission | null) => void;
  prove?: ProveException;
  now?: () => Date;
}): Promise<WageClaimExecutionResult> {
  const claim = wageClaimRecordSchema.parse(input.claim);
  const remediation = remediationRecordSchema.parse(input.remediation);
  if (
    remediation.organizationId !== input.organizationId
    || remediation.state !== "draft"
    || remediation.claimId !== claim.id
    || remediation.runId !== claim.runId
    || remediation.agreementId !== claim.agreementId
    || !remediation.claimNullifier
    || !remediation.amountAtomic
    || !remediation.token
    || !["submitted", "accepted"].includes(claim.state)
    || BigInt(remediation.claimNullifier) !== BigInt(claim.claimNullifier ?? "0")
  ) {
    throw new Error("The encrypted remediation draft does not match its proved wage claim.");
  }
  if (!input.sealAddress || BigInt(input.chainId) === 0n || BigInt(input.sealAddress) === 0n) {
    throw new Error("PAYO remediation proving requires non-zero chain and seal bindings.");
  }

  input.onStage?.("loading");
  const { run } = await input.client.getPayrollRun(claim.runId);
  if (run.organizationId !== input.organizationId || run.state !== "disputed") {
    throw new Error("Remediation can begin only after the wage claim is verified on-chain as disputed.");
  }
  const privateRun = decryptVaultRecord<{
    claimProofSource?: { buildInput?: SerializedPayrollIntegrityBuildRequest };
  }>(run.envelope, input.principal);
  const buildInput = privateRun.claimProofSource?.buildInput;
  if (!buildInput) {
    throw new Error("This payroll predates the encrypted claim-proof source and cannot be remediated through this workflow.");
  }
  const payroll = await buildPayrollIntegrityInputsFromSerialized(buildInput);
  assertSameRoot(payroll.agreementRoot, run.agreementRoot, "agreement root");
  assertSameRoot(payroll.manifestRoot, run.manifestRoot, "manifest root");
  assertSameRoot(payroll.policyRoot, run.policyRoot, "policy root");
  assertSameRoot(payroll.fxRoot, run.fxRoot, "FX root");
  assertSameRoot(payroll.runNullifier, run.runNullifier, "run nullifier");

  // Renew an otherwise valid historical FX authorization before spending
  // prover capacity. Remediation is allowed only after the claim has reached
  // the on-chain CLAIMED state, which the renewal endpoint verifies.
  input.onStage?.("preflight");
  await requireExceptionDeploymentReady({
    client: input.client,
    organizationId: input.organizationId,
    runId: claim.runId,
    workflowType: "wage_remediation",
    claimId: claim.id,
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    mode: PAYO_PROOF_MODE_REMEDIATE,
    proofVersion: 4,
    agreementRoot: payroll.agreementRoot,
    policyRoot: payroll.policyRoot,
    fxRoot: payroll.fxRoot,
  });

  const now = input.now?.() ?? new Date();
  const nowUnix = BigInt(Math.floor(now.getTime() / 1_000));
  const validityStart = nowUnix - 30n;
  const validityExpiry = validityStart + 3_600n;
  const rebuiltClaim = await buildWageClaimInputs({
    payroll,
    agreementId: claim.agreementId,
    claimKind: claim.claimKind,
    claimSalt: claim.claimSalt as `0x${string}`,
    validityStart,
    validityExpiry,
    disputedReferenceValueAtomic: claim.disputedReferenceValueAtomic,
    disputedFinalIncludedMask: claim.disputedFinalIncludedMask,
  });
  if (
    !claim.claimNullifier
    || !claim.shortfallAtomic
    || !claim.token
    || BigInt(rebuiltClaim.claimNullifier) !== BigInt(claim.claimNullifier)
    || rebuiltClaim.shortfallAtomic !== claim.shortfallAtomic
    || rebuiltClaim.token !== claim.token
  ) {
    throw new Error("The remediation could not reconstruct the accepted private claim preimage.");
  }
  const remediationInput = await buildWageRemediationInputs({
    claim: rebuiltClaim,
    amountAtomic: remediation.amountAtomic,
    token: remediation.token,
    remediationSalt: remediation.remediationSalt as `0x${string}`,
    validityStart,
    validityExpiry,
  });
  const requestId = generateUuidV7();
  const encryptedWitness = encryptVaultRecord(
    { circuitProfile: "wage_remediation", circuitInputs: remediationInput.witness.circuitInputs },
    {
      schemaVersion: 1,
      organizationId: input.organizationId,
      recordType: "payroll-proof-request",
      recordId: requestId,
      revision: 1,
    },
    [input.principal],
  );
  const proof = await (input.prove ?? proveEncryptedPayroll)({
    encryptedWitness,
    principal: input.principal,
    onProgress: (stage) => input.onStage?.(stage),
  });
  const publicInputs = proof.shards[0].publicInputs;
  const agreementRoot = canonicalRoot(publicInputs.agreementRootHigh, publicInputs.agreementRootLow);
  const policyRoot = canonicalRoot(publicInputs.policyRootHigh, publicInputs.policyRootLow);
  const fxRoot = canonicalRoot(publicInputs.fxRootHigh, publicInputs.fxRootLow);
  const proofClaimNullifier = canonicalRoot(publicInputs.runNullifierHigh, publicInputs.runNullifierLow);
  assertSameRoot(agreementRoot, run.agreementRoot, "agreement root");
  assertSameRoot(policyRoot, run.policyRoot, "policy root");
  assertSameRoot(fxRoot, run.fxRoot, "FX root");
  if (BigInt(proofClaimNullifier) !== BigInt(claim.claimNullifier)) {
    throw new Error("The remediation proof is not bound to the accepted claim nullifier.");
  }

  input.onStage?.("preflight");
  await requireExceptionDeploymentReady({
    client: input.client,
    organizationId: input.organizationId,
    runId: claim.runId,
    workflowType: "wage_remediation",
    claimId: claim.id,
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    mode: PAYO_PROOF_MODE_REMEDIATE,
    proofVersion: 4,
    agreementRoot,
    policyRoot,
    fxRoot,
  });

  input.onStage?.("persisting");
  const proofBundleId = generateUuidV7();
  await input.client.storeEncryptedProofBundle(prepareEncryptedPayrollIntegrityBundle({
    id: proofBundleId,
    organizationId: input.organizationId,
    runId: claim.runId,
    revision: 1,
    proof,
    subjectRecordId: remediation.id,
    principals: [input.principal],
  }));
  const proofTimestamp = new Date().toISOString();
  const provenRemediation = remediationRecordSchema.parse({
    ...remediation,
    revision: remediation.revision + 1,
    updatedAt: proofTimestamp,
    proofBundleId,
    state: "proven",
  });
  await storeCanonicalEncryptedRecord({
    client: input.client,
    organizationId: input.organizationId,
    recordType: "remediation",
    record: provenRemediation,
    principals: [input.principal],
  });

  const recipient = buildInput.lines.find(({ agreementId }) => agreementId === claim.agreementId)?.recipientAddress;
  if (!recipient) throw new Error("The remediation recipient is absent from the encrypted payroll source.");
  const token = PAYROLL_TOKENS[remediation.token];
  const walletRecipients = [{
    address: recipient,
    amount: formatTokenAmount(BigInt(remediation.amountAtomic), token, token.decimals),
    token: remediation.token,
  }];
  const sealed = buildPayoSealedAction({
    sealAddress: input.sealAddress,
    chainId: input.chainId,
    shards: proof.shards,
    mode: PAYO_PROOF_MODE_REMEDIATE,
    nowUnixSeconds: nowUnix,
  });
  const settlementId = generateUuidV7();
  const walletRequestId = generateUuidV7();
  const idempotencyKey = `wage-remediation:${remediation.id}:${walletRequestId}`;
  const totals = {
    STRK: remediation.token === "STRK" ? remediation.amountAtomic : "0",
    USDC: remediation.token === "USDC" ? remediation.amountAtomic : "0",
  };
  const tokenTotalsCommitment = commitPayoActionTokenTotals({
    organizationId: input.organizationId,
    runId: claim.runId,
    workflowType: "wage_remediation",
    subjectRecordId: remediation.id,
    totals,
  });
  const settlementTimestamp = new Date().toISOString();
  const settlementRecord = settlementRecordSchema.parse({
    schemaVersion: 1,
    id: settlementId,
    organizationId: input.organizationId,
    revision: 1,
    createdAt: settlementTimestamp,
    updatedAt: settlementTimestamp,
    runId: claim.runId,
    workflowType: "wage_remediation",
    subjectRecordId: remediation.id,
    walletRequestId,
    idempotencyKey,
    tokenTotals: totals,
    tokenTotalsCommitment,
    state: "approval_pending",
    noteEvidenceState: "unavailable",
  });
  const settlementEnvelope = encryptVaultRecord(settlementRecord, {
    schemaVersion: 1,
    organizationId: input.organizationId,
    recordType: "settlement",
    recordId: settlementId,
    revision: 1,
  }, [input.principal]);
  const pending: PendingExceptionSubmission = {
    version: 1,
    workflowType: "wage_remediation",
    organizationId: input.organizationId,
    runId: claim.runId,
    subjectRecordId: remediation.id,
    proofBundleId,
    settlementId,
    walletRequestId,
    idempotencyKey,
    tokenTotalsCommitment,
    proofShards: [proof.shards[0].proofCalldata, proof.shards[1].proofCalldata],
    createdAt: settlementTimestamp,
  };
  input.onStage?.("recording");
  await retryWrite(() => input.client.createSettlementIntent({
    id: settlementId,
    organizationId: input.organizationId,
    runId: claim.runId,
    workflowType: "wage_remediation",
    subjectRecordId: remediation.id,
    walletRequestId,
    idempotencyKey,
    tokenTotalsCommitment,
    envelope: settlementEnvelope,
  }));
  input.persistPendingSubmission?.(pending);

  input.onStage?.("wallet");
  const transactionHash = await input.submitException("wage_remediation", walletRecipients, sealed.invokeAction);
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(transactionHash)) {
    throw new Error("Ready submitted remediation without returning a valid transaction hash.");
  }
  const submitted = { ...pending, transactionHash };
  input.persistPendingSubmission?.(submitted);
  input.onStage?.("recording");
  await retryWrite(() => input.client.recordSettlementSubmission(settlementId, transactionHash));
  await retryWrite(() => input.client.enqueueProofVerification({
    settlementId,
    proofBundleId,
    shards: pending.proofShards,
  }));
  await storeCanonicalEncryptedRecord({
    client: input.client,
    organizationId: input.organizationId,
    recordType: "remediation",
    record: {
      ...provenRemediation,
      revision: provenRemediation.revision + 1,
      updatedAt: new Date().toISOString(),
      settlementId,
      state: "submitted",
    },
    principals: [input.principal],
  });
  input.persistPendingSubmission?.(null);
  input.onStage?.("queued");
  return { ...submitted, verificationQueued: true };
}

export async function resumeProofBoundWageRemediation(input: {
  client: PayoClient;
  organizationId: string;
  principal: VaultPrincipalKeyPair;
  chainId: string;
  sealAddress: string;
  claim: WageClaimRecord;
  remediation: RemediationRecord;
  pendingSubmission: PendingExceptionSubmission;
  submitException: (
    workflow: "wage_remediation",
    recipients: Array<{ address: string; amount: string; token: "STRK" | "USDC" }>,
    action: STRK20_INVOKE_ACTION,
  ) => Promise<string>;
  onStage?: (stage: PayrollExecutionStage) => void;
  persistPendingSubmission?: (submission: PendingExceptionSubmission | null) => void;
  now?: () => Date;
}): Promise<WageClaimExecutionResult> {
  const pending = parsePendingExceptionSubmission(input.pendingSubmission);
  const claim = wageClaimRecordSchema.parse(input.claim);
  const remediation = remediationRecordSchema.parse(input.remediation);
  if (
    pending.workflowType !== "wage_remediation"
    || pending.organizationId !== input.organizationId
    || pending.subjectRecordId !== remediation.id
    || pending.runId !== remediation.runId
    || remediation.organizationId !== input.organizationId
    || remediation.claimId !== claim.id
    || remediation.runId !== claim.runId
    || remediation.agreementId !== claim.agreementId
    || remediation.state !== "proven"
    || remediation.proofBundleId !== pending.proofBundleId
    || !remediation.claimNullifier
    || !remediation.amountAtomic
    || !remediation.token
    || !claim.claimNullifier
    || BigInt(remediation.claimNullifier) !== BigInt(claim.claimNullifier)
    || !["submitted", "accepted"].includes(claim.state)
  ) {
    throw new Error("The saved Ready approval does not match this proven remediation.");
  }
  if (!input.sealAddress || BigInt(input.chainId) === 0n || BigInt(input.sealAddress) === 0n) {
    throw new Error("PAYO remediation recovery requires non-zero chain and seal bindings.");
  }

  input.onStage?.("loading");
  const settlementResponse = await input.client.getSettlement(pending.settlementId);
  const settlement = settlementResponse.settlement as Record<string, unknown>;
  if (
    settlement.organizationId !== input.organizationId
    || settlement.runId !== pending.runId
    || settlement.workflowType !== "wage_remediation"
    || settlement.subjectRecordId !== remediation.id
    || settlement.tokenTotalsCommitment !== pending.tokenTotalsCommitment
  ) {
    throw new Error("The durable remediation approval intent does not match the saved proof.");
  }
  const serverTransactionHash = typeof settlement.transactionHash === "string"
    ? settlement.transactionHash
    : undefined;
  if (!serverTransactionHash && settlement.state !== "approval_pending") {
    throw new Error("This remediation approval can no longer be resumed because its settlement is " + String(settlement.state) + ".");
  }

  const proofResponse = await input.client.getEncryptedRecord({
    organizationId: input.organizationId,
    recordId: pending.proofBundleId,
  }) as { record?: { envelope?: EncryptedVaultRecord } };
  if (!proofResponse.record?.envelope) {
    throw new Error("The encrypted remediation proof is unavailable for Ready recovery.");
  }
  const proofPayload = resumableExceptionProofSchema.parse(
    decryptVaultRecord(proofResponse.record.envelope, input.principal),
  );
  const shards = proofPayload.shards.map((shard) => ({
    shardIndex: shard.shardIndex,
    proof: new Uint8Array(),
    proofCalldata: shard.proofCalldata,
    calldataHash: shard.calldataHash,
    publicInputs: shard.publicInputs as PayrollIntegrityPublicInputs,
  })) as [PayrollIntegrityShardProof, PayrollIntegrityShardProof];
  if (
    JSON.stringify(shards[0].proofCalldata) !== JSON.stringify(pending.proofShards[0])
    || JSON.stringify(shards[1].proofCalldata) !== JSON.stringify(pending.proofShards[1])
  ) {
    throw new Error("The saved remediation proof calldata changed after Ready approval was prepared.");
  }
  const proofClaimNullifier = canonicalRoot(
    shards[0].publicInputs.runNullifierHigh,
    shards[0].publicInputs.runNullifierLow,
  );
  if (BigInt(proofClaimNullifier) !== BigInt(claim.claimNullifier)) {
    throw new Error("The saved remediation proof is bound to a different wage claim.");
  }

  const { run } = await input.client.getPayrollRun(claim.runId);
  if (run.organizationId !== input.organizationId || run.state !== "disputed") {
    throw new Error("The payroll is no longer eligible for private remediation.");
  }
  const privateRun = decryptVaultRecord<{
    claimProofSource?: { buildInput?: SerializedPayrollIntegrityBuildRequest };
  }>(run.envelope, input.principal);
  const buildInput = privateRun.claimProofSource?.buildInput;
  if (!buildInput) {
    throw new Error("The encrypted remediation recipient source is unavailable.");
  }
  const recipient = buildInput.lines.find(({ agreementId }) => agreementId === claim.agreementId)?.recipientAddress;
  if (!recipient) throw new Error("The remediation recipient is absent from the encrypted payroll source.");

  let transactionHash = serverTransactionHash ?? pending.transactionHash;
  if (!transactionHash) {
    const nowUnix = BigInt(Math.floor((input.now?.() ?? new Date()).getTime() / 1_000));
    if (BigInt(shards[0].publicInputs.validityExpiry) <= nowUnix + 30n) {
      throw new Error("The saved remediation proof expired before Ready approval. Create a fresh remediation draft.");
    }
    await requireConfirmedPayrollProof({
      client: input.client,
      organizationId: input.organizationId,
      runId: claim.runId,
      principal: input.principal,
      onStage: input.onStage,
    });
    input.onStage?.("preflight");
    await requireExceptionDeploymentReady({
      client: input.client,
      organizationId: input.organizationId,
      runId: claim.runId,
      workflowType: "wage_remediation",
      claimId: claim.id,
      chainId: input.chainId,
      sealAddress: input.sealAddress,
      mode: PAYO_PROOF_MODE_REMEDIATE,
      proofVersion: 4,
      agreementRoot: canonicalRoot(shards[0].publicInputs.agreementRootHigh, shards[0].publicInputs.agreementRootLow),
      policyRoot: canonicalRoot(shards[0].publicInputs.policyRootHigh, shards[0].publicInputs.policyRootLow),
      fxRoot: canonicalRoot(shards[0].publicInputs.fxRootHigh, shards[0].publicInputs.fxRootLow),
    });
    const token = PAYROLL_TOKENS[remediation.token];
    const walletRecipients = [{
      address: recipient,
      amount: formatTokenAmount(BigInt(remediation.amountAtomic), token, token.decimals),
      token: remediation.token,
    }];
    const sealed = buildPayoSealedAction({
      sealAddress: input.sealAddress,
      chainId: input.chainId,
      shards,
      mode: PAYO_PROOF_MODE_REMEDIATE,
      nowUnixSeconds: nowUnix,
    });
    input.onStage?.("wallet");
    transactionHash = await input.submitException("wage_remediation", walletRecipients, sealed.invokeAction);
    if (!/^0x[0-9a-fA-F]{1,64}$/.test(transactionHash)) {
      throw new Error("Ready submitted remediation without returning a valid transaction hash.");
    }
    input.persistPendingSubmission?.({ ...pending, transactionHash });
  }
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(transactionHash)) {
    throw new Error("The recovered remediation transaction hash is invalid.");
  }

  input.onStage?.("recording");
  await retryWrite(() => input.client.recordSettlementSubmission(pending.settlementId, transactionHash!));
  await retryWrite(() => input.client.enqueueProofVerification({
    settlementId: pending.settlementId,
    proofBundleId: pending.proofBundleId,
    shards: pending.proofShards,
  }));
  await storeCanonicalEncryptedRecord({
    client: input.client,
    organizationId: input.organizationId,
    recordType: "remediation",
    record: {
      ...remediation,
      revision: remediation.revision + 1,
      updatedAt: new Date().toISOString(),
      settlementId: pending.settlementId,
      state: "submitted",
    },
    principals: [input.principal],
  });
  const submitted = { ...pending, transactionHash };
  input.persistPendingSubmission?.(null);
  input.onStage?.("queued");
  return { ...submitted, verificationQueued: true };
}
