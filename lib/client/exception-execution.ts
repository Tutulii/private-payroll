import type { STRK20_INVOKE_ACTION } from "starknet";
import { decryptVaultRecord, encryptVaultRecord, type VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import {
  generateUuidV7,
  remediationRecordSchema,
  settlementRecordSchema,
  wageClaimRecordSchema,
} from "@/lib/domain/records";
import { commitPayoActionTokenTotals } from "@/lib/domain/settlement";
import { buildPayrollIntegrityInputsFromSerialized, type SerializedPayrollIntegrityBuildRequest } from "@/lib/proof/input-builder";
import { proveEncryptedPayroll, type ProofProgressListener } from "@/lib/proof/client";
import type { ProofWorkerSuccess } from "@/lib/proof/protocol";
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
import type { PayrollExecutionStage } from "./payroll-execution";

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
  if (BigInt(proofClaimNullifier) !== BigInt(claimInput.claimNullifier)) {
    throw new Error("The wage-claim proof returned a different claim nullifier.");
  }

  input.onStage?.("preflight");
  const { readiness } = await input.client.checkDeploymentReadiness({
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    mode: PAYO_PROOF_MODE_CLAIM,
    proofVersion: 3,
    agreementRoot,
    policyRoot,
    fxRoot,
  });
  if (!readiness.ready) {
    throw new Error(`PAYO claim deployment is not ready: ${readiness.checks.filter(({ ready }) => !ready).map(({ message }) => message).join(" ")}`);
  }

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
  if (BigInt(proofClaimNullifier) !== BigInt(claim.claimNullifier)) {
    throw new Error("The remediation proof is not bound to the accepted claim nullifier.");
  }

  input.onStage?.("preflight");
  const { readiness } = await input.client.checkDeploymentReadiness({
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    mode: PAYO_PROOF_MODE_REMEDIATE,
    proofVersion: 4,
    agreementRoot,
    policyRoot,
    fxRoot,
  });
  if (!readiness.ready) {
    throw new Error(`PAYO remediation deployment is not ready: ${readiness.checks.filter(({ ready }) => !ready).map(({ message }) => message).join(" ")}`);
  }

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
