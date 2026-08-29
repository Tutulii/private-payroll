import type { STRK20_INVOKE_ACTION } from "starknet";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import { settlementRecordSchema, generateUuidV7 } from "@/lib/domain/records";
import { commitPayoActionTokenTotals } from "@/lib/domain/settlement";
import {
  wageRemediationPrivateSchema,
  type WageRemediationSummary,
} from "@/lib/domain/wage-remediation";
import { buildAuthorizedExceptionAction } from "@/lib/starknet/payo-exception-seal";
import { formatTokenAmount, PAYROLL_TOKENS } from "@/lib/starknet/tokens";
import type { PayrollRecipient } from "@/app/starknet/starknet-wallet";
import type { PayoClient } from "./payo-client";
import { openStoredExceptionProof } from "./exception-proof-recovery";
import {
  awaitWalletOrRecoveredTransaction,
  readRecoveredSettlementTransactionHash,
} from "./wallet-submission-recovery";

type RemediationPaymentClient = Pick<
  PayoClient,
  | "getWageRemediation"
  | "getEncryptedProofBundle"
  | "createSettlementIntent"
  | "getSettlement"
  | "recordSettlementSubmission"
  | "cancelSettlementApproval"
>;

function commitment(high: string, low: string): bigint {
  const upper = BigInt(high);
  const lower = BigInt(low);
  if (upper < 0n || upper >= 1n << 128n || lower < 0n || lower >= 1n << 128n) {
    throw new Error("Remediation proof contains a non-canonical commitment limb.");
  }
  return (upper << 128n) | lower;
}

function assertSummaryBinding(
  summary: WageRemediationSummary,
  privateRecord: ReturnType<typeof wageRemediationPrivateSchema.parse>,
) {
  if (
    privateRecord.id !== summary.id
    || privateRecord.organizationId !== summary.organizationId
    || privateRecord.runId !== summary.runId
    || privateRecord.workerClaimId !== summary.workerClaimId
    || privateRecord.proofBundleId !== summary.proofBundleId
    || BigInt(privateRecord.claimSubjectNullifier) !== BigInt(summary.claimSubjectNullifier)
    || BigInt(privateRecord.claimFactCommitment) !== BigInt(summary.claimFactCommitment)
    || BigInt(privateRecord.remediationSubjectNullifier)
      !== BigInt(summary.remediationSubjectNullifier)
    || BigInt(privateRecord.remediationFactCommitment)
      !== BigInt(summary.remediationFactCommitment)
    || BigInt(privateRecord.actionCommitment) !== BigInt(summary.actionCommitment)
    || BigInt(privateRecord.fxRoot) !== BigInt(summary.fxRoot)
    || privateRecord.validityExpiry
      !== String(Math.floor(new Date(summary.validityExpiresAt).getTime() / 1_000))
  ) throw new Error("The encrypted remediation differs from its durable public bindings.");
}

async function retryWrite<T>(operation: () => Promise<T>): Promise<T> {
  let failure: unknown;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      failure = error;
      if (attempt === 2) throw error;
      await new Promise<void>((resolve) =>
        globalThis.setTimeout(resolve, 250 * (attempt + 1)));
    }
  }
  throw failure;
}

export async function executeAuthorizedRemediationPayment(input: {
  client: RemediationPaymentClient;
  remediation: WageRemediationSummary;
  principal: VaultPrincipalKeyPair;
  sealAddress: string;
  submit: (
    workflow: "wage_remediation",
    recipients: PayrollRecipient[],
    action: STRK20_INVOKE_ACTION,
  ) => Promise<string>;
  onStage?: (stage: "loading" | "recording" | "wallet" | "submitted") => void;
}) {
  input.onStage?.("loading");
  const { remediation: fresh } = await input.client.getWageRemediation(
    input.remediation.id,
  );
  if (![
    "authorized",
    "payment_pending",
    "payment_confirmed",
    "reconciled",
  ].includes(fresh.state)) {
    throw new Error(`Remediation payment requires on-chain authorization; current state is ${fresh.state}.`);
  }
  const privateRecord = wageRemediationPrivateSchema.parse(
    decryptVaultRecord(fresh.envelope, input.principal),
  );
  assertSummaryBinding(fresh, privateRecord);
  const openedProof = await openStoredExceptionProof({
    client: input.client,
    proofBundleId: fresh.proofBundleId,
    principal: input.principal,
  });
  if (
    openedProof.metadata.proofVersion !== "7"
    || openedProof.proofBundle.verificationState !== "onchain_verified"
    || !openedProof.proofBundle.verificationTransactionHash
  ) throw new Error("Remediation v7 is not yet authorized on-chain.");
  const publicInputs = openedProof.metadata.publicInputs;
  if (
    commitment(publicInputs.subjectNullifierHigh, publicInputs.subjectNullifierLow)
      !== BigInt(privateRecord.remediationSubjectNullifier)
    || commitment(publicInputs.factCommitmentHigh, publicInputs.factCommitmentLow)
      !== BigInt(privateRecord.remediationFactCommitment)
    || commitment(publicInputs.parentNullifierHigh, publicInputs.parentNullifierLow)
      !== BigInt(privateRecord.claimSubjectNullifier)
    || commitment(publicInputs.parentFactCommitmentHigh, publicInputs.parentFactCommitmentLow)
      !== BigInt(privateRecord.claimFactCommitment)
    || commitment(publicInputs.manifestRootHigh, publicInputs.manifestRootLow)
      !== BigInt(privateRecord.actionCommitment)
    || commitment(publicInputs.fxRootHigh, publicInputs.fxRootLow)
      !== BigInt(privateRecord.fxRoot)
    || publicInputs.validityExpiry !== privateRecord.validityExpiry
  ) throw new Error("The authorized Remediation v7 proof does not match its private payment.");
  if (BigInt(privateRecord.validityExpiry) <= BigInt(Math.floor(Date.now() / 1_000))) {
    throw new Error("The Remediation v7 private-payment authorization has expired.");
  }

  const totals = privateRecord.token === "STRK"
    ? { STRK: privateRecord.amountAtomic, USDC: "0" }
    : { STRK: "0", USDC: privateRecord.amountAtomic };
  const tokenTotalsCommitment = commitPayoActionTokenTotals({
    organizationId: privateRecord.organizationId,
    runId: privateRecord.runId,
    workflowType: "wage_remediation",
    subjectRecordId: privateRecord.id,
    totals,
  });
  let settlementId = fresh.settlementId;
  let settlement: Record<string, unknown> | undefined;
  if (settlementId) {
    ({ settlement } = await input.client.getSettlement(settlementId));
    if (
      settlement.organizationId !== privateRecord.organizationId
      || settlement.runId !== privateRecord.runId
      || settlement.workflowType !== "wage_remediation"
      || settlement.subjectRecordId !== privateRecord.id
      || settlement.tokenTotalsCommitment !== tokenTotalsCommitment
    ) throw new Error("The existing remediation payment intent has different immutable bindings.");
    if (typeof settlement.transactionHash === "string") {
      return {
        remediation: fresh,
        privateRecord,
        settlementId,
        transactionHash: settlement.transactionHash,
        replayed: true,
      };
    }
    if (settlement.state !== "approval_pending") {
      throw new Error(`The remediation payment cannot resume from settlement state ${String(settlement.state)}.`);
    }
  } else {
    if (fresh.state !== "authorized") {
      throw new Error("The remediation has no recoverable payment intent.");
    }
    input.onStage?.("recording");
    settlementId = generateUuidV7();
    const walletRequestId = generateUuidV7();
    const idempotencyKey = `wage-remediation-v7:${privateRecord.id}:${walletRequestId}`;
    const timestamp = new Date().toISOString();
    const settlementRecord = settlementRecordSchema.parse({
      schemaVersion: 1,
      id: settlementId,
      organizationId: privateRecord.organizationId,
      revision: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
      runId: privateRecord.runId,
      workflowType: "wage_remediation",
      subjectRecordId: privateRecord.id,
      walletRequestId,
      idempotencyKey,
      tokenTotals: totals,
      tokenTotalsCommitment,
      state: "approval_pending",
      noteEvidenceState: "unavailable",
    });
    const envelope = encryptVaultRecord(settlementRecord, {
      schemaVersion: 1,
      organizationId: privateRecord.organizationId,
      recordType: "settlement",
      recordId: settlementId,
      revision: 1,
    }, [input.principal]);
    const stored = await retryWrite(() => input.client.createSettlementIntent({
      id: settlementId!,
      organizationId: privateRecord.organizationId,
      runId: privateRecord.runId,
      workflowType: "wage_remediation",
      subjectRecordId: privateRecord.id,
      walletRequestId,
      idempotencyKey,
      tokenTotalsCommitment,
      envelope,
    }));
    settlement = stored.settlement;
  }

  const action = buildAuthorizedExceptionAction({
    sealAddress: input.sealAddress,
    mode: 3,
    publicInputs,
  });
  const recipients: PayrollRecipient[] = [{
    address: privateRecord.recipientAddress,
    amount: formatTokenAmount(
      BigInt(privateRecord.amountAtomic),
      PAYROLL_TOKENS[privateRecord.token],
    ),
    token: privateRecord.token,
  }];
  input.onStage?.("wallet");
  const transactionHash = await awaitWalletOrRecoveredTransaction({
    submit: () => input.submit("wage_remediation", recipients, action),
    readRecoveredTransactionHash: () =>
      readRecoveredSettlementTransactionHash(input.client, settlementId!),
  });
  input.onStage?.("recording");
  await retryWrite(() =>
    input.client.recordSettlementSubmission(settlementId!, transactionHash));
  input.onStage?.("submitted");
  return {
    remediation: fresh,
    privateRecord,
    settlementId,
    transactionHash,
    replayed: false,
  };
}

export async function cancelAuthorizedRemediationPayment(input: {
  client: Pick<PayoClient, "cancelSettlementApproval">;
  remediation: WageRemediationSummary;
}) {
  if (!input.remediation.settlementId || input.remediation.state !== "payment_pending") {
    throw new Error("This remediation has no unsigned Ready approval to cancel.");
  }
  return input.client.cancelSettlementApproval(input.remediation.settlementId);
}
