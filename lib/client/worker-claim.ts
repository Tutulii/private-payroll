import type {
  PayrollStatementEvidenceGrantSummary,
  PayrollStatementEvidencePrivate,
} from "@/lib/domain/employer-statement";
import type { ExceptionClaimKind } from "@/lib/domain/exception-protocol";
import type {
  ObligationClaimAccessGrantSummary,
  ObligationClaimAccessPrivate,
} from "@/lib/domain/obligation-snapshot-plan";
import {
  workerClaimCreateSchema,
  workerClaimPrivateSchema,
  type WorkerClaimCreate,
  type WorkerClaimPrivate,
  type WorkerClaimSummary,
} from "@/lib/domain/worker-claim";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  type VaultPrincipal,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import {
  buildWageClaimV2Inputs,
  type PayrollStatementEvidence,
  type WageClaimSnapshotBuild,
  type WageClaimV2Build,
} from "@/lib/proof/exception-input-builder";
import type { ExceptionProofWorkerSuccess } from "@/lib/proof/protocol";
import { prepareEncryptedExceptionProofBundle } from "./proof-bundle";
import { openPayrollStatementEvidence } from "./employer-statement";
import {
  openObligationClaimAccess,
  type OpenedObligationClaimAccess,
} from "./obligation-snapshot-plan";
import type { PayoClient } from "./payo-client";

type WorkerClaimClient = Pick<
  PayoClient,
  | "createWorkerClaim"
  | "proveExceptionRemotely"
  | "storeEncryptedProofBundle"
  | "enqueueExceptionAuthorization"
>;

export type PreparedWorkerClaimV2 = {
  opened: OpenedObligationClaimAccess;
  evidence: { source: "unsettled_period" } | PayrollStatementEvidence;
  build: WageClaimV2Build;
  privateRecord: WorkerClaimPrivate;
  create: WorkerClaimCreate;
  proofRecipients: readonly VaultPrincipal[];
};

function snapshotBuild(access: ObligationClaimAccessPrivate): WageClaimSnapshotBuild {
  return {
    snapshot: access.snapshot,
    snapshotCommitment: access.snapshotCommitment,
    claimRoot: access.snapshot.obligationRoot,
    lines: [access.witness],
  } as WageClaimSnapshotBuild;
}

function proofEvidence(
  evidence: PayrollStatementEvidencePrivate,
): PayrollStatementEvidence {
  const target = evidence.target.kind === "empty"
    ? {
        kind: "empty" as const,
        manifestRoot: evidence.target.manifestRoot,
        manifestMembership: {
          siblings: evidence.target.manifestMembership.siblings,
          pathBits: evidence.target.manifestMembership.pathBits,
        },
      }
    : {
        kind: "line" as const,
        deductionsAtomic: evidence.target.deductionsAtomic,
        lineSalt: evidence.target.lineSalt,
        classificationTreatment: evidence.target.classificationTreatment,
        finalIncludedMask: evidence.target.finalIncludedMask,
        referenceValueAtomic: evidence.target.referenceValueAtomic,
        manifestRoot: evidence.target.manifestRoot,
        manifestMembership: {
          siblings: evidence.target.manifestMembership.siblings,
          pathBits: evidence.target.manifestMembership.pathBits,
        },
      };
  return {
    source: evidence.statement.source,
    observedAt: BigInt(evidence.statement.observedAt),
    availabilityCommitment: evidence.statement.availabilityCommitment,
    target,
    fxSnapshots: evidence.fxSnapshots,
    ...(evidence.selectedFxIndex === undefined
      ? {}
      : { selectedFxIndex: evidence.selectedFxIndex }),
  };
}

async function selectClaimEvidence(input: {
  claimKind: ExceptionClaimKind;
  opened: OpenedObligationClaimAccess;
  principal: VaultPrincipalKeyPair;
  statementEvidence: readonly PayrollStatementEvidenceGrantSummary[];
}): Promise<{ source: "unsettled_period" } | PayrollStatementEvidence> {
  const routes = input.statementEvidence.filter((grant) =>
    grant.claimAccessGrantId === input.opened.access.grantId
    && grant.claimantPrincipalId === input.principal.principalId
    && grant.revokedAt === null
    && grant.statement.state === "registered");
  const opened = await Promise.all(routes.map((grant) =>
    openPayrollStatementEvidence({
      grant,
      principal: input.principal,
      claimAccess: input.opened.access,
    })));

  if (input.claimKind === "missing_obligation") {
    if (opened.length === 0) return { source: "unsettled_period" };
    const missing = opened.find((evidence) =>
      evidence.target.kind === "empty"
      && BigInt(evidence.statement.fxRoot) === 0n);
    if (!missing) {
      throw new Error(
        "Registered employer evidence contains a payment for this obligation; a missing-obligation claim would be false.",
      );
    }
    return proofEvidence(missing);
  }

  if (input.claimKind === "below_committed_floor") {
    const fx = opened.find((evidence) =>
      evidence.target.kind === "line"
      && evidence.selectedFxIndex !== undefined
      && evidence.fxSnapshots.length > 0
      && BigInt(evidence.statement.fxRoot) !== 0n);
    if (!fx) {
      throw new Error(
        "Below-floor claims require the worker's registered FX statement evidence.",
      );
    }
    return proofEvidence(fx);
  }

  const finalPay = opened.find((evidence) =>
    evidence.target.kind === "line"
    && BigInt(evidence.statement.fxRoot) === 0n);
  if (!finalPay) {
    throw new Error(
      "Incomplete-final-pay claims require the worker's registered base statement evidence.",
    );
  }
  return proofEvidence(finalPay);
}

function uniqueRecipients(
  claimant: VaultPrincipalKeyPair,
  issuer: VaultPrincipal,
): readonly VaultPrincipal[] {
  if (claimant.principalId === issuer.principalId) {
    throw new Error(
      "A protected wage claim requires distinct worker and employer PAYO identities.",
    );
  }
  return [claimant, issuer];
}

export async function prepareWorkerClaimV2(input: {
  grant: ObligationClaimAccessGrantSummary;
  statementEvidence?: readonly PayrollStatementEvidenceGrantSummary[];
  claimKind: ExceptionClaimKind;
  chainId: string;
  sealAddress: string;
  principal: VaultPrincipalKeyPair;
  now?: Date;
  claimId?: string;
  proofBundleId?: string;
}): Promise<PreparedWorkerClaimV2> {
  const opened = await openObligationClaimAccess({
    grant: input.grant,
    principal: input.principal,
  });
  const access = opened.access;
  if (!access.recipientSalt) {
    throw new Error(
      "This claim packet predates private remediation recipient recovery. Use a newly protected payday.",
    );
  }

  const now = input.now ?? new Date();
  const nowSeconds = BigInt(Math.floor(now.getTime() / 1_000));
  const graceEndsAt = BigInt(access.snapshot.graceEndsAt);
  const claimEndsAt = BigInt(access.snapshot.claimEndsAt);
  if (nowSeconds < graceEndsAt) {
    throw new Error("This protected payday is still inside its claim grace period.");
  }
  if (nowSeconds + 120n >= claimEndsAt) {
    throw new Error("This protected payday has too little claim time remaining.");
  }
  const validityStart = nowSeconds;
  const validityExpiry = nowSeconds + 1_800n < claimEndsAt
    ? nowSeconds + 1_800n
    : claimEndsAt;

  const evidence = await selectClaimEvidence({
    claimKind: input.claimKind,
    opened,
    principal: input.principal,
    statementEvidence: input.statementEvidence ?? [],
  });
  const build = await buildWageClaimV2Inputs({
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    snapshot: snapshotBuild(access),
    agreementId: access.binding.agreementId,
    claimCapabilitySecret: opened.claimCapabilitySecret,
    claimKind: input.claimKind,
    evidence,
    validityStart,
    validityExpiry,
  });

  const claimId = input.claimId ?? generateUuidV7(now.getTime());
  const proofBundleId = input.proofBundleId
    ?? generateUuidV7(now.getTime() + 1);
  const proofRecipients = uniqueRecipients(
    input.principal,
    access.issuerPrincipal,
  );
  const timestamp = now.toISOString();
  const privateRecord = workerClaimPrivateSchema.parse({
    format: "payo-worker-wage-claim-v2",
    schemaVersion: 2,
    id: claimId,
    claimAccessGrantId: access.grantId,
    snapshotPlanId: access.snapshotPlanId,
    organizationId: access.organizationId,
    runId: access.runId,
    agreementId: access.binding.agreementId,
    claimKind: input.claimKind,
    claimFact: build.claimFact,
    claimFactCommitment: build.claimFactCommitment,
    proofBundleId,
    claimantPrincipal: {
      principalId: input.principal.principalId,
      publicKey: input.principal.publicKey,
    },
    remediationWitness: {
      snapshot: access.snapshot,
      recipientAddress: access.witness.calculated.recipientAddress,
      recipientSalt: access.recipientSalt,
      agreement: access.witness.agreement,
      agreementMembership: access.witness.agreementMembership,
    },
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  const envelope = encryptVaultRecord(privateRecord, {
    schemaVersion: 1,
    organizationId: access.organizationId,
    recordType: "wage-claim-v2",
    recordId: claimId,
    revision: 1,
  }, proofRecipients);
  const create = workerClaimCreateSchema.parse({
    id: claimId,
    claimAccessGrantId: access.grantId,
    organizationId: access.organizationId,
    runId: access.runId,
    revision: 1,
    proofBundleId,
    claimSubjectNullifier: build.claimSubjectNullifier,
    claimFactCommitment: build.claimFactCommitment,
    envelope,
  });
  return { opened, evidence, build, privateRecord, create, proofRecipients };
}


export async function prepareStoredWorkerClaimV2(input: {
  claim: WorkerClaimSummary;
  grant: ObligationClaimAccessGrantSummary;
  statementEvidence?: readonly PayrollStatementEvidenceGrantSummary[];
  chainId: string;
  sealAddress: string;
  principal: VaultPrincipalKeyPair;
  now?: Date;
}): Promise<PreparedWorkerClaimV2> {
  if (input.claim.claimantPrincipalId !== input.principal.principalId) {
    throw new Error("Only the worker who owns this Claim v6 can resume it.");
  }
  if (input.claim.state !== "prepared") {
    throw new Error("Only a persisted Claim v6 without a proof can resume proving.");
  }
  const privateRecord = workerClaimPrivateSchema.parse(
    decryptVaultRecord(input.claim.envelope, input.principal),
  );
  if (
    privateRecord.id !== input.claim.id
    || privateRecord.claimAccessGrantId !== input.claim.claimAccessGrantId
    || privateRecord.organizationId !== input.claim.organizationId
    || privateRecord.runId !== input.claim.runId
    || privateRecord.proofBundleId !== input.claim.proofBundleId
    || BigInt(privateRecord.claimFact.claimSubjectNullifier)
      !== BigInt(input.claim.claimSubjectNullifier)
    || BigInt(privateRecord.claimFactCommitment)
      !== BigInt(input.claim.claimFactCommitment)
  ) throw new Error("The stored Claim v6 ciphertext differs from its durable bindings.");
  const rebuilt = await prepareWorkerClaimV2({
    grant: input.grant,
    statementEvidence: input.statementEvidence,
    claimKind: privateRecord.claimKind,
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    principal: input.principal,
    now: input.now,
    claimId: input.claim.id,
    proofBundleId: input.claim.proofBundleId,
  });
  if (
    BigInt(rebuilt.build.claimSubjectNullifier)
      !== BigInt(input.claim.claimSubjectNullifier)
    || BigInt(rebuilt.build.claimFactCommitment)
      !== BigInt(input.claim.claimFactCommitment)
    || JSON.stringify(rebuilt.build.claimFact)
      !== JSON.stringify(privateRecord.claimFact)
  ) throw new Error("The rebuilt Claim v6 witness changed its immutable claim fact.");
  const create = workerClaimCreateSchema.parse({
    id: input.claim.id,
    claimAccessGrantId: input.claim.claimAccessGrantId,
    organizationId: input.claim.organizationId,
    runId: input.claim.runId,
    revision: 1,
    proofBundleId: input.claim.proofBundleId,
    claimSubjectNullifier: input.claim.claimSubjectNullifier,
    claimFactCommitment: input.claim.claimFactCommitment,
    envelope: input.claim.envelope,
  });
  return {
    ...rebuilt,
    privateRecord,
    create,
    proofRecipients: uniqueRecipients(
      input.principal,
      rebuilt.opened.access.issuerPrincipal,
    ),
  };
}

export async function proveAndSubmitWorkerClaimV2(input: {
  client: WorkerClaimClient;
  prepared: PreparedWorkerClaimV2;
  principal: VaultPrincipalKeyPair;
  proverBaseUrl: string;
  onStage?: (
    stage: "persisting_claim" | "proving" | "persisting_proof" | "authorizing",
  ) => void;
}) {
  const { prepared } = input;
  if (
    prepared.create.envelope.wrappedKeys.every(({ principalId }) =>
      principalId !== input.principal.principalId)
  ) {
    throw new Error("The connected worker cannot decrypt this prepared claim.");
  }

  input.onStage?.("persisting_claim");
  const storedClaim = await input.client.createWorkerClaim(prepared.create);
  if (
    storedClaim.claim.id !== prepared.create.id
    || storedClaim.claim.proofBundleId !== prepared.create.proofBundleId
  ) {
    throw new Error("PAYO returned a different durable worker claim.");
  }

  input.onStage?.("proving");
  const requestId = generateUuidV7();
  const encryptedWitness = encryptVaultRecord({
    exceptionCircuitProfile: "wage_claim_v6",
    circuitInput: prepared.build.circuitInputs,
  }, {
    schemaVersion: 1,
    organizationId: prepared.create.organizationId,
    recordType: "payroll-proof-request",
    recordId: requestId,
    revision: 1,
  }, [input.principal]);
  const proof = await input.client.proveExceptionRemotely({
    proverBaseUrl: input.proverBaseUrl,
    encryptedWitness,
    principal: input.principal,
    claimAccessGrantId: prepared.create.claimAccessGrantId,
  });
  if (proof.profile !== "wage_claim_v6") {
    throw new Error("The prover returned a different exception profile.");
  }

  input.onStage?.("persisting_proof");
  const proofBundle = prepareEncryptedExceptionProofBundle({
    id: prepared.create.proofBundleId,
    organizationId: prepared.create.organizationId,
    runId: prepared.create.runId,
    revision: 1,
    proof,
    subjectRecordId: prepared.create.id,
    principals: prepared.proofRecipients,
  });
  await input.client.storeEncryptedProofBundle(proofBundle);

  input.onStage?.("authorizing");
  const authorization = await input.client.enqueueExceptionAuthorization({
    proofBundleId: prepared.create.proofBundleId,
    proofCalldata: proof.proof.proofCalldata,
  });
  return {
    claim: storedClaim.claim,
    proof: proof as ExceptionProofWorkerSuccess,
    proofBundle,
    authorization: authorization.authorization,
  };
}
