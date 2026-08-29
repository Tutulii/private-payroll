import { advancedPlanProofCommitment } from "@/lib/proof/advanced-plan-commitment";
import {
  buildPayrollAgreementSnapshot,
  type PayrollIntegrityLineInput,
} from "@/lib/proof/input-builder";
import { buildObligationSnapshotPlanInputs } from "@/lib/proof/exception-input-builder";
import {
  obligationClaimAccessPrivateSchema,
  obligationSnapshotPlanCreateSchema,
  obligationSnapshotPlanPrivateSchema,
  type ObligationClaimAccessPrivate,
  type ObligationClaimAccessGrantSummary,
  type ObligationSnapshotPlanCreate,
  type ObligationSnapshotPlanPrivate,
  type ObligationSnapshotPlanPublic,
  type ObligationSnapshotPlanSummary,
} from "@/lib/domain/obligation-snapshot-plan";
import { claimCapabilityCommitmentV2 } from "@/lib/domain/exception-protocol";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  hashRecipientCommitment,
  hashTextCommitment,
} from "@/lib/crypto/commitments";
import { deriveClaimCapabilitySecret } from "@/lib/crypto/claim-capability";
import { toHex } from "@/lib/crypto/encoding";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { calculatePayrollLine } from "@/lib/domain/payroll";
import { createProofCommitter } from "@/lib/proof/commitments";
import { resolvePayrollPolicyCohort } from "@/lib/policy/execution-catalog";
import { PayoApiError, type PayoClient } from "./payo-client";
import {
  buildPayrollExecutionLines,
  payrollAgreementDueAt,
  type PayrollExecutionObligation,
} from "./payroll-execution";
import { recordProofScheduleCommitment } from "./agreement-directory";

const DEFAULT_GRACE_SECONDS = 15 * 60;
const DEFAULT_CLAIM_WINDOW_SECONDS = 90 * 24 * 60 * 60;
const MAX_GRACE_SECONDS = 30 * 24 * 60 * 60;
const MAX_CLAIM_WINDOW_SECONDS = 366 * 24 * 60 * 60;

export type PreparedObligationSnapshotPlan = {
  create: ObligationSnapshotPlanCreate;
  privatePlan: ObligationSnapshotPlanPrivate;
  claimAccess: Array<{ record: ObligationClaimAccessPrivate; envelope: ObligationSnapshotPlanCreate["claimAccessGrants"][number]["envelope"] }>;
  lines: PayrollIntegrityLineInput[];
};

export type OpenedObligationClaimAccess = {
  access: ObligationClaimAccessPrivate;
  claimCapabilitySecret: `0x${string}`;
};

/**
 * Opens one worker-only claim packet and independently reconstructs every
 * commitment needed by Claim v6. The API routing record is not treated as a
 * proof of correctness: ciphertext, capability, agreement leaf and both
 * Merkle openings must all agree with the immutable public snapshot.
 */
export async function openObligationClaimAccess(input: {
  grant: ObligationClaimAccessGrantSummary;
  principal: VaultPrincipalKeyPair;
}): Promise<OpenedObligationClaimAccess> {
  if (
    input.grant.claimantPrincipalId !== input.principal.principalId
    || input.grant.revokedAt !== null
    || input.grant.envelope.aad.organizationId !== input.grant.plan.organizationId
    || input.grant.envelope.aad.recordType !== "obligation-claim-access"
    || input.grant.envelope.aad.recordId !== input.grant.id
    || input.grant.envelope.aad.revision !== 1
  ) throw new Error("This worker claim-access route is invalid or revoked.");

  const access = obligationClaimAccessPrivateSchema.parse(
    decryptVaultRecord(input.grant.envelope, input.principal),
  );
  const plan = input.grant.plan;
  const publicBindingsMatch = access.grantId === input.grant.id
    && access.snapshotPlanId === plan.id
    && access.runId === plan.runId
    && access.organizationId === plan.organizationId
    && access.cycleId === plan.cycleId
    && access.payrollRevision === plan.revision
    && BigInt(access.snapshotCommitment) === BigInt(plan.snapshotFact)
    && BigInt(access.snapshot.runNullifier) === BigInt(plan.runNullifier)
    && BigInt(access.snapshot.baseAgreementRoot) === BigInt(plan.agreementRoot)
    && BigInt(access.snapshot.obligationRoot) === BigInt(plan.claimRoot)
    && BigInt(access.snapshot.policyRoot) === BigInt(plan.policyRoot)
    && BigInt(access.snapshot.ownerAddress) === BigInt(plan.ownerAddress)
    && Number(access.snapshot.dueAt) * 1_000 === new Date(plan.dueAt).getTime()
    && Number(access.snapshot.graceEndsAt) * 1_000 === new Date(plan.graceEndsAt).getTime()
    && Number(access.snapshot.claimEndsAt) * 1_000 === new Date(plan.claimEndsAt).getTime();
  if (!publicBindingsMatch) {
    throw new Error("The worker claim packet does not match its immutable public snapshot.");
  }

  const secret = deriveClaimCapabilitySecret(input.principal);
  if (BigInt(claimCapabilityCommitmentV2(secret)) !== BigInt(access.binding.claimCapabilityCommitment)) {
    throw new Error("This vault does not control the worker claim capability committed before payday.");
  }

  const witness = access.witness;
  const calculated = calculatePayrollLine(witness.calculated);
  if (hashCanonicalJson(calculated) !== hashCanonicalJson(witness.calculated)) {
    throw new Error("The worker claim packet contains inconsistent payroll arithmetic.");
  }
  const agreement = witness.agreement;
  const earningsCount = Number(agreement.earnings_count);
  const classificationDeclared = Number(agreement.classification_declared);
  if (classificationDeclared !== 1 && classificationDeclared !== 2) {
    throw new Error("The worker claim packet contains an invalid classification.");
  }
  const idCommitment = toHex(hashTextCommitment("PAYO_AGREEMENT_ID_V1", witness.agreementId));
  const committer = await createProofCommitter();
  const agreementLeaf = committer.proofAgreementCommitment({
    agreementIdCommitment: idCommitment,
    recipientCommitment: toHex(Uint8Array.from(agreement.recipient_commitment)),
    earningsAtomic: agreement.earnings.slice(0, earningsCount),
    token: agreement.token === "0" ? "STRK" : "USDC",
    policyCommitment: toHex(Uint8Array.from(agreement.policy_commitment)),
    scheduleCommitment: toHex(Uint8Array.from(agreement.schedule_commitment)),
    dueAt: BigInt(agreement.due_at),
    validUntil: BigInt(agreement.valid_until),
    classificationDeclared,
    classificationScore: Number(agreement.classification_score),
    classificationEmployeeThreshold: Number(agreement.classification_employee_threshold),
    finalPayMode: agreement.final_pay_mode,
    finalRequiredMask: Number(agreement.final_required_mask),
    finalComponentsAtomic: agreement.final_components,
    fxFloorAtomic: agreement.fx_floor_atomic,
    referenceCurrency: agreement.reference_currency === "0" ? "USD" : "GBP",
    salt: toHex(Uint8Array.from(agreement.salt)),
  });
  const claimLeaf = committer.proofClaimObligationCommitment({
    agreementLeaf,
    claimCapabilityCommitment: access.binding.claimCapabilityCommitment,
    expectedNetAtomic: witness.expectedNetAtomic,
  });
  const merkleRoot = (
    leaf: string,
    membership: typeof witness.agreementMembership,
  ) => membership.siblings.reduce((current, sibling, level) => membership.path_bits[level]
    ? committer.proofMerkleNode(sibling, current)
    : committer.proofMerkleNode(current, sibling), leaf as `0x${string}`);
  const privateBindingsMatch = witness.agreementId === access.binding.agreementId
    && witness.calculated.agreementId === access.binding.agreementId
    && BigInt(idCommitment) === BigInt(toHex(Uint8Array.from(agreement.id_commitment)))
    && BigInt(agreementLeaf) === BigInt(witness.agreementLeaf)
    && BigInt(claimLeaf) === BigInt(witness.claimLeaf)
    && BigInt(witness.expectedNetAtomic) === BigInt(witness.calculated.netAtomic)
    && BigInt(toHex(Uint8Array.from(agreement.recipient_commitment)))
      === BigInt(access.binding.recipientCommitment)
    && (access.recipientSalt === undefined
      || BigInt(toHex(hashRecipientCommitment(
        witness.calculated.recipientAddress,
        access.recipientSalt,
      ))) === BigInt(access.binding.recipientCommitment))
    && BigInt(toHex(Uint8Array.from(agreement.schedule_commitment)))
      === BigInt(access.binding.scheduleCommitment)
    && BigInt(merkleRoot(agreementLeaf, witness.agreementMembership))
      === BigInt(access.snapshot.baseAgreementRoot)
    && BigInt(merkleRoot(claimLeaf, witness.claimMembership))
      === BigInt(access.snapshot.obligationRoot);
  if (!privateBindingsMatch) {
    throw new Error("The worker claim packet failed its agreement or Merkle binding checks.");
  }
  return { access, claimCapabilitySecret: secret };
}

/**
 * A snapshot cycle is a concrete payday, not merely an agreement identity.
 * The proof-schedule commitment changes when a recurring/checkpoint plan
 * advances, preventing a later period from colliding with an older snapshot.
 */
export function deriveObligationSnapshotCycleId(
  organizationId: string,
  obligations: readonly PayrollExecutionObligation[],
): string {
  return `snapshot:${hashCanonicalJson({
    domain: "PAYO_OBLIGATION_SNAPSHOT_CYCLE_V1",
    organizationId,
    obligations: obligations.map(({ agreement }) => ({
      agreementId: agreement.agreement.id,
      agreementRevision: agreement.revision,
      scheduleCommitment: recordProofScheduleCommitment(agreement),
      dueAt: payrollAgreementDueAt(agreement).toString(),
    })).sort((left, right) => left.agreementId.localeCompare(right.agreementId)),
  }).slice(2, 50)}`;
}

function unixSeconds(value: string): bigint {
  const milliseconds = new Date(value).getTime();
  if (!Number.isSafeInteger(milliseconds)) throw new Error("Snapshot plan contains an invalid date.");
  return BigInt(Math.floor(milliseconds / 1_000));
}

/** Opens a durable plan only after matching every public and directory binding. */
export function openObligationSnapshotPlan(input: {
  plan: ObligationSnapshotPlanPublic;
  principal: VaultPrincipalKeyPair;
  organizationId: string;
  ownerAddress: string;
  obligations: readonly PayrollExecutionObligation[];
}): ObligationSnapshotPlanPrivate {
  const privatePlan = obligationSnapshotPlanPrivateSchema.parse(
    decryptVaultRecord(input.plan.envelope, input.principal),
  );
  const cycleId = deriveObligationSnapshotCycleId(input.organizationId, input.obligations);
  const selectedByAgreement = new Map(input.obligations.map(({ agreement, payee }) => [
    agreement.agreement.id,
    { agreement, payee },
  ]));
  const publicBindingsMatch = input.plan.organizationId === input.organizationId
    && privatePlan.organizationId === input.organizationId
    && privatePlan.planId === input.plan.id
    && privatePlan.runId === input.plan.runId
    && privatePlan.cycleId === cycleId
    && input.plan.cycleId === cycleId
    && privatePlan.payrollRevision === input.plan.revision
    && BigInt(privatePlan.snapshot.ownerAddress) === BigInt(input.ownerAddress)
    && BigInt(input.plan.ownerAddress) === BigInt(input.ownerAddress)
    && BigInt(privatePlan.snapshot.baseAgreementRoot) === BigInt(input.plan.agreementRoot)
    && BigInt(privatePlan.snapshot.obligationRoot) === BigInt(input.plan.claimRoot)
    && BigInt(privatePlan.snapshot.policyRoot) === BigInt(input.plan.policyRoot)
    && BigInt(privatePlan.snapshot.runNullifier) === BigInt(input.plan.runNullifier)
    && BigInt(privatePlan.snapshotCommitment) === BigInt(input.plan.snapshotFact)
    && BigInt(privatePlan.snapshot.dueAt) === unixSeconds(input.plan.dueAt)
    && BigInt(privatePlan.snapshot.graceEndsAt) === unixSeconds(input.plan.graceEndsAt)
    && BigInt(privatePlan.snapshot.claimEndsAt) === unixSeconds(input.plan.claimEndsAt);
  const directoryBindingsMatch = privatePlan.agreementBindings.length === selectedByAgreement.size
    && privatePlan.agreementBindings.every((binding) => {
      const selected = selectedByAgreement.get(binding.agreementId);
      return Boolean(selected)
        && binding.payeeId === selected!.payee.id
        && (binding.claimantPrincipalId === undefined
          || binding.claimantPrincipalId === selected!.payee.claimIdentityPrincipalId)
        && (binding.claimantPublicKey === undefined
          || binding.claimantPublicKey === selected!.payee.claimIdentityPublicKey)
        && BigInt(binding.agreementCommitment) === BigInt(selected!.agreement.agreementCommitment)
        && BigInt(binding.recipientCommitment) === BigInt(selected!.agreement.recipientCommitment)
        && BigInt(binding.scheduleCommitment) === BigInt(recordProofScheduleCommitment(selected!.agreement))
        && BigInt(binding.claimCapabilityCommitment)
          === BigInt(selected!.agreement.claimCapabilityCommitment ?? "0x0");
    });
  if (!publicBindingsMatch || !directoryBindingsMatch) {
    throw new Error("The durable snapshot does not match this exact encrypted payday and Ready owner.");
  }
  return privatePlan;
}

/** Resolves the one canonical registered snapshot for an exact due selection. */
export async function loadRegisteredObligationSnapshotPlan(input: {
  client: Pick<PayoClient, "findRegisteredObligationSnapshotPlan">;
  principal: VaultPrincipalKeyPair;
  organizationId: string;
  ownerAddress: string;
  agreementRoot: `0x${string}`;
  obligations: readonly PayrollExecutionObligation[];
}): Promise<ObligationSnapshotPlanPrivate> {
  const cycleId = deriveObligationSnapshotCycleId(input.organizationId, input.obligations);
  const { plan } = await input.client.findRegisteredObligationSnapshotPlan({
    organizationId: input.organizationId,
    cycleId,
    agreementRoot: input.agreementRoot,
  });
  if (plan.state !== "registered") {
    throw new Error("This exact pre-payday snapshot is not available for a new payroll.");
  }
  return openObligationSnapshotPlan({
    plan,
    principal: input.principal,
    organizationId: input.organizationId,
    ownerAddress: input.ownerAddress,
    obligations: input.obligations,
  });
}

/**
 * Prepares the encrypted fact that must be persisted and registered before
 * payday. It intentionally does not fetch FX or generate a proof.
 */
export async function prepareObligationSnapshotPlan(input: {
  organizationId: string;
  organizationSecret: string;
  ownerAddress: string;
  obligations: readonly PayrollExecutionObligation[];
  principal: VaultPrincipalKeyPair;
  revision?: number;
  gracePeriodSeconds?: number;
  claimWindowSeconds?: number;
  now?: Date;
}): Promise<PreparedObligationSnapshotPlan> {
  if (input.obligations.length < 1 || input.obligations.length > 50) {
    throw new Error("A pre-payday snapshot requires 1–50 obligations.");
  }
  if (input.obligations.some(({ agreement }) => agreement.agreement.agreementVersion !== "payo-agreement-v2")) {
    throw new Error(
      "Pre-payday claim protection requires advanced PAYO v2 agreements; legacy payrolls remain legacy app-bound evidence.",
    );
  }
  const revision = input.revision ?? 1;
  if (!Number.isInteger(revision) || revision < 1 || revision >= 2 ** 32) {
    throw new Error("Snapshot payroll revision must be a positive u32.");
  }
  const gracePeriodSeconds = input.gracePeriodSeconds ?? DEFAULT_GRACE_SECONDS;
  const claimWindowSeconds = input.claimWindowSeconds ?? DEFAULT_CLAIM_WINDOW_SECONDS;
  if (
    !Number.isSafeInteger(gracePeriodSeconds)
    || gracePeriodSeconds < 60
    || gracePeriodSeconds > MAX_GRACE_SECONDS
  ) throw new Error("Snapshot grace period must be between one minute and 30 days.");
  if (
    !Number.isSafeInteger(claimWindowSeconds)
    || claimWindowSeconds <= gracePeriodSeconds
    || claimWindowSeconds > MAX_CLAIM_WINDOW_SECONDS
  ) throw new Error("Snapshot claim window must follow grace and be no longer than 366 days.");

  const dueAt = payrollAgreementDueAt(input.obligations[0].agreement);
  if (input.obligations.some(({ agreement }) => payrollAgreementDueAt(agreement) !== dueAt)) {
    throw new Error("One snapshot can contain only agreements sharing one exact payday.");
  }
  const now = input.now ?? new Date();
  const nowUnix = BigInt(Math.floor(now.getTime() / 1_000));
  if (dueAt <= nowUnix + 120n) {
    throw new Error("Prepare and register this snapshot at least two minutes before payday.");
  }
  const dueDate = new Date(Number(dueAt) * 1_000);
  const cycleId = deriveObligationSnapshotCycleId(input.organizationId, input.obligations);
  const policies = resolvePayrollPolicyCohort(
    input.obligations.map(({ agreement }) => agreement.agreement),
    dueDate,
  );
  const advancedScheduleCommitments = new Map<string, `0x${string}`>(await Promise.all(
    input.obligations.flatMap(({ agreement }) => agreement.agreement.agreementVersion === "payo-agreement-v2"
      ? [advancedPlanProofCommitment(agreement.agreement).then((commitment) => [agreement.agreement.id, commitment] as const)]
      : []),
  ));
  const lines = buildPayrollExecutionLines({
    organizationId: input.organizationId,
    obligations: input.obligations,
    validityStart: dueAt,
    createLineSalt: () => `0x${"00".repeat(32)}`,
    advancedScheduleCommitments,
  });
  const payroll = await buildPayrollAgreementSnapshot({
    organizationSecret: input.organizationSecret,
    cycleId,
    revision,
    policies,
    lines,
  });
  const capabilityCommitments = Object.fromEntries(input.obligations.map(({ agreement, payee }) => {
    const agreementCapability = agreement.claimCapabilityCommitment;
    const payeeCapability = payee.claimCapabilityCommitment;
    if (!agreementCapability || !payeeCapability || BigInt(agreementCapability) !== BigInt(payeeCapability)) {
      throw new Error(`Agreement ${agreement.agreement.id} has no matching worker claim identity.`);
    }
    return [agreement.agreement.id, agreementCapability];
  }));
  const snapshotBuild = await buildObligationSnapshotPlanInputs({
    ownerAddress: input.ownerAddress,
    payroll,
    claimCapabilityCommitments: capabilityCommitments,
    graceEndsAt: dueAt + BigInt(gracePeriodSeconds),
    claimEndsAt: dueAt + BigInt(claimWindowSeconds),
  });
  const byAgreement = new Map(input.obligations.map((obligation) => [
    obligation.agreement.agreement.id,
    obligation,
  ]));
  const planId = generateUuidV7(now.getTime());
  const runId = generateUuidV7(now.getTime() + 1);
  const claimAccessGrantIds = snapshotBuild.lines.map((_, index) =>
    generateUuidV7(now.getTime() + 2 + index),
  );
  const agreementBindings = snapshotBuild.lines.map((line, index) => {
    const obligation = byAgreement.get(line.agreementId);
    if (!obligation) throw new Error(`Snapshot lost agreement ${line.agreementId} while sorting.`);
    return {
      agreementId: line.agreementId,
      payeeId: obligation.payee.id,
      claimAccessGrantId: claimAccessGrantIds[index],
      claimantPrincipalId: obligation.payee.claimIdentityPrincipalId,
      claimantPublicKey: obligation.payee.claimIdentityPublicKey,
      agreementCommitment: obligation.agreement.agreementCommitment as `0x${string}`,
      recipientCommitment: obligation.agreement.recipientCommitment as `0x${string}`,
      scheduleCommitment: line.calculated.scheduleCommitment as `0x${string}`,
      claimCapabilityCommitment: line.claimCapabilityCommitment,
    };
  });
  const privatePlan = obligationSnapshotPlanPrivateSchema.parse({
    format: "payo-obligation-snapshot-plan-v1",
    planId,
    runId,
    organizationId: input.organizationId,
    cycleId,
    payrollRevision: revision,
    snapshot: snapshotBuild.snapshot,
    snapshotCommitment: snapshotBuild.snapshotCommitment,
    agreementBindings,
    claimWitness: {
      claimRoot: snapshotBuild.claimRoot,
      lines: snapshotBuild.lines,
    },
    createdAt: now.toISOString(),
  });
  const claimAccess = snapshotBuild.lines.map((line, index) => {
    const obligation = byAgreement.get(line.agreementId);
    const binding = agreementBindings[index];
    if (!obligation || !binding || binding.agreementId !== line.agreementId) {
      throw new Error("Snapshot claim access lost its ordered agreement binding.");
    }
    const claimantPrincipalId = obligation.payee.claimIdentityPrincipalId;
    const claimantPublicKey = obligation.payee.claimIdentityPublicKey;
    if (!claimantPrincipalId || !claimantPublicKey) {
      throw new Error("Agreement " + line.agreementId + " has no worker claim encryption identity.");
    }
    const grantId = binding.claimAccessGrantId;
    if (!grantId) throw new Error("Snapshot lost its worker claim-access identifier.");
    const record = obligationClaimAccessPrivateSchema.parse({
      format: "payo-obligation-claim-access-v1",
      grantId,
      snapshotPlanId: planId,
      runId,
      organizationId: input.organizationId,
      cycleId,
      payrollRevision: revision,
      snapshot: snapshotBuild.snapshot,
      snapshotCommitment: snapshotBuild.snapshotCommitment,
      recipientSalt: obligation.agreement.recipientSalt,
      binding,
      witness: line,
      issuerPrincipal: {
        principalId: input.principal.principalId,
        publicKey: input.principal.publicKey,
      },
      createdAt: now.toISOString(),
    });
    const envelope = encryptVaultRecord(record, {
      schemaVersion: 1,
      organizationId: input.organizationId,
      recordType: "obligation-claim-access",
      recordId: grantId,
      revision: 1,
    }, [{
      principalId: claimantPrincipalId,
      publicKey: claimantPublicKey,
    }]);
    return { record, envelope };
  });
  const envelope = encryptVaultRecord(privatePlan, {
    schemaVersion: 1,
    organizationId: input.organizationId,
    recordType: "obligation-snapshot-plan",
    recordId: planId,
    revision: 1,
  }, [input.principal]);
  const create = obligationSnapshotPlanCreateSchema.parse({
    id: planId,
    runId,
    organizationId: input.organizationId,
    cycleId,
    payrollRevision: revision,
    ownerAddress: input.ownerAddress,
    snapshot: snapshotBuild.snapshot,
    snapshotCommitment: snapshotBuild.snapshotCommitment,
    claimAccessGrants: claimAccess.map(({ record, envelope: accessEnvelope }) => ({
      id: record.grantId,
      claimantPrincipalId: accessEnvelope.wrappedKeys[0]!.principalId,
      envelope: accessEnvelope,
    })),
    envelope,
  });
  return { create, privatePlan, claimAccess, lines };
}

export async function createDurableObligationSnapshotPlan(input: Parameters<
  typeof prepareObligationSnapshotPlan
>[0] & { client: Pick<PayoClient, "createObligationSnapshotPlan"> }) {
  const { client, ...preparation } = input;
  const prepared = await prepareObligationSnapshotPlan(preparation);
  const response = await client.createObligationSnapshotPlan(prepared.create);
  if (response.plan.id !== prepared.create.id || response.plan.runId !== prepared.create.runId) {
    throw new Error("PAYO returned a different snapshot-plan reservation.");
  }
  return { ...prepared, stored: response.plan };
}

export type SnapshotRegistrationPlan = Pick<
  ObligationSnapshotPlanSummary,
  "id" | "state" | "registrationTransactionHash"
> & {
  snapshot: ObligationSnapshotPlanCreate["snapshot"];
  snapshotCommitment: string;
};

/**
 * Completes the durable registration state machine. It always checks canonical
 * state before opening Ready, allowing recovery if the browser closed after a
 * successful transaction but before PAYO recorded its hash.
 */
export async function registerDurableObligationSnapshotPlan(input: {
  client: Pick<
    PayoClient,
    "recordObligationSnapshotSubmission" | "reconcileObligationSnapshotPlan"
  >;
  plan: SnapshotRegistrationPlan;
  ensureAgreementRoot: (agreementRoot: string) => Promise<void>;
  registerSnapshot: (input: {
    snapshot: ObligationSnapshotPlanCreate["snapshot"];
    snapshotCommitment: string;
  }) => Promise<string>;
}) {
  if (input.plan.state === "registered" || input.plan.state === "consumed") {
    return { plan: input.plan, recovered: true as const };
  }

  try {
    const canonical = await input.client.reconcileObligationSnapshotPlan(input.plan.id);
    return { ...canonical, recovered: true as const };
  } catch (error) {
    if (!(error instanceof PayoApiError) || error.code !== "SNAPSHOT_NOT_REGISTERED") {
      throw error;
    }
  }

  // A submitted plan has a durable transaction identity. Never open a second
  // wallet request while its canonical result is unresolved.
  if (input.plan.state === "submitted" || input.plan.registrationTransactionHash) {
    throw new Error(
      "The snapshot transaction is recorded but not finalized on the configured seal. Retry reconciliation; do not submit it again.",
    );
  }
  if (input.plan.state !== "prepared") {
    throw new Error(`Snapshot plan ${input.plan.id} cannot be registered from state ${input.plan.state}.`);
  }

  await input.ensureAgreementRoot(input.plan.snapshot.baseAgreementRoot);
  const transactionHash = await input.registerSnapshot({
    snapshot: input.plan.snapshot,
    snapshotCommitment: input.plan.snapshotCommitment,
  });
  await input.client.recordObligationSnapshotSubmission({
    planId: input.plan.id,
    transactionHash,
  });
  const canonical = await input.client.reconcileObligationSnapshotPlan(input.plan.id);
  return { ...canonical, transactionHash, recovered: false as const };
}
