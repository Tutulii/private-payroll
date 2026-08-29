import {
  employerStatementCreateSchema,
  employerStatementPrivateSchema,
  payrollStatementEvidencePrivateSchema,
  type EmployerStatementCreate,
  type EmployerStatementSummary,
  type PayrollStatementEvidenceGrantSummary,
  type PayrollStatementEvidencePrivate,
} from "@/lib/domain/employer-statement";
import {
  payrollStatementCommitmentV2,
  type PayrollStatementV2,
} from "@/lib/domain/exception-protocol";
import {
  obligationSnapshotPlanPrivateSchema,
  type ObligationClaimAccessPrivate,
  type ObligationSnapshotPlanPrivate,
  type ObligationSnapshotPlanPublic,
} from "@/lib/domain/obligation-snapshot-plan";
import { fxSnapshotCommitment, type FxSnapshot } from "@/lib/domain/fx";
import { calculatePayrollLine } from "@/lib/domain/payroll";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  encryptedVaultRecordSchema,
  type VaultPrincipal,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import { normalizedHexBytes, toHex } from "@/lib/crypto/encoding";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  buildPayrollIntegrityInputsFromSerialized,
  type SerializedPayrollIntegrityBuildRequest,
} from "@/lib/proof/input-builder";
import {
  createProofCommitter,
  PAYO_PROOF_EMPTY_LEAF,
} from "@/lib/proof/commitments";
import { PayoApiError, type PayoClient } from "./payo-client";

const ZERO = "0x" + "00".repeat(32);

export type EmployerStatementLineInput = {
  agreementId: string;
  target: {
    kind: "empty";
  } | {
    kind: "line";
    deductionsAtomic: string[];
    lineSalt: string;
    classificationTreatment: 1 | 2;
    finalIncludedMask: number;
    referenceValueAtomic: string;
  };
};

export type PreparedEmployerStatement = {
  create: EmployerStatementCreate;
  privateStatement: ReturnType<typeof employerStatementPrivateSchema.parse>;
  evidence: PayrollStatementEvidencePrivate[];
  profile: "base" | "fx";
};

type EmployerStatementPreparationClient = Pick<
  PayoClient,
  | "createEmployerStatement"
  | "getEmployerStatement"
  | "getObligationSnapshotPlan"
  | "getPayrollRun"
  | "listEmployerStatements"
>;

export type DurablePayrollEmployerStatement = {
  stored: EmployerStatementSummary;
  statement: PayrollStatementV2;
  statementCommitment: string;
  recovered: boolean;
};

function commitment(value: string, label: string) {
  try {
    return toHex(normalizedHexBytes(value, 32));
  } catch {
    throw new Error(label + " must be a canonical 32-byte commitment.");
  }
}

function decimalAmount(value: string, label: string): string {
  if (!/^(0|[1-9][0-9]*)$/.test(value) || BigInt(value) >= 1n << 128n) {
    throw new Error(label + " must fit in u128.");
  }
  return value;
}

function statementTargetLeaf(input: {
  line: EmployerStatementLineInput;
  snapshotLine: ObligationSnapshotPlanPrivate["claimWitness"]["lines"][number];
  committer: Awaited<ReturnType<typeof createProofCommitter>>;
}) {
  if (input.line.target.kind === "empty") {
    return {
      target: { kind: "empty" as const },
      leaf: PAYO_PROOF_EMPTY_LEAF,
    };
  }
  const target = input.line.target;
  if (target.deductionsAtomic.length > 8) {
    throw new Error("An employer statement line supports at most eight deductions.");
  }
  target.deductionsAtomic.forEach((amount) =>
    decimalAmount(amount, "Statement deduction"),
  );
  decimalAmount(target.referenceValueAtomic, "Statement reference value");
  if (
    !Number.isInteger(target.finalIncludedMask)
    || target.finalIncludedMask < 0
    || target.finalIncludedMask > 31
  ) {
    throw new Error("Statement final-pay mask must fit in five bits.");
  }
  const original = input.snapshotLine.calculated;
  const calculated = calculatePayrollLine({
    agreementId: original.agreementId,
    recipientAddress: original.recipientAddress,
    token: original.token,
    earningsAtomic: original.earningsAtomic,
    deductionsAtomic: target.deductionsAtomic,
    committedPolicyId: original.committedPolicyId,
    scheduleCommitment: original.scheduleCommitment,
    salt: commitment(target.lineSalt, "Statement line salt"),
  });
  return {
    target: {
      ...target,
      lineSalt: commitment(target.lineSalt, "Statement line salt"),
    },
    leaf: input.committer.proofPayrollCommitment(
      calculated,
      input.snapshotLine.agreementLeaf,
      {
        classificationTreatment: target.classificationTreatment,
        finalIncludedMask: target.finalIncludedMask,
        referenceValueAtomic: target.referenceValueAtomic,
      },
    ),
  };
}

function assertExactSnapshotBindings(input: {
  snapshotPlan: ObligationSnapshotPlanPrivate;
  lines: readonly EmployerStatementLineInput[];
}) {
  const { snapshotPlan } = input;
  if (
    snapshotPlan.claimWitness.lines.length !== snapshotPlan.agreementBindings.length
    || snapshotPlan.claimWitness.lines.length !== input.lines.length
  ) {
    throw new Error(
      "Employer statement lines must cover every immutable snapshot slot exactly once.",
    );
  }
  const provided = new Map(input.lines.map((line) => [line.agreementId, line]));
  if (
    provided.size !== input.lines.length
    || snapshotPlan.claimWitness.lines.some((line) => !provided.has(line.agreementId))
  ) {
    throw new Error(
      "Employer statement lines must match every immutable agreement exactly once.",
    );
  }
  for (const [index, witness] of snapshotPlan.claimWitness.lines.entries()) {
    const binding = snapshotPlan.agreementBindings[index];
    if (
      !binding
      || binding.agreementId !== witness.agreementId
      || binding.claimAccessGrantId === undefined
      || binding.claimantPrincipalId === undefined
      || binding.claimantPublicKey === undefined
    ) {
      throw new Error(
        "This snapshot predates worker-scoped statement evidence; prepare a new protected payday.",
      );
    }
  }
}

export async function prepareEmployerStatements(input: {
  snapshotPlan: ObligationSnapshotPlanPrivate;
  lines: readonly EmployerStatementLineInput[];
  fxSnapshots?: readonly FxSnapshot[];
  principal: VaultPrincipalKeyPair;
  employerRecipients?: readonly VaultPrincipal[];
  now?: Date;
}): Promise<PreparedEmployerStatement[]> {
  assertExactSnapshotBindings(input);
  const now = input.now ?? new Date();
  const observedAt = BigInt(Math.floor(now.getTime() / 1_000));
  if (observedAt < BigInt(input.snapshotPlan.snapshot.dueAt)) {
    throw new Error("Employer evidence cannot be prepared before the committed payday.");
  }
  if (observedAt > BigInt(input.snapshotPlan.snapshot.claimEndsAt)) {
    throw new Error("Employer evidence is outside the committed claim window.");
  }
  const recipients = input.employerRecipients ?? [input.principal];
  if (
    recipients.length < 1
    || !recipients.some(({ principalId }) => principalId === input.principal.principalId)
    || new Set(recipients.map(({ principalId }) => principalId)).size !== recipients.length
  ) {
    throw new Error(
      "Employer statement recipients must be unique and include the issuing principal.",
    );
  }
  const fxSnapshots = [...(input.fxSnapshots ?? [])];
  if (fxSnapshots.length > 2) {
    throw new Error("An employer statement supports at most two FX snapshots.");
  }

  const committer = await createProofCommitter();
  const inputByAgreement = new Map(
    input.lines.map((line) => [line.agreementId, line]),
  );
  const preparedTargets = input.snapshotPlan.claimWitness.lines.map(
    (snapshotLine) => statementTargetLeaf({
      line: inputByAgreement.get(snapshotLine.agreementId)!,
      snapshotLine,
      committer,
    }),
  );
  const manifestLeaves = preparedTargets.map(({ leaf }) => leaf);
  const manifest = committer.buildProofFixedMerkleRoot(manifestLeaves);
  const manifestOpenings = preparedTargets.map((_, index) =>
    committer.buildProofFixedMerkleMembership(manifestLeaves, index),
  );
  const fxRoot = fxSnapshots.length
    ? committer.buildProofCatalog(fxSnapshots.map(fxSnapshotCommitment)).root
    : commitment(ZERO, "Zero FX root");
  const profiles: Array<{
    profile: "base" | "fx";
    fxRoot: ReturnType<typeof commitment>;
  }> = [
    { profile: "base", fxRoot: commitment(ZERO, "Zero FX root") },
    ...(fxSnapshots.length
      ? [{ profile: "fx" as const, fxRoot }]
      : []),
  ];
  const createdAt = now.toISOString();
  const prepared: PreparedEmployerStatement[] = [];

  for (const [profileIndex, profile] of profiles.entries()) {
    const statementId = generateUuidV7(
      now.getTime() + profileIndex * (input.lines.length + 2),
    );
    const statement: PayrollStatementV2 = {
      schemaVersion: 2,
      runNullifier: input.snapshotPlan.snapshot.runNullifier,
      snapshotCommitment: input.snapshotPlan.snapshotCommitment,
      manifestRoot: manifest,
      fxRoot: profile.fxRoot,
      availabilityCommitment: manifest,
      observedAt: observedAt.toString(),
      source: "employer_statement",
    };
    const statementCommitment = payrollStatementCommitmentV2(statement);
    const evidence = input.snapshotPlan.claimWitness.lines.map(
      (snapshotLine, index) => {
        const binding = input.snapshotPlan.agreementBindings[index]!;
        const evidenceId = generateUuidV7(
          now.getTime()
            + profileIndex * (input.lines.length + 2)
            + index
            + 1,
        );
        const opening = manifestOpenings[index]!;
        const selectedFxIndex = fxSnapshots.findIndex((snapshotFx) =>
          snapshotFx.baseToken === snapshotLine.calculated.token
          && snapshotFx.referenceCurrency
            === (snapshotLine.agreement.reference_currency === "0" ? "USD" : "GBP"),
        );
        const requiresFxEvidence =
          profile.profile === "fx"
          && BigInt(snapshotLine.agreement.fx_floor_atomic) > 0n;
        if (requiresFxEvidence && selectedFxIndex < 0) {
          throw new Error(
            "Employer FX evidence is missing the protected worker conversion snapshot.",
          );
        }
        return payrollStatementEvidencePrivateSchema.parse({
          format: "payo-payroll-statement-evidence-v1",
          schemaVersion: 1,
          id: evidenceId,
          statementId,
          claimAccessGrantId: binding.claimAccessGrantId!,
          snapshotPlanId: input.snapshotPlan.planId,
          organizationId: input.snapshotPlan.organizationId,
          runId: input.snapshotPlan.runId,
          agreementId: snapshotLine.agreementId,
          statement,
          statementCommitment,
          target: {
            ...preparedTargets[index]!.target,
            manifestRoot: manifest,
            manifestMembership: {
              siblings: opening.siblings.map((value) => BigInt(value).toString()),
              pathBits: opening.pathBits,
            },
          },
          fxSnapshots: profile.profile === "fx" ? fxSnapshots : [],
          ...(requiresFxEvidence ? { selectedFxIndex } : {}),
          issuerPrincipal: {
            principalId: input.principal.principalId,
            publicKey: input.principal.publicKey,
          },
          createdAt,
        });
      },
    );
    const privateStatement = employerStatementPrivateSchema.parse({
      format: "payo-employer-statement-v2",
      schemaVersion: 2,
      id: statementId,
      snapshotPlanId: input.snapshotPlan.planId,
      organizationId: input.snapshotPlan.organizationId,
      runId: input.snapshotPlan.runId,
      ownerAddress: input.snapshotPlan.snapshot.ownerAddress,
      statement,
      statementCommitment,
      evidenceGrantIds: evidence.map(({ id }) => id),
      createdAt,
    });
    const evidenceGrants = evidence.map((record, index) => {
      const binding = input.snapshotPlan.agreementBindings[index]!;
      const claimant: VaultPrincipal = {
        principalId: binding.claimantPrincipalId!,
        publicKey: binding.claimantPublicKey!,
      };
      return {
        id: record.id,
        claimAccessGrantId: record.claimAccessGrantId,
        claimantPrincipalId: claimant.principalId,
        envelope: encryptVaultRecord(record, {
          schemaVersion: 1,
          organizationId: input.snapshotPlan.organizationId,
          recordType: "payroll-statement-evidence",
          recordId: record.id,
          revision: 1,
        }, [claimant]),
      };
    });
    const envelope = encryptVaultRecord(privateStatement, {
      schemaVersion: 1,
      organizationId: input.snapshotPlan.organizationId,
      recordType: "employer-statement-v2",
      recordId: statementId,
      revision: 1,
    }, recipients);
    const create = employerStatementCreateSchema.parse({
      id: statementId,
      snapshotPlanId: input.snapshotPlan.planId,
      organizationId: input.snapshotPlan.organizationId,
      runId: input.snapshotPlan.runId,
      revision: 1,
      ownerAddress: input.snapshotPlan.snapshot.ownerAddress,
      statement,
      statementCommitment,
      evidenceGrants,
      envelope,
    });
    prepared.push({
      create,
      privateStatement,
      evidence,
      profile: profile.profile,
    });
  }

  return prepared;
}

function reconstructManifestRoot(input: {
  leaf: string;
  membership: PayrollStatementEvidencePrivate["target"]["manifestMembership"];
  committer: Awaited<ReturnType<typeof createProofCommitter>>;
}) {
  return input.membership.siblings.reduce(
    (current, sibling, level) => input.membership.pathBits[level]
      ? input.committer.proofMerkleNode(sibling, current)
      : input.committer.proofMerkleNode(current, sibling),
    commitment(input.leaf, "Statement target leaf"),
  );
}

export async function openPayrollStatementEvidence(input: {
  grant: PayrollStatementEvidenceGrantSummary;
  principal: VaultPrincipalKeyPair;
  claimAccess: ObligationClaimAccessPrivate;
}) {
  const { grant, principal, claimAccess } = input;
  if (
    grant.claimantPrincipalId !== principal.principalId
    || grant.revokedAt !== null
    || grant.statement.state !== "registered"
    || grant.claimAccessGrantId !== claimAccess.grantId
    || grant.envelope.aad.organizationId !== grant.statement.organizationId
    || grant.envelope.aad.recordType !== "payroll-statement-evidence"
    || grant.envelope.aad.recordId !== grant.id
    || grant.envelope.aad.revision !== 1
  ) {
    throw new Error("This registered worker statement-evidence route is invalid.");
  }
  const evidence = payrollStatementEvidencePrivateSchema.parse(
    decryptVaultRecord(grant.envelope, principal),
  );
  const publicBindingsMatch = evidence.id === grant.id
    && evidence.statementId === grant.statementId
    && evidence.claimAccessGrantId === grant.claimAccessGrantId
    && evidence.snapshotPlanId === claimAccess.snapshotPlanId
    && evidence.organizationId === grant.statement.organizationId
    && evidence.runId === grant.statement.runId
    && evidence.runId === claimAccess.runId
    && evidence.agreementId === claimAccess.binding.agreementId
    && BigInt(evidence.statementCommitment)
      === BigInt(grant.statement.statementFact)
    && BigInt(evidence.statement.manifestRoot)
      === BigInt(grant.statement.manifestRoot)
    && BigInt(evidence.statement.fxRoot) === BigInt(grant.statement.fxRoot)
    && BigInt(evidence.statement.availabilityCommitment)
      === BigInt(grant.statement.availabilityCommitment)
    && Number(evidence.statement.observedAt) * 1_000
      === new Date(grant.statement.observedAt).getTime()
    && BigInt(evidence.statement.snapshotCommitment)
      === BigInt(claimAccess.snapshotCommitment)
    && BigInt(evidence.statement.runNullifier)
      === BigInt(claimAccess.snapshot.runNullifier);
  if (!publicBindingsMatch) {
    throw new Error(
      "The encrypted worker statement evidence differs from registered public commitments.",
    );
  }

  const committer = await createProofCommitter();
  const target = statementTargetLeaf({
    line: {
      agreementId: evidence.agreementId,
      target: evidence.target.kind === "empty"
        ? { kind: "empty" }
        : {
            kind: "line",
            deductionsAtomic: evidence.target.deductionsAtomic,
            lineSalt: evidence.target.lineSalt,
            classificationTreatment: evidence.target.classificationTreatment,
            finalIncludedMask: evidence.target.finalIncludedMask,
            referenceValueAtomic: evidence.target.referenceValueAtomic,
          },
    },
    snapshotLine: claimAccess.witness,
    committer,
  });
  const root = reconstructManifestRoot({
    leaf: target.leaf,
    membership: evidence.target.manifestMembership,
    committer,
  });
  const expectedPath = evidence.target.manifestMembership.pathBits.every(
    (bit, level) => bit === Boolean((claimAccess.witness.index >> level) & 1),
  );
  if (
    !expectedPath
    || BigInt(root) !== BigInt(evidence.target.manifestRoot)
    || BigInt(root) !== BigInt(evidence.statement.manifestRoot)
  ) {
    throw new Error(
      "The worker statement line does not open the registered manifest slot.",
    );
  }
  const evidenceFxRoot = evidence.fxSnapshots.length
    ? committer.buildProofCatalog(
        evidence.fxSnapshots.map(fxSnapshotCommitment),
      ).root
    : ZERO;
  if (BigInt(evidenceFxRoot) !== BigInt(evidence.statement.fxRoot)) {
    throw new Error("The encrypted worker FX catalog differs from its statement.");
  }
  return evidence;
}


type PayrollRunForEmployerStatement = Awaited<
  ReturnType<PayoClient["getPayrollRun"]>
>["run"];

function assertSameCommitment(
  actual: string | null | undefined,
  expected: string,
  label: string,
) {
  if (!actual || BigInt(actual) !== BigInt(expected)) {
    throw new Error("The encrypted payroll and " + label + " do not match.");
  }
}

function dateUnixSeconds(value: string, label: string): bigint {
  const milliseconds = new Date(value).getTime();
  if (!Number.isSafeInteger(milliseconds)) {
    throw new Error(label + " contains an invalid timestamp.");
  }
  return BigInt(Math.floor(milliseconds / 1_000));
}

function openSnapshotPlanForPayroll(input: {
  plan: ObligationSnapshotPlanPublic;
  run: PayrollRunForEmployerStatement;
  principal: VaultPrincipalKeyPair;
}) {
  const privatePlan = obligationSnapshotPlanPrivateSchema.parse(
    decryptVaultRecord(input.plan.envelope, input.principal),
  );
  const plan = input.plan;
  const run = input.run;
  const publicBindingsMatch = ["registered", "consumed"].includes(plan.state)
    && privatePlan.planId === plan.id
    && privatePlan.runId === plan.runId
    && privatePlan.organizationId === plan.organizationId
    && privatePlan.cycleId === plan.cycleId
    && privatePlan.payrollRevision === plan.revision
    && BigInt(privatePlan.snapshot.ownerAddress) === BigInt(plan.ownerAddress)
    && BigInt(privatePlan.snapshot.baseAgreementRoot) === BigInt(plan.agreementRoot)
    && BigInt(privatePlan.snapshot.obligationRoot) === BigInt(plan.claimRoot)
    && BigInt(privatePlan.snapshot.policyRoot) === BigInt(plan.policyRoot)
    && BigInt(privatePlan.snapshot.runNullifier) === BigInt(plan.runNullifier)
    && BigInt(privatePlan.snapshotCommitment) === BigInt(plan.snapshotFact)
    && BigInt(privatePlan.snapshot.dueAt) === dateUnixSeconds(plan.dueAt, "Snapshot")
    && BigInt(privatePlan.snapshot.graceEndsAt)
      === dateUnixSeconds(plan.graceEndsAt, "Snapshot grace window")
    && BigInt(privatePlan.snapshot.claimEndsAt)
      === dateUnixSeconds(plan.claimEndsAt, "Snapshot claim window");
  const runBindingsMatch = run.id === plan.runId
    && run.organizationId === plan.organizationId
    && run.obligationSnapshotPlanId === plan.id
    && privatePlan.runId === run.id
    && privatePlan.organizationId === run.organizationId
    && BigInt(privatePlan.snapshot.baseAgreementRoot) === BigInt(run.agreementRoot ?? "0")
    && BigInt(privatePlan.snapshot.policyRoot) === BigInt(run.policyRoot ?? "0")
    && BigInt(privatePlan.snapshot.runNullifier) === BigInt(run.runNullifier ?? "0");
  if (!publicBindingsMatch || !runBindingsMatch) {
    throw new Error(
      "The employer-evidence snapshot does not match this exact confirmed payroll.",
    );
  }
  return privatePlan;
}

async function assertSnapshotWitnessesMatchPayroll(input: {
  snapshotPlan: ObligationSnapshotPlanPrivate;
  payroll: Awaited<ReturnType<typeof buildPayrollIntegrityInputsFromSerialized>>;
}) {
  const byAgreement = new Map(
    input.payroll.proofBindings.map((binding) => [binding.agreementId, binding]),
  );
  if (
    byAgreement.size !== input.payroll.proofBindings.length
    || input.snapshotPlan.claimWitness.lines.length !== byAgreement.size
  ) {
    throw new Error(
      "The confirmed payroll does not cover every immutable snapshot agreement exactly once.",
    );
  }
  const committer = await createProofCommitter();
  for (const witness of input.snapshotPlan.claimWitness.lines) {
    const binding = byAgreement.get(witness.agreementId);
    if (!binding) {
      throw new Error("The confirmed payroll omitted an immutable snapshot agreement.");
    }
    const expectedCalculated = {
      ...binding.calculated,
      salt: witness.calculated.salt,
    };
    const expectedClaimLeaf = committer.proofClaimObligationCommitment({
      agreementLeaf: binding.agreementLeaf,
      claimCapabilityCommitment: witness.claimCapabilityCommitment,
      expectedNetAtomic: witness.expectedNetAtomic,
    });
    const membershipPathMatches = (
      membership: typeof witness.agreementMembership,
    ) => membership.path_bits.every(
      (bit, level) => bit === Boolean((witness.index >> level) & 1),
    );
    const merkleRoot = (
      leaf: string,
      membership: typeof witness.agreementMembership,
    ) => membership.siblings.reduce(
      (current, sibling, level) => membership.path_bits[level]
        ? committer.proofMerkleNode(sibling, current)
        : committer.proofMerkleNode(current, sibling),
      commitment(leaf, "Snapshot Merkle leaf"),
    );
    const matches = witness.index === binding.index
      && BigInt(witness.agreementLeaf) === BigInt(binding.agreementLeaf)
      && hashCanonicalJson(witness.agreement) === hashCanonicalJson(binding.agreement)
      && hashCanonicalJson(witness.calculated) === hashCanonicalJson(expectedCalculated)
      && BigInt(witness.expectedNetAtomic) === BigInt(binding.calculated.netAtomic)
      && BigInt(witness.claimLeaf) === BigInt(expectedClaimLeaf)
      && membershipPathMatches(witness.agreementMembership)
      && membershipPathMatches(witness.claimMembership)
      && BigInt(merkleRoot(witness.agreementLeaf, witness.agreementMembership))
        === BigInt(input.snapshotPlan.snapshot.baseAgreementRoot)
      && BigInt(merkleRoot(witness.claimLeaf, witness.claimMembership))
        === BigInt(input.snapshotPlan.snapshot.obligationRoot);
    if (!matches) {
      throw new Error(
        "The confirmed payroll differs from its immutable worker claim witness.",
      );
    }
  }
}

async function loadExistingPayrollEmployerStatement(input: {
  client: EmployerStatementPreparationClient;
  organizationId: string;
  run: PayrollRunForEmployerStatement;
  snapshotPlanId: string;
  principal: VaultPrincipalKeyPair;
}): Promise<DurablePayrollEmployerStatement | null> {
  const { statements } = await input.client.listEmployerStatements(
    input.organizationId,
  );
  const candidates = statements.filter((statement) =>
    statement.runId === input.run.id
    && statement.snapshotPlanId === input.snapshotPlanId
    && BigInt(statement.fxRoot) === BigInt(input.run.fxRoot ?? "0"));
  if (candidates.length > 1) {
    throw new Error(
      "PAYO found multiple employer statements for one payroll FX binding.",
    );
  }
  const candidate = candidates[0];
  if (!candidate) return null;
  const { statement: stored } = await input.client.getEmployerStatement(candidate.id);
  const envelope = encryptedVaultRecordSchema.parse(stored.envelope);
  const privateStatement = employerStatementPrivateSchema.parse(
    decryptVaultRecord(envelope, input.principal),
  );
  const bindingsMatch = privateStatement.id === stored.id
    && privateStatement.snapshotPlanId === input.snapshotPlanId
    && privateStatement.organizationId === input.organizationId
    && privateStatement.runId === input.run.id
    && BigInt(privateStatement.ownerAddress) === BigInt(stored.ownerAddress)
    && BigInt(privateStatement.statementCommitment) === BigInt(stored.statementFact)
    && BigInt(privateStatement.statement.manifestRoot) === BigInt(stored.manifestRoot)
    && BigInt(privateStatement.statement.fxRoot) === BigInt(stored.fxRoot)
    && BigInt(privateStatement.statement.availabilityCommitment)
      === BigInt(stored.availabilityCommitment)
    && BigInt(privateStatement.statement.manifestRoot)
      === BigInt(input.run.manifestRoot ?? "0")
    && BigInt(privateStatement.statement.fxRoot) === BigInt(input.run.fxRoot ?? "0")
    && Number(privateStatement.statement.observedAt) * 1_000
      === new Date(stored.observedAt).getTime();
  if (!bindingsMatch) {
    throw new Error(
      "The durable employer statement differs from its encrypted payroll evidence.",
    );
  }
  return {
    stored,
    statement: privateStatement.statement,
    statementCommitment: privateStatement.statementCommitment,
    recovered: true,
  };
}

/**
 * Derives one exact employer statement from a confirmed encrypted vNext
 * payroll. The statement is durable before Ready opens and can be recovered
 * after reload without recreating evidence or requesting a second transaction.
 */
export async function prepareDurableEmployerStatementForPayroll(input: {
  client: EmployerStatementPreparationClient;
  organizationId: string;
  runId: string;
  snapshotPlanId: string;
  principal: VaultPrincipalKeyPair;
  now?: Date;
}): Promise<DurablePayrollEmployerStatement> {
  const [{ run }, { plan }] = await Promise.all([
    input.client.getPayrollRun(input.runId),
    input.client.getObligationSnapshotPlan(input.snapshotPlanId),
  ]);
  if (
    run.organizationId !== input.organizationId
    || !["confirmed", "reconciled", "disputed"].includes(run.state)
    || !run.transactionHash
  ) {
    throw new Error(
      "Employer evidence requires a canonically confirmed private payroll.",
    );
  }
  const snapshotPlan = openSnapshotPlanForPayroll({
    plan,
    run,
    principal: input.principal,
  });
  const recovered = await loadExistingPayrollEmployerStatement({
    client: input.client,
    organizationId: input.organizationId,
    run,
    snapshotPlanId: input.snapshotPlanId,
    principal: input.principal,
  });
  if (recovered) return recovered;

  const privateRun = decryptVaultRecord<{
    obligationSnapshotPlanId?: string;
    claimProofSource?: { buildInput?: SerializedPayrollIntegrityBuildRequest };
  }>(run.envelope, input.principal);
  const buildInput = privateRun.claimProofSource?.buildInput;
  if (
    privateRun.obligationSnapshotPlanId !== input.snapshotPlanId
    || !buildInput
  ) {
    throw new Error(
      "This payroll does not contain its exact vNext employer-evidence source.",
    );
  }
  const payroll = await buildPayrollIntegrityInputsFromSerialized(buildInput);
  assertSameCommitment(run.agreementRoot, payroll.agreementRoot, "agreement root");
  assertSameCommitment(run.manifestRoot, payroll.manifestRoot, "manifest root");
  assertSameCommitment(run.policyRoot, payroll.policyRoot, "policy root");
  assertSameCommitment(run.fxRoot, payroll.fxRoot, "FX root");
  assertSameCommitment(run.runNullifier, payroll.runNullifier, "run nullifier");
  await assertSnapshotWitnessesMatchPayroll({ snapshotPlan, payroll });

  const lines: EmployerStatementLineInput[] = payroll.proofBindings.map(
    (binding) => ({
      agreementId: binding.agreementId,
      target: {
        kind: "line",
        deductionsAtomic: binding.source.deductionsAtomic,
        lineSalt: binding.source.lineSalt,
        classificationTreatment: binding.source.classification.declared,
        finalIncludedMask: binding.source.finalPay?.includedMask ?? 0,
        referenceValueAtomic: binding.line.reference_value_atomic,
      },
    }),
  );
  const prepared = await prepareEmployerStatements({
    snapshotPlan,
    lines,
    fxSnapshots: buildInput.fxSnapshots,
    principal: input.principal,
    now: input.now,
  });
  const exact = prepared.find(({ create }) =>
    BigInt(create.statement.manifestRoot) === BigInt(payroll.manifestRoot)
    && BigInt(create.statement.fxRoot) === BigInt(payroll.fxRoot));
  if (!exact) {
    throw new Error(
      "PAYO could not reproduce the confirmed payroll employer-evidence roots.",
    );
  }

  try {
    const response = await input.client.createEmployerStatement(exact.create);
    if (
      response.statement.id !== exact.create.id
      || response.statement.runId !== input.runId
      || BigInt(response.statement.statementFact)
        !== BigInt(exact.create.statementCommitment)
    ) {
      throw new Error("PAYO returned a different employer-statement reservation.");
    }
    return {
      stored: response.statement,
      statement: exact.create.statement,
      statementCommitment: exact.create.statementCommitment,
      recovered: false,
    };
  } catch (error) {
    // A prior browser request may have reached PostgreSQL even if its response
    // was lost. Recover that immutable row before surfacing an error.
    const raced = await loadExistingPayrollEmployerStatement({
      client: input.client,
      organizationId: input.organizationId,
      run,
      snapshotPlanId: input.snapshotPlanId,
      principal: input.principal,
    });
    if (raced) return raced;
    throw error;
  }
}

export async function createDurableEmployerStatements(input: {
  client: Pick<PayoClient, "createEmployerStatement">;
  prepared: readonly PreparedEmployerStatement[];
}) {
  const stored: Array<EmployerStatementSummary & { replayed: boolean }> = [];
  for (const prepared of input.prepared) {
    const response = await input.client.createEmployerStatement(prepared.create);
    if (
      response.statement.id !== prepared.create.id
      || response.statement.runId !== prepared.create.runId
      || BigInt(response.statement.statementFact)
        !== BigInt(prepared.create.statementCommitment)
    ) {
      throw new Error("PAYO returned a different employer-statement reservation.");
    }
    stored.push(response.statement);
  }
  return stored;
}

export async function registerDurableEmployerStatement(input: {
  client: Pick<
    PayoClient,
    "recordEmployerStatementSubmission" | "reconcileEmployerStatement"
  >;
  stored: Pick<
    EmployerStatementSummary,
    "id" | "state" | "registrationTransactionHash"
  >;
  statement: PayrollStatementV2;
  statementCommitment: string;
  registerStatement: (input: {
    statement: PayrollStatementV2;
    statementCommitment: string;
  }) => Promise<string>;
}) {
  if (input.stored.state === "registered") {
    return { statement: input.stored, recovered: true as const };
  }
  try {
    const canonical = await input.client.reconcileEmployerStatement(
      input.stored.id,
    );
    return { ...canonical, recovered: true as const };
  } catch (error) {
    if (
      !(error instanceof PayoApiError)
      || error.code !== "STATEMENT_NOT_REGISTERED"
    ) {
      throw error;
    }
  }
  if (
    input.stored.state === "submitted"
    || input.stored.registrationTransactionHash
  ) {
    throw new Error(
      "The employer-statement transaction is recorded but not finalized. Retry reconciliation; do not submit it again.",
    );
  }
  if (input.stored.state !== "prepared") {
    throw new Error(
      "Employer statement cannot be registered from state " + input.stored.state + ".",
    );
  }
  const transactionHash = await input.registerStatement({
    statement: input.statement,
    statementCommitment: input.statementCommitment,
  });
  await input.client.recordEmployerStatementSubmission({
    statementId: input.stored.id,
    transactionHash,
  });
  const canonical = await input.client.reconcileEmployerStatement(
    input.stored.id,
  );
  return { ...canonical, transactionHash, recovered: false as const };
}
