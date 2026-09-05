import { hashRecipientCommitment } from "@/lib/crypto/commitments";
import { normalizedHexBytes, toHex } from "@/lib/crypto/encoding";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  type VaultPrincipal,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import { toCircuitFxSnapshot, type FxSnapshot } from "@/lib/domain/fx";
import type { ExceptionToken } from "@/lib/domain/exception-protocol";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  deriveExceptionBookTotalsSalt,
  utcAnnualPayrollBookPeriod,
} from "@/lib/domain/universal-payroll-book";
import {
  wageRemediationCreateSchema,
  wageRemediationPrivateSchema,
  type WageRemediationSummary,
} from "@/lib/domain/wage-remediation";
import {
  workerClaimPrivateSchema,
  type WorkerClaimPrivate,
  type WorkerClaimSummary,
} from "@/lib/domain/worker-claim";
import {
  buildWageRemediationV2Inputs,
  type AcceptedWageClaimV2Build,
} from "@/lib/proof/exception-input-builder";
import {
  createProofCommitter,
} from "@/lib/proof/commitments";
import { randomCommitmentSalt } from "@/lib/proof/input-builder";
import { buildExceptionPayrollBookEntryInputs } from "@/lib/proof/vesting-transition-input";
import {
  prepareEncryptedExceptionProofBundle,
  prepareVestingBookProofSubmission,
} from "./proof-bundle";
import type { PayoClient } from "./payo-client";

function witnessHex(value: readonly number[]): `0x${string}` {
  return toHex(Uint8Array.from(value));
}

function commitmentHex(value: string): `0x${string}` {
  return toHex(normalizedHexBytes(value, 32));
}

async function acceptedClaimBuild(
  claim: WorkerClaimPrivate,
): Promise<AcceptedWageClaimV2Build> {
  const witness = claim.remediationWitness;
  const agreement = witness.agreement;
  const committer = await createProofCommitter();
  const earningsCount = Number(agreement.earnings_count);
  if (
    !Number.isSafeInteger(earningsCount)
    || earningsCount < 1
    || earningsCount > agreement.earnings.length
  ) {
    throw new Error("Accepted claim contains an invalid agreement earnings count.");
  }
  const agreementLeaf = committer.proofAgreementCommitment({
    agreementIdCommitment: witnessHex(agreement.id_commitment),
    recipientCommitment: witnessHex(agreement.recipient_commitment),
    earningsAtomic: agreement.earnings.slice(0, earningsCount),
    token: agreement.token === "0" ? "STRK" : "USDC",
    policyCommitment: witnessHex(agreement.policy_commitment),
    scheduleCommitment: witnessHex(agreement.schedule_commitment),
    dueAt: BigInt(agreement.due_at),
    validUntil: BigInt(agreement.valid_until),
    classificationDeclared: Number(agreement.classification_declared) as 1 | 2,
    classificationScore: Number(agreement.classification_score),
    classificationEmployeeThreshold: Number(
      agreement.classification_employee_threshold,
    ),
    finalPayMode: agreement.final_pay_mode,
    finalRequiredMask: Number(agreement.final_required_mask),
    finalComponentsAtomic: agreement.final_components,
    fxFloorAtomic: agreement.fx_floor_atomic,
    referenceCurrency: agreement.reference_currency === "0" ? "USD" : "GBP",
    salt: witnessHex(agreement.salt),
  });
  if (BigInt(agreementLeaf) !== BigInt(claim.claimFact.agreementLeaf)) {
    throw new Error("Accepted claim agreement witness does not match its Claim v6 fact.");
  }
  const reconstructedRoot = witness.agreementMembership.siblings.reduce(
    (current, sibling, level) => witness.agreementMembership.path_bits[level]
      ? committer.proofMerkleNode(sibling, current)
      : committer.proofMerkleNode(current, sibling),
    agreementLeaf,
  );
  if (
    BigInt(reconstructedRoot) !== BigInt(witness.snapshot.baseAgreementRoot)
    || BigInt(witness.snapshot.policyRoot) === 0n
  ) {
    throw new Error("Accepted claim agreement opening does not match its immutable snapshot.");
  }
  const recipientCommitment = toHex(hashRecipientCommitment(
    witness.recipientAddress,
    witness.recipientSalt,
  ));
  if (
    BigInt(recipientCommitment)
      !== BigInt(witnessHex(agreement.recipient_commitment))
  ) {
    throw new Error("Accepted claim recipient address does not match its private commitment.");
  }
  return {
    claimFact: claim.claimFact,
    claimFactCommitment: commitmentHex(claim.claimFactCommitment),
    claimSubjectNullifier: commitmentHex(claim.claimFact.claimSubjectNullifier),
    snapshot: {
      snapshot: {
        baseAgreementRoot: witness.snapshot.baseAgreementRoot,
        policyRoot: witness.snapshot.policyRoot,
      },
    },
    target: {
      agreement,
      agreementMembership: witness.agreementMembership,
    },
  };
}


export function minimumWageRemediationAmount(input: {
  acceptedClaim: WorkerClaimPrivate;
  fxSnapshot?: FxSnapshot;
}): string {
  const claim = workerClaimPrivateSchema.parse(input.acceptedClaim);
  const shortfall = BigInt(claim.claimFact.shortfallAtomic);
  if (claim.claimFact.claimKind !== "below_committed_floor") {
    return shortfall.toString();
  }
  if (!input.fxSnapshot) {
    throw new Error("An FX-floor remediation requires a fresh FX snapshot.");
  }
  const fx = toCircuitFxSnapshot(input.fxSnapshot);
  const expectedToken = claim.claimFact.obligationToken === "STRK" ? 0 : 1;
  const expectedCurrency = claim.claimFact.shortfallUnit === "usd_6"
    ? 0
    : claim.claimFact.shortfallUnit === "gbp_6" ? 1 : -1;
  if (fx.token !== expectedToken || fx.referenceCurrency !== expectedCurrency) {
    throw new Error("The fresh FX snapshot does not match the accepted claim token and reference currency.");
  }
  const numerator = BigInt(fx.priceNumerator);
  const denominator = BigInt(fx.priceDenominator);
  const haircut = BigInt(10_000 - fx.haircutBps);
  if (numerator <= 0n || denominator <= 0n || haircut <= 0n) {
    throw new Error("The fresh FX conversion cannot value this remediation.");
  }
  const divisor = numerator * haircut;
  let amount = (shortfall * denominator * 10_000n + divisor - 1n) / divisor;
  const referenceValue = (candidate: bigint) =>
    candidate * numerator / denominator * haircut / 10_000n;
  while (referenceValue(amount) < shortfall) amount += 1n;
  return amount.toString();
}

export async function prepareWageRemediationV2(input: {
  acceptedClaim: WorkerClaimPrivate;
  claimState: "accepted";
  organizationId: string;
  runId: string;
  chainId: string;
  sealAddress: string;
  amountAtomic: string;
  token: ExceptionToken;
  fxSnapshots?: readonly FxSnapshot[];
  selectedFxIndex?: number;
  principal: VaultPrincipalKeyPair;
  employerRecipients?: readonly VaultPrincipal[];
  remediationId?: string;
  proofBundleId?: string;
  remediationSecret?: `0x${string}`;
  actionSalt?: `0x${string}`;
  validityStart?: bigint;
  validityExpiry?: bigint;
  now?: Date;
}) {
  const claim = workerClaimPrivateSchema.parse(input.acceptedClaim);
  if (
    input.claimState !== "accepted"
    || claim.organizationId !== input.organizationId
    || claim.runId !== input.runId
  ) {
    throw new Error("Remediation requires the selected on-chain accepted Claim v6 record.");
  }
  const now = input.now ?? new Date();
  const validityStart = input.validityStart
    ?? BigInt(Math.floor(now.getTime() / 1_000));
  const validityExpiry = input.validityExpiry ?? validityStart + 1_800n;
  const remediationSecret = input.remediationSecret ?? randomCommitmentSalt();
  const actionSalt = input.actionSalt ?? randomCommitmentSalt();
  const acceptedBuild = await acceptedClaimBuild(claim);
  const build = await buildWageRemediationV2Inputs({
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    claim: acceptedBuild,
    remediationSecret,
    actionSalt,
    amountAtomic: input.amountAtomic,
    token: input.token,
    fxSnapshots: input.fxSnapshots,
    selectedFxIndex: input.selectedFxIndex,
    validityStart,
    validityExpiry,
  });
  const remediationId = input.remediationId ?? generateUuidV7(now.getTime());
  const proofBundleId = input.proofBundleId
    ?? generateUuidV7(now.getTime() + 1);
  const recipients = [
    claim.claimantPrincipal,
    ...(input.employerRecipients ?? [input.principal]),
  ];
  if (
    !recipients.some(({ principalId }) =>
      principalId === input.principal.principalId)
    || new Set(recipients.map(({ principalId }) => principalId)).size
      !== recipients.length
  ) {
    throw new Error(
      "Remediation recipients must uniquely include the claimant and issuing employer.",
    );
  }
  const recipientCommitment = witnessHex(
    claim.remediationWitness.agreement.recipient_commitment,
  );
  const privateRecord = wageRemediationPrivateSchema.parse({
    format: "payo-wage-remediation-v2",
    schemaVersion: 2,
    id: remediationId,
    workerClaimId: claim.id,
    organizationId: input.organizationId,
    runId: input.runId,
    proofBundleId,
    claimFact: claim.claimFact,
    claimSubjectNullifier: claim.claimFact.claimSubjectNullifier,
    claimFactCommitment: claim.claimFactCommitment,
    remediationSubjectNullifier: build.remediationSubjectNullifier,
    remediationFactCommitment: build.remediationFactCommitment,
    actionCommitment: build.actionCommitment,
    recipientAddress: claim.remediationWitness.recipientAddress,
    recipientSalt: claim.remediationWitness.recipientSalt,
    recipientCommitment,
    token: input.token,
    tokenDecimals: input.token === "STRK" ? 18 : 6,
    amountAtomic: input.amountAtomic,
    referenceValueAtomic: build.referenceValueAtomic,
    referenceUnit: claim.claimFact.shortfallUnit,
    fxRoot: build.fxRoot,
    ...(claim.claimFact.claimKind === "below_committed_floor" ? {
      fxEvidence: {
        snapshots: [...(input.fxSnapshots ?? [])],
        selectedFxIndex: input.selectedFxIndex ?? 0,
      },
    } : {}),
    remediationSecret,
    actionSalt,
    validityStart: validityStart.toString(),
    validityExpiry: validityExpiry.toString(),
    createdAt: now.toISOString(),
  });
  const envelope = encryptVaultRecord(privateRecord, {
    schemaVersion: 1,
    organizationId: input.organizationId,
    recordType: "wage-remediation-v2",
    recordId: remediationId,
    revision: 1,
  }, recipients);
  const create = wageRemediationCreateSchema.parse({
    id: remediationId,
    workerClaimId: claim.id,
    organizationId: input.organizationId,
    runId: input.runId,
    revision: 1,
    proofBundleId,
    claimSubjectNullifier: privateRecord.claimSubjectNullifier,
    claimFactCommitment: privateRecord.claimFactCommitment,
    remediationSubjectNullifier: privateRecord.remediationSubjectNullifier,
    remediationFactCommitment: privateRecord.remediationFactCommitment,
    actionCommitment: privateRecord.actionCommitment,
    fxRoot: privateRecord.fxRoot,
    validityExpiry: privateRecord.validityExpiry,
    envelope,
  });
  return {
    privateRecord,
    create,
    build,
    proofRecipients: recipients,
    bookOwnerAddress: claim.remediationWitness.snapshot.ownerAddress,
  };
}



export async function prepareStoredWageRemediationV2(input: {
  remediation: WageRemediationSummary;
  acceptedClaim: WorkerClaimPrivate;
  chainId: string;
  sealAddress: string;
  principal: VaultPrincipalKeyPair;
  now?: Date;
}) {
  if (input.remediation.state !== "prepared") {
    throw new Error("Only a persisted Remediation v7 without a proof can resume proving.");
  }
  const privateRecord = wageRemediationPrivateSchema.parse(
    decryptVaultRecord(input.remediation.envelope, input.principal),
  );
  if (
    privateRecord.id !== input.remediation.id
    || privateRecord.workerClaimId !== input.remediation.workerClaimId
    || privateRecord.organizationId !== input.remediation.organizationId
    || privateRecord.runId !== input.remediation.runId
    || privateRecord.proofBundleId !== input.remediation.proofBundleId
    || BigInt(privateRecord.remediationSubjectNullifier)
      !== BigInt(input.remediation.remediationSubjectNullifier)
    || BigInt(privateRecord.remediationFactCommitment)
      !== BigInt(input.remediation.remediationFactCommitment)
    || BigInt(privateRecord.actionCommitment)
      !== BigInt(input.remediation.actionCommitment)
  ) throw new Error("The stored Remediation v7 ciphertext differs from its durable bindings.");
  const now = input.now ?? new Date();
  if (BigInt(privateRecord.validityExpiry)
    <= BigInt(Math.floor(now.getTime() / 1_000)) + 120n) {
    throw new Error("This prepared Remediation v7 proof window expired; create a fresh remediation attempt.");
  }
  const rebuilt = await prepareWageRemediationV2({
    acceptedClaim: input.acceptedClaim,
    claimState: "accepted",
    organizationId: privateRecord.organizationId,
    runId: privateRecord.runId,
    chainId: input.chainId,
    sealAddress: input.sealAddress,
    amountAtomic: privateRecord.amountAtomic,
    token: privateRecord.token,
    fxSnapshots: privateRecord.fxEvidence?.snapshots,
    selectedFxIndex: privateRecord.fxEvidence?.selectedFxIndex,
    principal: input.principal,
    employerRecipients: [input.principal],
    remediationId: privateRecord.id,
    proofBundleId: privateRecord.proofBundleId,
    remediationSecret: privateRecord.remediationSecret as `0x${string}`,
    actionSalt: privateRecord.actionSalt as `0x${string}`,
    validityStart: BigInt(privateRecord.validityStart),
    validityExpiry: BigInt(privateRecord.validityExpiry),
    now: new Date(privateRecord.createdAt),
  });
  if (
    BigInt(rebuilt.build.remediationSubjectNullifier)
      !== BigInt(privateRecord.remediationSubjectNullifier)
    || BigInt(rebuilt.build.remediationFactCommitment)
      !== BigInt(privateRecord.remediationFactCommitment)
    || BigInt(rebuilt.build.actionCommitment) !== BigInt(privateRecord.actionCommitment)
    || BigInt(rebuilt.build.fxRoot) !== BigInt(privateRecord.fxRoot)
  ) throw new Error("The rebuilt Remediation v7 witness changed its immutable private action.");
  const create = wageRemediationCreateSchema.parse({
    id: input.remediation.id,
    workerClaimId: input.remediation.workerClaimId,
    organizationId: input.remediation.organizationId,
    runId: input.remediation.runId,
    revision: 1,
    proofBundleId: input.remediation.proofBundleId,
    claimSubjectNullifier: input.remediation.claimSubjectNullifier,
    claimFactCommitment: input.remediation.claimFactCommitment,
    remediationSubjectNullifier: input.remediation.remediationSubjectNullifier,
    remediationFactCommitment: input.remediation.remediationFactCommitment,
    actionCommitment: input.remediation.actionCommitment,
    fxRoot: input.remediation.fxRoot,
    validityExpiry: privateRecord.validityExpiry,
    envelope: input.remediation.envelope,
  });
  return { ...rebuilt, privateRecord, create };
}

export function openAcceptedWorkerClaimV2(input: {
  claim: WorkerClaimSummary;
  principal: VaultPrincipalKeyPair;
}): WorkerClaimPrivate {
  if (input.claim.state !== "accepted") {
    throw new Error("Only an on-chain accepted Claim v6 can be remediated.");
  }
  if (input.claim.claimantPrincipalId === input.principal.principalId) {
    throw new Error("The employer remediation action requires an employer PAYO identity.");
  }
  const claim = workerClaimPrivateSchema.parse(
    decryptVaultRecord(input.claim.envelope, input.principal),
  );
  if (
    claim.id !== input.claim.id
    || claim.organizationId !== input.claim.organizationId
    || claim.runId !== input.claim.runId
    || claim.claimAccessGrantId !== input.claim.claimAccessGrantId
    || claim.proofBundleId !== input.claim.proofBundleId
    || claim.claimantPrincipal.principalId !== input.claim.claimantPrincipalId
    || BigInt(claim.claimFact.claimSubjectNullifier)
      !== BigInt(input.claim.claimSubjectNullifier)
    || BigInt(claim.claimFactCommitment) !== BigInt(input.claim.claimFactCommitment)
  ) {
    throw new Error("The encrypted Claim v6 record differs from its accepted routing commitments.");
  }
  return claim;
}

type RemediationProofClient = Pick<
  PayoClient,
  | "createWageRemediation"
  | "proveExceptionRemotely"
  | "storeEncryptedProofBundle"
  | "enqueueExceptionAuthorization"
>;

export async function proveAndAuthorizeWageRemediationV2(input: {
  client: RemediationProofClient;
  prepared: Awaited<ReturnType<typeof prepareWageRemediationV2>>;
  principal: VaultPrincipalKeyPair;
  proverBaseUrl: string;
  bookSealAddress: string;
  onStage?: (stage: "persisting_remediation" | "proving" | "persisting_proof" | "authorizing") => void;
}) {
  const { prepared } = input;
  if (!prepared.create.envelope.wrappedKeys.some(({ principalId }) =>
    principalId === input.principal.principalId)) {
    throw new Error("The employer cannot decrypt this prepared remediation.");
  }
  input.onStage?.("persisting_remediation");
  const stored = await input.client.createWageRemediation(prepared.create);
  if (
    stored.remediation.id !== prepared.create.id
    || stored.remediation.proofBundleId !== prepared.create.proofBundleId
  ) throw new Error("PAYO returned a different durable remediation attempt.");

  input.onStage?.("proving");
  const requestId = generateUuidV7();
  const period = utcAnnualPayrollBookPeriod(prepared.build.publicInputs.validityStart);
  const exceptionBookBuild = await buildExceptionPayrollBookEntryInputs({
    source: prepared.build.publicInputs,
    entryKind: "remediation",
    bookSealAddress: input.bookSealAddress,
    sourceSealAddress: prepared.build.publicInputs.sealAddress,
    ownerAddress: prepared.bookOwnerAddress,
    runNullifier: prepared.privateRecord.claimFact.runNullifier,
    periodStart: period.periodStart,
    periodEnd: period.periodEnd,
    totalsSalt: deriveExceptionBookTotalsSalt({
      privateSecret: prepared.privateRecord.remediationSecret,
      subjectNullifier: prepared.privateRecord.remediationSubjectNullifier,
    }),
    claimFact: prepared.privateRecord.claimFact,
    remediation: {
      remediationSecret: prepared.privateRecord.remediationSecret,
      recipientCommitment: prepared.privateRecord.recipientCommitment,
      amountAtomic: prepared.privateRecord.amountAtomic,
      referenceValueAtomic: prepared.privateRecord.referenceValueAtomic,
      actionSalt: prepared.privateRecord.actionSalt,
    },
  });
  const encryptedWitness = encryptVaultRecord({
    exceptionCircuitProfile: "wage_remediation_v7",
    circuitInput: prepared.build.circuitInputs,
    exceptionBookBuild,
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
  });
  if (proof.profile !== "wage_remediation_v7" || proof.vestingBook?.entryKind !== "remediation") {
    throw new Error("The prover omitted or changed the Remediation v7 payroll-book proof.");
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
  const { authorization } = await input.client.enqueueExceptionAuthorization({
    proofBundleId: prepared.create.proofBundleId,
    request: {
      proofCalldata: proof.proof.proofCalldata,
      vestingBook: prepareVestingBookProofSubmission(proof.vestingBook),
    },
  });
  return { remediation: stored.remediation, proof, proofBundle, authorization };
}
