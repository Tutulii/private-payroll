export type ProofProfileAgreement = {
  id: string;
  agreement: {
    agreementVersion: "payo-agreement-v1" | "payo-agreement-v2";
    statutoryPolicy?: { catalogRoot: string };
  };
};

export type AuthorizationSelectionObligation = {
  agreement: {
    id: string;
    revision: number;
    updatedAt: string;
    agreementCommitment: string;
    proofScheduleCommitment?: string;
    agreement: { id: string };
  };
  payee: {
    id: string;
    revision: number;
    updatedAt: string;
    recipientAddress: string;
  };
};

/**
 * React receives freshly decrypted agreement objects whenever payroll history
 * refreshes. Object identity is therefore not a valid signal that the
 * proof-bound authorization selection changed. This key includes every record
 * revision/binding that can make the scheduled root stale while remaining
 * stable across equivalent refresh results.
 */
export function obligationAuthorizationSelectionKey(
  organizationId: string | null | undefined,
  obligations: readonly AuthorizationSelectionObligation[],
): string | null {
  if (!organizationId || obligations.length === 0) return null;
  return JSON.stringify({
    organizationId,
    obligations: obligations.map(({ agreement, payee }) => ({
      agreementRecordId: agreement.id,
      agreementId: agreement.agreement.id,
      agreementRevision: agreement.revision,
      agreementUpdatedAt: agreement.updatedAt,
      agreementCommitment: agreement.agreementCommitment.toLowerCase(),
      proofScheduleCommitment: agreement.proofScheduleCommitment?.toLowerCase() ?? null,
      payeeRecordId: payee.id,
      payeeRevision: payee.revision,
      payeeUpdatedAt: payee.updatedAt,
      recipientAddress: payee.recipientAddress.toLowerCase(),
    })),
  });
}

export function payeesMissingActiveAgreements<Payee extends { id: string; status: string }>(
  payees: readonly Payee[],
  agreements: readonly { payeeId: string; effectiveUntil?: string }[],
): Payee[] {
  return payees.filter(({ id, status }) => status === "active" && !agreements.some(
    (agreement) => agreement.payeeId === id && !agreement.effectiveUntil,
  ));
}

function profileFor(id: string, agreements: readonly ProofProfileAgreement[]) {
  const agreement = agreements.find((candidate) => candidate.id === id)?.agreement;
  if (!agreement) return undefined;
  return `${agreement.agreementVersion}:${agreement.statutoryPolicy?.catalogRoot.toLowerCase() ?? "legacy-policy"}`;
}

/**
 * A v1 payroll and a v2 advanced-obligation proof have different verifier
 * payloads, and one run has exactly one policy-catalog root. Selection therefore
 * behaves as a verifier+policy cohort: choosing an incompatible item atomically
 * replaces the previous selection.
 */
export function toggleProofProfileSelection(input: {
  current: readonly string[];
  selectedId: string;
  dueAgreements: readonly ProofProfileAgreement[];
}): string[] {
  if (input.current.includes(input.selectedId)) {
    return input.current.filter((id) => id !== input.selectedId);
  }
  const selectedProfile = profileFor(input.selectedId, input.dueAgreements);
  if (!selectedProfile) return [...input.current];
  return [
    ...input.current.filter((id) => profileFor(id, input.dueAgreements) === selectedProfile),
    input.selectedId,
  ];
}

export function reconcileProofProfileSelection(input: {
  current: readonly string[];
  dueIds: readonly string[];
  agreements: readonly ProofProfileAgreement[];
}): string[] {
  const selectedProfile = input.current
    .map((id) => profileFor(id, input.agreements))
    .find((profile) => profile !== undefined);
  const defaultProfile = input.dueIds
    .map((id) => profileFor(id, input.agreements))
    .find((profile) => profile !== undefined);
  const profile = selectedProfile ?? defaultProfile;
  if (!profile) return [];
  const compatible = input.dueIds.filter((id) => profileFor(id, input.agreements) === profile);
  return input.current.length
    ? input.current.filter((id) => compatible.includes(id))
    : compatible;
}


export const PAYDAY_COHORT_WINDOW_SECONDS = 15 * 60;

type UpcomingPaydayCandidate = {
  dueAt: bigint;
  agreement: ProofProfileAgreement & {
    agreement: ProofProfileAgreement["agreement"] & {
      paymentPlan?: { kind: string };
    };
  };
};

/**
 * Groups nearby recurring agreements into the payday people expect from the UI.
 * The common timestamp is always the latest original due time, so alignment can
 * delay an earlier obligation by at most 15 minutes but can never accelerate it.
 * Non-recurring obligations retain their exact contractual checkpoint.
 */
export function selectUpcomingPaydayCohort<T extends UpcomingPaydayCandidate>(
  candidates: readonly T[],
  windowSeconds = PAYDAY_COHORT_WINDOW_SECONDS,
): { obligations: T[]; dueAt: bigint | null; requiresAlignment: boolean } {
  if (!Number.isSafeInteger(windowSeconds) || windowSeconds < 0 || windowSeconds > 60 * 60) {
    throw new Error("The payroll cohort window must be between zero and 60 minutes.");
  }
  const ordered = [...candidates].sort((left, right) =>
    left.dueAt === right.dueAt
      ? left.agreement.id.localeCompare(right.agreement.id)
      : left.dueAt < right.dueAt ? -1 : 1);
  const first = ordered[0];
  if (!first) return { obligations: [], dueAt: null, requiresAlignment: false };
  const firstProfile = profileFor(first.agreement.id, ordered.map(({ agreement }) => agreement));
  const firstPlan = first.agreement.agreement;
  const recurring = firstPlan.agreementVersion === "payo-agreement-v2"
    && firstPlan.paymentPlan?.kind === "recurring";
  const maximumDueAt = first.dueAt + BigInt(windowSeconds);
  const obligations = ordered.filter((candidate) => {
    if (profileFor(candidate.agreement.id, ordered.map(({ agreement }) => agreement)) !== firstProfile) return false;
    if (!recurring) return candidate.dueAt === first.dueAt;
    return candidate.agreement.agreement.agreementVersion === "payo-agreement-v2"
      && candidate.agreement.agreement.paymentPlan?.kind === "recurring"
      && candidate.dueAt <= maximumDueAt;
  });
  const dueAt = obligations.reduce(
    (latest, candidate) => candidate.dueAt > latest ? candidate.dueAt : latest,
    first.dueAt,
  );
  return {
    obligations,
    dueAt,
    requiresAlignment: obligations.some((candidate) => candidate.dueAt !== dueAt),
  };
}
