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
