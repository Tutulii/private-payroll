export type ProofProfileAgreement = {
  id: string;
  agreement: {
    agreementVersion: "payo-agreement-v1" | "payo-agreement-v2";
    statutoryPolicy?: { catalogRoot: string };
  };
};

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
