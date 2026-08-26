import { describe, expect, it } from "vitest";
import { reconcileProofProfileSelection, toggleProofProfileSelection } from "./payroll-selection";

const agreements = [
  { id: "legacy-a", agreement: { agreementVersion: "payo-agreement-v1" as const } },
  { id: "legacy-b", agreement: { agreementVersion: "payo-agreement-v1" as const } },
  { id: "advanced-a", agreement: { agreementVersion: "payo-agreement-v2" as const } },
  { id: "advanced-b", agreement: { agreementVersion: "payo-agreement-v2" as const } },
];

describe("payroll proof-profile selection", () => {
  it("replaces legacy selections when an advanced obligation is chosen", () => {
    expect(toggleProofProfileSelection({
      current: ["legacy-a", "legacy-b"],
      selectedId: "advanced-a",
      dueAgreements: agreements,
    })).toEqual(["advanced-a"]);
  });

  it("keeps compatible advanced obligations in one batch", () => {
    expect(toggleProofProfileSelection({
      current: ["advanced-a"],
      selectedId: "advanced-b",
      dueAgreements: agreements,
    })).toEqual(["advanced-a", "advanced-b"]);
  });

  it("removes stale and incompatible selections after a refresh", () => {
    expect(reconcileProofProfileSelection({
      current: ["advanced-a", "legacy-a"],
      dueIds: ["legacy-a", "advanced-a", "advanced-b"],
      agreements,
    })).toEqual(["advanced-a"]);
  });

  it("keeps different policy catalog roots in separate payroll cohorts", () => {
    const policyAgreements = [
      { id: "net", agreement: { agreementVersion: "payo-agreement-v1" as const, statutoryPolicy: { catalogRoot: "0x1" } } },
      { id: "employee", agreement: { agreementVersion: "payo-agreement-v1" as const, statutoryPolicy: { catalogRoot: "0x2" } } },
    ];
    expect(toggleProofProfileSelection({
      current: ["net"],
      selectedId: "employee",
      dueAgreements: policyAgreements,
    })).toEqual(["employee"]);
  });
});
