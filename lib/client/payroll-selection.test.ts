import { describe, expect, it } from "vitest";
import {
  obligationAuthorizationSelectionKey,
  payeesMissingActiveAgreements,
  reconcileProofProfileSelection,
  toggleProofProfileSelection,
} from "./payroll-selection";

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

describe("obligation authorization selection identity", () => {
  const obligation = {
    agreement: {
      id: "018f1000-0000-7000-8000-000000000001",
      revision: 2,
      updatedAt: "2026-08-27T01:00:00.000Z",
      agreementCommitment: `0x${"11".repeat(32)}`,
      proofScheduleCommitment: `0x${"22".repeat(32)}`,
      agreement: { id: "018f1000-0000-7000-8000-000000000002" },
    },
    payee: {
      id: "018f1000-0000-7000-8000-000000000003",
      revision: 1,
      updatedAt: "2026-08-27T00:00:00.000Z",
      recipientAddress: "0xABC",
    },
  };

  it("stays stable when a history refresh returns equivalent new objects", () => {
    const first = obligationAuthorizationSelectionKey("org-1", [obligation]);
    const refreshed = obligationAuthorizationSelectionKey(
      "org-1",
      [structuredClone(obligation)],
    );
    expect(refreshed).toBe(first);
  });

  it("changes when a proof-bound agreement or recipient revision changes", () => {
    const first = obligationAuthorizationSelectionKey("org-1", [obligation]);
    expect(obligationAuthorizationSelectionKey("org-1", [{
      ...obligation,
      agreement: { ...obligation.agreement, revision: 3 },
    }])).not.toBe(first);
    expect(obligationAuthorizationSelectionKey("org-1", [{
      ...obligation,
      payee: { ...obligation.payee, recipientAddress: "0xDEF" },
    }])).not.toBe(first);
  });

  it("preserves line ordering because it is part of the Merkle root", () => {
    const second = {
      ...structuredClone(obligation),
      agreement: {
        ...structuredClone(obligation.agreement),
        id: "018f1000-0000-7000-8000-000000000004",
      },
    };
    expect(obligationAuthorizationSelectionKey("org-1", [obligation, second]))
      .not.toBe(obligationAuthorizationSelectionKey("org-1", [second, obligation]));
  });
});

describe("payroll setup visibility", () => {
  const payees = [
    { id: "ready", status: "active", displayName: "Ready worker" },
    { id: "missing", status: "active", displayName: "Needs agreement" },
    { id: "ended", status: "active", displayName: "Needs replacement" },
    { id: "inactive", status: "inactive", displayName: "Inactive worker" },
  ];

  it("keeps active people without a current agreement visible for setup", () => {
    expect(payeesMissingActiveAgreements(payees, [
      { payeeId: "ready" },
      { payeeId: "ended", effectiveUntil: "2026-08-26T00:00:00.000Z" },
    ]).map(({ id }) => id)).toEqual(["missing", "ended"]);
  });
});
