"use client";

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { PayoVaultContext, type PayoVaultContextValue, type VaultSession } from "./payo-vault";
import type { PayoClient } from "@/lib/client/payo-client";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  type EncryptedVaultRecord,
  type VaultPrincipalKeyPair,
} from "@/lib/crypto/vault";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { wageClaimRecordSchema } from "@/lib/domain/records";

const ORGANIZATION_ID = "018f1000-0000-7000-8000-000000000030";
const ORGANIZATION_SECRET = `0x${"30".repeat(32)}`;
const STORAGE_KEY = "payo:phase3-browser-evidence:v1";
const SYNTHETIC_ROOT = `0x${"42".repeat(32)}`;
const SYNTHETIC_SETTLEMENT_ID = "018f1000-0000-7000-8000-000000000035";
const SYNTHETIC_SETTLEMENT_RUN_ID = "018f1000-0000-7000-8000-000000000036";
const SYNTHETIC_SNAPSHOT_PLAN_ID = "018f1000-0000-7000-8000-000000000037";
const SYNTHETIC_CLAIM_GRANT_ID = "018f1000-0000-7000-8000-000000000038";

// This key can only decrypt synthetic records created in the server-gated browser-evidence route.
// It is deliberately unrelated to any PAYO deployment, user, or funded Starknet account.
const SYNTHETIC_PRINCIPAL: VaultPrincipalKeyPair = {
  principalId: "phase3-browser-evidence",
  publicKey: "KsD1+YKrizU8vEyTJQ2MrSbRreOHGeXtvoaLYUXVoF8=",
  secretKey: "pT60QxIT6W8XlFM5ejV1bLRKfjGqc4vEXQuJFgpiEQU=",
};

type StoredRecord = {
  id: string;
  recordType: string;
  revision: number;
  envelope: EncryptedVaultRecord;
  createdAt: string;
};

type BrowserEvidenceState = {
  records: StoredRecord[];
  runs: Array<Record<string, unknown>>;
  schedules: Array<{
    agreementId: string;
    agreementRevision: number;
    scheduleCommitment: string;
    dueAt: string;
    materializedAt: string | null;
  }>;
};

export type BrowserEvidenceExport = {
  organizationId: string;
  records: Array<StoredRecord & { plaintext: unknown; envelopeHash: string }>;
  runs: Array<Record<string, unknown>>;
  schedules: BrowserEvidenceState["schedules"];
};

declare global {
  interface Window {
    __PAYO_BROWSER_EVIDENCE__?: {
      reset: () => void;
      exportState: () => BrowserEvidenceExport;
      setRuns: (runs: Array<Record<string, unknown>>) => void;
      markLatestClaimSubmitted: () => void;
    };
  }
}

function emptyState(): BrowserEvidenceState {
  return { records: [], runs: [], schedules: [] };
}

function readState(): BrowserEvidenceState {
  if (typeof window === "undefined") return emptyState();
  const serialized = window.sessionStorage.getItem(STORAGE_KEY);
  if (!serialized) return emptyState();
  try {
    const parsed = JSON.parse(serialized) as Partial<BrowserEvidenceState>;
    return {
      records: Array.isArray(parsed.records) ? parsed.records : [],
      runs: Array.isArray(parsed.runs) ? parsed.runs : [],
      schedules: Array.isArray(parsed.schedules) ? parsed.schedules : [],
    };
  } catch {
    return emptyState();
  }
}

function writeState(state: BrowserEvidenceState): void {
  window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function storeRecord(state: BrowserEvidenceState, record: StoredRecord): BrowserEvidenceState {
  const records = state.records.filter(({ id, revision }) =>
    id !== record.id || revision !== record.revision);
  records.push(record);
  return { ...state, records };
}

function latestRecords(state: BrowserEvidenceState): StoredRecord[] {
  const latest = new Map<string, StoredRecord>();
  for (const record of state.records) {
    const current = latest.get(record.id);
    if (!current || current.revision < record.revision) latest.set(record.id, record);
  }
  return [...latest.values()];
}

function syntheticSnapshotPlan(runId: string) {
  return {
    id: SYNTHETIC_SNAPSHOT_PLAN_ID,
    runId,
    organizationId: ORGANIZATION_ID,
    cycleId: "browser-vnext-evidence",
    revision: 1,
    ownerAddress: "0x123",
    agreementRoot: SYNTHETIC_ROOT,
    claimRoot: "0x" + "43".repeat(32),
    policyRoot: SYNTHETIC_ROOT,
    runNullifier: "0x" + "44".repeat(32),
    snapshotFact: "0x" + "45".repeat(32),
    dueAt: "2026-08-26T00:00:00.000Z",
    graceEndsAt: "2026-08-26T00:15:00.000Z",
    claimEndsAt: "2027-08-26T00:00:00.000Z",
    state: "consumed" as const,
    registrationTransactionHash: "0x111",
    registeredAt: "2026-08-25T23:50:00.000Z",
    consumedAt: "2026-08-26T00:01:00.000Z",
    createdAt: "2026-08-25T23:49:00.000Z",
    updatedAt: "2026-08-26T00:01:00.000Z",
  };
}

function metadata(record: StoredRecord) {
  return {
    id: record.id,
    recordType: record.recordType,
    revision: record.revision,
    envelopeHash: hashCanonicalJson(record.envelope),
    supersededAt: null,
    createdAt: record.createdAt,
  };
}

export function PayoBrowserEvidenceProvider({ children }: { children: ReactNode }) {
  const [, setRevision] = useState(0);
  const session = useMemo<VaultSession>(() => ({
    organizationId: ORGANIZATION_ID,
    organizationSecret: ORGANIZATION_SECRET,
    principal: SYNTHETIC_PRINCIPAL,
  }), []);

  const mutate = useCallback((update: (state: BrowserEvidenceState) => BrowserEvidenceState) => {
    const next = update(readState());
    writeState(next);
    setRevision((value) => value + 1);
    return next;
  }, []);

  const client = useMemo(() => ({
    async storeEncryptedRecord(input: {
      recordId: string;
      recordType: string;
      revision: number;
      envelope: EncryptedVaultRecord;
    }) {
      const record: StoredRecord = {
        id: input.recordId,
        recordType: input.recordType,
        revision: input.revision,
        envelope: input.envelope,
        createdAt: new Date().toISOString(),
      };
      mutate((state) => storeRecord(state, record));
      return { record: metadata(record) };
    },
    async storeEncryptedRecords(input: {
      records: Array<{
        recordId: string;
        recordType: string;
        revision: number;
        envelope: EncryptedVaultRecord;
      }>;
    }) {
      const createdAt = new Date().toISOString();
      const records = input.records.map((record) => ({
        id: record.recordId,
        recordType: record.recordType,
        revision: record.revision,
        envelope: record.envelope,
        createdAt,
      }));
      mutate((state) => records.reduce(storeRecord, state));
      return { records: records.map(metadata) };
    },
    async getEncryptedRecord(input: { recordId: string; revision?: number }) {
      const candidates = readState().records.filter(({ id, revision }) =>
        id === input.recordId && (input.revision === undefined || revision === input.revision));
      const record = candidates.sort((left, right) => right.revision - left.revision)[0];
      if (!record) throw new Error("Synthetic encrypted record not found.");
      return { record: { ...metadata(record), envelope: record.envelope } };
    },
    async listEncryptedRecords(_organizationId: string, recordType?: string) {
      const records = latestRecords(readState())
        .filter((record) => !recordType || record.recordType === recordType)
        .map(metadata);
      return { records };
    },

    async listObligationClaimAccessGrants() {
      const run = readState().runs.find(({ id, obligationSnapshotPlanId }) =>
        typeof id === "string" && obligationSnapshotPlanId === SYNTHETIC_SNAPSHOT_PLAN_ID);
      if (!run || typeof run.id !== "string") return { grants: [] };
      return { grants: [{
        id: SYNTHETIC_CLAIM_GRANT_ID,
        claimantPrincipalId: SYNTHETIC_PRINCIPAL.principalId,
        revokedAt: null,
        plan: syntheticSnapshotPlan(run.id),
        envelope: encryptVaultRecord({ syntheticBrowserClaimAccess: true }, {
          schemaVersion: 1,
          organizationId: ORGANIZATION_ID,
          recordType: "obligation-claim-access",
          recordId: SYNTHETIC_CLAIM_GRANT_ID,
          revision: 1,
        }, [SYNTHETIC_PRINCIPAL]),
      }] };
    },
    async listPayrollStatementEvidence() {
      return { evidence: [] };
    },
    async listWorkerClaims() {
      return { claims: [] };
    },
    async listWageRemediations() {
      return { remediations: [] };
    },
    async listObligationSnapshotPlans() {
      const plans = readState().runs.flatMap((run) => {
        if (
          typeof run.id !== "string"
          || typeof run.obligationSnapshotPlanId !== "string"
          || typeof run.transactionHash !== "string"
        ) return [];
        return [syntheticSnapshotPlan(run.id)];
      });
      return { plans };
    },
    async listEmployerStatements() {
      return { statements: [] };
    },
    async listPayrollRuns() {
      return { runs: readState().runs };
    },
    async getPayrollRun(runId: string) {
      const run = readState().runs.find(({ id }) => id === runId);
      if (!run) throw new Error("Synthetic payroll run not found.");
      const lines = Array.isArray(run.lines) ? run.lines : [];
      const envelope = encryptVaultRecord({
        claimProofSource: { buildInput: { lines } },
      }, {
        schemaVersion: 1,
        organizationId: ORGANIZATION_ID,
        recordType: "payroll-run",
        recordId: runId,
        revision: 1,
      }, [SYNTHETIC_PRINCIPAL]);
      return {
        run: {
          id: runId,
          organizationId: ORGANIZATION_ID,
          state: run.state,
          agreementRoot: SYNTHETIC_ROOT,
          manifestRoot: SYNTHETIC_ROOT,
          policyRoot: SYNTHETIC_ROOT,
          fxRoot: SYNTHETIC_ROOT,
          runNullifier: SYNTHETIC_ROOT,
          envelope,
        },
      };
    },
    async checkDeploymentReadiness() {
      return {
        readiness: {
          ready: true,
          blockNumber: 1,
          chainId: "0x534e5f4d41494e",
          sealAddress: "0x1",
          poolAddress: "0x1",
          catalogRegistryAddress: "0x1",
          obligationRegistryAddress: "0x1",
          verifierAddress: "0x1",
          checks: [],
        },
      };
    },
    async registerObligationSchedules(input: {
      schedules: BrowserEvidenceState["schedules"];
    }) {
      const now = new Date();
      let stored: BrowserEvidenceState["schedules"] = [];
      mutate((state) => {
        const incomingAgreementIds = new Set(input.schedules.map(({ agreementId }) => agreementId));
        stored = input.schedules.map((schedule) => ({
          ...schedule,
          materializedAt: new Date(schedule.dueAt) <= now ? now.toISOString() : null,
        }));
        return {
          ...state,
          schedules: [
            ...state.schedules.filter(({ agreementId }) => !incomingAgreementIds.has(agreementId)),
            ...stored,
          ],
        };
      });
      return { schedules: stored.map((schedule) => ({ ...schedule, replayed: false })) };
    },
    async listDueObligationSchedules() {
      const now = Date.now();
      return {
        schedules: readState().schedules.filter((schedule) =>
          schedule.materializedAt && new Date(schedule.dueAt).getTime() <= now),
      };
    },
    async listSettlements() {
      return { settlements: [{
        id: SYNTHETIC_SETTLEMENT_ID,
        runId: SYNTHETIC_SETTLEMENT_RUN_ID,
        workflowType: "payroll",
        subjectRecordId: "",
        state: "finalized",
        tokenTotalsCommitment: SYNTHETIC_ROOT,
        transactionHash: "0x789",
        submittedAt: "2026-08-26T00:00:00.000Z",
        confirmedAt: "2026-08-26T00:01:00.000Z",
        finalizedAt: "2026-08-26T00:02:00.000Z",
        confirmationDepth: 12,
        lastErrorCode: null,
        proofValidityExpiry: null,
        proofVerificationState: "complete",
        proofVerificationLastErrorCode: null,
        createdAt: "2026-08-26T00:00:00.000Z",
        updatedAt: "2026-08-26T00:02:00.000Z",
      }] };
    },
    async listAuditEvents() {
      return { events: [] };
    },
    async listDisclosureGrants() {
      return { grants: [] };
    },
  }) as unknown as PayoClient, [mutate]);

  useEffect(() => {
    window.__PAYO_BROWSER_EVIDENCE__ = {
      reset() {
        writeState(emptyState());
        setRevision((value) => value + 1);
      },
      exportState() {
        const state = readState();
        return {
          organizationId: ORGANIZATION_ID,
          records: latestRecords(state).map((record) => ({
            ...record,
            plaintext: decryptVaultRecord(record.envelope, SYNTHETIC_PRINCIPAL),
            envelopeHash: hashCanonicalJson(record.envelope),
          })),
          runs: state.runs,
          schedules: state.schedules,
        };
      },
      setRuns(runs) {
        mutate((state) => ({ ...state, runs }));
      },
      markLatestClaimSubmitted() {
        mutate((state) => {
          const claimRecord = latestRecords(state)
            .filter(({ recordType }) => recordType === "wage-claim")
            .sort((left, right) => right.createdAt.localeCompare(left.createdAt))[0];
          if (!claimRecord) throw new Error("Create a claim through the Activity UI first.");
          const claim = wageClaimRecordSchema.parse(
            decryptVaultRecord(claimRecord.envelope, SYNTHETIC_PRINCIPAL),
          );
          const revision = claim.revision + 1;
          const submitted = wageClaimRecordSchema.parse({
            ...claim,
            revision,
            updatedAt: new Date().toISOString(),
            claimNullifier: `0x${"31".repeat(32)}`,
            shortfallAtomic: "3",
            token: "STRK",
            proofBundleId: "018f1000-0000-7000-8000-000000000032",
            settlementId: "018f1000-0000-7000-8000-000000000033",
            state: "submitted",
          });
          const envelope = encryptVaultRecord(submitted, {
            schemaVersion: 1,
            organizationId: ORGANIZATION_ID,
            recordType: "wage-claim",
            recordId: submitted.id,
            revision,
          }, [SYNTHETIC_PRINCIPAL]);
          return storeRecord(state, {
            id: submitted.id,
            recordType: "wage-claim",
            revision,
            envelope,
            createdAt: new Date().toISOString(),
          });
        });
      },
    };
    return () => {
      delete window.__PAYO_BROWSER_EVIDENCE__;
    };
  }, [mutate]);

  const value = useMemo<PayoVaultContextValue>(() => ({
    configured: true,
    ready: true,
    authenticated: true,
    principalId: SYNTHETIC_PRINCIPAL.principalId,
    organizations: [{
      id: ORGANIZATION_ID,
      recoveryState: "second_admin",
      keyVersion: 1,
      role: "admin",
      encryptedProfile: encryptVaultRecord({ name: "Phase 3 browser evidence" }, {
        schemaVersion: 1,
        organizationId: ORGANIZATION_ID,
        recordType: "organization-profile",
        recordId: "018f1000-0000-7000-8000-000000000031",
        revision: 1,
      }, [SYNTHETIC_PRINCIPAL]),
      vaultPublicKey: SYNTHETIC_PRINCIPAL.publicKey,
      createdAt: "2026-08-26T00:00:00.000Z",
    }],
    selectedOrganizationId: ORGANIZATION_ID,
    session,
    recoveryReady: true,
    loading: false,
    error: "",
    client,
    sessionExpiresAt: "2026-08-27T23:59:59.000Z",
    login: async () => undefined,
    logout: async () => undefined,
    selectOrganization: () => undefined,
    createWorkspace: async () => undefined,
    unlockWorkspace: async () => undefined,
    importRecoveryPackage: () => undefined,
    downloadRecoveryPackage: () => undefined,
    confirmRecoverySaved: async () => undefined,
    createSecondAdminRequest: async () => undefined,
    addSecondAdministrator: async () => undefined,
    rotateVault: async () => undefined,
    lockWorkspace: () => undefined,
    refreshOrganizations: async () => undefined,
  }), [client, session]);

  return <PayoVaultContext.Provider value={value}>{children}</PayoVaultContext.Provider>;
}
