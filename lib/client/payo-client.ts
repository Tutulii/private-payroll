import { deriveRunNullifier } from "@/lib/crypto/commitments";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  encryptVaultRecord,
  type EncryptedVaultRecord,
  type VaultPrincipal,
} from "@/lib/crypto/vault";
import {
  calculatePayrollManifest,
  type PayrollRunState,
  type PrivatePayrollLine,
} from "@/lib/domain/payroll";
import type { FxSnapshot, PragmaProtectedFxSnapshot } from "@/lib/domain/fx";
import type { DueObligationSignal, ObligationScheduleItem, ObligationScheduleRegistration } from "@/lib/domain/obligation-schedule";
import { generateUuidV7, payrollLineRecordSchema } from "@/lib/domain/records";
import type { EncryptedPayrollIntegrityBundleCreate } from "@/lib/domain/proof-bundle";
import type {
  PayoReadinessRequest,
  PayoReadinessResult,
} from "@/lib/starknet/readiness";
import type { VaultRotationRequest } from "@/lib/domain/vault-lifecycle";
import type { SignedCapability } from "@/lib/domain/capability";
import { decodeRemoteProofResponse, type RemoteProofRequest } from "@/lib/proof/remote-prover";
import type { ProofWorkerSuccess } from "@/lib/proof/protocol";
import type { SerializedPayrollIntegrityBuildRequest } from "@/lib/proof/input-builder";
import type { ReadySessionPayload } from "@/lib/auth/ready-session";
import type { TypedData } from "starknet";

type AccessTokenProvider = () => Promise<string | null>;

export class PayoApiError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly status: number,
  ) {
    super(message);
  }
}

export type PreparedEncryptedRun = {
  id: string;
  organizationId: string;
  cycleId: string;
  revision: number;
  dueAt: string;
  ciphertext: string;
  envelope: EncryptedVaultRecord;
  agreementRoot: `0x${string}`;
  manifestRoot: `0x${string}`;
  policyRoot: `0x${string}`;
  fxRoot: `0x${string}`;
  runNullifier: `0x${string}`;
  lineRecords: Array<{
    id: string;
    revision: number;
    envelope: EncryptedVaultRecord;
  }>;
};

export function prepareEncryptedPayrollRun(input: {
  id: string;
  organizationId: string;
  cycleId: string;
  revision: number;
  dueAt: string;
  lines: readonly PrivatePayrollLine[];
  lineRecordMetadata: readonly {
    agreementId: string;
    payeeId: string;
    recipientCommitment: `0x${string}`;
    policyCommitment: `0x${string}`;
  }[];
  organizationSecret: string;
  principals: readonly VaultPrincipal[];
  proofBinding: {
    agreementRoot: `0x${string}`;
    manifestRoot: `0x${string}`;
    policyRoot: `0x${string}`;
    fxRoot: `0x${string}`;
    runNullifier: `0x${string}`;
  };
  claimProofSource: {
    buildInput: SerializedPayrollIntegrityBuildRequest;
  };
  now?: Date;
}): PreparedEncryptedRun {
  const manifest = calculatePayrollManifest(input.lines);
  if (input.lineRecordMetadata.length !== manifest.lines.length) {
    throw new Error("Every encrypted payroll line requires authenticated record metadata.");
  }
  const metadataByAgreement = new Map(input.lineRecordMetadata.map((metadata) => [metadata.agreementId, metadata]));
  if (metadataByAgreement.size !== manifest.lines.length) {
    throw new Error("Encrypted payroll-line metadata must use unique agreement identifiers.");
  }
  const expectedNullifier = deriveRunNullifier({
    organizationSecret: input.organizationSecret,
    cycleId: input.cycleId,
    revision: input.revision,
  });
  if (BigInt(expectedNullifier) !== BigInt(input.proofBinding.runNullifier)) {
    throw new Error("Encrypted payroll run does not match its proof-bound nullifier.");
  }
  for (const [label, value] of Object.entries(input.proofBinding)) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`${label} is not a canonical 32-byte proof root.`);
  }
  const envelope = encryptVaultRecord(
    {
      schemaVersion: 1,
      cycleId: input.cycleId,
      dueAt: input.dueAt,
      ...input.proofBinding,
      manifest,
      claimProofSource: input.claimProofSource,
    },
    {
      schemaVersion: 1,
      organizationId: input.organizationId,
      recordType: "payroll-run",
      recordId: input.id,
      revision: input.revision,
    },
    input.principals,
  );
  const now = input.now ?? new Date();
  const timestamp = now.toISOString();
  const lineRecords = manifest.lines.map((line, index) => {
    const metadata = metadataByAgreement.get(line.agreementId);
    if (!metadata) throw new Error(`Payroll line ${line.agreementId} is missing its encrypted record metadata.`);
    const id = generateUuidV7(now.getTime() + index + 1);
    const leafCommitment = hashCanonicalJson({
      domain: "PAYO_PAYROLL_LINE_RECORD_V1",
      runId: input.id,
      agreementId: line.agreementId,
      payeeId: metadata.payeeId,
      recipientCommitment: metadata.recipientCommitment,
      grossAtomic: line.grossAtomic,
      deductionsAtomic: line.deductionsAtomic,
      netAtomic: line.netAtomic,
      token: line.token,
      policyCommitment: metadata.policyCommitment,
      scheduleCommitment: line.scheduleCommitment,
      lineSalt: line.salt,
    });
    const record = payrollLineRecordSchema.parse({
      schemaVersion: 1,
      id,
      organizationId: input.organizationId,
      revision: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
      runId: input.id,
      agreementId: line.agreementId,
      payeeId: metadata.payeeId,
      token: line.token,
      grossAtomic: line.grossAtomic,
      deductionsAtomic: line.deductionsAtomic,
      netAtomic: line.netAtomic,
      recipientCommitment: metadata.recipientCommitment,
      policyCommitment: metadata.policyCommitment,
      scheduleCommitment: line.scheduleCommitment,
      leafCommitment,
    });
    return {
      id,
      revision: 1,
      envelope: encryptVaultRecord(record, {
        schemaVersion: 1,
        organizationId: input.organizationId,
        recordType: "payroll-line",
        recordId: id,
        revision: 1,
      }, input.principals),
    };
  });
  return {
    id: input.id,
    organizationId: input.organizationId,
    cycleId: input.cycleId,
    revision: input.revision,
    dueAt: input.dueAt,
    ciphertext: envelope.ciphertext,
    envelope,
    lineRecords,
    ...input.proofBinding,
  };
}

export class PayoClient {
  constructor(
    private readonly getAccessToken: AccessTokenProvider,
    private readonly baseUrl = "",
  ) {}

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const accessToken = await this.getAccessToken();
    if (!accessToken) throw new Error("Sign in before accessing the PAYO vault.");
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/json",
        ...(init.body ? { "content-type": "application/json" } : {}),
        ...init.headers,
      },
    });
    const body = await response.json();
    if (!response.ok) {
      throw new PayoApiError(
        body?.error?.message ?? "PAYO API request failed.",
        body?.error?.code ?? "PAYO_API_ERROR",
        response.status,
      );
    }
    return body as T;
  }

  private async unauthenticatedRequest<T>(path: string, init: RequestInit): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        accept: "application/json",
        ...(init.body ? { "content-type": "application/json" } : {}),
        ...init.headers,
      },
    });
    const body = await response.json();
    if (!response.ok) {
      throw new PayoApiError(
        body?.error?.message ?? "PAYO authentication failed.",
        body?.error?.code ?? "AUTH_ERROR",
        response.status,
      );
    }
    return body as T;
  }

  async createReadyAuthenticationChallenge(input: { walletAddress: string; chainId: string }) {
    return this.unauthenticatedRequest<{
      challenge: { challengeId: string; expiresAt: string; typedData: TypedData };
    }>("/api/v1/auth/challenge", { method: "POST", body: JSON.stringify(input) });
  }

  async verifyReadyAuthentication(input: { challengeId: string; signature: string[] }) {
    return this.unauthenticatedRequest<{ session: ReadySessionPayload }>(
      "/api/v1/auth/verify",
      { method: "POST", body: JSON.stringify(input) },
    );
  }

  async revokeReadyAuthentication(): Promise<void> {
    const accessToken = await this.getAccessToken();
    if (!accessToken) return;
    const response = await fetch(`${this.baseUrl}/api/v1/auth/session`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok && response.status !== 401) {
      const body = await response.json();
      throw new PayoApiError(
        body?.error?.message ?? "PAYO session revocation failed.",
        body?.error?.code ?? "AUTH_ERROR",
        response.status,
      );
    }
  }

  async createReadyRecoveryLink(input: { organizationId: string; legacyPrincipalId: string }) {
    return this.request<{
      recoveryLink: { challengeId: string; expiresAt: string; envelope: EncryptedVaultRecord };
    }>("/api/v1/auth/recovery-link", { method: "POST", body: JSON.stringify(input) });
  }

  async completeReadyRecoveryLink(input: { challengeId: string; proof: string }) {
    return this.request<{ session: ReadySessionPayload }>(
      "/api/v1/auth/recovery-link",
      { method: "PATCH", body: JSON.stringify(input) },
    );
  }

  async createOrganization(input: {
    organizationId: string;
    encryptedProfile: EncryptedVaultRecord;
    vaultPublicKey: string;
    initialPrincipal: {
      recordId: string;
      envelope: EncryptedVaultRecord;
    };
  }) {
    return this.request<{ organization: { id: string; createdAt: string } }>(
      "/api/v1/organizations",
      { method: "POST", body: JSON.stringify(input) },
    );
  }

  async createPayrollRun(input: PreparedEncryptedRun) {
    return this.request<{ run: Record<string, unknown> }>("/api/v1/runs", {
      method: "POST",
      body: JSON.stringify({
        id: input.id,
        organizationId: input.organizationId,
        cycleId: input.cycleId,
        revision: input.revision,
        dueAt: input.dueAt,
        ciphertext: input.ciphertext,
        envelope: input.envelope,
        agreementRoot: input.agreementRoot,
        manifestRoot: input.manifestRoot,
        policyRoot: input.policyRoot,
        fxRoot: input.fxRoot,
        runNullifier: input.runNullifier,
        lineRecords: input.lineRecords,
      }),
    });
  }

  async listPayrollRuns(organizationId: string) {
    return this.request<{ runs: Array<Record<string, unknown>> }>(
      `/api/v1/runs?organizationId=${encodeURIComponent(organizationId)}`,
    );
  }

  async getPayrollRun(runId: string) {
    return this.request<{
      run: {
        id: string;
        organizationId: string;
        state: PayrollRunState;
        agreementRoot: string | null;
        manifestRoot: string | null;
        policyRoot: string | null;
        fxRoot: string | null;
        runNullifier: string | null;
        envelope: EncryptedVaultRecord;
      };
    }>(`/api/v1/runs/${encodeURIComponent(runId)}`);
  }

  async transitionPayrollRun(input: {
    runId: string;
    state: PayrollRunState;
    transactionHash?: string;
  }) {
    return this.request<{ run: Record<string, unknown> }>(
      `/api/v1/runs/${encodeURIComponent(input.runId)}`,
      {
        method: "PATCH",
        body: JSON.stringify({
          state: input.state,
          ...(input.transactionHash ? { transactionHash: input.transactionHash } : {}),
        }),
      },
    );
  }

  async getSealedPayrollRecovery(runId: string) {
    return this.request<{
      recovery: {
        recoveryKind: "submission" | "verification";
        runId: string;
        proofBundleId: string;
        settlementId?: string;
        transactionHash: string;
        blockNumber: string;
      };
    }>(`/api/v1/runs/${encodeURIComponent(runId)}/seal-recovery`);
  }

  async getFxSnapshots(tokens: readonly ("STRK" | "USDC")[]) {
    return this.request<{ blockNumber: number; snapshots: FxSnapshot[] }>(
      `/api/v1/fx-snapshots?tokens=${encodeURIComponent([...new Set(tokens)].join(","))}`,
    );
  }

  async getProtectedFxSnapshots(tokens: readonly ("STRK" | "USDC")[]) {
    return this.request<{
      blockNumber: number;
      blockTimestamp: number;
      snapshots: PragmaProtectedFxSnapshot[];
    }>(
      `/api/v1/fx-snapshots?profile=phase3&tokens=${encodeURIComponent([...new Set(tokens)].join(","))}`,
    );
  }

  async getPayrollFxCatalog(input: {
    organizationId: string;
    medianTokens: readonly ("STRK" | "USDC")[];
    protectedTokens: readonly ("STRK" | "USDC")[];
  }) {
    const query = new URLSearchParams({
      organizationId: input.organizationId,
      medianTokens: [...new Set(input.medianTokens)].join(","),
      protectedTokens: [...new Set(input.protectedTokens)].join(","),
    });
    return this.request<{
      snapshots: FxSnapshot[];
      catalogRoot: `0x${string}`;
      publicationWindow: { observedAt: number; maximumAgeSeconds: number; expiresAt: number };
      publicationTicket: string;
      sourceBlocks: { protected: number | null; median: number | null };
    }>(`/api/v1/fx-catalog?${query.toString()}`);
  }

  async publishPayrollFxRoot(input: {
    organizationId: string;
    catalogRoot: `0x${string}`;
    publicationTicket: string;
    proofVersion: 1 | 2;
    shards: [string[], string[]];
  }) {
    return this.request<{
      catalogRoot: `0x${string}`;
      alreadyActive: boolean;
      transactionHash: string | null;
    }>("/api/v1/fx-publications", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async provePayrollIntegrityRemotely(input: Omit<RemoteProofRequest, "version" | "requestId"> & {
    proverBaseUrl: string;
  }): Promise<ProofWorkerSuccess> {
    const endpoint = new URL("/api/v1/prove-payroll", input.proverBaseUrl);
    if (endpoint.protocol !== "https:" && endpoint.hostname !== "127.0.0.1" && endpoint.hostname !== "localhost") {
      throw new Error("The self-hosted prover must use HTTPS.");
    }
    const accessToken = await this.getAccessToken();
    if (!accessToken) throw new Error("Sign in before using the self-hosted prover.");
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 30 * 60_000);
    try {
      let response: Response;
      try {
        response = await fetch(endpoint, {
          method: "POST",
          headers: {
            authorization: `Bearer ${accessToken}`,
            accept: "application/json",
            "content-type": "application/json",
          },
          body: JSON.stringify({
            version: 1,
            requestId: crypto.randomUUID(),
            encryptedWitness: input.encryptedWitness,
            principal: input.principal,
          } satisfies RemoteProofRequest),
          signal: controller.signal,
        });
      } catch {
        if (controller.signal.aborted) {
          throw new PayoApiError(
            "The remote ZK prover did not respond within 30 minutes.",
            "PROVER_TIMEOUT",
            408,
          );
        }
        const browserOrigin = window.location.origin;
        throw new PayoApiError(
          `The remote ZK prover could not be reached from ${browserOrigin}. Local PAYO sessions cannot use a prover authenticated against a different deployment; use the deployed PAYO origin or configure a same-environment prover.`,
          "PROVER_FETCH_FAILED",
          0,
        );
      }
      const body = await response.json();
      if (!response.ok) {
        throw new PayoApiError(
          body?.error?.message ?? "The self-hosted prover request failed.",
          body?.error?.code ?? "PROVER_ERROR",
          response.status,
        );
      }
      return decodeRemoteProofResponse(body);
    } finally {
      window.clearTimeout(timeout);
    }
  }

  async checkDeploymentReadiness(input: PayoReadinessRequest) {
    return this.request<{ readiness: PayoReadinessResult }>(
      "/api/v1/deployment-readiness",
      { method: "POST", body: JSON.stringify(input) },
    );
  }

  async listOrganizations() {
    return this.request<{
      organizations: Array<{
        id: string;
        encryptedProfile: EncryptedVaultRecord;
        recoveryState: "required" | "package_downloaded" | "second_admin";
        recoveryConfiguredAt: string | null;
        keyVersion: number;
        role: "admin" | "operator" | "reviewer";
        vaultPublicKey: string;
        createdAt: string;
      }>;
    }>("/api/v1/organizations");
  }

  async acknowledgeRecoveryPackage(organizationId: string, packageHash: string) {
    return this.request<{ vault: Record<string, unknown> }>(
      `/api/v1/organizations/${encodeURIComponent(organizationId)}/vault`,
      { method: "POST", body: JSON.stringify({ packageHash }) },
    );
  }

  async addSecondAdministrator(input: {
    organizationId: string;
    grantId: string;
    granteePrincipalId: string;
    vaultPublicKey: string;
    keyVersion: number;
    envelope: EncryptedVaultRecord;
    encryptedProfile: EncryptedVaultRecord;
  }) {
    const { organizationId, ...body } = input;
    return this.request<{ grant: Record<string, unknown> }>(
      `/api/v1/organizations/${encodeURIComponent(organizationId)}/second-admins`,
      { method: "POST", body: JSON.stringify(body) },
    );
  }

  async getVaultKeyGrant(organizationId: string) {
    return this.request<{
      grant: { id: string; keyVersion: number; envelope: EncryptedVaultRecord; createdAt: string };
    }>(`/api/v1/organizations/${encodeURIComponent(organizationId)}/vault-key-grant`);
  }

  async rotateVault(organizationId: string, rotation: VaultRotationRequest) {
    return this.request<{ vault: { keyVersion: number; recoveryState: "package_downloaded" | "second_admin" } }>(
      `/api/v1/organizations/${encodeURIComponent(organizationId)}/vault/rotation`,
      { method: "POST", body: JSON.stringify(rotation) },
    );
  }

  async getVaultState(organizationId: string) {
    return this.request<{ vault: Record<string, unknown> }>(
      `/api/v1/organizations/${encodeURIComponent(organizationId)}/vault`,
    );
  }

  async storeEncryptedRecord(input: {
    organizationId: string;
    recordId: string;
    recordType: string;
    revision: number;
    envelope: EncryptedVaultRecord;
  }) {
    return this.request<{ record: Record<string, unknown> }>("/api/v1/vault-records", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async storeEncryptedRecords(input: {
    organizationId: string;
    records: Array<{
      recordId: string;
      recordType: string;
      revision: number;
      envelope: EncryptedVaultRecord;
    }>;
  }) {
    return this.request<{ records: Array<Record<string, unknown>> }>("/api/v1/vault-records", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async getEncryptedRecord(input: {
    organizationId: string;
    recordId: string;
    revision?: number;
  }) {
    const search = new URLSearchParams({
      organizationId: input.organizationId,
      recordId: input.recordId,
    });
    if (input.revision !== undefined) search.set("revision", String(input.revision));
    return this.request<{ record: Record<string, unknown> }>(`/api/v1/vault-records?${search}`);
  }

  async listEncryptedRecords(organizationId: string, recordType?: string) {
    const search = new URLSearchParams({ organizationId });
    if (recordType) search.set("recordType", recordType);
    return this.request<{
      records: Array<{
        id: string;
        recordType: string;
        revision: number;
        envelopeHash: string;
        supersededAt: string | null;
        createdAt: string;
      }>;
    }>(`/api/v1/vault-records?${search}`);
  }

  async registerObligationSchedules(input: {
    organizationId: string;
    schedules: ObligationScheduleRegistration[];
  }) {
    return this.request<{
      schedules: Array<ObligationScheduleItem & { materializedAt: string | null; replayed: boolean }>;
    }>("/api/v1/obligation-schedules", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async listDueObligationSchedules(organizationId: string, limit = 100) {
    const search = new URLSearchParams({ organizationId, limit: String(limit) });
    return this.request<{ schedules: DueObligationSignal[] }>(`/api/v1/obligation-schedules?${search}`);
  }

  async registerEncryptedAgentCapability(input: {
    signedCapability: SignedCapability;
    recordId: string;
    revision: 1;
    envelope: EncryptedVaultRecord;
  }) {
    return this.request<{ capability: { id: string; capabilityHash: string; expiresAt: string; replayed: boolean } }>(
      "/api/v1/capabilities",
      { method: "POST", body: JSON.stringify(input) },
    );
  }

  async revokeEncryptedAgentCapability(input: {
    capabilityId: string;
    organizationId: string;
    revision: number;
    envelope: EncryptedVaultRecord;
  }) {
    return this.request<{ capability: { id: string; revokedAt: string; replayed: boolean } }>(
      "/api/v1/capabilities",
      { method: "DELETE", body: JSON.stringify(input) },
    );
  }

  async createSettlementIntent(input: {
    id: string;
    organizationId: string;
    runId: string;
    workflowType: "payroll" | "wage_claim" | "wage_remediation";
    subjectRecordId: string;
    walletRequestId: string;
    idempotencyKey: string;
    tokenTotalsCommitment: string;
    envelope: EncryptedVaultRecord;
  }) {
    const { idempotencyKey, ...body } = input;
    return this.request<{ settlement: Record<string, unknown> }>("/api/v1/settlements", {
      method: "POST",
      headers: { "idempotency-key": idempotencyKey },
      body: JSON.stringify(body),
    });
  }

  async listSettlements(organizationId: string, limit = 50) {
    const search = new URLSearchParams({ organizationId, limit: String(limit) });
    return this.request<{
      settlements: Array<{
        id: string;
        runId: string;
        workflowType: "payroll" | "wage_claim" | "wage_remediation";
        subjectRecordId: string;
        state: string;
        tokenTotalsCommitment: string;
        transactionHash: string | null;
        submittedAt: string | null;
        confirmedAt: string | null;
        finalizedAt: string | null;
        blockNumber: string | null;
        confirmationDepth: number;
        lastErrorCode: string | null;
        createdAt: string;
        updatedAt: string;
      }>;
    }>(`/api/v1/settlements?${search}`);
  }

  async listAuditEvents(organizationId: string, limit = 100) {
    const search = new URLSearchParams({ organizationId, limit: String(limit) });
    return this.request<{
      events: Array<{
        id: string;
        actorId: string;
        action: string;
        subjectId: string | null;
        metadata: Record<string, unknown>;
        createdAt: string;
      }>;
    }>(`/api/v1/audit-events?${search}`);
  }

  async createReceipt(input: {
    id: string;
    organizationId: string;
    runId: string;
    settlementId: string;
    scope: "employer" | "worker" | "auditor" | "tax";
    granteePrincipalId: string;
    packageCommitment: string;
    expiresAt?: string;
    envelope: EncryptedVaultRecord;
  }) {
    return this.request<{ receipt: Record<string, unknown> }>("/api/v1/receipts", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async listReceipts(organizationId: string) {
    const search = new URLSearchParams({ organizationId });
    return this.request<{ receipts: Array<Record<string, unknown>> }>(`/api/v1/receipts?${search}`);
  }

  async createDisclosureGrant(input: {
    id: string;
    organizationId: string;
    runId: string;
    granteePrincipalId: string;
    fieldScope: string[];
    validAfter: string;
    expiresAt: string;
    envelope: EncryptedVaultRecord;
  }) {
    return this.request<{ grant: Record<string, unknown> }>("/api/v1/disclosures", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async listDisclosureGrants(organizationId: string) {
    const search = new URLSearchParams({ organizationId });
    return this.request<{
      grants: Array<{
        id: string;
        runId: string;
        granteePrincipalId: string;
        fieldScope: string[];
        validAfter: string;
        expiresAt: string;
        revokedAt: string | null;
        createdAt: string;
      }>;
    }>(`/api/v1/disclosures?${search}`);
  }

  async revokeDisclosureGrant(organizationId: string, grantId: string) {
    return this.request<{ grant: Record<string, unknown> }>("/api/v1/disclosures", {
      method: "DELETE",
      body: JSON.stringify({ organizationId, grantId }),
    });
  }

  async storeEncryptedProofBundle(input: EncryptedPayrollIntegrityBundleCreate) {
    return this.request<{ proofBundle: Record<string, unknown> }>("/api/v1/proof-packages", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async recordSettlementSubmission(settlementId: string, transactionHash: string) {
    return this.request<{ settlement: Record<string, unknown> }>(
      `/api/v1/settlements/${encodeURIComponent(settlementId)}`,
      { method: "PATCH", body: JSON.stringify({ transactionHash }) },
    );
  }

  async getSettlement(settlementId: string) {
    return this.request<{ settlement: Record<string, unknown> }>(
      `/api/v1/settlements/${encodeURIComponent(settlementId)}`,
    );
  }

  async cancelSettlementApproval(settlementId: string) {
    return this.request<{ settlement: Record<string, unknown> }>(
      `/api/v1/settlements/${encodeURIComponent(settlementId)}`,
      { method: "DELETE" },
    );
  }

  async enqueueProofVerification(input: {
    settlementId: string;
    proofBundleId: string;
    shards: [string[], string[]];
  }) {
    return this.request<{ proofVerification: Record<string, unknown> }>(
      `/api/v1/settlements/${encodeURIComponent(input.settlementId)}/proof-verification`,
      {
        method: "POST",
        body: JSON.stringify({ proofBundleId: input.proofBundleId, shards: input.shards }),
      },
    );
  }

  async getProofVerification(settlementId: string) {
    return this.request<{ proofVerification: Record<string, unknown> }>(
      `/api/v1/settlements/${encodeURIComponent(settlementId)}/proof-verification`,
    );
  }
}
