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
import type {
  ObligationClaimAccessGrantSummary,
  ObligationSnapshotPlanCreate,
  ObligationSnapshotPlanPublic,
  ObligationSnapshotPlanSummary,
} from "@/lib/domain/obligation-snapshot-plan";
import { generateUuidV7, payrollLineRecordSchema } from "@/lib/domain/records";
import type { EncryptedPayoProofBundleCreate } from "@/lib/domain/proof-bundle";
import type { WorkerClaimCreate, WorkerClaimSummary } from "@/lib/domain/worker-claim";
import type { WageRemediationCreate, WageRemediationSummary } from "@/lib/domain/wage-remediation";
import type {
  EmployerStatementCreate,
  EmployerStatementSummary,
  PayrollStatementEvidenceGrantSummary,
} from "@/lib/domain/employer-statement";
import type {
  PayoReadinessRequest,
  PayoReadinessResult,
} from "@/lib/starknet/readiness";
import type { VaultRotationRequest } from "@/lib/domain/vault-lifecycle";
import type { SignedCapability } from "@/lib/domain/capability";
import type { AgentExecutionReceipt } from "@/lib/domain/agent-execution";
import type { DirectPrivacyAccountConfig } from "@/lib/domain/direct-privacy";
import { decodeRemoteProofJobResponse, decodeRemoteProofResponse, type RemoteProofRequest } from "@/lib/proof/remote-prover";
import type {
  ExceptionProofWorkerSuccess,
  PayoProofWorkerSuccess,
  ProofWorkerSuccess,
} from "@/lib/proof/protocol";
import type { SerializedPayrollIntegrityBuildRequest } from "@/lib/proof/input-builder";
import type { ReadySessionPayload } from "@/lib/auth/ready-session";
import type { Call, TypedData } from "starknet";

type AccessTokenProvider = () => Promise<string | null>;

export type ExceptionAuthorizationStatus = {
  id: string;
  organizationId: string;
  runId: string;
  proofBundleId: string;
  workflowType: "wage_claim" | "wage_remediation";
  subjectRecordId: string;
  state: "pending" | "leased" | "complete" | "dead";
  transactionHash: string | null;
  attempts: number;
  lastErrorCode: string | null;
  lastErrorMessage: string | null;
  authorizedAt: string | null;
  createdAt: string;
  updatedAt: string;
  replayed?: boolean;
  requeued?: boolean;
};

export type PayrollAuthorizationStatus = {
  id: string;
  organizationId: string;
  runId: string;
  payrollProofBundleId: string;
  snapshotProofBundleId: string;
  state: "pending" | "leased" | "complete" | "dead";
  activeStep: "begin" | "snapshot" | "shard0" | "shard1";
  transactionHash: string | null;
  beginTransactionHash: string | null;
  snapshotTransactionHash: string | null;
  shard0TransactionHash: string | null;
  shard1TransactionHash: string | null;
  attempts: number;
  lastErrorCode: string | null;
  lastErrorMessage: string | null;
  authorizedAt: string | null;
  createdAt: string;
  updatedAt: string;
  replayed?: boolean;
};

export type DirectPrivacyAccountClientSummary = {
  id: string;
  capabilityId: string;
  stateVersion: number;
  authorizedRunCount: number;
  activationState: "pending" | "active";
  activeExecutionId: string | null;
  activeLeaseExpiresAt: string | null;
  createdAt: string;
  updatedAt: string;
  config: {
    policyAccountAddress: string;
    policyId: string;
    validBeforeUnix: string;
    maxCallsPerPeriod: number;
    maxCallCount: number;
  };
};

export type DirectPrivacyAccountClientPublic = {
  id: string;
  config: DirectPrivacyAccountConfig;
  proofPrincipal: VaultPrincipal;
  stateVersion: number;
  authorizedRunCount: number;
  activationState: "pending" | "active";
  activation: {
    blockNumber: string;
    blockHash: string;
    classHash: string;
    blockTimestamp: string;
    activatedAt: string;
  } | null;
};
export type AgentAccessTokenSummary = {
  tokenId: string;
  capabilityId: string;
  expiresAt: string;
  revokedAt: string | null;
  lastSeenAt: string | null;
  createdAt: string;
};

export type AgentMcpConnection = AgentAccessTokenSummary & {
  accessToken: string;
  organizationId: string;
  principalId: string;
  issuerPublicKey: string;
};


export class PayoApiError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly status: number,
  ) {
    super(message);
  }
}

async function parseApiResponse(
  response: Response,
  fallbackMessage: string,
  fallbackCode: string,
): Promise<unknown> {
  const rawBody = await response.text();
  if (!rawBody.trim()) {
    throw new PayoApiError(
      response.ok
        ? "PAYO received an empty response from the service. The request is safe to retry."
        : `${fallbackMessage} The service returned an empty response.`,
      `${fallbackCode}_EMPTY_RESPONSE`,
      response.ok ? 502 : response.status,
    );
  }
  try {
    return JSON.parse(rawBody) as unknown;
  } catch {
    throw new PayoApiError(
      `${fallbackMessage} The service returned an invalid response.`,
      `${fallbackCode}_INVALID_RESPONSE`,
      response.ok ? 502 : response.status,
    );
  }
}

function retryableApiRead(error: unknown): boolean {
  return error instanceof PayoApiError
    ? error.status === 408 || error.status === 429 || error.status >= 500
    : error instanceof TypeError;
}

function retryDelay(attempt: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 300 * (attempt + 1)));
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
  obligationSnapshotPlanId?: string;
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
  obligationSnapshotPlanId?: string;
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
      ...(input.obligationSnapshotPlanId
        ? { obligationSnapshotPlanId: input.obligationSnapshotPlanId }
        : {}),
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
    ...(input.obligationSnapshotPlanId
      ? { obligationSnapshotPlanId: input.obligationSnapshotPlanId }
      : {}),
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
    const method = (init.method ?? "GET").toUpperCase();
    const maximumAttempts = method === "GET" || method === "HEAD" ? 3 : 1;
    const requestDeadline = Date.now() + (maximumAttempts > 1 ? 12_000 : 20_000);
    let lastError: unknown;
    for (let attempt = 0; attempt < maximumAttempts; attempt += 1) {
      const remainingMs = requestDeadline - Date.now();
      if (remainingMs <= 0) break;
      const controller = new AbortController();
      const forwardAbort = () => controller.abort(init.signal?.reason);
      init.signal?.addEventListener("abort", forwardAbort, { once: true });
      const timeout = setTimeout(() => controller.abort("PAYO_API_TIMEOUT"), remainingMs);
      try {
        const response = await fetch(`${this.baseUrl}${path}`, {
          ...init,
          signal: controller.signal,
          headers: {
            authorization: `Bearer ${accessToken}`,
            accept: "application/json",
            ...(init.body ? { "content-type": "application/json" } : {}),
            ...init.headers,
          },
        });
        const body = await parseApiResponse(response, "PAYO API request failed.", "PAYO_API");
        if (!response.ok) {
          const apiBody = body as { error?: { message?: string; code?: string } };
          throw new PayoApiError(
            apiBody?.error?.message ?? "PAYO API request failed.",
            apiBody?.error?.code ?? "PAYO_API_ERROR",
            response.status,
          );
        }
        return body as T;
      } catch (error) {
        lastError = controller.signal.aborted && !init.signal?.aborted
          ? new PayoApiError(
              "PAYO's data service did not respond before the request deadline.",
              "PAYO_API_TIMEOUT",
              504,
            )
          : error instanceof TypeError
          ? new PayoApiError(
              "PAYO could not reach its data service. The request is safe to retry.",
              "PAYO_API_NETWORK_ERROR",
              503,
            )
          : error;
        if (attempt + 1 >= maximumAttempts || !retryableApiRead(lastError)) throw lastError;
        await retryDelay(attempt);
      } finally {
        clearTimeout(timeout);
        init.signal?.removeEventListener("abort", forwardAbort);
      }
    }
    throw lastError ?? new PayoApiError(
      "PAYO's data service did not respond before the request deadline.",
      "PAYO_API_TIMEOUT",
      504,
    );
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
    const body = await parseApiResponse(response, "PAYO authentication failed.", "AUTH");
    if (!response.ok) {
      const apiBody = body as { error?: { message?: string; code?: string } };
      throw new PayoApiError(
        apiBody?.error?.message ?? "PAYO authentication failed.",
        apiBody?.error?.code ?? "AUTH_ERROR",
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
      const body = await parseApiResponse(response, "PAYO session revocation failed.", "AUTH");
      const apiBody = body as { error?: { message?: string; code?: string } };
      throw new PayoApiError(
        apiBody?.error?.message ?? "PAYO session revocation failed.",
        apiBody?.error?.code ?? "AUTH_ERROR",
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
        ...(input.obligationSnapshotPlanId
          ? { obligationSnapshotPlanId: input.obligationSnapshotPlanId }
          : {}),
        lineRecords: input.lineRecords,
      }),
    });
  }

  async listObligationClaimAccessGrants() {
    return this.request<{ grants: ObligationClaimAccessGrantSummary[] }>(
      "/api/v1/claim-access",
    );
  }

  async createWorkerClaim(input: WorkerClaimCreate) {
    return this.request<{ claim: WorkerClaimSummary & { replayed: boolean } }>(
      "/api/v1/worker-claims",
      { method: "POST", body: JSON.stringify(input) },
    );
  }

  async listWorkerClaims(organizationId?: string) {
    const query = organizationId
      ? "?" + new URLSearchParams({ organizationId }).toString()
      : "";
    return this.request<{ claims: WorkerClaimSummary[] }>(
      "/api/v1/worker-claims" + query,
    );
  }


  async createWageRemediation(input: WageRemediationCreate) {
    return this.request<{
      remediation: WageRemediationSummary & { replayed: boolean };
    }>("/api/v1/wage-remediations", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async listWageRemediations(organizationId?: string) {
    const query = organizationId
      ? "?" + new URLSearchParams({ organizationId }).toString()
      : "";
    return this.request<{ remediations: WageRemediationSummary[] }>(
      "/api/v1/wage-remediations" + query,
    );
  }

  async getWageRemediation(remediationId: string) {
    return this.request<{ remediation: WageRemediationSummary }>(
      "/api/v1/wage-remediations/" + encodeURIComponent(remediationId),
    );
  }

  async attachWageRemediationSettlement(input: {
    remediationId: string;
    settlementId: string;
  }) {
    return this.request<{ remediation: WageRemediationSummary }>(
      "/api/v1/wage-remediations/" + encodeURIComponent(input.remediationId),
      {
        method: "PATCH",
        body: JSON.stringify({ settlementId: input.settlementId }),
      },
    );
  }

  async createObligationSnapshotPlan(input: ObligationSnapshotPlanCreate) {
    return this.request<{
      plan: ObligationSnapshotPlanSummary & { replayed: boolean };
    }>("/api/v1/obligation-snapshots", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async listObligationSnapshotPlans(organizationId: string) {
    const query = new URLSearchParams({ organizationId });
    return this.request<{ plans: ObligationSnapshotPlanSummary[] }>(
      `/api/v1/obligation-snapshots?${query.toString()}`,
    );
  }

  async findRegisteredObligationSnapshotPlan(input: {
    organizationId: string;
    cycleId: string;
    agreementRoot: `0x${string}`;
  }) {
    const query = new URLSearchParams(input);
    return this.request<{ plan: ObligationSnapshotPlanPublic }>(
      `/api/v1/obligation-snapshots?${query.toString()}`,
    );
  }

  async getObligationSnapshotPlan(planId: string) {
    return this.request<{ plan: ObligationSnapshotPlanPublic }>(
      `/api/v1/obligation-snapshots/${encodeURIComponent(planId)}`,
    );
  }

  async recordObligationSnapshotSubmission(input: {
    planId: string;
    transactionHash: string;
  }) {
    return this.request<{
      plan: ObligationSnapshotPlanSummary & { replayed: boolean };
    }>(`/api/v1/obligation-snapshots/${encodeURIComponent(input.planId)}`, {
      method: "PATCH",
      body: JSON.stringify({ transactionHash: input.transactionHash }),
    });
  }

  async reconcileObligationSnapshotPlan(planId: string) {
    return this.request<{
      plan: ObligationSnapshotPlanSummary & { replayed: boolean };
      blockNumber: number;
    }>(`/api/v1/obligation-snapshots/${encodeURIComponent(planId)}`, {
      method: "PUT",
    });
  }

  async createEmployerStatement(input: EmployerStatementCreate) {
    return this.request<{
      statement: EmployerStatementSummary & { replayed: boolean };
    }>("/api/v1/employer-statements", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async listEmployerStatements(organizationId: string) {
    const query = new URLSearchParams({ organizationId });
    return this.request<{ statements: EmployerStatementSummary[] }>(
      "/api/v1/employer-statements?" + query.toString(),
    );
  }

  async getEmployerStatement(statementId: string) {
    return this.request<{ statement: EmployerStatementSummary }>(
      "/api/v1/employer-statements/" + encodeURIComponent(statementId),
    );
  }

  async recordEmployerStatementSubmission(input: {
    statementId: string;
    transactionHash: string;
  }) {
    return this.request<{
      statement: EmployerStatementSummary & { replayed: boolean };
    }>("/api/v1/employer-statements/" + encodeURIComponent(input.statementId), {
      method: "PATCH",
      body: JSON.stringify({ transactionHash: input.transactionHash }),
    });
  }

  async reconcileEmployerStatement(statementId: string) {
    return this.request<{
      statement: EmployerStatementSummary & { replayed: boolean };
      blockNumber: number;
    }>("/api/v1/employer-statements/" + encodeURIComponent(statementId), {
      method: "PUT",
    });
  }

  async listPayrollStatementEvidence() {
    return this.request<{ evidence: PayrollStatementEvidenceGrantSummary[] }>(
      "/api/v1/statement-evidence",
    );
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
        obligationSnapshotPlanId: string | null;
        transactionHash: string | null;
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
    type FxPublicationJob = {
      id: string;
      catalogRoot: `0x${string}`;
      state: "pending" | "leased" | "complete" | "dead";
      transactionHash: string | null;
      attempts: number;
      lastErrorCode: string | null;
      lastErrorMessage: string | null;
    };
    const queued = await this.request<{ job: FxPublicationJob }>("/api/v1/fx-publications", {
      method: "POST",
      body: JSON.stringify(input),
    });
    let job = queued.job;
    const deadline = Date.now() + 20 * 60_000;
    const query = new URLSearchParams({
      organizationId: input.organizationId,
      catalogRoot: input.catalogRoot,
    });
    while (job.state !== "complete") {
      if (job.state === "dead") {
        throw new PayoApiError(
          job.lastErrorMessage ?? "The proved FX root could not be published.",
          job.lastErrorCode ?? "FX_PUBLICATION_FAILED",
          422,
        );
      }
      if (Date.now() >= deadline) {
        throw new PayoApiError(
          "The FX root is still being authorized in the background. This payroll is safe to retry.",
          "FX_PUBLICATION_POLL_TIMEOUT",
          504,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      try {
        const result = await this.request<{ job: FxPublicationJob }>(
          `/api/v1/fx-publications?${query.toString()}`,
        );
        job = result.job;
      } catch (error) {
        if (!retryableApiRead(error)) throw error;
      }
    }
    return {
      catalogRoot: job.catalogRoot,
      alreadyActive: job.transactionHash === null,
      transactionHash: job.transactionHash,
    };
  }

  async renewHistoricalFxRoot(input: {
    organizationId: string;
    runId: string;
    workflowType: "wage_claim" | "employer_statement";
  } | {
    organizationId: string;
    runId: string;
    workflowType: "wage_remediation";
    claimId: string;
  }) {
    type FxRenewalJob = {
      id: string;
      catalogRoot: `0x${string}`;
      state: "pending" | "leased" | "complete" | "dead";
      transactionHash: string | null;
      attempts: number;
      lastErrorCode: string | null;
      lastErrorMessage: string | null;
    };
    const queued = await this.request<{ job: FxRenewalJob }>(
      `/api/v1/runs/${encodeURIComponent(input.runId)}/fx-renewal`,
      {
        method: "POST",
        body: JSON.stringify(input.workflowType === "wage_remediation"
          ? { workflowType: input.workflowType, claimId: input.claimId }
          : { workflowType: input.workflowType }),
      },
    );
    let job = queued.job;
    const deadline = Date.now() + 20 * 60_000;
    const query = new URLSearchParams({
      organizationId: input.organizationId,
      catalogRoot: job.catalogRoot,
    });
    while (job.state !== "complete") {
      if (job.state === "dead") {
        throw new PayoApiError(
          job.lastErrorMessage ?? "The historical FX root could not be renewed.",
          job.lastErrorCode ?? "FX_RENEWAL_FAILED",
          422,
        );
      }
      if (Date.now() >= deadline) {
        throw new PayoApiError(
          "The historical FX root is still being renewed. This claim is safe to retry.",
          "FX_RENEWAL_POLL_TIMEOUT",
          504,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      try {
        const result = await this.request<{ job: FxRenewalJob }>(
          `/api/v1/fx-publications?${query.toString()}`,
        );
        job = result.job;
      } catch (error) {
        if (!retryableApiRead(error)) throw error;
      }
    }
    return {
      catalogRoot: job.catalogRoot,
      transactionHash: job.transactionHash,
    };
  }

  private async provePayoRemotely(input: Omit<RemoteProofRequest, "version" | "requestId"> & {
    proverBaseUrl: string;
  }): Promise<PayoProofWorkerSuccess> {
    const endpoint = new URL("/api/v1/prove-payroll", input.proverBaseUrl);
    if (endpoint.protocol !== "https:" && endpoint.hostname !== "127.0.0.1" && endpoint.hostname !== "localhost") {
      throw new Error("The self-hosted prover must use HTTPS.");
    }
    const accessToken = await this.getAccessToken();
    if (!accessToken) throw new Error("Sign in before using the self-hosted prover.");
    const requestId = input.encryptedWitness.aad.recordId;
    const pollEndpoint = new URL(endpoint);
    pollEndpoint.searchParams.set("requestId", requestId);
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 30 * 60_000);
    const deadline = Date.now() + 30 * 60_000;
    const requestBody = JSON.stringify({
      version: 2,
      requestId,
      encryptedWitness: input.encryptedWitness,
      principal: input.principal,
      ...(input.claimAccessGrantId ? { claimAccessGrantId: input.claimAccessGrantId } : {}),
    });
    let accepted = false;
    let initialFailures = 0;
    try {
      while (Date.now() < deadline) {
        let response: Response;
        try {
          response = await fetch(accepted ? pollEndpoint : endpoint, {
            method: accepted ? "GET" : "POST",
            headers: {
              authorization: "Bearer " + accessToken,
              accept: "application/json",
              ...(!accepted ? { "content-type": "application/json" } : {}),
            },
            ...(!accepted ? { body: requestBody } : {}),
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
          initialFailures += 1;
          if (!accepted && initialFailures >= 3) {
            throw new PayoApiError(
              "The remote ZK prover could not start or recover the proof job after three connection attempts.",
              "PROVER_FETCH_FAILED",
              0,
            );
          }
          await new Promise((resolve) => window.setTimeout(resolve, Math.min(5_000, initialFailures * 1_000)));
          continue;
        }

        let body: unknown;
        try {
          body = await parseApiResponse(response, "The self-hosted prover request failed.", "PROVER");
        } catch (error) {
          if (!retryableApiRead(error)) throw error;
          await new Promise((resolve) => window.setTimeout(resolve, 2_000));
          continue;
        }
        if (!response.ok) {
          const apiBody = body as { error?: { message?: string; code?: string } };
          const code = apiBody?.error?.code ?? "PROVER_ERROR";
          if (accepted && response.status === 404 && code === "PROVER_JOB_NOT_FOUND") {
            accepted = false;
            initialFailures = 0;
            continue;
          }
          if (response.status === 429 || response.status >= 500) {
            await new Promise((resolve) => window.setTimeout(resolve, 3_000));
            continue;
          }
          throw new PayoApiError(
            apiBody?.error?.message ?? "The self-hosted prover request failed.",
            code,
            response.status,
          );
        }
        if (response.status === 200) {
          const proof = decodeRemoteProofResponse(body);
          if (proof.requestId !== requestId) {
            throw new PayoApiError("The prover returned a result for a different proof job.", "PROVER_JOB_MISMATCH", 502);
          }
          return proof;
        }
        const job = decodeRemoteProofJobResponse(body);
        if (job.requestId !== requestId) {
          throw new PayoApiError("The prover returned a different proof job.", "PROVER_JOB_MISMATCH", 502);
        }
        accepted = true;
        initialFailures = 0;
        await new Promise((resolve) => window.setTimeout(resolve, 3_000));
      }
      throw new PayoApiError(
        "The remote ZK prover did not respond within 30 minutes.",
        "PROVER_TIMEOUT",
        408,
      );
    } finally {
      window.clearTimeout(timeout);
    }
  }

  async provePayrollIntegrityRemotely(input: Omit<RemoteProofRequest, "version" | "requestId"> & {
    proverBaseUrl: string;
  }): Promise<ProofWorkerSuccess> {
    const proof = await this.provePayoRemotely(input);
    if (proof.type !== "proof-complete") {
      throw new PayoApiError(
        "The prover returned an exception proof for a payroll request.",
        "PROVER_PROFILE_MISMATCH",
        502,
      );
    }
    return proof;
  }

  async proveExceptionRemotely(input: Omit<RemoteProofRequest, "version" | "requestId"> & {
    proverBaseUrl: string;
  }): Promise<ExceptionProofWorkerSuccess> {
    const proof = await this.provePayoRemotely(input);
    if (proof.type !== "exception-proof-complete") {
      throw new PayoApiError(
        "The prover returned a payroll proof for an exception request.",
        "PROVER_PROFILE_MISMATCH",
        502,
      );
    }
    return proof;
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

  async issueAgentMcpConnection(capabilityId: string, ttlSeconds = 14_400) {
    return this.request<{ connection: AgentMcpConnection }>(
      "/api/v1/capabilities/" + encodeURIComponent(capabilityId) + "/access-token",
      { method: "POST", body: JSON.stringify({ ttlSeconds }) },
    );
  }

  async listAgentMcpConnections(capabilityId: string) {
    return this.request<{ tokens: AgentAccessTokenSummary[] }>(
      "/api/v1/capabilities/" + encodeURIComponent(capabilityId) + "/access-token",
    );
  }

  async revokeAgentMcpConnections(capabilityId: string) {
    return this.request<{ revocation: { capabilityId: string; revokedCount: number } }>(
      "/api/v1/capabilities/" + encodeURIComponent(capabilityId) + "/access-token",
      { method: "DELETE" },
    );
  }

  async listAgentApprovals(organizationId: string, limit = 50) {
    const search = new URLSearchParams({ organizationId, limit: String(limit) });
    return this.request<{ executions: AgentExecutionReceipt[] }>(
      `/api/v1/agent-approvals?${search}`,
    );
  }

  async listAgentExecutions(organizationId: string, limit = 50) {
    const search = new URLSearchParams({ organizationId, limit: String(limit) });
    return this.request<{ executions: AgentExecutionReceipt[] }>(
      `/api/v1/agent-executions?${search}`,
    );
  }

  async listDirectPrivacyAccounts(organizationId: string) {
    const search = new URLSearchParams({ organizationId });
    return this.request<{ accounts: DirectPrivacyAccountClientSummary[] }>(
      `/api/v1/direct-privacy-accounts?${search}`,
    );
  }

  async getDirectPrivacyAccount(accountId: string) {
    const search = new URLSearchParams({ accountId });
    return this.request<{
      account: DirectPrivacyAccountClientPublic;
      configurationCall: Call;
    }>(`/api/v1/direct-privacy-accounts?${search}`);
  }

  async provisionDirectPrivacyAccount(input: {
    organizationId: string;
    capabilityId: string;
    runIds: string[];
    policyAccountAddress: string;
    policyId: string;
    validForSeconds: number;
    periodSeconds: number;
    maxCallsPerPeriod: number;
    maxCallCount: number;
  }) {
    return this.request<{
      account: DirectPrivacyAccountClientPublic;
      configurationCall: Call;
      replayed?: boolean;
    }>("/api/v1/direct-privacy-accounts", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async stageDirectPrivacyRunWitness(input: {
    accountId: string;
    encryptedWitness: EncryptedVaultRecord;
  }) {
    return this.request<{
      witness: {
        runId: string;
        runVersion: number;
        witnessCommitment: string;
        replayed: boolean;
      };
    }>(`/api/v1/direct-privacy-accounts/${encodeURIComponent(input.accountId)}/runs`, {
      method: "POST",
      body: JSON.stringify({ encryptedWitness: input.encryptedWitness }),
    });
  }

  async activateDirectPrivacyAccount(accountId: string) {
    return this.request<{
      account: DirectPrivacyAccountClientPublic;
      configurationTransactionHash?: string;
    }>(`/api/v1/direct-privacy-accounts/${encodeURIComponent(accountId)}/activation`, {
      method: "POST",
    });
  }

  async linkAgentExecutionApproval(input: {
    capabilityId: string;
    executionId: string;
    settlementId: string;
  }) {
    return this.request<{ execution: AgentExecutionReceipt }>(
      `/api/v1/capabilities/${encodeURIComponent(input.capabilityId)}`
        + `/executions/${encodeURIComponent(input.executionId)}/approval`,
      { method: "POST", body: JSON.stringify({ settlementId: input.settlementId }) },
    );
  }

  async cancelAgentExecutionApproval(input: {
    capabilityId: string;
    executionId: string;
  }) {
    return this.request<{ execution: AgentExecutionReceipt }>(
      `/api/v1/capabilities/${encodeURIComponent(input.capabilityId)}`
        + `/executions/${encodeURIComponent(input.executionId)}/approval`,
      { method: "DELETE" },
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
    agentPlanCommitment?: string;
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
        proofValidityExpiry: string | null;
        proofVerificationState: string | null;
        proofVerificationLastErrorCode: string | null;
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

  async storeEncryptedProofBundle(input: EncryptedPayoProofBundleCreate) {
    return this.request<{ proofBundle: Record<string, unknown> }>("/api/v1/proof-packages", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async getEncryptedProofBundle(proofBundleId: string) {
    return this.request<{ proofBundle: {
      id: string;
      organizationId: string;
      runId: string;
      proofType: string;
      proofVersion: string;
      subjectRecordId: string;
      proofPackage: unknown;
      verificationState: string;
      verificationTransactionHash: string | null;
      createdAt: string;
      revision: number;
      envelope: EncryptedVaultRecord;
    } }>(
      `/api/v1/proof-packages/${encodeURIComponent(proofBundleId)}`,
    );
  }

  async enqueueExceptionAuthorization(input: {
    proofBundleId: string;
    proofCalldata: string[];
  }) {
    return this.request<{ authorization: ExceptionAuthorizationStatus }>(
      `/api/v1/proof-packages/${encodeURIComponent(input.proofBundleId)}/authorization`,
      {
        method: "POST",
        body: JSON.stringify({ proofCalldata: input.proofCalldata }),
      },
    );
  }

  async getExceptionAuthorization(proofBundleId: string) {
    return this.request<{ authorization: ExceptionAuthorizationStatus }>(
      `/api/v1/proof-packages/${encodeURIComponent(proofBundleId)}/authorization`,
    );
  }

  async enqueuePayrollAuthorization(input: {
    runId: string;
    payrollProofBundleId: string;
    snapshotProofBundleId: string;
    payrollShards: [string[], string[]];
    snapshotProof: string[];
  }) {
    return this.request<{ authorization: PayrollAuthorizationStatus }>(
      `/api/v1/runs/${encodeURIComponent(input.runId)}/payroll-authorization`,
      {
        method: "POST",
        body: JSON.stringify({
          payrollProofBundleId: input.payrollProofBundleId,
          snapshotProofBundleId: input.snapshotProofBundleId,
          payrollShards: input.payrollShards,
          snapshotProof: input.snapshotProof,
        }),
      },
    );
  }

  async getPayrollAuthorization(runId: string) {
    return this.request<{ authorization: PayrollAuthorizationStatus }>(
      `/api/v1/runs/${encodeURIComponent(runId)}/payroll-authorization`,
    );
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
