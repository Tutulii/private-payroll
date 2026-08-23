import {
  buildFixedMerkleRoot,
  deriveRunNullifier,
  hashPayrollLeaf,
  hashTextCommitment,
} from "@/lib/crypto/commitments";
import { toHex } from "@/lib/crypto/encoding";
import {
  encryptVaultRecord,
  type EncryptedVaultRecord,
  type VaultPrincipal,
} from "@/lib/crypto/vault";
import {
  calculatePayrollManifest,
  type PrivatePayrollLine,
} from "@/lib/domain/payroll";

type AccessTokenProvider = () => Promise<string | null>;

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
  runNullifier: `0x${string}`;
};

export function prepareEncryptedPayrollRun(input: {
  id: string;
  organizationId: string;
  cycleId: string;
  revision: number;
  dueAt: string;
  lines: readonly PrivatePayrollLine[];
  organizationSecret: string;
  principals: readonly VaultPrincipal[];
}): PreparedEncryptedRun {
  const manifest = calculatePayrollManifest(input.lines);
  const agreementRoot = buildFixedMerkleRoot(manifest.lines.map((line) =>
    toHex(hashTextCommitment("PAYO_AGREEMENT_ID_V1", line.agreementId))
  ));
  const manifestRoot = buildFixedMerkleRoot(manifest.lines.map((line) => hashPayrollLeaf(line)));
  const runNullifier = deriveRunNullifier({
    organizationSecret: input.organizationSecret,
    cycleId: input.cycleId,
    revision: input.revision,
  });
  const envelope = encryptVaultRecord(
    {
      schemaVersion: 1,
      cycleId: input.cycleId,
      dueAt: input.dueAt,
      agreementRoot,
      manifestRoot,
      runNullifier,
      manifest,
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
  return {
    id: input.id,
    organizationId: input.organizationId,
    cycleId: input.cycleId,
    revision: input.revision,
    dueAt: input.dueAt,
    ciphertext: envelope.ciphertext,
    envelope,
    agreementRoot,
    manifestRoot,
    runNullifier,
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
      throw new Error(body?.error?.message ?? "PAYO API request failed.");
    }
    return body as T;
  }

  async createOrganization(input: {
    organizationId: string;
    encryptedProfile: EncryptedVaultRecord;
    vaultPublicKey: string;
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
        manifestRoot: input.manifestRoot,
        runNullifier: input.runNullifier,
      }),
    });
  }

  async listPayrollRuns(organizationId: string) {
    return this.request<{ runs: Array<Record<string, unknown>> }>(
      `/api/v1/runs?organizationId=${encodeURIComponent(organizationId)}`,
    );
  }
}
