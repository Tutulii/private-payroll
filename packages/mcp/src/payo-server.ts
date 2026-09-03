import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { encryptedVaultRecordSchema } from "../../../lib/crypto/vault";
import {
  agentCapabilitySchema,
  agentExecutionRequestSchema,
  authorizeAgentAction,
  authorizePaymentBatch,
  paymentIntentBatchSchema,
  verifySignedCapability,
  type AgentAction,
  type AgentCapability,
} from "../../../lib/domain/capability";
import { encryptedRunCreateSchema } from "../../../lib/domain/payroll";
import { uuidV7Schema, vaultPrincipalIdSchema } from "../../../lib/domain/records";
import { PayoApiClient } from "./client";

export interface PayoApiTransport {
  request<T>(path: string, init?: RequestInit): Promise<T>;
}

export type PayoMcpServerConfig = {
  apiUrl: string;
  accessToken: string;
  capabilityId: string;
  pinnedIssuerKey: string;
  api?: PayoApiTransport;
};

const outputSchema = {
  ok: z.boolean(),
  data: z.record(z.string(), z.unknown()),
};
const organizationRunSchema = {
  organizationId: z.string().min(8).max(128),
  runId: z.string().min(8).max(128),
};
const disclosureCreateSchema = z.object({
  id: uuidV7Schema,
  organizationId: uuidV7Schema,
  runId: uuidV7Schema,
  granteePrincipalId: vaultPrincipalIdSchema,
  fieldScope: z.array(z.enum([
    "identity", "gross", "deductions", "net", "token", "schedule",
    "classification", "aggregate", "settlement", "exception",
  ])).min(1).max(10),
  validAfter: z.string().datetime(),
  expiresAt: z.string().datetime(),
  envelope: encryptedVaultRecordSchema,
}).strict();

function result(data: Record<string, unknown>) {
  const structuredContent = { ok: true, data };
  return {
    content: [{ type: "text" as const, text: JSON.stringify(structuredContent, null, 2) }],
    structuredContent,
  };
}

function publicRun(run: Record<string, unknown>): Record<string, unknown> {
  const allowed = new Set([
    "id", "cycleId", "revision", "state", "dueAt", "agreementRoot",
    "manifestRoot", "policyRoot", "fxRoot", "runNullifier",
    "transactionHash", "obligationSnapshotPlanId", "createdAt", "updatedAt",
  ]);
  return Object.fromEntries(Object.entries(run).filter(([key]) => allowed.has(key)));
}

function assertRunOrganization(
  run: Record<string, unknown>,
  organizationId: string,
): void {
  if (run.organizationId !== organizationId) {
    throw new Error("CAPABILITY_MISMATCH: Run is outside the capability organization.");
  }
}

export function createPayoMcpServer(config: PayoMcpServerConfig): McpServer {
  if (!config.accessToken || !config.capabilityId || !config.pinnedIssuerKey) {
    throw new Error("PAYO MCP authentication and capability configuration are required.");
  }
  const api = config.api ?? new PayoApiClient({
    baseUrl: config.apiUrl,
    accessToken: config.accessToken,
  });
  const server = new McpServer({ name: "payo-private-payroll", version: "0.2.0" });

  async function loadCapability(): Promise<AgentCapability> {
    const response = await api.request<{ capability: unknown }>(
      "/api/v1/capabilities?capabilityId=" + encodeURIComponent(config.capabilityId),
    );
    const signed = verifySignedCapability(response.capability);
    if (signed.issuerPublicKey !== config.pinnedIssuerKey) {
      throw new Error("CAPABILITY_ISSUER_MISMATCH: Capability was signed by an untrusted issuer.");
    }
    if (signed.capability.id !== config.capabilityId) {
      throw new Error("CAPABILITY_ID_MISMATCH: PAYO returned a different capability.");
    }
    return agentCapabilitySchema.parse(signed.capability);
  }

  async function requireAction(action: AgentAction): Promise<AgentCapability> {
    const capability = await loadCapability();
    const decision = authorizeAgentAction(capability, action);
    if (!decision.allowed) throw new Error("CAPABILITY_DENIED: " + decision.reasonCode);
    return capability;
  }

  function assertOrganization(capability: AgentCapability, organizationId: string): void {
    if (organizationId !== capability.organizationId) {
      throw new Error("CAPABILITY_MISMATCH: Organization is outside the capability scope.");
    }
  }

  server.registerTool("payo_get_capability", {
    description: "Inspect this agent's currently active PAYO permission boundaries.",
    outputSchema,
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async () => result({ capability: await loadCapability() }));

  server.registerTool("payo_list_due_obligations", {
    description: "List due, retryable payroll run metadata without returning salary plaintext.",
    inputSchema: { organizationId: z.string().min(8).max(128) },
    outputSchema,
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ organizationId }) => {
    const capability = await requireAction("list_due_obligations");
    assertOrganization(capability, organizationId);
    const response = await api.request<{ runs: Array<Record<string, unknown>> }>(
      "/api/v1/runs?organizationId=" + encodeURIComponent(organizationId),
    );
    const retryable = new Set(["draft", "calculated", "proven", "failed"]);
    const now = Date.now();
    return result({ runs: response.runs.filter((run) => {
      const dueAt = typeof run.dueAt === "string" ? Date.parse(run.dueAt) : Number.NaN;
      return retryable.has(String(run.state)) && Number.isFinite(dueAt) && dueAt <= now;
    }).map(publicRun) });
  });

  server.registerTool("payo_draft_run", {
    description: "Persist a client-encrypted payroll draft. Plaintext salary fields are rejected.",
    inputSchema: encryptedRunCreateSchema,
    outputSchema,
    annotations: { idempotentHint: true, openWorldHint: false },
  }, async (input) => {
    const capability = await requireAction("draft_run");
    assertOrganization(capability, input.organizationId);
    const response = await api.request<{ run: Record<string, unknown> }>("/api/v1/runs", {
      method: "POST",
      body: JSON.stringify(input),
    });
    assertRunOrganization(response.run, input.organizationId);
    return result({ run: publicRun(response.run) });
  });

  server.registerTool("payo_validate_run", {
    description: "Advisory validation against the freshly reloaded signed capability; execution revalidates transactionally.",
    inputSchema: {
      organizationId: z.string().min(8).max(128),
      intents: paymentIntentBatchSchema,
    },
    outputSchema,
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ organizationId, intents }) => {
    const capability = await requireAction("validate_run");
    assertOrganization(capability, organizationId);
    if (intents.some((intent) => intent.organizationId !== organizationId)) {
      throw new Error("CAPABILITY_MISMATCH: Payment intents cross organizations.");
    }
    return result({ validation: authorizePaymentBatch(capability, intents) });
  });

  server.registerTool("payo_request_execution", {
    description: "Request Ready approval or bounded policy-account execution from strict payment intents only.",
    inputSchema: {
      request: agentExecutionRequestSchema,
      idempotencyKey: z.string().regex(/^[A-Za-z0-9._:-]{16,256}$/),
    },
    outputSchema,
    annotations: { destructiveHint: true, idempotentHint: true, openWorldHint: false },
  }, async ({ request, idempotencyKey }) => {
    const capability = await requireAction("request_execution");
    const organizationId = request.intents[0].organizationId;
    assertOrganization(capability, organizationId);
    const validation = authorizePaymentBatch(capability, request.intents);
    if (!validation.allowed) {
      throw new Error("CAPABILITY_DENIED: One or more payment intents are outside policy.");
    }
    const response = await api.request<{ execution: Record<string, unknown> }>(
      "/api/v1/capabilities/" + encodeURIComponent(config.capabilityId) + "/executions",
      {
        method: "POST",
        headers: { "idempotency-key": idempotencyKey },
        body: JSON.stringify(request),
      },
    );
    return result({
      execution: response.execution,
      validation,
      executionSubmitted: ["submitted", "confirmed", "reconciled"].includes(
        String(response.execution.state),
      ),
      status: response.execution.state,
    });
  });

  server.registerTool("payo_get_run_status", {
    description: "Read a redacted payroll lifecycle status within the capability organization.",
    inputSchema: organizationRunSchema,
    outputSchema,
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ organizationId, runId }) => {
    const capability = await requireAction("get_run_status");
    assertOrganization(capability, organizationId);
    const response = await api.request<{ run: Record<string, unknown> }>(
      "/api/v1/runs/" + encodeURIComponent(runId),
    );
    assertRunOrganization(response.run, organizationId);
    return result({ run: publicRun(response.run) });
  });

  server.registerTool("payo_get_receipt", {
    description: "Read redacted proof, settlement, and optional agent-reconciliation status for a run.",
    inputSchema: {
      ...organizationRunSchema,
      executionId: uuidV7Schema.optional(),
    },
    outputSchema,
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ organizationId, runId, executionId }) => {
    const capability = await requireAction("get_receipt");
    assertOrganization(capability, organizationId);
    const response = await api.request<{ run: Record<string, unknown> }>(
      "/api/v1/runs/" + encodeURIComponent(runId),
    );
    assertRunOrganization(response.run, organizationId);
    let execution: Record<string, unknown> | undefined;
    if (executionId) {
      const executionResponse = await api.request<{ execution: Record<string, unknown> }>(
        "/api/v1/capabilities/" + encodeURIComponent(config.capabilityId)
          + "/executions?executionId=" + encodeURIComponent(executionId),
      );
      if (executionResponse.execution.runId !== runId) {
        throw new Error("CAPABILITY_MISMATCH: Execution is not bound to this payroll run.");
      }
      execution = executionResponse.execution;
    }
    return result({ receipt: {
      runId,
      state: response.run.state,
      manifestRoot: response.run.manifestRoot,
      runNullifier: response.run.runNullifier,
      transactionHash: execution?.transactionHash ?? response.run.transactionHash,
      executionId: execution?.executionId,
      executionState: execution?.state,
      executionErrorCode: execution?.errorCode,
      requestCommitment: execution?.requestCommitment,
      reconciled: execution?.state === "reconciled",
      updatedAt: execution?.updatedAt ?? response.run.updatedAt,
    } });
  });

  server.registerTool("payo_create_disclosure", {
    description: "Store a recipient-encrypted, scoped and expiring disclosure grant for one payroll run.",
    inputSchema: disclosureCreateSchema,
    outputSchema,
    annotations: { idempotentHint: true, openWorldHint: false },
  }, async (disclosure) => {
    const capability = await requireAction("create_disclosure");
    assertOrganization(capability, disclosure.organizationId);
    if (
      disclosure.envelope.aad.organizationId !== disclosure.organizationId
      || disclosure.envelope.aad.recordId !== disclosure.id
      || disclosure.envelope.aad.recordType !== "disclosure-grant"
      || disclosure.envelope.aad.revision !== 1
    ) {
      throw new Error("AAD_MISMATCH: Encrypted disclosure identity does not match the request.");
    }
    if (new Date(disclosure.expiresAt) <= new Date(disclosure.validAfter)) {
      throw new Error("DISCLOSURE_WINDOW_INVALID: Expiry must follow activation.");
    }
    const response = await api.request<{ grant: Record<string, unknown> }>(
      "/api/v1/disclosures",
      { method: "POST", body: JSON.stringify(disclosure) },
    );
    return result({ grant: response.grant });
  });

  return server;
}
