#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  agentCapabilitySchema,
  authorizeAgentAction,
  authorizePaymentBatch,
  paymentIntentBatchSchema,
  verifySignedCapability,
  type AgentAction,
  type AgentCapability,
} from "../../../lib/domain/capability";
import { encryptedRunCreateSchema, proofPackageSchema } from "../../../lib/domain/payroll";
import { PayoApiClient } from "./client";

const apiUrl = process.env.PAYO_API_URL ?? "http://localhost:3000";
const accessToken = process.env.PAYO_API_ACCESS_TOKEN;
const capabilityId = process.env.PAYO_CAPABILITY_ID;
const pinnedIssuerKey = process.env.PAYO_CAPABILITY_ISSUER_PUBLIC_KEY;

if (!accessToken || !capabilityId) {
  throw new Error("PAYO_API_ACCESS_TOKEN and PAYO_CAPABILITY_ID are required.");
}

const configuredAccessToken: string = accessToken;
const configuredCapabilityId: string = capabilityId;
const api = new PayoApiClient({ baseUrl: apiUrl, accessToken: configuredAccessToken });
const server = new McpServer({ name: "payo-private-payroll", version: "0.1.0" });
const outputSchema = {
  ok: z.boolean(),
  data: z.record(z.string(), z.unknown()),
};

function result(data: Record<string, unknown>) {
  const structuredContent = { ok: true, data };
  return {
    content: [{ type: "text" as const, text: JSON.stringify(structuredContent, null, 2) }],
    structuredContent,
  };
}

async function loadCapability(): Promise<AgentCapability> {
  const response = await api.request<{ capability: unknown }>(
    `/api/v1/capabilities?capabilityId=${encodeURIComponent(configuredCapabilityId)}`,
  );
  const signed = verifySignedCapability(response.capability);
  if (pinnedIssuerKey && signed.issuerPublicKey !== pinnedIssuerKey) {
    throw new Error("CAPABILITY_ISSUER_MISMATCH: Capability was signed by an untrusted issuer.");
  }
  return agentCapabilitySchema.parse(signed.capability);
}

async function requireAction(action: AgentAction): Promise<AgentCapability> {
  const capability = await loadCapability();
  const decision = authorizeAgentAction(capability, action);
  if (!decision.allowed) throw new Error(`CAPABILITY_DENIED: ${decision.reasonCode}`);
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
}, async () => {
  const capability = await loadCapability();
  return result({ capability });
});

server.registerTool("payo_list_due_obligations", {
  description: "List due payroll run metadata. PAYO never returns salary plaintext through this tool.",
  inputSchema: { organizationId: z.string().min(8).max(128) },
  outputSchema,
  annotations: { readOnlyHint: true },
}, async ({ organizationId }) => {
  const capability = await requireAction("list_due_obligations");
  assertOrganization(capability, organizationId);
  const response = await api.request<{ runs: Array<Record<string, unknown>> }>(
    `/api/v1/runs?organizationId=${encodeURIComponent(organizationId)}`,
  );
  const terminal = new Set(["reconciled", "cancelled"]);
  return result({ runs: response.runs.filter((run) => !terminal.has(String(run.state))) });
});

server.registerTool("payo_draft_run", {
  description: "Persist a client-encrypted payroll draft. Plaintext salary fields are not accepted.",
  inputSchema: encryptedRunCreateSchema,
  outputSchema,
}, async (input) => {
  const capability = await requireAction("draft_run");
  assertOrganization(capability, input.organizationId);
  const response = await api.request<{ run: Record<string, unknown> }>("/api/v1/runs", {
    method: "POST",
    body: JSON.stringify(input),
  });
  return result({ run: response.run });
});

server.registerTool("payo_validate_run", {
  description: "Validate every payment intent against signed recipient, token, purpose, time, and spending limits.",
  inputSchema: {
    organizationId: z.string().min(8).max(128),
    intents: paymentIntentBatchSchema,
  },
  outputSchema,
  annotations: { readOnlyHint: true },
}, async ({ organizationId, intents }) => {
  const capability = await requireAction("validate_run");
  assertOrganization(capability, organizationId);
  const validation = authorizePaymentBatch(capability, intents);
  return result({ validation });
});

server.registerTool("payo_request_execution", {
  description: "Request execution for a validated run. It cannot accept arbitrary contracts or calldata.",
  inputSchema: {
    organizationId: z.string().min(8).max(128),
    runId: z.string().min(8).max(128),
    intents: paymentIntentBatchSchema,
  },
  outputSchema,
}, async ({ organizationId, runId, intents }) => {
  const capability = await requireAction("request_execution");
  assertOrganization(capability, organizationId);
  const validation = authorizePaymentBatch(capability, intents);
  if (!validation.allowed) throw new Error("CAPABILITY_DENIED: One or more payment intents are outside policy.");

  if (!validation.requiresApproval) {
    return result({
      runId,
      validation,
      executionSubmitted: false,
      status: "delegated_signer_not_configured",
      message: "The bounded request is valid, but this MCP server deliberately has no generic wallet signer.",
    });
  }

  const response = await api.request<{ run: Record<string, unknown> }>(
    `/api/v1/runs/${encodeURIComponent(runId)}`,
    { method: "PATCH", body: JSON.stringify({ state: "approval_pending" }) },
  );
  return result({ run: response.run, validation, executionSubmitted: false, status: "approval_required" });
});

server.registerTool("payo_get_run_status", {
  description: "Read lifecycle and settlement metadata for a payroll run.",
  inputSchema: { runId: z.string().min(8).max(128) },
  outputSchema,
  annotations: { readOnlyHint: true },
}, async ({ runId }) => {
  await requireAction("get_run_status");
  const response = await api.request<{ run: Record<string, unknown> }>(
    `/api/v1/runs/${encodeURIComponent(runId)}`,
  );
  const metadata = Object.fromEntries(
    Object.entries(response.run).filter(([key]) => key !== "ciphertext" && key !== "envelope"),
  );
  return result({ run: metadata });
});

server.registerTool("payo_get_receipt", {
  description: "Read the proof root, nullifier, transaction hash, and reconciliation status for a run.",
  inputSchema: { runId: z.string().min(8).max(128) },
  outputSchema,
  annotations: { readOnlyHint: true },
}, async ({ runId }) => {
  await requireAction("get_receipt");
  const response = await api.request<{ run: Record<string, unknown> }>(
    `/api/v1/runs/${encodeURIComponent(runId)}`,
  );
  return result({ receipt: {
    runId,
    state: response.run.state,
    manifestRoot: response.run.manifestRoot,
    runNullifier: response.run.runNullifier,
    transactionHash: response.run.transactionHash,
    updatedAt: response.run.updatedAt,
  } });
});

server.registerTool("payo_create_disclosure", {
  description: "Store a verifier-bound selective-disclosure proof package without revealing unrelated payroll rows.",
  inputSchema: proofPackageSchema,
  outputSchema,
}, async (proofPackage) => {
  const capability = await requireAction("create_disclosure");
  assertOrganization(capability, proofPackage.organizationId);
  const response = await api.request<{ proofPackage: Record<string, unknown> }>(
    "/api/v1/proof-packages",
    { method: "POST", body: JSON.stringify(proofPackage) },
  );
  return result({ proofPackage: response.proofPackage });
});

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("PAYO MCP server running over stdio.");
