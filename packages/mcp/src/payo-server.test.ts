import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it } from "vitest";
import {
  agentActionSchema,
  signCapability,
  type AgentCapability,
  type AgentExecutionRequest,
} from "../../../lib/domain/capability";
import { generateUuidV7 } from "../../../lib/domain/records";
import { VAULT_ALGORITHM } from "../../../lib/crypto/vault";
import { PayoApiClient } from "./client";
import {
  createPayoMcpServer,
  type PayoApiTransport,
} from "./payo-server";

const openServers: Array<{ client: Client; server: ReturnType<typeof createPayoMcpServer> }> = [];

function id(fill: number): string {
  return generateUuidV7(1_800_000_000_000 + fill, new Uint8Array(10).fill(fill));
}

function capabilityFixture() {
  const now = Date.now();
  const capability: AgentCapability = {
    capabilityVersion: "payo-agent-capability-v1",
    id: id(1),
    organizationId: id(2),
    principalId: "agent:test",
    allowedActions: agentActionSchema.options,
    allowedTokens: ["STRK"],
    recipientScope: { mode: "allowlist", addresses: ["0x123"] },
    purposeCodes: ["payroll"],
    limits: [{
      token: "STRK",
      maxPerPaymentAtomic: "100",
      maxPerPeriodAtomic: "1000",
      spentThisPeriodAtomic: "0",
      periodStartsAt: new Date(now - 60_000).toISOString(),
      periodEndsAt: new Date(now + 3_600_000).toISOString(),
      approvalThresholdAtomic: "50",
    }],
    executionMode: "request_approval",
    maxCallCount: 10,
    usedCallCount: 0,
    validAfter: new Date(now - 60_000).toISOString(),
    expiresAt: new Date(now + 3_600_000).toISOString(),
    nonce: "phase4-mcp-test-nonce-0001",
  };
  const issuerSecret = new Uint8Array(32).fill(7);
  const signed = signCapability(capability, issuerSecret);
  return { capability, signed };
}

function executionRequest(
  capability: AgentCapability,
  runId: string,
): AgentExecutionRequest {
  const createdAt = new Date();
  return {
    requestVersion: "payo-agent-execution-v1",
    runId,
    intents: [{
      intentVersion: "payo-payment-intent-v1",
      intentId: id(4),
      organizationId: capability.organizationId,
      runId,
      action: "request_execution",
      token: "STRK",
      recipientAddress: "0x123",
      amountAtomic: "10",
      purposeCode: "payroll",
      capabilityNonce: capability.nonce,
      createdAt: createdAt.toISOString(),
      validUntil: new Date(createdAt.getTime() + 60_000).toISOString(),
    }],
  };
}

function encryptedEnvelope(input: {
  organizationId: string;
  recordId: string;
  recordType: string;
}) {
  return {
    version: 1 as const,
    algorithm: VAULT_ALGORITHM,
    aad: {
      schemaVersion: 1 as const,
      organizationId: input.organizationId,
      recordType: input.recordType,
      recordId: input.recordId,
      revision: 1,
    },
    nonce: "n".repeat(16),
    ciphertext: "c".repeat(24),
    wrappedKeys: [{
      principalId: "recipient:test",
      ephemeralPublicKey: "p".repeat(16),
      nonce: "w".repeat(16),
      ciphertext: "k".repeat(24),
    }],
  };
}

async function connect(input: {
  api: PayoApiTransport;
  capabilityId: string;
  pinnedIssuerKey: string;
}) {
  const server = createPayoMcpServer({
    apiUrl: "https://payo.test",
    accessToken: "ready-session-token",
    capabilityId: input.capabilityId,
    pinnedIssuerKey: input.pinnedIssuerKey,
    api: input.api,
  });
  const client = new Client({ name: "payo-mcp-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  openServers.push({ client, server });
  return client;
}

function data(result: Awaited<ReturnType<Client["callTool"]>>): Record<string, unknown> {
  return (result.structuredContent as { data: Record<string, unknown> }).data;
}

afterEach(async () => {
  while (openServers.length) {
    const active = openServers.pop()!;
    await active.client.close().catch(() => undefined);
    await active.server.close().catch(() => undefined);
  }
});

describe("PAYO MCP production transport", () => {
  it("executes all eight tools with tenant binding, redaction and reconciliation status", async () => {
    const { capability, signed } = capabilityFixture();
    const runId = id(3);
    const executionId = id(5);
    const disclosureId = id(6);
    const calls: Array<{ path: string; init?: RequestInit }> = [];
    const run = {
      id: runId,
      organizationId: capability.organizationId,
      cycleId: "cycle-1",
      revision: 1,
      state: "confirmed",
      dueAt: new Date(Date.now() - 60_000).toISOString(),
      manifestRoot: "0x" + "11".repeat(32),
      runNullifier: "0x" + "22".repeat(32),
      transactionHash: "0xabc",
      updatedAt: new Date().toISOString(),
      ciphertext: "must-never-leave-mcp",
      envelope: { secret: true },
    };
    const api: PayoApiTransport = {
      async request<T>(path: string, init?: RequestInit): Promise<T> {
        calls.push({ path, init });
        if (path.startsWith("/api/v1/capabilities?")) return { capability: signed } as T;
        if (path.startsWith("/api/v1/runs?")) {
          return {
            runs: [
              { ...run, state: "draft" },
              { ...run, id: id(7), state: "confirmed" },
              { ...run, id: id(8), state: "draft", dueAt: new Date(Date.now() + 60_000).toISOString() },
            ],
          } as T;
        }
        if (path === "/api/v1/runs" && init?.method === "POST") {
          return { run: { ...run, state: "draft" } } as T;
        }
        if (path === "/api/v1/capabilities/" + capability.id + "/executions" && init?.method === "POST") {
          return { execution: {
            executionId,
            capabilityId: capability.id,
            runId,
            state: "approval_pending",
            requiresApproval: true,
          } } as T;
        }
        if (path === "/api/v1/runs/" + runId) return { run } as T;
        if (path.includes("/executions?executionId=")) {
          return { execution: {
            executionId,
            capabilityId: capability.id,
            runId,
            state: "reconciled",
            transactionHash: "0xdef",
            requestCommitment: "0x" + "33".repeat(32),
            updatedAt: new Date().toISOString(),
          } } as T;
        }
        if (path === "/api/v1/disclosures" && init?.method === "POST") {
          return { grant: { id: disclosureId, state: "active" } } as T;
        }
        throw new Error("Unexpected API request: " + path);
      },
    };
    const client = await connect({
      api,
      capabilityId: capability.id,
      pinnedIssuerKey: signed.issuerPublicKey,
    });
    const tools = await client.listTools();
    expect(tools.tools.map(({ name }) => name).sort()).toEqual([
      "payo_create_disclosure",
      "payo_draft_run",
      "payo_get_capability",
      "payo_get_receipt",
      "payo_get_run_status",
      "payo_list_due_obligations",
      "payo_request_execution",
      "payo_validate_run",
    ]);
    expect((await client.callTool({
      name: "payo_get_capability",
      arguments: {},
    })).isError).not.toBe(true);
    const due = await client.callTool({
      name: "payo_list_due_obligations",
      arguments: { organizationId: capability.organizationId },
    });
    expect((data(due).runs as Array<Record<string, unknown>>)).toHaveLength(1);
    expect(JSON.stringify(data(due))).not.toContain("must-never-leave-mcp");

    const draft = {
      id: runId,
      organizationId: capability.organizationId,
      cycleId: "cycle-1",
      revision: 1,
      dueAt: run.dueAt,
      ciphertext: "x".repeat(24),
      envelope: { encrypted: true },
      agreementRoot: "0x" + "01".repeat(32),
      manifestRoot: "0x" + "02".repeat(32),
      policyRoot: "0x" + "03".repeat(32),
      fxRoot: "0x" + "04".repeat(32),
      runNullifier: "0x" + "05".repeat(32),
      lineRecords: [{ id: id(9), revision: 1, envelope: { encrypted: true } }],
    };
    const drafted = await client.callTool({ name: "payo_draft_run", arguments: draft });
    expect(JSON.stringify(data(drafted))).not.toContain("must-never-leave-mcp");
    const request = executionRequest(capability, runId);
    expect((await client.callTool({
      name: "payo_validate_run",
      arguments: { organizationId: capability.organizationId, intents: request.intents },
    })).isError).not.toBe(true);
    expect((await client.callTool({
      name: "payo_request_execution",
      arguments: { request, idempotencyKey: "phase4:mcp:request:0001" },
    })).isError).not.toBe(true);
    expect((await client.callTool({
      name: "payo_get_run_status",
      arguments: { organizationId: capability.organizationId, runId },
    })).isError).not.toBe(true);
    const receipt = await client.callTool({
      name: "payo_get_receipt",
      arguments: { organizationId: capability.organizationId, runId, executionId },
    });
    expect(data(receipt)).toMatchObject({ receipt: {
      executionId,
      executionState: "reconciled",
      reconciled: true,
      transactionHash: "0xdef",
    } });

    const validAfter = new Date().toISOString();
    const disclosure = {
      id: disclosureId,
      organizationId: capability.organizationId,
      runId,
      granteePrincipalId: "recipient:test",
      fieldScope: ["settlement"],
      validAfter,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      envelope: encryptedEnvelope({
        organizationId: capability.organizationId,
        recordId: disclosureId,
        recordType: "disclosure-grant",
      }),
    };
    expect((await client.callTool({
      name: "payo_create_disclosure",
      arguments: disclosure,
    })).isError).not.toBe(true);
    expect(calls.some(({ path }) => path === "/api/v1/disclosures")).toBe(true);
  });

  it("rejects cross-tenant access and arbitrary-call injection before execution", async () => {
    const { capability, signed } = capabilityFixture();
    const runId = id(3);
    let executionRequests = 0;
    const api: PayoApiTransport = {
      async request<T>(path: string): Promise<T> {
        if (path.startsWith("/api/v1/capabilities?")) return { capability: signed } as T;
        if (path.includes("/executions")) executionRequests += 1;
        throw new Error("Unexpected API request: " + path);
      },
    };
    const client = await connect({
      api,
      capabilityId: capability.id,
      pinnedIssuerKey: signed.issuerPublicKey,
    });
    const crossTenant = await client.callTool({
      name: "payo_list_due_obligations",
      arguments: { organizationId: id(15) },
    });
    expect(crossTenant.isError).toBe(true);

    const request = executionRequest(capability, runId);
    const injected = await client.callTool({
      name: "payo_request_execution",
      arguments: {
        request: { ...request, calls: [{ to: "0xdead", selector: "upgrade", calldata: [] }] },
        idempotencyKey: "phase4:mcp:injected:0001",
      },
    });
    expect(injected.isError).toBe(true);
    expect(executionRequests).toBe(0);

    const overspend = structuredClone(request);
    overspend.intents[0].amountAtomic = "1001";
    const periodBypass = await client.callTool({
      name: "payo_request_execution",
      arguments: {
        request: overspend,
        idempotencyKey: "phase4:mcp:overspend:0001",
      },
    });
    expect(periodBypass.isError).toBe(true);
    expect(executionRequests).toBe(0);
  });

  it("fails closed when the API returns a run from another tenant", async () => {
    const { capability, signed } = capabilityFixture();
    const runId = id(3);
    const api: PayoApiTransport = {
      async request<T>(path: string): Promise<T> {
        if (path.startsWith("/api/v1/capabilities?")) return { capability: signed } as T;
        if (path === "/api/v1/runs/" + runId) {
          return { run: { id: runId, organizationId: id(16), state: "confirmed" } } as T;
        }
        throw new Error("Unexpected API request: " + path);
      },
    };
    const client = await connect({
      api,
      capabilityId: capability.id,
      pinnedIssuerKey: signed.issuerPublicKey,
    });
    const response = await client.callTool({
      name: "payo_get_run_status",
      arguments: { organizationId: capability.organizationId, runId },
    });
    expect(response.isError).toBe(true);
    expect(JSON.stringify(response.content)).toContain("CAPABILITY_MISMATCH");
  });

  it("rejects an otherwise valid capability from an unpinned issuer", async () => {
    const { capability, signed } = capabilityFixture();
    const api: PayoApiTransport = {
      async request<T>(): Promise<T> {
        return { capability: signed } as T;
      },
    };
    const client = await connect({
      api,
      capabilityId: capability.id,
      pinnedIssuerKey: "not-the-issuer",
    });
    const response = await client.callTool({ name: "payo_get_capability", arguments: {} });
    expect(response.isError).toBe(true);
    expect(JSON.stringify(response.content)).toContain("CAPABILITY_ISSUER_MISMATCH");
  });
});

describe("PayoApiClient transport security", () => {
  it("allows HTTPS and loopback HTTP but rejects credential-bearing or plaintext remote URLs", () => {
    expect(() => new PayoApiClient({
      baseUrl: "https://private-payroll.fly.dev",
      accessToken: "token",
    })).not.toThrow();
    expect(() => new PayoApiClient({
      baseUrl: "http://localhost:3000",
      accessToken: "token",
    })).not.toThrow();
    expect(() => new PayoApiClient({
      baseUrl: "http://payo.example",
      accessToken: "token",
    })).toThrow("must use HTTPS");
    expect(() => new PayoApiClient({
      baseUrl: "https://user:secret@payo.example",
      accessToken: "token",
    })).toThrow("cannot contain credentials");
  });
});
