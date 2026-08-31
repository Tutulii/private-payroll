#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createPayoMcpServer } from "./payo-server";

const apiUrl = process.env.PAYO_API_URL ?? "http://localhost:3000";
const accessToken = process.env.PAYO_API_ACCESS_TOKEN;
const capabilityId = process.env.PAYO_CAPABILITY_ID;
const pinnedIssuerKey = process.env.PAYO_CAPABILITY_ISSUER_PUBLIC_KEY;

if (!accessToken || !capabilityId || !pinnedIssuerKey) {
  throw new Error(
    "PAYO_API_ACCESS_TOKEN, PAYO_CAPABILITY_ID, and "
      + "PAYO_CAPABILITY_ISSUER_PUBLIC_KEY are required.",
  );
}

const server = createPayoMcpServer({
  apiUrl,
  accessToken,
  capabilityId,
  pinnedIssuerKey,
});
await server.connect(new StdioServerTransport());
console.error("PAYO MCP server running over stdio.");
