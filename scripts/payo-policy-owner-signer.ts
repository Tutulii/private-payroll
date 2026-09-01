import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Account, RpcProvider } from "starknet";
import {
  verifySignerAuthorization,
  type PolicySignerConstraints,
} from "../lib/server/policy-owner-signer-protocol";
import { PolicyOwnerSignerService } from "../lib/server/policy-owner-signer-service";

const MAX_BODY_BYTES = 20 * 1024 * 1024;
const REPLAY_TTL_MS = 60_000;

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function positiveInteger(name: string, fallback: number, maximum: number): number {
  const value = process.env[name]?.trim();
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > maximum) {
    throw new Error(`${name} is outside the supported range.`);
  }
  return parsed;
}

function header(request: IncomingMessage, name: string): string {
  const value = request.headers[name];
  if (typeof value !== "string") throw new Error("SIGNER_AUTH_REQUIRED");
  return value;
}

async function body(request: IncomingMessage): Promise<string> {
  if (!String(request.headers["content-type"] ?? "").toLowerCase().startsWith("application/json")) {
    throw new Error("SIGNER_JSON_REQUIRED");
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += value.length;
    if (size > MAX_BODY_BYTES) throw new Error("SIGNER_BODY_TOO_LARGE");
    chunks.push(value);
  }
  if (size === 0) throw new Error("SIGNER_BODY_REQUIRED");
  return Buffer.concat(chunks).toString("utf8");
}

function json(response: ServerResponse, status: number, payload: unknown): void {
  const output = JSON.stringify(payload);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(output),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(output);
}

const rpcUrl = required("STARKNET_RPC_URL");
const ownerPrivateKey = required("PAYO_POLICY_OWNER_PRIVATE_KEY");
const signerSecret = required("PAYO_POLICY_SIGNER_SECRET");
if (Buffer.byteLength(signerSecret) < 32) throw new Error("PAYO_POLICY_SIGNER_SECRET is too short.");

const constraints: PolicySignerConstraints = {
  chainId: required("PAYO_CHAIN_ID"),
  policyAccountAddress: required("PAYO_AGENT_POLICY_ACCOUNT_ADDRESS"),
  poolAddress: required("PAYO_STRK20_POOL_ADDRESS"),
  sealAddress: required("PAYO_AGENT_SEAL_ADDRESS"),
  viewingPublicKey: required("PAYO_AGENT_POLICY_VIEWING_PUBLIC_KEY"),
  tokenAddresses: [
    required("PAYO_AGENT_STRK_TOKEN_ADDRESS"),
    required("PAYO_AGENT_USDC_TOKEN_ADDRESS"),
  ],
  maxProofActions: positiveInteger("PAYO_POLICY_SIGNER_MAX_PROOF_ACTIONS", 64, 256),
  maxCreatedNotes: positiveInteger("PAYO_POLICY_SIGNER_MAX_CREATED_NOTES", 8, 64),
  maxPolicyLifetimeSeconds: positiveInteger(
    "PAYO_POLICY_SIGNER_MAX_LIFETIME_SECONDS",
    366 * 24 * 60 * 60,
    366 * 24 * 60 * 60,
  ),
  maxCalls: positiveInteger("PAYO_POLICY_SIGNER_MAX_CALLS", 256, 256),
};
const provider = new RpcProvider({ nodeUrl: rpcUrl });
const account = new Account({
  provider,
  address: constraints.policyAccountAddress,
  signer: ownerPrivateKey,
  cairoVersion: "1",
});
const service = new PolicyOwnerSignerService({
  provider,
  account,
  ownerPrivateKey,
  constraints,
  expectedSignerPublicKey: process.env.PAYO_POLICY_OWNER_PUBLIC_KEY?.trim(),
});

await service.attestDeployment();

const replayNonces = new Map<string, number>();
function acceptNonce(nonce: string, now: number): void {
  for (const [value, expiresAt] of replayNonces) {
    if (expiresAt <= now) replayNonces.delete(value);
  }
  if (replayNonces.has(nonce)) throw new Error("SIGNER_AUTH_REPLAYED");
  replayNonces.set(nonce, now + REPLAY_TTL_MS);
}

const server = createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/health") {
    json(response, 200, {
      status: "ok",
      service: "payo-policy-owner-signer",
      signerPublicKey: service.signerPublicKey,
    });
    return;
  }
  const path = request.url ?? "";
  if (
    request.method !== "POST"
    || ![
      "/v1/sign-proof-invocation",
      "/v1/estimate-policy",
      "/v1/configure-policy",
    ].includes(path)
  ) {
    json(response, 404, { code: "SIGNER_ROUTE_NOT_FOUND" });
    return;
  }
  try {
    const rawBody = await body(request);
    const timestamp = header(request, "x-payo-signer-timestamp");
    const nonce = header(request, "x-payo-signer-nonce");
    const authorization = header(request, "x-payo-signer-authorization");
    verifySignerAuthorization({
      secret: signerSecret,
      timestamp,
      nonce,
      method: request.method,
      path,
      body: rawBody,
      authorization,
    });
    acceptNonce(nonce, Date.now());
    let parsed: unknown;
    try { parsed = JSON.parse(rawBody); } catch { throw new Error("SIGNER_JSON_INVALID"); }
    const result = path === "/v1/sign-proof-invocation"
      ? await service.signProofInvocation(parsed)
      : path === "/v1/estimate-policy"
        ? await service.estimatePolicy(parsed)
        : await service.configurePolicy(parsed);
    json(response, 200, result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "SIGNER_REQUEST_REJECTED";
    const authenticationError = message.includes("authentication")
      || message.includes("authorization")
      || message.startsWith("SIGNER_AUTH_");
    json(response, authenticationError ? 401 : 400, {
      code: authenticationError ? "SIGNER_AUTH_REJECTED" : "SIGNER_POLICY_REJECTED",
    });
  }
});

server.requestTimeout = 21 * 60_000;
server.headersTimeout = 10_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 32;
const port = positiveInteger("PORT", 3000, 65_535);
// Fly's private 6PN DNS resolves internal applications over IPv6. Binding to
// IPv4 only makes an otherwise healthy isolated signer unreachable from the
// web/worker even though the machine-local health check can still pass.
const listenHost = process.env.HOST?.trim() || "::";
if (!["::", "::1", "0.0.0.0", "127.0.0.1"].includes(listenHost)) {
  throw new Error("HOST must be an explicit IPv4 or IPv6 listen address.");
}
server.listen(port, listenHost);

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => server.close(() => process.exit(0)));
}
