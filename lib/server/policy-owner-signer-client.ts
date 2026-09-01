import "server-only";

import { randomBytes, randomUUID } from "node:crypto";
import {
  SignerInterface,
  type Call,
  type DeclareSignerDetails,
  type DeployAccountSignerDetails,
  type InvocationsSignerDetails,
  type Signature,
  type TypedData,
} from "starknet";
import type { z } from "zod";
import {
  createSignerAuthorization,
  policyConfigurationResponseSchema,
  policySignerResponseSchema,
  serializePolicyConfigurationRequest,
  serializeProofSigningRequest,
} from "./policy-owner-signer-protocol";

type SignerClientOptions = {
  url: string;
  secret: string;
  expectedPublicKey: string;
  proofTimeoutMs?: number;
  configurationTimeoutMs?: number;
};

function sameFelt(left: string, right: string): boolean {
  try { return BigInt(left) === BigInt(right); } catch { return false; }
}

function validateSignerUrl(raw: string): string {
  const url = new URL(raw);
  const privateHttp = url.protocol === "http:"
    && (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname.endsWith(".internal"));
  if (url.username || url.password || (url.protocol !== "https:" && !privateHttp)) {
    throw new Error("PAYO_POLICY_SIGNER_URL must be HTTPS or a private/local HTTP endpoint.");
  }
  return url.href.replace(/\/$/, "");
}

function requiredSignerOptions(): SignerClientOptions {
  const url = process.env.PAYO_POLICY_SIGNER_URL?.trim();
  const secret = process.env.PAYO_POLICY_SIGNER_SECRET?.trim();
  const expectedPublicKey = process.env.PAYO_POLICY_SIGNER_PUBLIC_KEY?.trim();
  if (!url || !secret || !expectedPublicKey) {
    throw new Error("The isolated PAYO policy signer is not configured.");
  }
  if (Buffer.byteLength(secret) < 32) {
    throw new Error("PAYO_POLICY_SIGNER_SECRET must contain at least 32 bytes.");
  }
  try {
    if (BigInt(expectedPublicKey) <= 0n) throw new Error("invalid");
  } catch {
    throw new Error("PAYO_POLICY_SIGNER_PUBLIC_KEY is invalid.");
  }
  return { url: validateSignerUrl(url), secret, expectedPublicKey };
}

export class PolicyOwnerSignerClient extends SignerInterface {
  readonly url: string;
  readonly expectedPublicKey: string;
  readonly #secret: string;
  readonly #proofTimeoutMs: number;
  readonly #configurationTimeoutMs: number;

  constructor(options: SignerClientOptions) {
    super();
    this.url = validateSignerUrl(options.url);
    if (Buffer.byteLength(options.secret) < 32) throw new Error("The policy signer secret is too short.");
    if (BigInt(options.expectedPublicKey) <= 0n) throw new Error("The expected policy signer key is invalid.");
    this.#secret = options.secret;
    this.expectedPublicKey = options.expectedPublicKey;
    this.#proofTimeoutMs = options.proofTimeoutMs ?? 30_000;
    this.#configurationTimeoutMs = options.configurationTimeoutMs ?? 20 * 60_000;
  }

  static fromEnvironment(): PolicyOwnerSignerClient {
    return new PolicyOwnerSignerClient(requiredSignerOptions());
  }

  async #post<T>(input: {
    path: string;
    body: unknown;
    schema: z.ZodType<T>;
    timeoutMs: number;
  }): Promise<T> {
    const body = JSON.stringify(input.body);
    const timestamp = Date.now().toString();
    const nonce = randomBytes(16).toString("hex");
    const authorization = createSignerAuthorization({
      secret: this.#secret,
      timestamp,
      nonce,
      method: "POST",
      path: input.path,
      body,
    });
    let response: Response;
    try {
      response = await fetch(`${this.url}${input.path}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-payo-signer-timestamp": timestamp,
          "x-payo-signer-nonce": nonce,
          "x-payo-signer-authorization": authorization,
        },
        body,
        cache: "no-store",
        signal: AbortSignal.timeout(input.timeoutMs),
      });
    } catch (error) {
      throw new Error("The isolated policy signer could not be reached.", { cause: error });
    }
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const code = payload && typeof payload === "object" && "code" in payload
        ? String(payload.code)
        : "POLICY_SIGNER_REJECTED";
      throw new Error(`The isolated policy signer rejected the request (${code}).`);
    }
    return input.schema.parse(payload);
  }

  async getPubKey(): Promise<string> {
    return this.expectedPublicKey;
  }

  async signTransaction(calls: Call[], details: InvocationsSignerDetails): Promise<Signature> {
    const request = serializeProofSigningRequest({ requestId: randomUUID(), calls, details });
    const response = await this.#post({
      path: "/v1/sign-proof-invocation",
      body: request,
      schema: policySignerResponseSchema,
      timeoutMs: this.#proofTimeoutMs,
    });
    if (
      response.requestId !== request.requestId
      || !sameFelt(response.signerPublicKey, this.expectedPublicKey)
    ) throw new Error("The isolated policy signer response is not bound to this request.");
    return response.signature as Signature;
  }

  async configurePolicy(call: Call): Promise<{ transactionHash?: string; replayed: boolean }> {
    const request = serializePolicyConfigurationRequest({ requestId: randomUUID(), call });
    const response = await this.#post({
      path: "/v1/configure-policy",
      body: request,
      schema: policyConfigurationResponseSchema,
      timeoutMs: this.#configurationTimeoutMs,
    });
    if (
      response.requestId !== request.requestId
      || !sameFelt(response.signerPublicKey, this.expectedPublicKey)
    ) throw new Error("The isolated policy signer response is not bound to this request.");
    return {
      ...(response.transactionHash ? { transactionHash: response.transactionHash } : {}),
      replayed: response.replayed,
    };
  }

  async signMessage(typedData: TypedData, accountAddress: string): Promise<Signature> {
    void typedData;
    void accountAddress;
    throw new Error("The isolated policy signer does not sign messages.");
  }

  async signDeployAccountTransaction(details: DeployAccountSignerDetails): Promise<Signature> {
    void details;
    throw new Error("The isolated policy signer does not sign deployments.");
  }

  async signDeclareTransaction(details: DeclareSignerDetails): Promise<Signature> {
    void details;
    throw new Error("The isolated policy signer does not sign declarations.");
  }
}
