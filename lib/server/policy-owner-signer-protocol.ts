import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { ec, stark, type Call, type InvocationsSignerDetails, type Signature } from "starknet";
import { z } from "zod";

const FELT_PRIME = (1n << 251n) + 17n * (1n << 192n) + 1n;
const U128_LIMIT = 1n << 128n;
const U120_LIMIT = 1n << 120n;
const U32_LIMIT = 1n << 32n;
const PROOF_L2_GAS_MAX_AMOUNT = 100_000_000n;
const AUTH_VERSION = "payo-policy-signer-auth-v1";

const canonicalFeltSchema = z.string().regex(/^0x(?:0|[1-9a-f][0-9a-f]{0,62})$/);
const requestIdSchema = z.string().uuid();
const resourceBoundSchema = z.object({
  max_amount: canonicalFeltSchema,
  max_price_per_unit: canonicalFeltSchema,
}).strict();
const serializedCallSchema = z.object({
  contractAddress: canonicalFeltSchema,
  entrypoint: z.string().min(1).max(64),
  calldata: z.array(canonicalFeltSchema).max(200_000),
}).strict();

export const policyProofSigningRequestSchema = z.object({
  version: z.literal("payo-policy-proof-signing-v1"),
  requestId: requestIdSchema,
  calls: z.array(serializedCallSchema).length(1),
  details: z.object({
    walletAddress: canonicalFeltSchema,
    cairoVersion: z.literal("1"),
    chainId: canonicalFeltSchema,
    version: z.literal("0x3"),
    nonce: canonicalFeltSchema,
    resourceBounds: z.object({
      l1_gas: resourceBoundSchema,
      l2_gas: resourceBoundSchema,
      l1_data_gas: resourceBoundSchema,
    }).strict(),
    tip: canonicalFeltSchema,
    paymasterData: z.array(canonicalFeltSchema).max(0),
    accountDeploymentData: z.array(canonicalFeltSchema).max(0),
    nonceDataAvailabilityMode: z.literal("L1"),
    feeDataAvailabilityMode: z.literal("L1"),
    skipValidate: z.literal(true),
  }).strict(),
}).strict();
export type PolicyProofSigningRequest = z.infer<typeof policyProofSigningRequestSchema>;

export const policyConfigurationRequestSchema = z.object({
  version: z.literal("payo-policy-configuration-v1"),
  requestId: requestIdSchema,
  call: serializedCallSchema,
}).strict();
export type PolicyConfigurationRequest = z.infer<typeof policyConfigurationRequestSchema>;

export function serializePolicyConfigurationRequest(input: {
  requestId: string;
  call: Call;
}): PolicyConfigurationRequest {
  if (!Array.isArray(input.call.calldata)) {
    throw new Error("The policy configuration calldata must already be flattened.");
  }
  return policyConfigurationRequestSchema.parse({
    version: "payo-policy-configuration-v1",
    requestId: input.requestId,
    call: {
      contractAddress: canonicalFelt(input.call.contractAddress),
      entrypoint: input.call.entrypoint,
      calldata: input.call.calldata.map((value) => canonicalFelt(String(value))),
    },
  });
}

export const policySignerResponseSchema = z.object({
  version: z.literal("payo-policy-signer-response-v1"),
  requestId: requestIdSchema,
  signerPublicKey: canonicalFeltSchema,
  signature: z.array(canonicalFeltSchema).length(2),
}).strict();

export const policyConfigurationResponseSchema = z.object({
  version: z.literal("payo-policy-configuration-response-v1"),
  requestId: requestIdSchema,
  signerPublicKey: canonicalFeltSchema,
  transactionHash: canonicalFeltSchema.nullable(),
  replayed: z.boolean(),
}).strict();

export const policyConfigurationEstimateResponseSchema = z.object({
  version: z.literal("payo-policy-configuration-estimate-response-v1"),
  requestId: requestIdSchema,
  signerPublicKey: canonicalFeltSchema,
  blockNumber: z.number().int().nonnegative(),
  blockHash: canonicalFeltSchema,
  estimatedFeeFri: z.string().regex(/^(?:0|[1-9][0-9]*)$/),
  replayed: z.boolean(),
}).strict();

export type PolicySignerConstraints = {
  chainId: string;
  policyAccountAddress: string;
  poolAddress: string;
  sealAddress: string;
  viewingPublicKey: string;
  tokenAddresses: readonly string[];
  maxProofActions: number;
  maxCreatedNotes: number;
  maxPolicyLifetimeSeconds: number;
  maxCalls: number;
};

export function canonicalFelt(value: string | number | bigint): `0x${string}` {
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= FELT_PRIME) throw new Error("Value is not a canonical Starknet felt.");
  return `0x${parsed.toString(16)}`;
}

function sameFelt(left: string, right: string): boolean {
  try { return BigInt(left) === BigInt(right); } catch { return false; }
}

function availabilityMode(value: unknown): "L1" | "L2" {
  if (value === "L1" || value === 0 || value === "0") return "L1";
  if (value === "L2" || value === 1 || value === "1") return "L2";
  throw new Error("Unsupported data-availability mode.");
}

function serializeResourceBound(value: { max_amount: string | number | bigint; max_price_per_unit: string | number | bigint }) {
  return {
    max_amount: canonicalFelt(value.max_amount),
    max_price_per_unit: canonicalFelt(value.max_price_per_unit),
  };
}

export function serializeProofSigningRequest(input: {
  requestId: string;
  calls: Call[];
  details: InvocationsSignerDetails;
}): PolicyProofSigningRequest {
  const calls = input.calls.map((call) => {
    if (!Array.isArray(call.calldata)) throw new Error("The proof invocation calldata must already be flattened.");
    return {
      contractAddress: canonicalFelt(call.contractAddress),
      entrypoint: call.entrypoint,
      calldata: call.calldata.map((value) => canonicalFelt(String(value))),
    };
  });
  return policyProofSigningRequestSchema.parse({
    version: "payo-policy-proof-signing-v1",
    requestId: input.requestId,
    calls,
    details: {
      walletAddress: canonicalFelt(input.details.walletAddress),
      cairoVersion: input.details.cairoVersion,
      chainId: canonicalFelt(input.details.chainId),
      version: canonicalFelt(input.details.version),
      nonce: canonicalFelt(input.details.nonce),
      resourceBounds: {
        l1_gas: serializeResourceBound(input.details.resourceBounds.l1_gas),
        l2_gas: serializeResourceBound(input.details.resourceBounds.l2_gas),
        l1_data_gas: serializeResourceBound(input.details.resourceBounds.l1_data_gas),
      },
      tip: canonicalFelt(input.details.tip),
      paymasterData: input.details.paymasterData.map((value) => canonicalFelt(value)),
      accountDeploymentData: input.details.accountDeploymentData.map((value) => canonicalFelt(value)),
      nonceDataAvailabilityMode: availabilityMode(input.details.nonceDataAvailabilityMode),
      feeDataAvailabilityMode: availabilityMode(input.details.feeDataAvailabilityMode),
      skipValidate: input.details.skipValidate,
    },
  });
}

export function deserializeProofSigningRequest(request: PolicyProofSigningRequest): {
  calls: Call[];
  details: InvocationsSignerDetails;
} {
  return {
    calls: request.calls.map((call) => ({ ...call })),
    details: {
      ...request.details,
      chainId: request.details.chainId as InvocationsSignerDetails["chainId"],
      version: "0x3",
      nonce: request.details.nonce,
      resourceBounds: {
        l1_gas: {
          max_amount: BigInt(request.details.resourceBounds.l1_gas.max_amount),
          max_price_per_unit: BigInt(request.details.resourceBounds.l1_gas.max_price_per_unit),
        },
        l2_gas: {
          max_amount: BigInt(request.details.resourceBounds.l2_gas.max_amount),
          max_price_per_unit: BigInt(request.details.resourceBounds.l2_gas.max_price_per_unit),
        },
        l1_data_gas: {
          max_amount: BigInt(request.details.resourceBounds.l1_data_gas.max_amount),
          max_price_per_unit: BigInt(request.details.resourceBounds.l1_data_gas.max_price_per_unit),
        },
      },
      nonceDataAvailabilityMode: request.details.nonceDataAvailabilityMode,
      feeDataAvailabilityMode: request.details.feeDataAvailabilityMode,
    },
  };
}

function exactBound(
  actual: { max_amount: string; max_price_per_unit: string },
  expectedAmount: bigint,
): boolean {
  return BigInt(actual.max_amount) === expectedAmount && BigInt(actual.max_price_per_unit) === 0n;
}

function assertRestrictedProofActions(
  calldata: readonly string[],
  constraints: PolicySignerConstraints,
): void {
  let cursor = 2;
  const take = (label: string): bigint => {
    if (cursor >= calldata.length) {
      throw new Error(`The STRK20 proof action stream ended before ${label}.`);
    }
    return BigInt(calldata[cursor++]);
  };
  const assertNonzero = (value: bigint, label: string): void => {
    if (value === 0n) throw new Error(`The STRK20 ${label} is zero.`);
  };
  const assertU32 = (value: bigint, label: string): void => {
    if (value >= U32_LIMIT) throw new Error(`The STRK20 ${label} is outside u32.`);
  };
  const assertAllowedToken = (value: bigint): void => {
    if (!constraints.tokenAddresses.some((token) => sameFelt(token, value.toString()))) {
      throw new Error("The STRK20 proof action uses an unsupported payroll token.");
    }
  };

  const actionCount = take("action count");
  if (
    actionCount < 1n
    || actionCount > BigInt(constraints.maxProofActions)
  ) throw new Error("The STRK20 proof action count is outside the isolated signer limit.");

  let createdNotes = 0;
  for (let index = 0n; index < actionCount; index += 1n) {
    const variant = take(`action ${index} variant`);
    if (variant === 1n) {
      const recipient = take(`action ${index} OpenChannel recipient`);
      const channelIndex = take(`action ${index} OpenChannel index`);
      const random = take(`action ${index} OpenChannel random`);
      const salt = take(`action ${index} OpenChannel salt`);
      assertNonzero(recipient, "OpenChannel recipient");
      assertU32(channelIndex, "OpenChannel index");
      assertNonzero(random, "OpenChannel random");
      assertNonzero(salt, "OpenChannel salt");
    } else if (variant === 2n) {
      const recipient = take(`action ${index} OpenSubchannel recipient`);
      const publicKey = take(`action ${index} OpenSubchannel public key`);
      const channelKey = take(`action ${index} OpenSubchannel channel key`);
      const channelIndex = take(`action ${index} OpenSubchannel index`);
      const token = take(`action ${index} OpenSubchannel token`);
      const salt = take(`action ${index} OpenSubchannel salt`);
      assertNonzero(recipient, "OpenSubchannel recipient");
      assertNonzero(publicKey, "OpenSubchannel public key");
      assertNonzero(channelKey, "OpenSubchannel channel key");
      assertU32(channelIndex, "OpenSubchannel index");
      assertAllowedToken(token);
      assertNonzero(salt, "OpenSubchannel salt");
    } else if (variant === 3n) {
      const recipient = take(`action ${index} CreateEncNote recipient`);
      const publicKey = take(`action ${index} CreateEncNote public key`);
      const token = take(`action ${index} CreateEncNote token`);
      const amount = take(`action ${index} CreateEncNote amount`);
      const noteIndex = take(`action ${index} CreateEncNote index`);
      const salt = take(`action ${index} CreateEncNote salt`);
      assertNonzero(recipient, "CreateEncNote recipient");
      assertNonzero(publicKey, "CreateEncNote public key");
      assertAllowedToken(token);
      if (amount === 0n || amount >= U128_LIMIT) {
        throw new Error("The STRK20 encrypted-note amount is outside positive u128.");
      }
      assertU32(noteIndex, "CreateEncNote index");
      if (salt === 0n || salt >= U120_LIMIT) {
        throw new Error("The STRK20 encrypted-note salt is outside nonzero u120.");
      }
      createdNotes += 1;
    } else if (variant === 6n) {
      const channelKey = take(`action ${index} UseNote channel key`);
      const token = take(`action ${index} UseNote token`);
      const noteIndex = take(`action ${index} UseNote index`);
      assertNonzero(channelKey, "UseNote channel key");
      assertAllowedToken(token);
      assertU32(noteIndex, "UseNote index");
    } else {
      throw new Error(
        "The isolated signer forbids registration, deposits, open notes, withdrawals and external actions.",
      );
    }
  }
  if (cursor !== calldata.length) {
    throw new Error("The STRK20 proof action stream contains trailing calldata.");
  }
  if (createdNotes < 1 || createdNotes > constraints.maxCreatedNotes) {
    throw new Error("The STRK20 encrypted-note count is outside the isolated signer limit.");
  }
}

export function assertRestrictedProofSigningRequest(
  raw: unknown,
  constraints: PolicySignerConstraints,
): PolicyProofSigningRequest {
  const request = policyProofSigningRequestSchema.parse(raw);
  const call = request.calls[0];
  const details = request.details;
  if (
    !sameFelt(call.contractAddress, constraints.poolAddress)
    || call.entrypoint !== "compile_actions"
    || !sameFelt(details.walletAddress, constraints.poolAddress)
    || !sameFelt(details.chainId, constraints.chainId)
    || BigInt(details.version) !== 3n
    || BigInt(details.nonce) !== 0n
    || BigInt(details.tip) !== 0n
    || !exactBound(details.resourceBounds.l1_gas, 1n)
    || !exactBound(details.resourceBounds.l2_gas, PROOF_L2_GAS_MAX_AMOUNT)
    || !exactBound(details.resourceBounds.l1_data_gas, 1n)
    || details.paymasterData.length !== 0
    || details.accountDeploymentData.length !== 0
    || details.nonceDataAvailabilityMode !== "L1"
    || details.feeDataAvailabilityMode !== "L1"
    || details.skipValidate !== true
  ) throw new Error("The requested signature is not a canonical STRK20 proof invocation.");
  if (
    call.calldata.length < 3
    || !sameFelt(call.calldata[0], constraints.policyAccountAddress)
  ) throw new Error("The STRK20 proof invocation is not bound to the policy treasury.");
  let derivedViewingPublicKey: string;
  try { derivedViewingPublicKey = ec.starkCurve.getStarkKey(call.calldata[1]); } catch {
    throw new Error("The STRK20 proof invocation contains an invalid viewing key.");
  }
  if (!sameFelt(derivedViewingPublicKey, constraints.viewingPublicKey)) {
    throw new Error("The STRK20 proof invocation uses an unregistered viewing key.");
  }
  assertRestrictedProofActions(call.calldata, constraints);
  return request;
}

export function assertRestrictedPolicyConfiguration(
  raw: unknown,
  constraints: PolicySignerConstraints,
  nowUnixSeconds = Math.floor(Date.now() / 1_000),
): PolicyConfigurationRequest {
  const request = policyConfigurationRequestSchema.parse(raw);
  const { call } = request;
  if (
    !sameFelt(call.contractAddress, constraints.policyAccountAddress)
    || call.entrypoint !== "configure_policy"
    || call.calldata.length !== 19
  ) throw new Error("The signer only accepts one canonical policy configuration call.");
  const values = call.calldata.map(BigInt);
  const [policyId, sessionPublicKey, pool, seal, sealMode, proofVersion, schemaVersion] = values;
  const validAfter = values[14];
  const validBefore = values[15];
  const periodSeconds = values[16];
  const maxCallsPerPeriod = values[17];
  const maxCallCount = values[18];
  if (
    policyId === 0n
    || sessionPublicKey === 0n
    || !sameFelt(pool.toString(), constraints.poolAddress)
    || !sameFelt(seal.toString(), constraints.sealAddress)
    || sealMode !== 0n
    || (proofVersion !== 1n && proofVersion !== 2n)
    || schemaVersion !== 1n
    || (values[7] === 0n && values[8] === 0n)
    || values.slice(9, 14).some((value) => value === 0n)
    || validBefore <= validAfter
    || validBefore - validAfter > BigInt(constraints.maxPolicyLifetimeSeconds)
    || validAfter > BigInt(nowUnixSeconds + 300)
    || validBefore <= BigInt(nowUnixSeconds)
    || periodSeconds === 0n
    || periodSeconds > BigInt(constraints.maxPolicyLifetimeSeconds)
    || maxCallsPerPeriod === 0n
    || maxCallCount === 0n
    || maxCallsPerPeriod > maxCallCount
    || maxCallCount > BigInt(constraints.maxCalls)
  ) throw new Error("The policy configuration exceeds the isolated signer limits.");
  return request;
}

export function configuredPolicyMatches(call: PolicyConfigurationRequest["call"], state: readonly string[]): boolean {
  if (state.length !== 23 || BigInt(state[0]) !== 1n) return false;
  if (BigInt(state[1]) !== 0n) return false;
  return call.calldata.slice(1).every((value, index) => BigInt(value) === BigInt(state[index + 2]));
}

export function formatPolicySignature(signature: Signature): [`0x${string}`, `0x${string}`] {
  const formatted = stark.formatSignature(signature);
  if (formatted.length !== 2) throw new Error("The Stark signer returned a non-canonical signature.");
  return [canonicalFelt(formatted[0]), canonicalFelt(formatted[1])];
}

export function signerAuthMessage(input: {
  timestamp: string;
  nonce: string;
  method: string;
  path: string;
  body: string;
}): string {
  const digest = createHash("sha256").update(input.body).digest("hex");
  return [AUTH_VERSION, input.timestamp, input.nonce, input.method.toUpperCase(), input.path, digest].join("\n");
}

export function createSignerAuthorization(input: {
  secret: string;
  timestamp: string;
  nonce: string;
  method: string;
  path: string;
  body: string;
}): string {
  return createHmac("sha256", input.secret).update(signerAuthMessage(input)).digest("hex");
}

export function verifySignerAuthorization(input: {
  secret: string;
  timestamp: string;
  nonce: string;
  method: string;
  path: string;
  body: string;
  authorization: string;
  nowMs?: number;
  maxSkewMs?: number;
}): void {
  if (!/^\d{13}$/.test(input.timestamp) || !/^[0-9a-f]{32}$/.test(input.nonce)) {
    throw new Error("The signer authorization headers are invalid.");
  }
  const nowMs = input.nowMs ?? Date.now();
  if (Math.abs(nowMs - Number(input.timestamp)) > (input.maxSkewMs ?? 30_000)) {
    throw new Error("The signer request timestamp is stale.");
  }
  const expected = createSignerAuthorization(input);
  const actualBuffer = Buffer.from(input.authorization, "hex");
  const expectedBuffer = Buffer.from(expected, "hex");
  if (
    !/^[0-9a-f]{64}$/.test(input.authorization)
    || actualBuffer.length !== expectedBuffer.length
    || !timingSafeEqual(actualBuffer, expectedBuffer)
  ) throw new Error("The signer request authentication failed.");
}

export function signerPublicKey(privateKey: string): `0x${string}` {
  return canonicalFelt(ec.starkCurve.getStarkKey(privateKey));
}
