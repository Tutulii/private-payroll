import { randomUUID } from "node:crypto";
import { Signer, type Call, type InvocationsSignerDetails } from "starknet";
import { describe, expect, it } from "vitest";
import {
  assertRestrictedPolicyConfiguration,
  assertRestrictedProofSigningRequest,
  createSignerAuthorization,
  formatPolicySignature,
  serializePolicyConfigurationRequest,
  serializeProofSigningRequest,
  signerPublicKey,
  verifySignerAuthorization,
  type PolicySignerConstraints,
} from "./policy-owner-signer-protocol";
import { PolicyOwnerSignerService } from "./policy-owner-signer-service";

const ownerPrivateKey = "0x123456";
const viewingKey = "0x98765";
const now = 1_800_000_000;
const constraints: PolicySignerConstraints = {
  chainId: "0x534e5f4d41494e",
  policyAccountAddress: "0x111",
  poolAddress: "0x222",
  sealAddress: "0x333",
  viewingPublicKey: signerPublicKey(viewingKey),
  tokenAddresses: ["0xabc", "0xdef"],
  maxProofActions: 64,
  maxCreatedNotes: 8,
  maxPolicyLifetimeSeconds: 3_600,
  maxCalls: 8,
};

const details = {
  walletAddress: constraints.poolAddress,
  cairoVersion: "1",
  chainId: constraints.chainId,
  version: "0x3",
  nonce: 0n,
  resourceBounds: {
    l1_gas: { max_amount: 1n, max_price_per_unit: 0n },
    l2_gas: { max_amount: 100_000_000n, max_price_per_unit: 0n },
    l1_data_gas: { max_amount: 1n, max_price_per_unit: 0n },
  },
  tip: 0n,
  paymasterData: [],
  accountDeploymentData: [],
  nonceDataAvailabilityMode: "L1",
  feeDataAvailabilityMode: "L1",
  skipValidate: true,
} as InvocationsSignerDetails;

const proofCalls: Call[] = [{
  contractAddress: constraints.poolAddress,
  entrypoint: "compile_actions",
  calldata: [
    constraints.policyAccountAddress,
    viewingKey,
    "0x1",
    "0x3",
    "0x777",
    "0x888",
    "0xabc",
    "0x64",
    "0x0",
    "0x999",
  ],
}];

function proofRequest() {
  return serializeProofSigningRequest({ requestId: randomUUID(), calls: proofCalls, details });
}

function configurationCall(): Call {
  return {
    contractAddress: constraints.policyAccountAddress,
    entrypoint: "configure_policy",
    calldata: [
      "0x444", "0x555", constraints.poolAddress, constraints.sealAddress,
      "0x0", "0x0", "0x2", "0x1", "0x12", "0x34", "0x666", "0x777",
      "0x888", "0x999", "0xaaa", `0x${(now - 1).toString(16)}`,
      `0x${(now + 600).toString(16)}`, "0x258", "0x1", "0x1",
    ],
  };
}

describe("isolated policy-owner signer protocol", () => {
  it("accepts and reproduces only the canonical STRK20 proof signature", async () => {
    const request = assertRestrictedProofSigningRequest(proofRequest(), constraints);
    const service = new PolicyOwnerSignerService({
      provider: {} as never,
      account: {} as never,
      ownerPrivateKey,
      constraints,
      now: () => new Date(now * 1_000),
    });
    const response = await service.signProofInvocation(request);
    const expected = formatPolicySignature(await new Signer(ownerPrivateKey)
      .signTransaction(proofCalls, details));
    expect(response).toMatchObject({
      requestId: request.requestId,
      signerPublicKey: signerPublicKey(ownerPrivateKey),
      signature: expected,
    });
  });

  it("accepts bounded channel setup only when coupled to an encrypted payroll note", () => {
    const request = proofRequest();
    request.calls[0].calldata = [
      constraints.policyAccountAddress,
      viewingKey,
      "0x3",
      // OpenChannel(recipient, index, random, salt)
      "0x1", "0x777", "0x0", "0x111", "0x222",
      // OpenSubchannel(recipient, public key, channel key, index, token, salt)
      "0x2", "0x777", "0x888", "0x999", "0x0", "0xabc", "0x333",
      // CreateEncNote(recipient, public key, token, amount, note index, salt)
      "0x3", "0x777", "0x888", "0xabc", "0x64", "0x0", "0x444",
    ];
    expect(() => assertRestrictedProofSigningRequest(request, constraints)).not.toThrow();

    const setupOnly = structuredClone(request);
    setupOnly.calls[0].calldata = setupOnly.calls[0].calldata.slice(0, -7);
    setupOnly.calls[0].calldata[2] = "0x2";
    expect(() => assertRestrictedProofSigningRequest(setupOnly, constraints))
      .toThrow("encrypted-note count");
  });

  it("accepts exactly one pinned universal-book callback and rejects every substitution", () => {
    const universalConstraints = { ...constraints, bookSealAddress: "0x444" };
    const request = proofRequest();
    request.calls[0].calldata = [
      constraints.policyAccountAddress,
      viewingKey,
      "0x2",
      // CreateEncNote(recipient, public key, token, amount, index, salt)
      "0x3", "0x777", "0x888", "0xabc", "0x64", "0x0", "0x999",
      // InvokeExternal(book, [run high, run low, zero release, entry high, entry low])
      "0x8", "0x444", "0x6", "0x11", "0x12", "0x0", "0x0", "0x13", "0x14",
    ];
    expect(() => assertRestrictedProofSigningRequest(request, universalConstraints)).not.toThrow();

    const wrongTarget = structuredClone(request);
    wrongTarget.calls[0].calldata[11] = "0x445";
    expect(() => assertRestrictedProofSigningRequest(wrongTarget, universalConstraints))
      .toThrow("exact universal-book callback");

    const wrongRun = structuredClone(request);
    wrongRun.calls[0].calldata[13] = "0x0";
    wrongRun.calls[0].calldata[14] = "0x0";
    expect(() => assertRestrictedProofSigningRequest(wrongRun, universalConstraints))
      .toThrow("invalid agent bindings");

    const missing = structuredClone(request);
    missing.calls[0].calldata = missing.calls[0].calldata.slice(0, 10);
    missing.calls[0].calldata[2] = "0x1";
    expect(() => assertRestrictedProofSigningRequest(missing, universalConstraints))
      .toThrow("exactly one universal-book callback");
  });

  it.each([
    ["pool target", (value: ReturnType<typeof proofRequest>) => { value.calls[0].contractAddress = "0x999"; }],
    ["entrypoint", (value: ReturnType<typeof proofRequest>) => { value.calls[0].entrypoint = "apply_actions"; }],
    ["policy treasury", (value: ReturnType<typeof proofRequest>) => { value.calls[0].calldata[0] = "0x999"; }],
    ["viewing key", (value: ReturnType<typeof proofRequest>) => { value.calls[0].calldata[1] = "0x123"; }],
    ["chain", (value: ReturnType<typeof proofRequest>) => { value.details.chainId = "0x1"; }],
    ["nonce", (value: ReturnType<typeof proofRequest>) => { value.details.nonce = "0x1"; }],
    ["proof fee", (value: ReturnType<typeof proofRequest>) => { value.details.resourceBounds.l2_gas.max_price_per_unit = "0x1"; }],
    ["paymaster", (value: ReturnType<typeof proofRequest>) => { (value.details.paymasterData as string[]).push("0x1"); }],
    ["unsupported token", (value: ReturnType<typeof proofRequest>) => { value.calls[0].calldata[6] = "0x123"; }],
    ["zero actions", (value: ReturnType<typeof proofRequest>) => { value.calls[0].calldata = value.calls[0].calldata.slice(0, 3); value.calls[0].calldata[2] = "0x0"; }],
    ["forbidden action", (value: ReturnType<typeof proofRequest>) => { value.calls[0].calldata = [constraints.policyAccountAddress, viewingKey, "0x1", "0x5", "0xabc", "0x1"]; }],
    ["trailing calldata", (value: ReturnType<typeof proofRequest>) => { value.calls[0].calldata.push("0x1"); }],
  ])("rejects a substituted %s", (_label, mutate) => {
    const request = proofRequest();
    mutate(request);
    expect(() => assertRestrictedProofSigningRequest(request, constraints)).toThrow();
  });

  it("authenticates method, path, body, time and nonce without exposing the secret", () => {
    const input = {
      secret: "s".repeat(64),
      timestamp: "1800000000000",
      nonce: "ab".repeat(16),
      method: "POST",
      path: "/v1/sign-proof-invocation",
      body: JSON.stringify(proofRequest()),
    };
    const authorization = createSignerAuthorization(input);
    expect(() => verifySignerAuthorization({
      ...input,
      authorization,
      nowMs: 1_800_000_000_000,
    })).not.toThrow();
    expect(() => verifySignerAuthorization({
      ...input,
      body: `${input.body} `,
      authorization,
      nowMs: 1_800_000_000_000,
    })).toThrow("authentication failed");
    expect(() => verifySignerAuthorization({
      ...input,
      authorization,
      nowMs: 1_800_000_100_000,
    })).toThrow("timestamp is stale");
  });

  it("bounds every owner-authorized policy configuration field", () => {
    const valid = serializePolicyConfigurationRequest({
      requestId: randomUUID(),
      call: configurationCall(),
    });
    expect(assertRestrictedPolicyConfiguration(valid, constraints, now)).toEqual(valid);
    const universalConstraints = { ...constraints, bookSealAddress: "0x444" };
    const universal = structuredClone(valid);
    universal.call.calldata[4] = "0x444";
    universal.call.calldata[5] = "0x2";
    expect(assertRestrictedPolicyConfiguration(universal, universalConstraints, now)).toEqual(universal);
    const wrongBook = structuredClone(universal);
    wrongBook.call.calldata[4] = "0x445";
    expect(() => assertRestrictedPolicyConfiguration(wrongBook, universalConstraints, now))
      .toThrow("exceeds");

    const broad = structuredClone(valid);
    broad.call.calldata[19] = "0x9";
    expect(() => assertRestrictedPolicyConfiguration(broad, constraints, now)).toThrow("exceeds");
    const arbitrary = structuredClone(valid);
    arbitrary.call.entrypoint = "set_public_key";
    expect(() => assertRestrictedPolicyConfiguration(arbitrary, constraints, now)).toThrow("only accepts");
  });

  it("returns a pinned fee review without submitting the policy", async () => {
    const request = serializePolicyConfigurationRequest({
      requestId: randomUUID(),
      call: configurationCall(),
    });
    let submissions = 0;
    let estimatedAt: unknown;
    const service = new PolicyOwnerSignerService({
      provider: {
        getBlock: async () => ({ block_hash: "0xabc", block_number: 42 }),
        getChainId: async () => constraints.chainId,
        callContract: async (call: { entrypoint: string }) => {
          if (call.entrypoint === "get_public_key") return [signerPublicKey(ownerPrivateKey)];
          if (call.entrypoint === "get_policy") return ["0x0", ...Array.from({ length: 23 }, () => "0x0")];
          throw new Error("unexpected call");
        },
      } as never,
      account: {
        estimateInvokeFee: async (_call: unknown, options: { blockIdentifier?: unknown }) => {
          estimatedAt = options.blockIdentifier;
          return ({
            overall_fee: 123n,
            resourceBounds: details.resourceBounds,
          });
        },
        execute: async () => {
          submissions += 1;
          throw new Error("estimate must not submit");
        },
      } as never,
      ownerPrivateKey,
      constraints,
      now: () => new Date(now * 1_000),
    });
    await expect(service.estimatePolicy(request)).resolves.toMatchObject({
      blockNumber: 42,
      blockHash: "0xabc",
      estimatedFeeFri: "123",
      replayed: false,
    });
    expect(submissions).toBe(0);
    expect(estimatedAt).toBe("0xabc");
  });

  it("serializes concurrent configuration, submits once and returns an idempotent replay", async () => {
    const call = serializePolicyConfigurationRequest({ requestId: randomUUID(), call: configurationCall() });
    let state = ["0x0", ...Array.from({ length: 23 }, () => "0x0")];
    let submissions = 0;
    const provider = {
      getBlock: async () => ({ block_hash: "0xabc" }),
      getChainId: async () => constraints.chainId,
      callContract: async (request: { entrypoint: string }) => {
        if (request.entrypoint === "get_public_key") return [signerPublicKey(ownerPrivateKey)];
        if (request.entrypoint === "get_policy") return state;
        throw new Error("unexpected call");
      },
      waitForTransaction: async () => ({ isReverted: () => false }),
    };
    const account = {
      estimateInvokeFee: async () => ({ resourceBounds: details.resourceBounds }),
      execute: async () => {
        submissions += 1;
        state = ["0x1", "0x0", ...call.call.calldata.slice(1), "0x0", "0x0", "0x0"];
        return { transaction_hash: "0x123" };
      },
    };
    const service = new PolicyOwnerSignerService({
      provider: provider as never,
      account: account as never,
      ownerPrivateKey,
      constraints,
      now: () => new Date(now * 1_000),
    });
    const [first, second] = await Promise.all([
      service.configurePolicy(call),
      service.configurePolicy({ ...call, requestId: randomUUID() }),
    ]);
    expect(submissions).toBe(1);
    expect(first).toMatchObject({ transactionHash: "0x123", replayed: false });
    expect(second).toMatchObject({ transactionHash: null, replayed: true });
  });
});
