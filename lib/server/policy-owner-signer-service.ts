import { Account, RpcProvider, Signer } from "starknet";
import {
  assertRestrictedPolicyConfiguration,
  assertRestrictedProofSigningRequest,
  canonicalFelt,
  configuredPolicyMatches,
  deserializeProofSigningRequest,
  formatPolicySignature,
  signerPublicKey,
  type PolicySignerConstraints,
} from "./policy-owner-signer-protocol";

type PolicySignerProvider = Pick<
  RpcProvider,
  "getBlock" | "getChainId" | "callContract" | "waitForTransaction"
>;

type PolicySignerAccount = Pick<Account, "estimateInvokeFee" | "execute">;

function sameFelt(left: string, right: string): boolean {
  try { return BigInt(left) === BigInt(right); } catch { return false; }
}

export class PolicyOwnerSignerService {
  readonly signerPublicKey: `0x${string}`;
  readonly #provider: PolicySignerProvider;
  readonly #account: PolicySignerAccount;
  readonly #signer: Signer;
  readonly #constraints: PolicySignerConstraints;
  readonly #now: () => Date;
  #configurationQueue: Promise<unknown> = Promise.resolve();

  constructor(input: {
    provider: PolicySignerProvider;
    account: PolicySignerAccount;
    ownerPrivateKey: string;
    constraints: PolicySignerConstraints;
    expectedSignerPublicKey?: string;
    now?: () => Date;
  }) {
    this.signerPublicKey = signerPublicKey(input.ownerPrivateKey);
    if (
      input.expectedSignerPublicKey
      && !sameFelt(this.signerPublicKey, input.expectedSignerPublicKey)
    ) throw new Error("The isolated signer key does not match its pinned public key.");
    this.#provider = input.provider;
    this.#account = input.account;
    this.#signer = new Signer(input.ownerPrivateKey);
    this.#constraints = input.constraints;
    this.#now = input.now ?? (() => new Date());
  }

  async attestDeployment(): Promise<void> {
    const block = await this.#provider.getBlock("latest");
    const blockHash = block.block_hash;
    const [chainId, owner, registration] = await Promise.all([
      this.#provider.getChainId(),
      this.#provider.callContract({
        contractAddress: this.#constraints.policyAccountAddress,
        entrypoint: "get_public_key",
        calldata: [],
      }, blockHash),
      this.#provider.callContract({
        contractAddress: this.#constraints.poolAddress,
        entrypoint: "get_public_key",
        calldata: [this.#constraints.policyAccountAddress],
      }, blockHash),
    ]);
    if (
      !sameFelt(chainId, this.#constraints.chainId)
      || owner.length !== 1
      || !sameFelt(owner[0], this.signerPublicKey)
      || registration.length !== 1
      || !sameFelt(registration[0], this.#constraints.viewingPublicKey)
    ) throw new Error("The isolated signer deployment attestation failed.");
  }

  async signProofInvocation(raw: unknown) {
    const request = assertRestrictedProofSigningRequest(raw, this.#constraints);
    const { calls, details } = deserializeProofSigningRequest(request);
    const signature = formatPolicySignature(await this.#signer.signTransaction(calls, details));
    return {
      version: "payo-policy-signer-response-v1" as const,
      requestId: request.requestId,
      signerPublicKey: this.signerPublicKey,
      signature,
    };
  }

  configurePolicy(raw: unknown) {
    const operation = this.#configurationQueue.then(() => this.#configurePolicy(raw));
    this.#configurationQueue = operation.then(() => undefined, () => undefined);
    return operation;
  }

  async #configurePolicy(raw: unknown) {
    const request = assertRestrictedPolicyConfiguration(
      raw,
      this.#constraints,
      Math.floor(this.#now().getTime() / 1_000),
    );
    const block = await this.#provider.getBlock("latest");
    const blockHash = block.block_hash;
    const [chainId, owner, current] = await Promise.all([
      this.#provider.getChainId(),
      this.#provider.callContract({
        contractAddress: this.#constraints.policyAccountAddress,
        entrypoint: "get_public_key",
        calldata: [],
      }, blockHash),
      this.#provider.callContract({
        contractAddress: this.#constraints.policyAccountAddress,
        entrypoint: "get_policy",
        calldata: [request.call.calldata[0]],
      }, blockHash),
    ]);
    if (
      !sameFelt(chainId, this.#constraints.chainId)
      || owner.length !== 1
      || !sameFelt(owner[0], this.signerPublicKey)
    ) throw new Error("The isolated signer no longer controls the pinned policy account.");
    if (current.length !== 23) throw new Error("The policy account returned an invalid policy state.");
    if (BigInt(current[0]) === 1n) {
      if (!configuredPolicyMatches(request.call, current)) {
        throw new Error("The policy identifier is already configured with different limits.");
      }
      return {
        version: "payo-policy-configuration-response-v1" as const,
        requestId: request.requestId,
        signerPublicKey: this.signerPublicKey,
        transactionHash: null,
        replayed: true,
      };
    }
    const estimate = await this.#account.estimateInvokeFee(request.call);
    const submitted = await this.#account.execute(request.call, {
      resourceBounds: estimate.resourceBounds,
    });
    const receipt = await this.#provider.waitForTransaction(submitted.transaction_hash, {
      retries: 400,
      retryInterval: 3_000,
    });
    if (receipt.isReverted()) throw new Error("The policy configuration reverted on Starknet.");
    const verifiedBlock = await this.#provider.getBlock("latest");
    const verified = await this.#provider.callContract({
      contractAddress: this.#constraints.policyAccountAddress,
      entrypoint: "get_policy",
      calldata: [request.call.calldata[0]],
    }, verifiedBlock.block_hash);
    if (!configuredPolicyMatches(request.call, verified)) {
      throw new Error("The confirmed policy configuration failed read-back verification.");
    }
    return {
      version: "payo-policy-configuration-response-v1" as const,
      requestId: request.requestId,
      signerPublicKey: this.signerPublicKey,
      transactionHash: canonicalFelt(submitted.transaction_hash),
      replayed: false,
    };
  }
}
