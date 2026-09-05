import { ec, hash, num, shortString, type Call } from "starknet";
import {
  directPrivacyAccountConfigSchema,
  type DirectPrivacyAccountConfig,
} from "@/lib/domain/direct-privacy";

const U128_MASK = (1n << 128n) - 1n;

function felt(value: string | number | bigint): `0x${string}` {
  const parsed = BigInt(value);
  const prime = (1n << 251n) + 17n * (1n << 192n) + 1n;
  if (parsed < 0n || parsed >= prime) throw new Error("Policy account input is not a canonical Starknet felt.");
  return num.toHex(parsed) as `0x${string}`;
}

function selfCall(input: {
  policyAccountAddress: string;
  entrypoint: string;
  calldata: readonly (string | number | bigint)[];
}): Call {
  const address = felt(input.policyAccountAddress);
  if (!/^[_a-zA-Z][_a-zA-Z0-9]{0,63}$/.test(input.entrypoint)) {
    throw new Error("Policy account entrypoint is invalid.");
  }
  return {
    contractAddress: address,
    entrypoint: input.entrypoint,
    calldata: input.calldata.map(felt),
  };
}

function splitRoot(root: `0x${string}`): readonly [`0x${string}`, `0x${string}`] {
  const value = BigInt(root);
  return [felt(value >> 128n), felt(value & U128_MASK)];
}

/**
 * Exact owner-reviewed self-call for `PayoPolicyAccount::configure_policy`.
 * Ready submits this call through the account's normal SNIP-6 execution path;
 * the autonomous session secret never enters the browser response.
 */
export function buildConfigurePolicyCall(configInput: DirectPrivacyAccountConfig): Call {
  const config = directPrivacyAccountConfigSchema.parse(configInput);
  const [policyRootHigh, policyRootLow] = splitRoot(config.payrollPolicyRoot);
  return {
    contractAddress: config.policyAccountAddress,
    entrypoint: "configure_policy",
    calldata: [
      config.policyId,
      config.sessionPublicKey,
      config.poolAddress,
      config.sealAddress,
      config.bookSealAddress ?? "0x0",
      felt(config.sealMode),
      felt(config.proofVersion),
      felt(config.schemaVersion),
      policyRootHigh,
      policyRootLow,
      config.tokenSetCommitment,
      config.recipientSetCommitment,
      config.purposeCommitment,
      config.amountLimitCommitment,
      config.authorizedRunsRoot,
      felt(config.validAfterUnix),
      felt(config.validBeforeUnix),
      felt(config.periodSeconds),
      felt(config.maxCallsPerPeriod),
      felt(config.maxCallCount),
    ],
  };
}

/** Owner-only irreversible policy revocation. */
export function buildRevokePolicyCall(input: {
  policyAccountAddress: string;
  policyId: string;
}): Call {
  return selfCall({ ...input, entrypoint: "revoke_policy", calldata: [input.policyId] });
}

/** Owner-only session-key rotation; private keys are never call inputs. */
export function buildRotatePolicySessionKeyCall(input: {
  policyAccountAddress: string;
  policyId: string;
  newSessionPublicKey: string;
}): Call {
  const publicKey = felt(input.newSessionPublicKey);
  if (BigInt(publicKey) === 0n) throw new Error("The replacement session public key cannot be zero.");
  return selfCall({
    ...input,
    entrypoint: "rotate_session_key",
    calldata: [input.policyId, publicKey],
  });
}

/** Owner-only emergency pause/unpause. */
export function buildSetPolicyAccountPausedCall(input: {
  policyAccountAddress: string;
  paused: boolean;
}): Call {
  return selfCall({
    policyAccountAddress: input.policyAccountAddress,
    entrypoint: "set_policy_account_paused",
    calldata: [input.paused ? 1 : 0],
  });
}

/** Exact OpenZeppelin AccountComponent acceptance digest signed by the new owner. */
export function computePolicyOwnerAcceptanceHash(input: {
  policyAccountAddress: string;
  currentOwnerPublicKey: string;
}): `0x${string}` {
  return num.toHex(hash.computePoseidonHashOnElements([
    shortString.encodeShortString("StarkNet Message"),
    shortString.encodeShortString("accept_ownership"),
    felt(input.policyAccountAddress),
    felt(input.currentOwnerPublicKey),
  ])) as `0x${string}`;
}

/**
 * Owner recovery call. The current owner submits the account transaction, and
 * the replacement owner separately signs the fixed acceptance digest. This
 * prevents rotating a policy account to an unusable or unconsenting key.
 */
export function buildRotatePolicyOwnerCall(input: {
  policyAccountAddress: string;
  currentOwnerPublicKey: string;
  newOwnerPublicKey: string;
  newOwnerAcceptanceSignature: readonly [string, string];
}): Call {
  const newOwner = felt(input.newOwnerPublicKey);
  if (BigInt(newOwner) === 0n) throw new Error("The replacement owner public key cannot be zero.");
  const digest = computePolicyOwnerAcceptanceHash(input);
  const signature = input.newOwnerAcceptanceSignature.map(felt) as [`0x${string}`, `0x${string}`];
  const starkSignature = new ec.starkCurve.Signature(BigInt(signature[0]), BigInt(signature[1]));
  const ownerX = BigInt(newOwner).toString(16).padStart(64, "0");
  const accepted = ["02", "03"].some((prefix) => {
    try { return ec.starkCurve.verify(starkSignature, digest, `${prefix}${ownerX}`); } catch { return false; }
  });
  if (!accepted) {
    throw new Error("The replacement owner did not sign the policy-account acceptance digest.");
  }
  return selfCall({
    policyAccountAddress: input.policyAccountAddress,
    entrypoint: "set_public_key",
    calldata: [newOwner, signature.length, ...signature],
  });
}
