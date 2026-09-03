import "server-only";

import { num } from "starknet";

type AddressMapLike<T> = {
  get(key: bigint): T | undefined;
  has(key: bigint): boolean;
};

export type DirectPrivacyDiscoveredChannel = {
  publicKey?: bigint;
  key?: bigint;
  tokens: AddressMapLike<{ tokenIndex: number; noteNonce: number }>;
};

export type DirectPrivacyChannelRequirement = {
  recipient: bigint;
  token: bigint;
};

export type DirectPrivacyReadinessFailure = {
  code:
    | "DIRECT_TREASURY_REGISTRATION_REQUIRED"
    | "DIRECT_RECIPIENT_REGISTRATION_REQUIRED"
    | "DIRECT_CHANNEL_SETUP_REQUIRED"
    | "DIRECT_TOKEN_CHANNEL_SETUP_REQUIRED"
    | "DIRECT_DISCOVERY_RESPONSE_INVALID";
  message: string;
};

function hashFromBlockReference(value: unknown): bigint | null {
  try {
    if (typeof value === "string" && /^0x[0-9a-fA-F]{1,64}$/.test(value)) {
      return BigInt(value);
    }
    if (value && typeof value === "object" && "block_hash" in value) {
      const hash = (value as { block_hash: unknown }).block_hash;
      return typeof hash === "string" && /^0x[0-9a-fA-F]{1,64}$/.test(hash)
        ? BigInt(hash)
        : null;
    }
  } catch { /* invalid references fail closed */ }
  return null;
}

/** A response to a hash-pinned query must echo that exact hash, never a tag or height. */
export function isExactPinnedBlockReference(value: unknown, expectedHash: string): boolean {
  const actual = hashFromBlockReference(value);
  try {
    return actual !== null && actual === BigInt(expectedHash);
  } catch {
    return false;
  }
}

function label(value: bigint): string {
  const encoded = num.toHex(value);
  return encoded.length <= 18
    ? encoded
    : `${encoded.slice(0, 10)}…${encoded.slice(-6)}`;
}

/**
 * Checks the exact registration/channel state in one hash-pinned full
 * outgoing-channel snapshot. Callers using the bounded SDK `autoSetup` path
 * may accept absent channels/subchannels, but malformed discovered nonce state
 * always fails closed.
 */
export function findDirectPrivacyReadinessFailure(input: {
  channels: AddressMapLike<DirectPrivacyDiscoveredChannel> | undefined;
  treasuryAddress: bigint;
  requirements: readonly DirectPrivacyChannelRequirement[];
  allowSetup?: boolean;
}): DirectPrivacyReadinessFailure | null {
  const unique = new Map<string, DirectPrivacyChannelRequirement>();
  for (const requirement of input.requirements) {
    unique.set(`${requirement.recipient.toString()}:${requirement.token.toString()}`, requirement);
  }
  for (const requirement of unique.values()) {
    const channel = input.channels?.get(requirement.recipient);
    const isTreasury = requirement.recipient === input.treasuryAddress;
    if (!channel?.publicKey) {
      return {
        code: isTreasury
          ? "DIRECT_TREASURY_REGISTRATION_REQUIRED"
          : "DIRECT_RECIPIENT_REGISTRATION_REQUIRED",
        message: isTreasury
          ? "The direct private treasury is not registered at the pinned block."
          : `Private recipient ${label(requirement.recipient)} is not registered at the pinned block.`,
      };
    }
    if (!channel.key) {
      if (input.allowSetup) continue;
      return {
        code: "DIRECT_CHANNEL_SETUP_REQUIRED",
        message: `The private channel for ${label(requirement.recipient)} is not open at the pinned block.`,
      };
    }
    if (!channel.tokens?.has(requirement.token)) {
      if (input.allowSetup) continue;
      return {
        code: "DIRECT_TOKEN_CHANNEL_SETUP_REQUIRED",
        message: `The token channel for ${label(requirement.recipient)} is not ready at the pinned block.`,
      };
    }
    const tokenChannel = channel.tokens.get(requirement.token);
    if (!tokenChannel) {
      return {
        code: "DIRECT_DISCOVERY_RESPONSE_INVALID",
        message: `The token channel for ${label(requirement.recipient)} disappeared during readiness validation.`,
      };
    }
    if (
      !Number.isSafeInteger(tokenChannel.tokenIndex)
      || tokenChannel.tokenIndex < 0
      || !Number.isSafeInteger(tokenChannel.noteNonce)
      || tokenChannel.noteNonce < 0
    ) {
      return {
        code: "DIRECT_DISCOVERY_RESPONSE_INVALID",
        message: `The token channel for ${label(requirement.recipient)} contains invalid nonce state.`,
      };
    }
  }
  return null;
}
