import "server-only";

import { createHash } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { pathToFileURL } from "node:url";
import { z } from "zod";

export const PAYO_PRIVACY_SDK_VERSION = "0.14.3-rc.5" as const;
export const PAYO_PRIVACY_SDK_REVISION =
  "66e3caae8c0201227a6719696d004e30d90aea65" as const;
export const PAYO_PRIVACY_SDK_INDEX_SHA256 =
  "1d5257f4a6c03f3c7fd022bfb5c48b2d2be35fd19984b40a8f51e11f82f95aa4" as const;
export const PAYO_PRIVACY_SDK_CHANNEL_SHA256 =
  "92955679cda9aba7906f715d99b32d06cf1c9c8b81461eb0c9524134567b6934" as const;
export const PAYO_PRIVACY_SDK_PACKAGE_SHA256 =
  "2044b31d113637de182ecf96288296405c19bc0957fd8995f4cdb2d0a74d3859" as const;

const packageSchema = z.object({
  name: z.literal("@starkware-libs/starknet-privacy-sdk"),
  version: z.literal(PAYO_PRIVACY_SDK_VERSION),
  type: z.literal("module"),
}).passthrough();

export type PrivacySdkModule = {
  AddressMap: new <T>(entries?: Iterable<[bigint, T]>) => {
    entries(): IterableIterator<[bigint, T]>;
    get(key: bigint): T | undefined;
    set(key: bigint, value: T): unknown;
  };
  createPrivateTransfers: (input: Record<string, unknown>) => PrivacyTransfers;
  IndexerDiscoveryProvider: new (
    url: string,
    poolAddress: string,
    options?: Record<string, unknown>,
  ) => PrivacyDiscovery;
  ProvingServiceProofProvider: new (...args: unknown[]) => unknown;
  buildHistoryCursor: (...args: unknown[]) => unknown;
  SetupRequirement: Record<string, number>;
};

export type PrivacyTransfers = {
  execute: (
    actions: Record<string, unknown>,
    options: Record<string, unknown>,
  ) => Promise<PrivacyExecuteResult>;
  simulate: (
    actions: Record<string, unknown>,
    options: Record<string, unknown>,
  ) => Promise<PrivacyExecuteResult>;
  discoverNotes: (input?: Record<string, unknown>) => Promise<Record<string, unknown>>;
  discoverChannels: (
    recipients: string[] | "all" | "total-only",
    input?: Record<string, unknown>,
  ) => Promise<Record<string, unknown>>;
  discoverRequirement: (recipient: string, token: string) => Promise<number>;
  createProofInvocation: (
    actions: Record<string, unknown>,
    options?: Record<string, unknown>,
  ) => Promise<Record<string, unknown>>;
  executeWithInvocation: (
    invocation: Record<string, unknown>,
    blockIdentifier?: Record<string, unknown> | string | number,
  ) => Promise<PrivacyExecuteResult>;
  invalidateProofNonceCache: () => void;
};

export type PrivacyExecuteResult = {
  callAndProof: {
    call: { contractAddress: string; entrypoint: string; calldata?: readonly string[] };
    proof: {
      data: string;
      output: readonly string[];
      proofFacts: readonly string[];
      additionalData?: unknown;
    };
  };
  registry: unknown;
  warnings: readonly { code: string; message: string }[];
};

export type PrivacyDiscovery = {
  getHealth: () => Promise<{
    status: string;
    chain_head?: { block_number: number; block_hash: string; timestamp: number };
    lag_secs?: number;
  }>;
  discoverNotes: (...args: unknown[]) => Promise<Record<string, unknown>>;
  discoverChannels: (...args: unknown[]) => Promise<Record<string, unknown>>;
  fetchHistory: (...args: unknown[]) => Promise<Record<string, unknown>>;
};

export type PrivacySdkCodecs = {
  channelSerde: { encode(value: unknown): string; decode(value: string): unknown };
  witnessSerde: { encode(value: unknown): string; decode(value: string): unknown };
};

export type PinnedPrivacySdk = {
  root: string;
  version: typeof PAYO_PRIVACY_SDK_VERSION;
  revision: typeof PAYO_PRIVACY_SDK_REVISION;
  sdk: PrivacySdkModule;
  codecs: PrivacySdkCodecs;
};

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

async function readPinnedFile(path: string, expected: string, label: string): Promise<Uint8Array> {
  const bytes = await readFile(path);
  if (sha256(bytes) !== expected) {
    bytes.fill(0);
    throw new Error(`The configured Privacy SDK ${label} does not match PAYO's pinned artifact.`);
  }
  return bytes;
}

function assertRuntime(sdk: unknown, codecs: unknown): asserts sdk is PrivacySdkModule {
  const candidate = sdk as Partial<PrivacySdkModule> | null;
  const codecCandidate = codecs as Partial<PrivacySdkCodecs> | null;
  if (
    !candidate
    || typeof candidate.AddressMap !== "function"
    || typeof candidate.createPrivateTransfers !== "function"
    || typeof candidate.IndexerDiscoveryProvider !== "function"
    || typeof candidate.ProvingServiceProofProvider !== "function"
    || typeof candidate.buildHistoryCursor !== "function"
    || typeof candidate.SetupRequirement !== "object"
    || !codecCandidate
    || typeof codecCandidate.channelSerde?.encode !== "function"
    || typeof codecCandidate.channelSerde?.decode !== "function"
    || typeof codecCandidate.witnessSerde?.encode !== "function"
    || typeof codecCandidate.witnessSerde?.decode !== "function"
  ) {
    throw new Error("The pinned Privacy SDK runtime does not expose PAYO's required API.");
  }
}

let cached: Promise<PinnedPrivacySdk> | undefined;

/**
 * Keep audited absolute file-URL imports native at runtime. Next/Webpack must
 * not turn these into a build-time context module: the production image owns
 * the pinned SDK files, while the server bundle is built in a different
 * filesystem layer.
 */
function importPinnedRuntimeModule(specifier: string): Promise<unknown> {
  return import(/* webpackIgnore: true */ specifier);
}

/**
 * Loads only the audited SDK build. A directory name or package version is not
 * enough: all executable entrypoints used by PAYO are digest-bound.
 */
export function loadPinnedPrivacySdk(
  configuredRoot = process.env.PAYO_PRIVACY_SDK_ROOT,
): Promise<PinnedPrivacySdk> {
  if (!configuredRoot || !isAbsolute(configuredRoot)) {
    throw new Error("PAYO_PRIVACY_SDK_ROOT must be an absolute path to the pinned SDK package.");
  }
  cached ??= (async () => {
    const root = await realpath(configuredRoot);
    const packagePath = join(root, "package.json");
    const indexPath = join(root, "dist", "index.js");
    const channelPath = join(root, "dist", "internal", "channel.js");
    const [packageBytes] = await Promise.all([
      readPinnedFile(packagePath, PAYO_PRIVACY_SDK_PACKAGE_SHA256, "package manifest"),
      readPinnedFile(indexPath, PAYO_PRIVACY_SDK_INDEX_SHA256, "entrypoint"),
      readPinnedFile(channelPath, PAYO_PRIVACY_SDK_CHANNEL_SHA256, "private-state codec"),
    ]);
    let packageJson: unknown;
    try {
      packageJson = JSON.parse(new TextDecoder().decode(packageBytes));
    } finally {
      packageBytes.fill(0);
    }
    packageSchema.parse(packageJson);
    const [sdk, codecs] = await Promise.all([
      importPinnedRuntimeModule(
        `${pathToFileURL(indexPath).href}?payo=${PAYO_PRIVACY_SDK_INDEX_SHA256}`,
      ),
      importPinnedRuntimeModule(
        `${pathToFileURL(channelPath).href}?payo=${PAYO_PRIVACY_SDK_CHANNEL_SHA256}`,
      ),
    ]);
    assertRuntime(sdk, codecs);
    return {
      root,
      version: PAYO_PRIVACY_SDK_VERSION,
      revision: PAYO_PRIVACY_SDK_REVISION,
      sdk,
      codecs: codecs as PrivacySdkCodecs,
    };
  })().catch((error) => {
    cached = undefined;
    throw error;
  });
  return cached;
}

export function resetPinnedPrivacySdkForTests(): void {
  if (process.env.NODE_ENV !== "test") throw new Error("SDK loader reset is test-only.");
  cached = undefined;
}
