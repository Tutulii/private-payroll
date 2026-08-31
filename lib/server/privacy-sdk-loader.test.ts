import { resolve } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import {
  loadPinnedPrivacySdk,
  PAYO_PRIVACY_SDK_REVISION,
  PAYO_PRIVACY_SDK_VERSION,
  resetPinnedPrivacySdkForTests,
} from "./privacy-sdk-loader";

const sdkRoot = resolve(
  process.cwd(),
  "node_modules/@starkware-libs/starknet-privacy-sdk",
);

describe("pinned Privacy SDK loader", () => {
  beforeEach(() => resetPinnedPrivacySdkForTests());

  it("loads the exact rc.5 runtime and required production APIs", async () => {
    const runtime = await loadPinnedPrivacySdk(sdkRoot);
    expect(runtime.version).toBe(PAYO_PRIVACY_SDK_VERSION);
    expect(runtime.revision).toBe(PAYO_PRIVACY_SDK_REVISION);
    expect(runtime.sdk.createPrivateTransfers).toBeTypeOf("function");
    expect(runtime.sdk.IndexerDiscoveryProvider).toBeTypeOf("function");
    expect(runtime.sdk.buildHistoryCursor).toBeTypeOf("function");
    expect(runtime.codecs.channelSerde.encode).toBeTypeOf("function");
    expect(runtime.codecs.witnessSerde.decode).toBeTypeOf("function");
  });

  it("rejects an unpinned SDK build", async () => {
    await expect(loadPinnedPrivacySdk(process.cwd()))
      .rejects.toThrow(/pinned artifact|ENOENT/);
  });

  it("rejects relative SDK roots before reading code", () => {
    expect(() => loadPinnedPrivacySdk("../sdk")).toThrow(/absolute path/);
  });
});
