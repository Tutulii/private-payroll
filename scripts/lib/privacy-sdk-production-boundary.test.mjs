import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);

const runtimeRoots = ["app", "lib", "packages", "scripts"];
const sourceExtensions = new Set([".js", ".mjs", ".ts", ".tsx"]);
const ignoredSuffixes = [".test.js", ".test.mjs", ".test.ts", ".test.tsx"];
const forbiddenImport = "@starkware-libs/starknet-privacy-sdk/testing";

async function collectRuntimeSources(relativeDirectory) {
  const absoluteDirectory = path.join(repositoryRoot, relativeDirectory);
  const entries = await readdir(absoluteDirectory, { withFileTypes: true });
  const sources = [];

  for (const entry of entries) {
    const relativePath = path.join(relativeDirectory, entry.name);
    if (entry.isDirectory()) {
      sources.push(...(await collectRuntimeSources(relativePath)));
      continue;
    }
    if (!entry.isFile() || !sourceExtensions.has(path.extname(entry.name))) {
      continue;
    }
    if (ignoredSuffixes.some((suffix) => entry.name.endsWith(suffix))) {
      continue;
    }
    sources.push(relativePath);
  }

  return sources;
}

describe("privacy SDK production dependency boundary", () => {
  it("keeps the exact reviewed SDK archive pinned", async () => {
    const toolchains = JSON.parse(
      await readFile(path.join(repositoryRoot, "toolchains.lock.json"), "utf8"),
    );
    const archive = await readFile(
      path.join(
        repositoryRoot,
        "vendor/starkware-libs-starknet-privacy-sdk-0.14.3-rc.5.tgz",
      ),
    );
    expect(createHash("sha256").update(archive).digest("hex")).toBe(
      toolchains.starknet.privacySdkTarballSha256,
    );
  });

  it("keeps runtime code away from the SDK's Node Devnet testing export", async () => {
    const sources = (
      await Promise.all(runtimeRoots.map((root) => collectRuntimeSources(root)))
    ).flat();
    const violations = [];

    for (const relativePath of sources) {
      const source = await readFile(path.join(repositoryRoot, relativePath), "utf8");
      if (source.includes(forbiddenImport)) {
        violations.push(relativePath);
      }
    }

    expect(violations).toEqual([]);
  });

  it("loads the pinned production SDK while Devnet spawning fails closed", async () => {
    const sdk = await import("@starkware-libs/starknet-privacy-sdk");
    expect(sdk.createPrivateTransfers).toBeTypeOf("function");

    const { Devnet } = await import("starknet-devnet");
    await expect(Devnet.spawnInstalled()).rejects.toThrow(
      "starknet-devnet is disabled in PAYO production dependencies",
    );
  });
});
