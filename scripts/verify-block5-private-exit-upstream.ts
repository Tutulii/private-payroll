import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { hash, num } from "starknet";
import { STRK20_EKUBO_ANONYMIZER_CLASS_HASH } from "@/lib/starknet/private-exit";

const PINNED_UPSTREAM_COMMIT = "bc75e4bac71ad0ce10c6e63effc33b5b25131a4f";
const root = process.env.PAYO_PRIVATE_EXIT_UPSTREAM_ROOT?.trim();
if (!root) {
  throw new Error("PAYO_PRIVATE_EXIT_UPSTREAM_ROOT must point to the pinned starknet-privacy checkout.");
}

const scarb = process.env.PAYO_SCARB_BIN?.trim() || "scarb";
const snforge = process.env.PAYO_SNFORGE_BIN?.trim() || "snforge";
const output = resolve(
  process.env.PAYO_BLOCK5_EVIDENCE_OUTPUT?.trim()
    || "evidence/block5-private-exit-upstream.json",
);

function execute(binary: string, args: string[]) {
  const result = spawnSync(binary, args, {
    cwd: root,
    encoding: "utf8",
    env: process.env,
    maxBuffer: 32 * 1024 * 1024,
  });
  const transcript = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  if (result.status !== 0) {
    throw new Error(`${binary} ${args.join(" ")} failed:\n${transcript.slice(-8_000)}`);
  }
  return transcript;
}

function digest(path: string) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

const commit = execute("git", ["rev-parse", "HEAD"]).trim();
if (commit !== PINNED_UPSTREAM_COMMIT) {
  throw new Error(`Expected upstream commit ${PINNED_UPSTREAM_COMMIT}, received ${commit}.`);
}

const scarbVersion = execute(scarb, ["--version"]).split("\n")[0]?.trim();
const snforgeVersion = execute(snforge, ["--version"]).split("\n")[0]?.trim();
execute(scarb, [
  "--offline",
  "--profile",
  "release",
  "build",
  "-p",
  "ekubo_swap_anonymizer",
]);

const contractArtifact = resolve(
  root,
  "target/release/ekubo_swap_anonymizer_EkuboSwapAnonymizer.contract_class.json",
);
const contractClass = JSON.parse(readFileSync(contractArtifact, "utf8")) as Parameters<
  typeof hash.computeSierraContractClassHash
>[0];
const computedClassHash = num.toHex(hash.computeSierraContractClassHash(contractClass));
if (BigInt(computedClassHash) !== BigInt(STRK20_EKUBO_ANONYMIZER_CLASS_HASH)) {
  throw new Error(
    `Reviewed anonymizer class hash mismatch: expected ${STRK20_EKUBO_ANONYMIZER_CLASS_HASH}, received ${computedClassHash}.`,
  );
}

const unitTranscript = execute(snforge, ["test", "-p", "ekubo_swap_anonymizer"]);
if (!/Tests:\s+3 passed, 0 failed/.test(unitTranscript)) {
  throw new Error("The upstream anonymizer unit test count did not match the reviewed gate.");
}
const integrationTranscript = execute(snforge, [
  "test",
  "-p",
  "privacy",
  "test_e2e_ekubo_invoke",
  "--max-threads",
  "1",
]);
if (
  !/test_e2e_ekubo_invoke/.test(integrationTranscript)
  || !/Tests:\s+1 passed, 0 failed/.test(integrationTranscript)
) {
  throw new Error("The upstream STRK20/Ekubo composition test did not pass.");
}

const source = resolve(
  root,
  "packages/ekubo_swap_anonymizer/src/ekubo_swap_anonymizer.cairo",
);
const integrationSource = resolve(root, "packages/privacy/src/tests/test_e2e.cairo");
const lockfile = resolve(root, "Scarb.lock");
const evidence = {
  schemaVersion: "payo.block5.private-exit.upstream.v1",
  generatedAt: new Date().toISOString(),
  upstream: {
    repository: "https://github.com/starkware-libs/starknet-privacy",
    commit,
    lockfileSha256: digest(lockfile),
    anonymizerSourceSha256: digest(source),
    privacyIntegrationSourceSha256: digest(integrationSource),
  },
  toolchain: { scarb: scarbVersion, snforge: snforgeVersion },
  reviewedContract: {
    name: "EkuboSwapAnonymizer",
    classHash: computedClassHash,
    expectedClassHash: STRK20_EKUBO_ANONYMIZER_CLASS_HASH,
    releaseArtifactSha256: digest(contractArtifact),
  },
  checks: {
    pinnedUpstreamRevision: true,
    releaseClassHashReproduced: true,
    anonymizerAssertions: { passed: 3, failed: 0 },
    strk20OpenNoteSwapComposition: { passed: 1, failed: 0 },
  },
  scope: {
    network: "local Starknet Foundry execution",
    liveRpcDevnet: false,
    mainnetTransaction: false,
    note: "This proves the reviewed contract and STRK20 open-note composition locally. Live Devnet and Mainnet canaries remain release-gate evidence.",
  },
};

mkdirSync(dirname(output), { recursive: true });
const temporary = `${output}.tmp-${process.pid}`;
writeFileSync(temporary, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
renameSync(temporary, output);
process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
