import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { delimiter, resolve } from "node:path";
import { getZKHonkCallData, init as initGaraga } from "garaga";

const root = resolve(import.meta.dirname, "..");
const target = resolve(root, "circuits/payroll_integrity/target");
const circuitPath = resolve(target, "payo_payroll_integrity.json");
const requestedShard = process.argv[2];
if (requestedShard && requestedShard !== "0" && requestedShard !== "1") {
  throw new Error("Optional PayrollIntegrity shard must be 0 or 1.");
}
const shards = requestedShard ? [Number(requestedShard)] : [0, 1];
const bbBinary = process.env.PAYO_BB_BINARY || "bb";
const crsPath = process.env.PAYO_BB_CRS_PATH;
const reuseArtifacts = process.env.PAYO_PROOF_REUSE_ARTIFACTS === "true";
const artifactProfile = process.env.PAYO_PROOF_ARTIFACT_PROFILE || "native3";
const fixtureOutputDirectory = process.env.PAYO_PROOF_FIXTURE_OUTPUT_DIR
  ? resolve(root, process.env.PAYO_PROOF_FIXTURE_OUTPUT_DIR)
  : null;
if (!/^[a-z0-9-]{1,40}$/.test(artifactProfile)) {
  throw new Error("PAYO_PROOF_ARTIFACT_PROFILE must use lowercase letters, numbers, or hyphens.");
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function runBb(args) {
  const result = spawnSync(bbBinary, args, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, HARDWARE_CONCURRENCY: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error) {
    const pathHint = process.env.PATH?.split(delimiter).join(", ") ?? "(unset)";
    throw new Error(`Could not run ${bbBinary}; PATH=${pathHint}`, { cause: result.error });
  }
  if (result.status !== 0) throw new Error(`${bbBinary} ${args[0]} exited with status ${result.status}.`);
}

function bbArgs(command, args) {
  return crsPath ? [command, "-c", crsPath, ...args] : [command, ...args];
}

function parsePublicInputs(bytes) {
  if (bytes.length !== 17 * 32) {
    throw new Error(`Expected 17 PayrollIntegrity public inputs; received ${bytes.length / 32}.`);
  }
  return Array.from({ length: 17 }, (_, index) =>
    BigInt(`0x${bytes.subarray(index * 32, (index + 1) * 32).toString("hex")}`));
}

await initGaraga();
const manifests = [];

for (const shard of shards) {
  const witnessPath = resolve(
    target,
    artifactProfile === "native3"
      ? `witness-shard-${shard}.gz`
      : `witness-${artifactProfile}-shard-${shard}.gz`,
  );
  const outputPath = resolve(target, `${artifactProfile}-shard-${shard}`);
  const canonicalVk = resolve(target, `${artifactProfile}-shard-0/vk`);
  await mkdir(outputPath, { recursive: true });

  const proveArgs = [
    "--scheme", "ultra_honk",
    "--oracle_hash", "keccak",
    "--write_vk",
    "--verify",
    "--slow_low_memory",
    "--storage_budget", process.env.PAYO_BB_STORAGE_BUDGET || "2g",
    "-b", circuitPath,
    "-w", witnessPath,
    "-o", outputPath,
  ];
  if (shard === 1) proveArgs.push("-k", canonicalVk, "--vk_policy", "check");

  const startedAt = performance.now();
  if (!reuseArtifacts) runBb(bbArgs("prove", proveArgs));
  const provingTimeMs = Math.round(performance.now() - startedAt);

  const vkPath = shard === 0 ? resolve(outputPath, "vk") : canonicalVk;
  const proofPath = resolve(outputPath, "proof");
  const publicInputsPath = resolve(outputPath, "public_inputs");
  runBb(bbArgs("verify", [
    "--scheme", "ultra_honk",
    "--oracle_hash", "keccak",
    "-k", vkPath,
    "-p", proofPath,
    "-i", publicInputsPath,
  ]));

  const [proof, publicInputs, vk] = await Promise.all([
    readFile(proofPath),
    readFile(publicInputsPath),
    readFile(vkPath),
  ]);
  const decoded = parsePublicInputs(publicInputs);
  if (decoded[16] !== BigInt(shard)) {
    throw new Error(`Shard ${shard} proof exposes shard index ${decoded[16]}.`);
  }
  if (manifests[0]) {
    const firstInputs = parsePublicInputs(await readFile(resolve(target, `${artifactProfile}-shard-0/public_inputs`)));
    for (let index = 0; index < 16; index += 1) {
      if (decoded[index] !== firstInputs[index]) {
        throw new Error(`Shard public input ${index} does not match shard zero.`);
      }
    }
    if (sha256(vk) !== manifests[0].verificationKeySha256) {
      throw new Error("Shard proofs were not generated against the same verification key.");
    }
  }

  const serializedCalldata = getZKHonkCallData(proof, publicInputs, vk);
  const declaredLength = Number(serializedCalldata[0]);
  if (declaredLength !== serializedCalldata.length - 1) {
    throw new Error(
      `Garaga calldata declares ${declaredLength} felts but contains ${serializedCalldata.length - 1}.`,
    );
  }
  // Garaga returns the Starknet ABI Span length followed by the proof felts.
  // Our Cairo dispatcher and Starknet.js add that length when serializing the
  // Span, so the portable proof fixture must contain only the inner felts.
  const calldata = serializedCalldata.slice(1);
  const fixtureLabel = artifactProfile === "native3"
    ? `shard-${shard}`
    : `${artifactProfile}-shard-${shard}`;
  const calldataPath = resolve(target, `proof_calldata-${fixtureLabel}.txt`);
  const calldataText = `${calldata.map((value) => `0x${value.toString(16)}`).join("\n")}\n`;
  await writeFile(calldataPath, calldataText);
  if (fixtureOutputDirectory) {
    await mkdir(fixtureOutputDirectory, { recursive: true });
    await writeFile(resolve(fixtureOutputDirectory, `proof_calldata-${fixtureLabel}.txt`), calldataText);
  }

  const manifest = {
    shard,
    scheme: "ultra_keccak_zk_honk",
    oracleHash: "keccak",
    reusedArtifacts: reuseArtifacts,
    selfVerified: true,
    provingTimeMs,
    proofBytes: (await stat(proofPath)).size,
    publicInputBytes: publicInputs.length,
    publicInputCount: decoded.length,
    verificationKeyBytes: vk.length,
    calldataFelts: calldata.length,
    proofSha256: sha256(proof),
    publicInputsSha256: sha256(publicInputs),
    verificationKeySha256: sha256(vk),
  };
  manifests.push(manifest);
  await writeFile(
    resolve(target, `prover-benchmark-${fixtureLabel}.json`),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
}

if (manifests.length === 2) {
  const benchmarkPath = artifactProfile === "native3"
    ? "prover-benchmark.json"
    : `prover-benchmark-${artifactProfile}.json`;
  await writeFile(resolve(target, benchmarkPath), `${JSON.stringify({
    scheme: "ultra_keccak_zk_honk",
    linkedShardCount: 2,
    selfVerified: manifests.every((manifest) => manifest.selfVerified),
    verificationKeySha256: manifests[0].verificationKeySha256,
    shards: manifests,
  }, null, 2)}\n`);
}
