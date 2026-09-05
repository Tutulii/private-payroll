import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { getZKHonkCallData, init as initGaraga } from "garaga";
import {
  hashProofCalldata,
  normalizeGaragaProofCalldata,
} from "@/lib/proof/starknet-calldata";
import { PAYO_VESTING_TRANSITION_PUBLIC_INPUT_COUNT } from "@/lib/proof/vesting-transition-input";

type Bindings = {
  proofVersion: number;
  entryKind: string;
  scheduleId: string;
  previousStateCommitment: string;
  nextStateCommitment: string;
  releaseNullifier: string;
  bookEntryCommitment: string;
  attestationRoot: string;
  publicInputs: string[][];
};

function sha256(value: Uint8Array): string {
  return `0x${createHash("sha256").update(value).digest("hex")}`;
}

function serializeFields(values: readonly string[]): Uint8Array {
  if (values.length !== PAYO_VESTING_TRANSITION_PUBLIC_INPUT_COUNT) {
    throw new Error(
      `Expected ${PAYO_VESTING_TRANSITION_PUBLIC_INPUT_COUNT} vesting public inputs; received ${values.length}.`,
    );
  }
  const output = new Uint8Array(values.length * 32);
  values.forEach((value, index) => {
    let remaining = BigInt(value);
    if (remaining < 0n || remaining >= 1n << 256n) {
      throw new Error(`Vesting public input ${index} is outside its canonical range.`);
    }
    for (let byte = 31; byte >= 0; byte -= 1) {
      output[index * 32 + byte] = Number(remaining & 0xffn);
      remaining >>= 8n;
    }
  });
  return output;
}

async function main() {
  const root = resolve(import.meta.dirname, "..");
  const target = resolve(root, "circuits/vesting_transition/target");
  const fixtureDirectory = resolve(target, "real-proof-fixture");
  const outputDirectory = resolve(root, "contracts/vesting_verifier_v3/tests");
  const verificationKeyPath = resolve(
    root,
    process.env.PAYO_VESTING_VK_PATH ?? "circuits/vesting_transition/target/vk/vk",
  );
  const [verificationKey, pinnedVerificationKeyHex, bindingsText] = await Promise.all([
    readFile(verificationKeyPath),
    readFile(resolve(root, "public/circuits/vesting_transition-v3.vk.hex"), "utf8"),
    readFile(resolve(fixtureDirectory, "bindings.json"), "utf8"),
  ]);
  const pinnedVerificationKey = Buffer.from(
    pinnedVerificationKeyHex.replace(/\s+/g, ""),
    "hex",
  );
  if (!Buffer.from(verificationKey).equals(pinnedVerificationKey)) {
    throw new Error("The real vesting proofs used an unpinned verification key.");
  }
  const bindings = JSON.parse(bindingsText) as Bindings;
  if (bindings.proofVersion !== 3 || bindings.entryKind !== "vesting") {
    throw new Error("The proof fixture is not a v3 vesting transition.");
  }
  if (bindings.publicInputs.length !== 2) {
    throw new Error("The proof fixture must contain two ordered shards.");
  }
  await initGaraga();
  await mkdir(outputDirectory, { recursive: true });
  const shards = [];
  for (let shard = 0; shard < 2; shard += 1) {
    const proofDirectory = resolve(fixtureDirectory, `proof-${shard}`);
    const [proof, publicInputs] = await Promise.all([
      readFile(resolve(proofDirectory, "proof")),
      readFile(resolve(proofDirectory, "public_inputs")),
    ]);
    const expectedPublicInputs = serializeFields(bindings.publicInputs[shard]);
    if (!Buffer.from(publicInputs).equals(Buffer.from(expectedPublicInputs))) {
      throw new Error(`Native proof shard ${shard} is not bound to the generated witness inputs.`);
    }
    if (
      BigInt(bindings.publicInputs[shard][PAYO_VESTING_TRANSITION_PUBLIC_INPUT_COUNT - 1])
      !== BigInt(shard)
    ) {
      throw new Error(`Vesting proof shard ${shard} has a non-canonical shard index.`);
    }
    const calldata = normalizeGaragaProofCalldata(
      getZKHonkCallData(proof, publicInputs, verificationKey),
    );
    await writeFile(
      resolve(outputDirectory, `proof_calldata_${shard}.txt`),
      `${calldata.join("\n")}\n`,
    );
    shards.push({
      shardIndex: shard,
      proofSha256: sha256(proof),
      publicInputsSha256: sha256(publicInputs),
      calldataHash: hashProofCalldata(calldata),
      calldataFelts: calldata.length,
    });
  }
  const manifest = {
    fixtureVersion: "payo-vesting-transition-real-proof-v1",
    proofVersion: bindings.proofVersion,
    scheme: "ultra_keccak_zk_honk",
    verificationKeySha256: sha256(verificationKey),
    scheduleId: bindings.scheduleId,
    previousStateCommitment: bindings.previousStateCommitment,
    nextStateCommitment: bindings.nextStateCommitment,
    releaseNullifier: bindings.releaseNullifier,
    bookEntryCommitment: bindings.bookEntryCommitment,
    attestationRoot: bindings.attestationRoot,
    shards,
  };
  await writeFile(
    resolve(outputDirectory, "proof_fixture_manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
