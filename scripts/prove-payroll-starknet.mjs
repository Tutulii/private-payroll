import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { UltraHonkBackend } from "@aztec/bb.js";
import { getZKHonkCallData } from "garaga";

const root = resolve(import.meta.dirname, "..");
const target = resolve(root, "circuits/payroll_integrity/target");
const circuitPath = resolve(target, "payo_payroll_integrity.json");
const witnessPath = resolve(target, "witness.gz");

function bytes32(value) {
  const clean = value.replace(/^0x/, "").padStart(64, "0");
  if (!/^[0-9a-f]{64}$/i.test(clean)) throw new Error(`Invalid public input: ${value}`);
  return Buffer.from(clean, "hex");
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

const circuit = JSON.parse(await readFile(circuitPath, "utf8"));
const witness = new Uint8Array(await readFile(witnessPath));
const backend = new UltraHonkBackend(circuit.bytecode, {
  threads: 1,
  logger: (message) => process.stdout.write(`[bb] ${message}\n`),
});
const startedAt = performance.now();

try {
  const proofData = await backend.generateProof(witness, { starknetZK: true });
  const provingTimeMs = Math.round(performance.now() - startedAt);
  const verified = await backend.verifyProof(proofData, { starknetZK: true });
  if (!verified) throw new Error("Barretenberg rejected the freshly generated Starknet ZK proof.");

  const verificationKey = await backend.getVerificationKey({ starknetZK: true });
  const publicInputs = Buffer.concat(proofData.publicInputs.map(bytes32));
  const proof = Buffer.from(proofData.proof);
  const vk = Buffer.from(verificationKey);
  // garaga 0.18.2's runtime omits the declared enum export; 1 is STARKNET.
  const calldata = getZKHonkCallData(proof, publicInputs, vk, 1);

  await mkdir(target, { recursive: true });
  await Promise.all([
    writeFile(resolve(target, "proof"), proof),
    writeFile(resolve(target, "vk"), vk),
    writeFile(resolve(target, "public_inputs"), publicInputs),
    writeFile(
      resolve(target, "prover-benchmark.json"),
      `${JSON.stringify({
        scheme: "ultra_starknet_zk_honk",
        selfVerified: true,
        provingTimeMs,
        maxResidentSetKb: process.resourceUsage().maxRSS,
        proofBytes: proof.length,
        publicInputBytes: publicInputs.length,
        verificationKeyBytes: vk.length,
        proofSha256: sha256(proof),
        publicInputsSha256: sha256(publicInputs),
        verificationKeySha256: sha256(vk),
      }, null, 2)}\n`,
    ),
    writeFile(
      resolve(target, "proof_calldata.txt"),
      `${calldata.map((value) => `0x${value.toString(16)}`).join("\n")}\n`,
    ),
  ]);

  process.stdout.write(`${JSON.stringify({
    selfVerified: true,
    provingTimeMs,
    proofBytes: proof.length,
    publicInputs: proofData.publicInputs.length,
    vkSha256: sha256(vk),
    calldataFelts: calldata.length,
  }, null, 2)}\n`);
} finally {
  witness.fill(0);
  await backend.destroy();
}
