import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { getZKHonkCallData, init as initGaraga } from "garaga";
import {
  SETTLEMENT_MATCH_CIRCUIT_SHA256,
  SETTLEMENT_MATCH_VERIFICATION_KEY_SHA256,
} from "@/lib/proof/protocol";
import {
  hashProofCalldata,
  normalizeGaragaProofCalldata,
  serializeSettlementMatchPublicInputs,
} from "@/lib/proof/starknet-calldata";

type Bindings = {
  proofVersion: number;
  settlementRoot: string;
  transactionReference: string;
  publicInputs: {
    proofVersion: string;
    manifestRootHigh: string;
    manifestRootLow: string;
    runNullifierHigh: string;
    runNullifierLow: string;
    transactionReferenceHigh: string;
    transactionReferenceLow: string;
    settlementRootHigh: string;
    settlementRootLow: string;
    chunkIndex: string;
    chunkCount: string;
  };
};

function sha256(value: Uint8Array): string {
  return "0x" + createHash("sha256").update(value).digest("hex");
}

function orderedPublicInputs(bindings: Bindings): string[] {
  const input = bindings.publicInputs;
  return [
    input.proofVersion,
    input.manifestRootHigh,
    input.manifestRootLow,
    input.runNullifierHigh,
    input.runNullifierLow,
    input.transactionReferenceHigh,
    input.transactionReferenceLow,
    input.settlementRootHigh,
    input.settlementRootLow,
    input.chunkIndex,
    input.chunkCount,
  ];
}

async function main() {
  const root = resolve(import.meta.dirname, "..");
  const target = resolve(root, "circuits/settlement_match/target");
  const proofDirectory = resolve(
    root,
    process.env.PAYO_PHASE4_SETTLEMENT_PROOF_DIR
      ?? "circuits/settlement_match/target/v8-proof-fixture",
  );
  const verificationKeyPath = resolve(
    root,
    process.env.PAYO_PHASE4_SETTLEMENT_VK_PATH
      ?? "circuits/settlement_match/target/vk-output/vk",
  );
  const [proof, publicInputs, verificationKey, bindingsText] = await Promise.all([
    readFile(resolve(proofDirectory, "proof")),
    readFile(resolve(proofDirectory, "public_inputs")),
    readFile(verificationKeyPath),
    readFile(resolve(target, "witness-v8-bindings.json"), "utf8"),
  ]);
  const bindings = JSON.parse(bindingsText) as Bindings;
  if (bindings.proofVersion !== 8 || bindings.publicInputs.proofVersion !== "8") {
    throw new Error("SettlementMatch fixture does not use proof version 8.");
  }
  const expectedPublicInputs = serializeSettlementMatchPublicInputs(
    orderedPublicInputs(bindings),
  );
  if (!Buffer.from(publicInputs).equals(Buffer.from(expectedPublicInputs))) {
    throw new Error("Native proof public inputs do not match the generated witness bindings.");
  }
  if (sha256(verificationKey) !== SETTLEMENT_MATCH_VERIFICATION_KEY_SHA256) {
    throw new Error("SettlementMatch proof used an unpinned verification key.");
  }
  await initGaraga();
  const proofCalldata = normalizeGaragaProofCalldata(
    getZKHonkCallData(proof, publicInputs, verificationKey),
  );
  const outputDirectory = resolve(root, "contracts/settlement_verifier_v8/tests");
  await mkdir(outputDirectory, { recursive: true });
  await Promise.all([
    writeFile(
      resolve(outputDirectory, "proof_calldata.txt"),
      proofCalldata.join("\n") + "\n",
    ),
    writeFile(
      resolve(target, "v8-proof-fixture-manifest.json"),
      JSON.stringify({
        proofVersion: 8,
        scheme: "ultra_keccak_zk_honk",
        circuitSha256: SETTLEMENT_MATCH_CIRCUIT_SHA256,
        verificationKeySha256: SETTLEMENT_MATCH_VERIFICATION_KEY_SHA256,
        proofSha256: sha256(proof),
        publicInputsSha256: sha256(publicInputs),
        calldataHash: hashProofCalldata(proofCalldata),
        calldataFelts: proofCalldata.length,
        settlementRoot: bindings.settlementRoot,
        transactionReference: bindings.transactionReference,
      }, null, 2) + "\n",
    ),
  ]);
  process.stdout.write(JSON.stringify({
    generated: true,
    proofSha256: sha256(proof),
    calldataHash: hashProofCalldata(proofCalldata),
    calldataFelts: proofCalldata.length,
  }, null, 2) + "\n");
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
