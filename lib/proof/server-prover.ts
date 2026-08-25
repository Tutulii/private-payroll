import "server-only";

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { BackendType, UltraHonkBackend } from "@aztec/bb.js";
import { getZKHonkCallData, init as initGaraga } from "garaga";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { decryptVaultRecord, type EncryptedVaultRecord, type VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import { buildPayrollIntegrityInputsFromSerialized } from "./input-builder";
import {
  mapPayrollPublicInputs,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  PAYROLL_MOBILE_WASM_MAXIMUM_PAGES,
  type EncryptedPayrollWitness,
  type PayrollIntegrityShardProof,
  type ProofWorkerSuccess,
} from "./protocol";
import {
  decodeVerificationKeyHex,
  hashProofCalldata,
  normalizeGaragaProofCalldata,
  serializePayrollPublicInputs,
} from "./starknet-calldata";
import { parseProverThreadCount } from "./prover-runtime";

type PinnedAssets = {
  circuit: CompiledCircuit;
  verificationKey: Uint8Array;
};

let pinnedAssets: Promise<PinnedAssets> | undefined;
let garagaReady: Promise<unknown> | undefined;

function sha256(value: string | Uint8Array): string {
  return `0x${createHash("sha256").update(value).digest("hex")}`;
}

async function loadPinnedAssets(): Promise<PinnedAssets> {
  if (!pinnedAssets) {
    pinnedAssets = Promise.all([
      readFile(resolve(process.cwd(), "public/circuits/payroll_integrity-v1.json"), "utf8"),
      readFile(resolve(process.cwd(), "public/circuits/payroll_integrity-v1.vk.hex"), "utf8"),
    ]).then(([circuitText, verificationKeyHex]) => {
      const verificationKey = decodeVerificationKeyHex(verificationKeyHex);
      if (sha256(circuitText) !== PAYROLL_INTEGRITY_CIRCUIT_SHA256) {
        throw new Error("The self-hosted prover circuit does not match the deployed circuit hash.");
      }
      if (sha256(verificationKey) !== PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256) {
        throw new Error("The self-hosted prover verification key does not match the deployed key hash.");
      }
      return { circuit: JSON.parse(circuitText) as CompiledCircuit, verificationKey };
    });
  }
  return pinnedAssets;
}

export async function provePayrollOnSelfHostedNode(input: {
  requestId: string;
  encryptedWitness: EncryptedVaultRecord;
  principal: VaultPrincipalKeyPair;
}): Promise<ProofWorkerSuccess> {
  const { circuit, verificationKey } = await loadPinnedAssets();
  garagaReady ??= initGaraga();
  await garagaReady;

  let payload = decryptVaultRecord<EncryptedPayrollWitness>(input.encryptedWitness, input.principal);
  if ("buildInput" in payload) {
    payload = (await buildPayrollIntegrityInputsFromSerialized(payload.buildInput)).witness;
  }
  if (!("circuitInputs" in payload) || payload.circuitInputs.length !== 2) {
    throw new Error("The encrypted proof request does not contain both linked witnesses.");
  }

  const noir = new Noir(circuit);
  const backend = new UltraHonkBackend(circuit.bytecode, {
    backend: BackendType.Wasm,
    threads: parseProverThreadCount(process.env.PAYO_PROVER_THREADS),
    memory: { maximum: PAYROLL_MOBILE_WASM_MAXIMUM_PAGES },
  });
  const startedAt = performance.now();
  let witnessToErase: Uint8Array | undefined;
  try {
    const shards: PayrollIntegrityShardProof[] = [];
    let commonPublicInputs: readonly string[] | undefined;
    for (const shardIndex of [0, 1] as const) {
      const { witness } = await noir.execute(payload.circuitInputs[shardIndex]);
      witnessToErase = witness;
      payload.circuitInputs[shardIndex] = {};
      const proofData = await backend.generateProof(witness, { keccakZK: true });
      witness.fill(0);
      witnessToErase = undefined;
      if (!await backend.verifyProof(proofData, { keccakZK: true })) {
        throw new Error(`Self-hosted proof shard ${shardIndex} failed local verification.`);
      }
      if (BigInt(proofData.publicInputs[16]) !== BigInt(shardIndex)) {
        throw new Error(`Self-hosted proof shard ${shardIndex} returned the wrong shard index.`);
      }
      if (commonPublicInputs) {
        for (let index = 0; index < 16; index += 1) {
          if (BigInt(commonPublicInputs[index]) !== BigInt(proofData.publicInputs[index])) {
            throw new Error("Self-hosted proof shards returned different deployment bindings.");
          }
        }
      } else {
        commonPublicInputs = proofData.publicInputs;
      }
      const proofCalldata = normalizeGaragaProofCalldata(getZKHonkCallData(
        proofData.proof,
        serializePayrollPublicInputs(proofData.publicInputs),
        verificationKey,
      ));
      shards.push({
        shardIndex,
        proof: proofData.proof,
        proofCalldata,
        calldataHash: hashProofCalldata(proofCalldata),
        publicInputs: mapPayrollPublicInputs(proofData.publicInputs),
      });
    }
    payload = { circuitInputs: [{}, {}] };
    return {
      version: 1,
      type: "proof-complete",
      requestId: input.requestId,
      scheme: "ultra_keccak_zk_honk",
      shards: shards as ProofWorkerSuccess["shards"],
      circuitSha256: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
      provingTimeMs: Math.round(performance.now() - startedAt),
    };
  } finally {
    witnessToErase?.fill(0);
    payload = { circuitInputs: [{}, {}] };
    await backend.destroy();
  }
}
