/// <reference lib="webworker" />

import { UltraHonkBackend } from "@aztec/bb.js";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { decryptVaultRecord } from "@/lib/crypto/vault";
import {
  mapPayrollPublicInputs,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_CIRCUIT_URL,
  safeProofFailure,
  type EncryptedPayrollWitness,
  type PayrollIntegrityShardProof,
  type ProofWorkerRequest,
  type ProofWorkerResponse,
} from "./protocol";

const scope = self as unknown as DedicatedWorkerGlobalScope;

function progress(requestId: string, stage: "loading" | "executing" | "proving" | "verifying") {
  const response: ProofWorkerResponse = { version: 1, type: "proof-progress", requestId, stage };
  scope.postMessage(response);
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return `0x${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

scope.addEventListener("message", async (event: MessageEvent<ProofWorkerRequest>) => {
  const request = event.data;
  const requestId = typeof request?.requestId === "string" ? request.requestId : "invalid-request";
  if (request?.version !== 1 || request.type !== "prove-payroll-integrity" || !request.requestId) {
    scope.postMessage(safeProofFailure(requestId, "INVALID_REQUEST"));
    return;
  }

  let circuitText: string;
  try {
    progress(requestId, "loading");
    const response = await fetch(PAYROLL_INTEGRITY_CIRCUIT_URL, { cache: "force-cache" });
    if (!response.ok) throw new Error("circuit response failed");
    circuitText = await response.text();
    if (await sha256Hex(circuitText) !== PAYROLL_INTEGRITY_CIRCUIT_SHA256) {
      throw new Error("circuit digest mismatch");
    }
  } catch {
    scope.postMessage(safeProofFailure(requestId, "CIRCUIT_LOAD_FAILED"));
    return;
  }

  let encryptedPayload: EncryptedPayrollWitness;
  try {
    encryptedPayload = decryptVaultRecord<EncryptedPayrollWitness>(request.encryptedWitness, request.principal);
    if (
      !encryptedPayload ||
      !Array.isArray(encryptedPayload.circuitInputs) ||
      encryptedPayload.circuitInputs.length !== 2 ||
      encryptedPayload.circuitInputs.some((input) => typeof input !== "object")
    ) throw new Error("missing linked shard inputs");
  } catch {
    scope.postMessage(safeProofFailure(requestId, "WITNESS_INVALID"));
    return;
  }

  let backend: UltraHonkBackend | undefined;
  let witnessToErase: Uint8Array | undefined;
  const startedAt = performance.now();
  try {
    const circuit = JSON.parse(circuitText) as CompiledCircuit;
    const noir = new Noir(circuit);
    backend = new UltraHonkBackend(circuit.bytecode, {
      threads: crossOriginIsolated ? Math.max(1, Math.min(4, navigator.hardwareConcurrency || 1)) : 1,
    });
    const shards: PayrollIntegrityShardProof[] = [];
    let commonPublicInputs: readonly string[] | undefined;
    for (const shardIndex of [0, 1] as const) {
      progress(requestId, "executing");
      const { witness } = await noir.execute(encryptedPayload.circuitInputs[shardIndex]);
      witnessToErase = witness;
      encryptedPayload.circuitInputs[shardIndex] = {};
      progress(requestId, "proving");
      const proofData = await backend.generateProof(witness, { keccakZK: true });
      witness.fill(0);
      witnessToErase = undefined;
      progress(requestId, "verifying");
      if (!await backend.verifyProof(proofData, { keccakZK: true })) {
        scope.postMessage(safeProofFailure(requestId, "SELF_VERIFY_FAILED"));
        return;
      }
      if (BigInt(proofData.publicInputs[16]) !== BigInt(shardIndex)) {
        scope.postMessage(safeProofFailure(requestId, "SELF_VERIFY_FAILED"));
        return;
      }
      if (commonPublicInputs) {
        for (let index = 0; index < 16; index += 1) {
          if (BigInt(commonPublicInputs[index]) !== BigInt(proofData.publicInputs[index])) {
            scope.postMessage(safeProofFailure(requestId, "SELF_VERIFY_FAILED"));
            return;
          }
        }
      } else {
        commonPublicInputs = proofData.publicInputs;
      }
      shards.push({
        shardIndex,
        proof: proofData.proof,
        publicInputs: mapPayrollPublicInputs(proofData.publicInputs),
      });
    }
    encryptedPayload = { circuitInputs: [{}, {}] };
    const result: ProofWorkerResponse = {
      version: 1,
      type: "proof-complete",
      requestId,
      scheme: "ultra_keccak_zk_honk",
      shards: shards as [PayrollIntegrityShardProof, PayrollIntegrityShardProof],
      circuitSha256: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
      provingTimeMs: Math.round(performance.now() - startedAt),
    };
    scope.postMessage(result, shards.map((shard) => shard.proof.buffer));
  } catch {
    scope.postMessage(safeProofFailure(requestId, "PROVING_FAILED"));
  } finally {
    witnessToErase?.fill(0);
    encryptedPayload = { circuitInputs: [{}, {}] };
    circuitText = "";
    await backend?.destroy();
  }
});
