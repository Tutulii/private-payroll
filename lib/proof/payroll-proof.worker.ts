/// <reference lib="webworker" />

import { UltraHonkBackend } from "@aztec/bb.js";
import { getZKHonkCallData, init as initGaraga } from "garaga";
import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";
import { decryptVaultRecord } from "@/lib/crypto/vault";
import { buildAdvancedObligationInputs } from "./advanced-obligation-input";
import { buildPayrollIntegrityInputsFromSerialized } from "./input-builder";
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  ADVANCED_OBLIGATION_CIRCUIT_URL,
  ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  ADVANCED_OBLIGATION_VERIFICATION_KEY_URL,
  classifyProofFailure,
  mapPayrollPublicInputs,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_CIRCUIT_URL,
  PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  PAYROLL_INTEGRITY_VERIFICATION_KEY_URL,
  PAYO_MAX_PROOF_CALLDATA_FELTS,
  payrollProverBackendOptions,
  safeProofFailure,
  WAGE_CLAIM_CIRCUIT_SHA256,
  WAGE_CLAIM_CIRCUIT_URL,
  WAGE_CLAIM_VERIFICATION_KEY_SHA256,
  WAGE_CLAIM_VERIFICATION_KEY_URL,
  WAGE_REMEDIATION_CIRCUIT_SHA256,
  WAGE_REMEDIATION_CIRCUIT_URL,
  WAGE_REMEDIATION_VERIFICATION_KEY_SHA256,
  WAGE_REMEDIATION_VERIFICATION_KEY_URL,
  type EncryptedPayrollWitness,
  type PayrollIntegrityShardProof,
  type ProofWorkerFailure,
  type ProofWorkerRequest,
  type ProofWorkerResponse,
  type ProofWorkerSuccess,
} from "./protocol";
import {
  decodeVerificationKeyHex,
  hashProofCalldata,
  normalizeGaragaProofCalldata,
  serializePayrollPublicInputs,
} from "./starknet-calldata";

const scope = self as unknown as DedicatedWorkerGlobalScope;
type CircuitProfile = "payroll" | "advanced" | "wage_claim" | "wage_remediation";

type BrowserAssets = {
  circuit: CompiledCircuit;
  verificationKey: Uint8Array;
  circuitSha256: string;
};

class WorkerProofError extends Error {
  constructor(readonly code: ProofWorkerFailure["code"]) {
    super(code);
  }
}

function progress(requestId: string, stage: "loading" | "executing" | "proving" | "verifying" | "encoding") {
  const response: ProofWorkerResponse = { version: 1, type: "proof-progress", requestId, stage };
  scope.postMessage(response);
}

async function sha256Hex(value: string | Uint8Array): Promise<string> {
  const source = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const bytes = new Uint8Array(source.byteLength);
  bytes.set(source);
  const digest = await crypto.subtle.digest("SHA-256", bytes.buffer);
  return `0x${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

async function loadBrowserAssets(profile: CircuitProfile): Promise<BrowserAssets> {
  const configuration = profile === "payroll" ? {
    circuitUrl: PAYROLL_INTEGRITY_CIRCUIT_URL,
    verificationKeyUrl: PAYROLL_INTEGRITY_VERIFICATION_KEY_URL,
    circuitSha256: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
    verificationKeySha256: PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  } : profile === "advanced" ? {
    circuitUrl: ADVANCED_OBLIGATION_CIRCUIT_URL,
    verificationKeyUrl: ADVANCED_OBLIGATION_VERIFICATION_KEY_URL,
    circuitSha256: ADVANCED_OBLIGATION_CIRCUIT_SHA256,
    verificationKeySha256: ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  } : profile === "wage_claim" ? {
    circuitUrl: WAGE_CLAIM_CIRCUIT_URL,
    verificationKeyUrl: WAGE_CLAIM_VERIFICATION_KEY_URL,
    circuitSha256: WAGE_CLAIM_CIRCUIT_SHA256,
    verificationKeySha256: WAGE_CLAIM_VERIFICATION_KEY_SHA256,
  } : {
    circuitUrl: WAGE_REMEDIATION_CIRCUIT_URL,
    verificationKeyUrl: WAGE_REMEDIATION_VERIFICATION_KEY_URL,
    circuitSha256: WAGE_REMEDIATION_CIRCUIT_SHA256,
    verificationKeySha256: WAGE_REMEDIATION_VERIFICATION_KEY_SHA256,
  };

  let circuitText: string;
  try {
    const response = await fetch(configuration.circuitUrl, { cache: "force-cache" });
    if (!response.ok) throw new Error("circuit response failed");
    circuitText = await response.text();
    if (await sha256Hex(circuitText) !== configuration.circuitSha256) {
      throw new Error("circuit digest mismatch");
    }
  } catch {
    throw new WorkerProofError("CIRCUIT_LOAD_FAILED");
  }

  try {
    const response = await fetch(configuration.verificationKeyUrl, { cache: "force-cache" });
    if (!response.ok) throw new Error("verification key response failed");
    const verificationKey = decodeVerificationKeyHex(await response.text());
    if (await sha256Hex(verificationKey) !== configuration.verificationKeySha256) {
      throw new Error("verification key digest mismatch");
    }
    return {
      circuit: JSON.parse(circuitText) as CompiledCircuit,
      verificationKey,
      circuitSha256: configuration.circuitSha256,
    };
  } catch {
    circuitText = "";
    throw new WorkerProofError("VERIFICATION_KEY_LOAD_FAILED");
  }
}

async function proveLinkedCircuit(input: {
  requestId: string;
  assets: BrowserAssets;
  circuitInputs: [InputMap, InputMap];
  label: string;
}): Promise<{ shards: [PayrollIntegrityShardProof, PayrollIntegrityShardProof]; provingTimeMs: number }> {
  const noir = new Noir(input.assets.circuit);
  const backend = new UltraHonkBackend(input.assets.circuit.bytecode, payrollProverBackendOptions({
    userAgent: navigator.userAgent,
    crossOriginIsolated,
    hardwareConcurrency: navigator.hardwareConcurrency || 1,
  }));
  const startedAt = performance.now();
  let witnessToErase: Uint8Array | undefined;
  try {
    const shards: PayrollIntegrityShardProof[] = [];
    let commonPublicInputs: readonly string[] | undefined;
    for (const shardIndex of [0, 1] as const) {
      progress(input.requestId, "executing");
      const { witness } = await noir.execute(input.circuitInputs[shardIndex]);
      witnessToErase = witness;
      input.circuitInputs[shardIndex] = {};
      progress(input.requestId, "proving");
      const proofData = await backend.generateProof(witness, { keccakZK: true });
      witness.fill(0);
      witnessToErase = undefined;
      progress(input.requestId, "verifying");
      if (!await backend.verifyProof(proofData, { keccakZK: true })) {
        throw new WorkerProofError("SELF_VERIFY_FAILED");
      }
      if (BigInt(proofData.publicInputs[16]) !== BigInt(shardIndex)) {
        throw new WorkerProofError("SELF_VERIFY_FAILED");
      }
      if (commonPublicInputs) {
        for (let index = 0; index < 16; index += 1) {
          if (BigInt(commonPublicInputs[index]) !== BigInt(proofData.publicInputs[index])) {
            throw new WorkerProofError("SELF_VERIFY_FAILED");
          }
        }
      } else {
        commonPublicInputs = proofData.publicInputs;
      }
      progress(input.requestId, "encoding");
      const proofCalldata = normalizeGaragaProofCalldata(getZKHonkCallData(
        proofData.proof,
        serializePayrollPublicInputs(proofData.publicInputs),
        input.assets.verificationKey,
      ));
      if (proofCalldata.length > PAYO_MAX_PROOF_CALLDATA_FELTS) {
        throw new WorkerProofError("CALLDATA_LIMIT_EXCEEDED");
      }
      shards.push({
        shardIndex,
        proof: proofData.proof,
        proofCalldata,
        calldataHash: hashProofCalldata(proofCalldata),
        publicInputs: mapPayrollPublicInputs(proofData.publicInputs),
      });
    }
    return {
      shards: shards as [PayrollIntegrityShardProof, PayrollIntegrityShardProof],
      provingTimeMs: Math.round(performance.now() - startedAt),
    };
  } finally {
    witnessToErase?.fill(0);
    input.circuitInputs[0] = {};
    input.circuitInputs[1] = {};
    await backend.destroy();
  }
}

scope.addEventListener("message", async (event: MessageEvent<ProofWorkerRequest>) => {
  const request = event.data;
  const requestId = typeof request?.requestId === "string" ? request.requestId : "invalid-request";
  if (request?.version !== 1 || request.type !== "prove-payroll-integrity" || !request.requestId) {
    scope.postMessage(safeProofFailure(requestId, "INVALID_REQUEST"));
    return;
  }

  let payload: EncryptedPayrollWitness | undefined;
  let failureCode: ProofWorkerFailure["code"] = "WITNESS_INVALID";
  try {
    progress(requestId, "loading");
    payload = decryptVaultRecord<EncryptedPayrollWitness>(request.encryptedWitness, request.principal);
    if (!payload || typeof payload !== "object") throw new WorkerProofError("WITNESS_INVALID");
    await initGaraga();

    let proof: ProofWorkerSuccess;
    if ("advancedBuildInput" in payload) {
      const payroll = await buildPayrollIntegrityInputsFromSerialized(payload.advancedBuildInput.payroll);
      const advanced = buildAdvancedObligationInputs({
        payroll,
        agreements: payload.advancedBuildInput.agreements,
      });
      payload = { circuitInputs: [{}, {}] };
      failureCode = "PROVING_FAILED";
      payroll.witness.circuitInputs = [{}, {}];
      const mergedProof = await proveLinkedCircuit({
        requestId,
        assets: await loadBrowserAssets("advanced"),
        circuitInputs: advanced.witness.circuitInputs,
        label: "AdvancedPayrollIntegrity",
      });
      proof = {
        version: 1,
        type: "proof-complete",
        requestId,
        scheme: "ultra_keccak_zk_honk",
        shards: mergedProof.shards,
        circuitSha256: ADVANCED_OBLIGATION_CIRCUIT_SHA256,
        provingTimeMs: mergedProof.provingTimeMs,
      };
    } else {
      let profile: CircuitProfile = "payroll";
      let circuitInputs: [InputMap, InputMap];
      if ("circuitProfile" in payload) {
        profile = payload.circuitProfile;
        circuitInputs = payload.circuitInputs;
      } else if ("buildInput" in payload) {
        circuitInputs = (await buildPayrollIntegrityInputsFromSerialized(payload.buildInput)).witness.circuitInputs;
      } else {
        circuitInputs = payload.circuitInputs;
      }
      if (!Array.isArray(circuitInputs) || circuitInputs.length !== 2) {
        throw new WorkerProofError("WITNESS_INVALID");
      }
      payload = { circuitInputs: [{}, {}] };
      failureCode = "PROVING_FAILED";
      const result = await proveLinkedCircuit({
        requestId,
        assets: await loadBrowserAssets(profile),
        circuitInputs,
        label: profile,
      });
      proof = {
        version: 1,
        type: "proof-complete",
        requestId,
        scheme: "ultra_keccak_zk_honk",
        shards: result.shards,
        circuitSha256: profile === "payroll"
          ? PAYROLL_INTEGRITY_CIRCUIT_SHA256
          : profile === "wage_claim"
            ? WAGE_CLAIM_CIRCUIT_SHA256
            : WAGE_REMEDIATION_CIRCUIT_SHA256,
        provingTimeMs: result.provingTimeMs,
      };
    }
    scope.postMessage(proof, proof.shards.map((shard) => shard.proof.buffer));
  } catch (error) {
    const code = error instanceof WorkerProofError
      ? error.code
      : classifyProofFailure(error, failureCode);
    scope.postMessage(safeProofFailure(requestId, code));
  } finally {
    payload = { circuitInputs: [{}, {}] };
  }
});
