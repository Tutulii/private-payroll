import "server-only";

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { BackendType, UltraHonkBackend } from "@aztec/bb.js";
import { getZKHonkCallData, init as initGaraga } from "garaga";
import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";
import { decryptVaultRecord, type EncryptedVaultRecord, type VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import { buildAdvancedObligationInputs } from "./advanced-obligation-input";
import { buildPayrollIntegrityInputsFromSerialized } from "./input-builder";
import { mapExceptionPublicInputsV2 } from "@/lib/domain/exception-protocol";
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  mapPayrollPublicInputs,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  PAYROLL_SERVER_WASM_MAXIMUM_PAGES,
  PAYO_MAX_PROOF_CALLDATA_FELTS,
  OBLIGATION_SNAPSHOT_LINK_CIRCUIT_SHA256,
  OBLIGATION_SNAPSHOT_LINK_VERIFICATION_KEY_SHA256,
  WAGE_CLAIM_CIRCUIT_SHA256,
  WAGE_CLAIM_VERIFICATION_KEY_SHA256,
  WAGE_REMEDIATION_CIRCUIT_SHA256,
  WAGE_REMEDIATION_VERIFICATION_KEY_SHA256,
  WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
  WAGE_CLAIM_VNEXT_VERIFICATION_KEY_SHA256,
  WAGE_REMEDIATION_VNEXT_CIRCUIT_SHA256,
  WAGE_REMEDIATION_VNEXT_VERIFICATION_KEY_SHA256,
  type ExceptionCircuitProfile,
  type ExceptionProofWorkerSuccess,
  type EncryptedPayrollWitness,
  type PayoProofWorkerSuccess,
  type PayrollIntegrityShardProof,
  type ProofWorkerSuccess,
} from "./protocol";
import {
  decodeVerificationKeyHex,
  hashProofCalldata,
  normalizeGaragaProofCalldata,
  serializePayrollPublicInputs,
  serializeExceptionPublicInputs,
} from "./starknet-calldata";
import { parseProverThreadCount } from "./prover-runtime";

type PinnedAssets = {
  circuit: CompiledCircuit;
  verificationKey: Uint8Array;
  circuitSha256: string;
};

const assetCache = new Map<string, Promise<PinnedAssets>>();
let garagaReady: Promise<unknown> | undefined;

function sha256(value: string | Uint8Array): string {
  return `0x${createHash("sha256").update(value).digest("hex")}`;
}

type CircuitProfile = "payroll" | "advanced" | "wage_claim" | "wage_remediation";

async function loadExceptionPinnedAssets(profile: ExceptionCircuitProfile): Promise<PinnedAssets> {
  const configuration = profile === "obligation_snapshot_v5" ? {
    circuitPath: "public/circuits/obligation_snapshot_link-v5.json",
    verificationKeyPath: "public/circuits/obligation_snapshot_link-v5.vk.hex",
    circuitSha256: OBLIGATION_SNAPSHOT_LINK_CIRCUIT_SHA256,
    verificationKeySha256: OBLIGATION_SNAPSHOT_LINK_VERIFICATION_KEY_SHA256,
  } : profile === "wage_claim_v6" ? {
    circuitPath: "public/circuits/wage_claim-v6.json",
    verificationKeyPath: "public/circuits/wage_claim-v6.vk.hex",
    circuitSha256: WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
    verificationKeySha256: WAGE_CLAIM_VNEXT_VERIFICATION_KEY_SHA256,
  } : {
    circuitPath: "public/circuits/wage_remediation-v7.json",
    verificationKeyPath: "public/circuits/wage_remediation-v7.vk.hex",
    circuitSha256: WAGE_REMEDIATION_VNEXT_CIRCUIT_SHA256,
    verificationKeySha256: WAGE_REMEDIATION_VNEXT_VERIFICATION_KEY_SHA256,
  };
  const cacheKey = `exception:${profile}`;
  if (!assetCache.has(cacheKey)) {
    assetCache.set(cacheKey, Promise.all([
      readFile(resolve(process.cwd(), configuration.circuitPath), "utf8"),
      readFile(resolve(process.cwd(), configuration.verificationKeyPath), "utf8"),
    ]).then(([circuitText, verificationKeyHex]) => {
      const verificationKey = decodeVerificationKeyHex(verificationKeyHex);
      if (sha256(circuitText) !== configuration.circuitSha256) {
        throw new Error(`The self-hosted ${profile} circuit does not match its pinned hash.`);
      }
      if (sha256(verificationKey) !== configuration.verificationKeySha256) {
        throw new Error(`The self-hosted ${profile} verification key does not match its pinned hash.`);
      }
      return {
        circuit: JSON.parse(circuitText) as CompiledCircuit,
        verificationKey,
        circuitSha256: configuration.circuitSha256,
      };
    }));
  }
  return assetCache.get(cacheKey)!;
}

async function loadPinnedAssets(profile: CircuitProfile): Promise<PinnedAssets> {
  const configuration = profile === "payroll" ? {
    circuitPath: "public/circuits/payroll_integrity-v1.json",
    verificationKeyPath: "public/circuits/payroll_integrity-v1.vk.hex",
    circuitSha256: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
    verificationKeySha256: PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  } : profile === "advanced" ? {
    circuitPath: "public/circuits/advanced_obligation-v2.json",
    verificationKeyPath: "public/circuits/advanced_obligation-v2.vk.hex",
    circuitSha256: ADVANCED_OBLIGATION_CIRCUIT_SHA256,
    verificationKeySha256: ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  } : profile === "wage_claim" ? {
    circuitPath: "public/circuits/wage_claim-v3.json",
    verificationKeyPath: "public/circuits/wage_claim-v3.vk.hex",
    circuitSha256: WAGE_CLAIM_CIRCUIT_SHA256,
    verificationKeySha256: WAGE_CLAIM_VERIFICATION_KEY_SHA256,
  } : {
    circuitPath: "public/circuits/wage_remediation-v4.json",
    verificationKeyPath: "public/circuits/wage_remediation-v4.vk.hex",
    circuitSha256: WAGE_REMEDIATION_CIRCUIT_SHA256,
    verificationKeySha256: WAGE_REMEDIATION_VERIFICATION_KEY_SHA256,
  };
  if (!assetCache.has(profile)) {
    assetCache.set(profile, Promise.all([
      readFile(resolve(process.cwd(), configuration.circuitPath), "utf8"),
      readFile(resolve(process.cwd(), configuration.verificationKeyPath), "utf8"),
    ]).then(([circuitText, verificationKeyHex]) => {
      const verificationKey = decodeVerificationKeyHex(verificationKeyHex);
      if (sha256(circuitText) !== configuration.circuitSha256) {
        throw new Error(`The self-hosted ${profile} circuit does not match its pinned hash.`);
      }
      if (sha256(verificationKey) !== configuration.verificationKeySha256) {
        throw new Error(`The self-hosted ${profile} verification key does not match its pinned hash.`);
      }
      return {
        circuit: JSON.parse(circuitText) as CompiledCircuit,
        verificationKey,
        circuitSha256: configuration.circuitSha256,
      };
    }));
  }
  return assetCache.get(profile)!;
}

async function proveLinkedCircuit(input: {
  assets: PinnedAssets;
  circuitInputs: [InputMap, InputMap];
  label: string;
}): Promise<{ shards: [PayrollIntegrityShardProof, PayrollIntegrityShardProof]; provingTimeMs: number }> {
  const noir = new Noir(input.assets.circuit);
  const backend = new UltraHonkBackend(input.assets.circuit.bytecode, {
    backend: BackendType.Wasm,
    threads: parseProverThreadCount(process.env.PAYO_PROVER_THREADS),
    memory: { maximum: PAYROLL_SERVER_WASM_MAXIMUM_PAGES },
  });
  const startedAt = performance.now();
  let witnessToErase: Uint8Array | undefined;
  try {
    const shards: PayrollIntegrityShardProof[] = [];
    let commonPublicInputs: readonly string[] | undefined;
    for (const shardIndex of [0, 1] as const) {
      const { witness } = await noir.execute(input.circuitInputs[shardIndex]);
      witnessToErase = witness;
      input.circuitInputs[shardIndex] = {};
      const proofData = await backend.generateProof(witness, { keccakZK: true });
      witness.fill(0);
      witnessToErase = undefined;
      if (!await backend.verifyProof(proofData, { keccakZK: true })) {
        throw new Error(`${input.label} proof shard ${shardIndex} failed local verification.`);
      }
      if (BigInt(proofData.publicInputs[16]) !== BigInt(shardIndex)) {
        throw new Error(`${input.label} proof shard ${shardIndex} returned the wrong shard index.`);
      }
      if (commonPublicInputs) {
        for (let index = 0; index < 16; index += 1) {
          if (BigInt(commonPublicInputs[index]) !== BigInt(proofData.publicInputs[index])) {
            throw new Error(`${input.label} proof shards returned different deployment bindings.`);
          }
        }
      } else {
        commonPublicInputs = proofData.publicInputs;
      }
      const proofCalldata = normalizeGaragaProofCalldata(getZKHonkCallData(
        proofData.proof,
        serializePayrollPublicInputs(proofData.publicInputs),
        input.assets.verificationKey,
      ));
      if (proofCalldata.length > PAYO_MAX_PROOF_CALLDATA_FELTS) {
        throw new Error(`${input.label} proof shard ${shardIndex} has ${proofCalldata.length} calldata felts; Starknet submissions permit at most ${PAYO_MAX_PROOF_CALLDATA_FELTS}.`);
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

async function proveExceptionCircuit(input: {
  assets: PinnedAssets;
  circuitInput: InputMap;
  profile: ExceptionCircuitProfile;
}): Promise<Omit<ExceptionProofWorkerSuccess, "version" | "type" | "requestId" | "scheme">> {
  const noir = new Noir(input.assets.circuit);
  const backend = new UltraHonkBackend(input.assets.circuit.bytecode, {
    backend: BackendType.Wasm,
    threads: parseProverThreadCount(process.env.PAYO_PROVER_THREADS),
    memory: { maximum: PAYROLL_SERVER_WASM_MAXIMUM_PAGES },
  });
  const startedAt = performance.now();
  let witnessToErase: Uint8Array | undefined;
  try {
    const { witness } = await noir.execute(input.circuitInput);
    witnessToErase = witness;
    input.circuitInput = {};
    const proofData = await backend.generateProof(witness, { keccakZK: true });
    witness.fill(0);
    witnessToErase = undefined;
    if (!await backend.verifyProof(proofData, { keccakZK: true })) {
      throw new Error(`${input.profile} proof failed local verification.`);
    }
    const publicInputs = mapExceptionPublicInputsV2(proofData.publicInputs);
    const expectedVersion = input.profile === "obligation_snapshot_v5"
      ? 5n
      : input.profile === "wage_claim_v6"
        ? 6n
        : 7n;
    if (
      BigInt(publicInputs.proofVersion) !== expectedVersion
      || BigInt(publicInputs.schemaVersion) !== 2n
      || BigInt(publicInputs.shardIndex) !== 0n
    ) {
      throw new Error(`${input.profile} returned the wrong versioned public-input ABI.`);
    }
    const proofCalldata = normalizeGaragaProofCalldata(getZKHonkCallData(
      proofData.proof,
      serializeExceptionPublicInputs(proofData.publicInputs),
      input.assets.verificationKey,
    ));
    if (proofCalldata.length > PAYO_MAX_PROOF_CALLDATA_FELTS) {
      throw new Error(`${input.profile} proof has ${proofCalldata.length} calldata felts; Starknet submissions permit at most ${PAYO_MAX_PROOF_CALLDATA_FELTS}.`);
    }
    return {
      profile: input.profile,
      circuitSha256: input.assets.circuitSha256,
      provingTimeMs: Math.round(performance.now() - startedAt),
      proof: {
        proof: proofData.proof,
        proofCalldata,
        calldataHash: hashProofCalldata(proofCalldata),
        publicInputs,
      },
    };
  } finally {
    witnessToErase?.fill(0);
    input.circuitInput = {};
    await backend.destroy();
  }
}

export async function provePayoExceptionOnSelfHostedNode(input: {
  requestId: string;
  encryptedWitness: EncryptedVaultRecord;
  principal: VaultPrincipalKeyPair;
}): Promise<ExceptionProofWorkerSuccess> {
  garagaReady ??= initGaraga();
  await garagaReady;
  let payload = decryptVaultRecord<EncryptedPayrollWitness>(input.encryptedWitness, input.principal);
  if (!("exceptionCircuitProfile" in payload) || !("circuitInput" in payload)) {
    throw new Error("The encrypted request does not contain a vNext PAYO exception witness.");
  }
  const profile = payload.exceptionCircuitProfile;
  const circuitInput = payload.circuitInput;
  payload = { circuitInputs: [{}, {}] };
  const result = await proveExceptionCircuit({
    assets: await loadExceptionPinnedAssets(profile),
    circuitInput,
    profile,
  });
  return {
    version: 2,
    type: "exception-proof-complete",
    requestId: input.requestId,
    scheme: "ultra_keccak_zk_honk",
    ...result,
  };
}

export async function provePayrollOnSelfHostedNode(input: {
  requestId: string;
  encryptedWitness: EncryptedVaultRecord;
  principal: VaultPrincipalKeyPair;
}): Promise<ProofWorkerSuccess> {
  garagaReady ??= initGaraga();
  await garagaReady;

  let payload = decryptVaultRecord<EncryptedPayrollWitness>(input.encryptedWitness, input.principal);
  if ("advancedBuildInput" in payload) {
    const payroll = await buildPayrollIntegrityInputsFromSerialized(payload.advancedBuildInput.payroll);
    const advanced = buildAdvancedObligationInputs({
      payroll,
      agreements: payload.advancedBuildInput.agreements,
    });
    payload = { circuitInputs: [{}, {}] };
    payroll.witness.circuitInputs = [{}, {}];
    const mergedProof = await proveLinkedCircuit({
      assets: await loadPinnedAssets("advanced"),
      circuitInputs: advanced.witness.circuitInputs,
      label: "AdvancedPayrollIntegrity",
    });
    return {
      version: 1,
      type: "proof-complete",
      requestId: input.requestId,
      scheme: "ultra_keccak_zk_honk",
      shards: mergedProof.shards,
      circuitSha256: ADVANCED_OBLIGATION_CIRCUIT_SHA256,
      provingTimeMs: mergedProof.provingTimeMs,
    };
  }
  if ("circuitProfile" in payload) {
    const profile = payload.circuitProfile;
    const proof = await proveLinkedCircuit({
      assets: await loadPinnedAssets(profile),
      circuitInputs: payload.circuitInputs,
      label: profile === "wage_claim" ? "WageClaim" : "WageRemediation",
    });
    payload = { circuitInputs: [{}, {}] };
    return {
      version: 1,
      type: "proof-complete",
      requestId: input.requestId,
      scheme: "ultra_keccak_zk_honk",
      shards: proof.shards,
      circuitSha256: profile === "wage_claim"
        ? WAGE_CLAIM_CIRCUIT_SHA256
        : WAGE_REMEDIATION_CIRCUIT_SHA256,
      provingTimeMs: proof.provingTimeMs,
    };
  }
  if ("buildInput" in payload) {
    payload = (await buildPayrollIntegrityInputsFromSerialized(payload.buildInput)).witness;
  }
  if (!("circuitInputs" in payload) || payload.circuitInputs.length !== 2) {
    throw new Error("The encrypted proof request does not contain both linked witnesses.");
  }
  const proof = await proveLinkedCircuit({
    assets: await loadPinnedAssets("payroll"),
    circuitInputs: payload.circuitInputs,
    label: "PayrollIntegrity",
  });
  payload = { circuitInputs: [{}, {}] };
  return {
    version: 1,
    type: "proof-complete",
    requestId: input.requestId,
    scheme: "ultra_keccak_zk_honk",
    shards: proof.shards,
    circuitSha256: PAYROLL_INTEGRITY_CIRCUIT_SHA256,
    provingTimeMs: proof.provingTimeMs,
  };
}

/**
 * Transport-level prover entrypoint. It inspects only the decrypted, authenticated
 * request envelope and preserves the strongly typed legacy prover APIs used by
 * offline fixture tooling.
 */
export async function provePayoOnSelfHostedNode(input: {
  requestId: string;
  encryptedWitness: EncryptedVaultRecord;
  principal: VaultPrincipalKeyPair;
}, authorization?: {
  expectedExceptionProfile?: ExceptionCircuitProfile;
}): Promise<PayoProofWorkerSuccess> {
  let payload = decryptVaultRecord<EncryptedPayrollWitness>(input.encryptedWitness, input.principal);
  const exceptionProfile = "exceptionCircuitProfile" in payload && "circuitInput" in payload
    ? payload.exceptionCircuitProfile
    : undefined;
  if (authorization?.expectedExceptionProfile
    && exceptionProfile !== authorization.expectedExceptionProfile) {
    throw new Error("The worker claim-access grant can prove only its Claim v6 witness.");
  }
  payload = { circuitInputs: [{}, {}] };
  return exceptionProfile
    ? provePayoExceptionOnSelfHostedNode(input)
    : provePayrollOnSelfHostedNode(input);
}
