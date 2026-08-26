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
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  mapPayrollPublicInputs,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  PAYROLL_MOBILE_WASM_MAXIMUM_PAGES,
  WAGE_CLAIM_CIRCUIT_SHA256,
  WAGE_CLAIM_VERIFICATION_KEY_SHA256,
  WAGE_REMEDIATION_CIRCUIT_SHA256,
  WAGE_REMEDIATION_VERIFICATION_KEY_SHA256,
  type EncryptedPayrollWitness,
  type PayrollIntegrityShardProof,
  type ProofWorkerSuccess,
} from "./protocol";
import {
  decodeVerificationKeyHex,
  hashProofCalldata,
  normalizeGaragaProofCalldata,
  orderedPayrollPublicInputs,
  serializePayrollPublicInputs,
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
    memory: { maximum: PAYROLL_MOBILE_WASM_MAXIMUM_PAGES },
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

function joinProofBytes(base: Uint8Array, advanced: Uint8Array): Uint8Array {
  const result = new Uint8Array(4 + base.length + advanced.length);
  new DataView(result.buffer).setUint32(0, base.length, false);
  result.set(base, 4);
  result.set(advanced, 4 + base.length);
  return result;
}

function combineAdvancedProofs(input: {
  base: [PayrollIntegrityShardProof, PayrollIntegrityShardProof];
  advanced: [PayrollIntegrityShardProof, PayrollIntegrityShardProof];
}): [PayrollIntegrityShardProof, PayrollIntegrityShardProof] {
  return input.base.map((base, index) => {
    const advanced = input.advanced[index];
    if (BigInt(base.publicInputs.proofVersion) !== 1n || BigInt(advanced.publicInputs.proofVersion) !== 2n) {
      throw new Error("The linked advanced proof versions are invalid.");
    }
    const baseValues = orderedPayrollPublicInputs(base.publicInputs);
    const advancedValues = orderedPayrollPublicInputs(advanced.publicInputs);
    for (let field = 0; field < baseValues.length; field += 1) {
      if (field !== 2 && BigInt(baseValues[field]) !== BigInt(advancedValues[field])) {
        throw new Error(`Advanced proof shard ${index} is not bound to PayrollIntegrity field ${field}.`);
      }
    }
    const proofCalldata = [
      `0x${base.proofCalldata.length.toString(16)}`,
      ...base.proofCalldata,
      ...advanced.proofCalldata,
    ];
    return {
      ...advanced,
      proof: joinProofBytes(base.proof, advanced.proof),
      proofCalldata,
      calldataHash: hashProofCalldata(proofCalldata),
    };
  }) as [PayrollIntegrityShardProof, PayrollIntegrityShardProof];
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
    const [baseAssets, advancedAssets] = await Promise.all([
      loadPinnedAssets("payroll"),
      loadPinnedAssets("advanced"),
    ]);
    const baseProof = await proveLinkedCircuit({
      assets: baseAssets,
      circuitInputs: payroll.witness.circuitInputs,
      label: "PayrollIntegrity",
    });
    const advancedProof = await proveLinkedCircuit({
      assets: advancedAssets,
      circuitInputs: advanced.witness.circuitInputs,
      label: "AdvancedObligation",
    });
    return {
      version: 1,
      type: "proof-complete",
      requestId: input.requestId,
      scheme: "ultra_keccak_zk_honk",
      shards: combineAdvancedProofs({ base: baseProof.shards, advanced: advancedProof.shards }),
      circuitSha256: ADVANCED_OBLIGATION_CIRCUIT_SHA256,
      provingTimeMs: baseProof.provingTimeMs + advancedProof.provingTimeMs,
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
