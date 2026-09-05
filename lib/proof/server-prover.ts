import "server-only";

import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { promisify } from "node:util";
import {
  BackendType,
  UltraHonkBackend,
} from "@aztec/bb.js";
import { getZKHonkCallData, init as initGaraga } from "garaga";
import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";
import { decryptVaultRecord, type EncryptedVaultRecord, type VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import { buildAdvancedObligationInputs } from "./advanced-obligation-input";
import { buildPayrollIntegrityInputsFromSerialized } from "./input-builder";
import { mapExceptionPublicInputsV2 } from "@/lib/domain/exception-protocol";
import { derivePayrollBookTotalsSalt } from "@/lib/domain/universal-payroll-book";
import {
  buildPayrollBookEntryInputs,
  buildVestingTransitionInputs,
  mapVestingTransitionPublicInputs,
  PAYO_VESTING_TRANSITION_PUBLIC_INPUT_COUNT,
  type VestingTransitionInputBuild,
} from "./vesting-transition-input";
import {
  buildSettlementMatchInputs,
  settlementTransactionReference,
  type SettlementEmittedNote,
  type SettlementMatchPublicInputs,
  type SettlementPayrollNote,
} from "./settlement-match";
import { settlementMatchWitnessSchema } from "./settlement-request";
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  mapPayrollPublicInputs,
  PAYROLL_INTEGRITY_CIRCUIT_SHA256,
  PAYROLL_INTEGRITY_VERIFICATION_KEY_SHA256,
  PAYROLL_SERVER_WASM_MAXIMUM_PAGES,
  PAYO_MAX_PROOF_CALLDATA_FELTS,
  PAYO_SETTLEMENT_MATCH_PUBLIC_INPUT_COUNT,
  SETTLEMENT_MATCH_CIRCUIT_SHA256,
  SETTLEMENT_MATCH_VERIFICATION_KEY_SHA256,
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
  VESTING_TRANSITION_CIRCUIT_SHA256,
  VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
  type ExceptionCircuitProfile,
  type ExceptionProofWorkerSuccess,
  type EncryptedPayrollWitness,
  type PayoProofWorkerSuccess,
  type PayrollIntegrityShardProof,
  type ProofWorkerSuccess,
  type SettlementMatchProofWorkerSuccess,
  type VestingBookProof,
  type VestingTransitionShardProof,
} from "./protocol";
import {
  decodeVerificationKeyHex,
  hashProofCalldata,
  normalizeGaragaProofCalldata,
  serializePayrollPublicInputs,
  serializeExceptionPublicInputs,
  serializeSettlementMatchPublicInputs,
  serializeVestingTransitionPublicInputs,
} from "./starknet-calldata";
import { parseProverThreadCount } from "./prover-runtime";

type PinnedAssets = {
  circuit: CompiledCircuit;
  verificationKey: Uint8Array;
  circuitSha256: string;
};

const assetCache = new Map<string, Promise<PinnedAssets>>();
let garagaReady: Promise<unknown> | undefined;
let settlementBbReady: Promise<string> | undefined;
const execFile = promisify(execFileCallback);

const SETTLEMENT_BB_BINARY_SHA256: Partial<Record<NodeJS.Architecture, string>> = {
  arm64: "0x0d5df6541bf9a8235305b380e48d7cdcb71e9525eef955946c0d8ac7f2f3277f",
  x64: "0x1c28d0bcd137ee1101eb12df8274c9118a4dda48b74872bae067e3c63879a7d0",
};

function sha256(value: string | Uint8Array): string {
  return `0x${createHash("sha256").update(value).digest("hex")}`;
}

async function loadPinnedSettlementBb(): Promise<string> {
  settlementBbReady ??= (async () => {
    const configured = process.env.PAYO_BB_PATH?.trim();
    if (!configured || !isAbsolute(configured)) {
      throw new Error("PAYO_BB_PATH must be the absolute path to PAYO's pinned native bb binary.");
    }
    const expected = SETTLEMENT_BB_BINARY_SHA256[process.arch];
    if (!expected) {
      throw new Error("SettlementMatch native proving is unsupported on this architecture.");
    }
    const binary = await readFile(configured);
    try {
      if (sha256(binary) !== expected) {
        throw new Error("The SettlementMatch native bb binary does not match PAYO's pinned digest.");
      }
    } finally {
      binary.fill(0);
    }
    return configured;
  })().catch((error) => {
    settlementBbReady = undefined;
    throw error;
  });
  return settlementBbReady;
}

type CircuitProfile = "payroll" | "advanced" | "vesting" | "wage_claim" | "wage_remediation";

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
  } : profile === "vesting" ? {
    circuitPath: "public/circuits/vesting_transition-v3.json",
    verificationKeyPath: "public/circuits/vesting_transition-v3.vk.hex",
    circuitSha256: VESTING_TRANSITION_CIRCUIT_SHA256,
    verificationKeySha256: VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
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

async function loadSettlementPinnedAssets(): Promise<PinnedAssets> {
  const cacheKey = "settlement-match-v8";
  if (!assetCache.has(cacheKey)) {
    assetCache.set(cacheKey, Promise.all([
      readFile(resolve(process.cwd(), "public/circuits/settlement_match-v8.json"), "utf8"),
      readFile(resolve(process.cwd(), "public/circuits/settlement_match-v8.vk.hex"), "utf8"),
    ]).then(([circuitText, verificationKeyHex]) => {
      const verificationKey = decodeVerificationKeyHex(verificationKeyHex);
      if (sha256(circuitText) !== SETTLEMENT_MATCH_CIRCUIT_SHA256) {
        throw new Error("The self-hosted SettlementMatch circuit does not match its pinned hash.");
      }
      if (sha256(verificationKey) !== SETTLEMENT_MATCH_VERIFICATION_KEY_SHA256) {
        throw new Error("The self-hosted SettlementMatch verification key does not match its pinned hash.");
      }
      return {
        circuit: JSON.parse(circuitText) as CompiledCircuit,
        verificationKey,
        circuitSha256: SETTLEMENT_MATCH_CIRCUIT_SHA256,
      };
    }));
  }
  return assetCache.get(cacheKey)!;
}

function decodeBbFieldVector(value: Uint8Array, label: string): string[] {
  if (value.length === 0 || value.length % 32 !== 0) {
    throw new Error(`${label} is not a canonical 32-byte field vector.`);
  }
  const fields: string[] = [];
  for (let offset = 0; offset < value.length; offset += 32) {
    fields.push(`0x${Buffer.from(value.subarray(offset, offset + 32)).toString("hex")}`);
  }
  return fields;
}

async function runPinnedBb(input: {
  bbPath: string;
  args: string[];
  threads: number;
}): Promise<void> {
  await execFile(input.bbPath, input.args, {
    env: {
      ...process.env,
      HARDWARE_CONCURRENCY: input.threads.toString(),
    },
    maxBuffer: 8 * 1_024 * 1_024,
    timeout: 30 * 60_000,
  });
}

function orderedSettlementPublicInputs(input: SettlementMatchPublicInputs): string[] {
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

function assertSettlementPublicInputs(
  actual: readonly string[],
  expected: SettlementMatchPublicInputs,
): void {
  const ordered = orderedSettlementPublicInputs(expected);
  if (actual.length !== PAYO_SETTLEMENT_MATCH_PUBLIC_INPUT_COUNT) {
    throw new Error("SettlementMatch returned the wrong public-input count.");
  }
  ordered.forEach((value, index) => {
    if (BigInt(actual[index]) !== BigInt(value)) {
      throw new Error("SettlementMatch returned a substituted public input at index " + index + ".");
    }
  });
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

async function proveVestingBookCircuit(input: {
  assets: PinnedAssets;
  build: VestingTransitionInputBuild;
}): Promise<VestingBookProof> {
  const noir = new Noir(input.assets.circuit);
  const backend = new UltraHonkBackend(input.assets.circuit.bytecode, {
    backend: BackendType.Wasm,
    threads: parseProverThreadCount(process.env.PAYO_PROVER_THREADS),
    memory: { maximum: PAYROLL_SERVER_WASM_MAXIMUM_PAGES },
  });
  const startedAt = performance.now();
  let witnessToErase: Uint8Array | undefined;
  try {
    const shards: VestingTransitionShardProof[] = [];
    let commonPublicInputs: readonly string[] | undefined;
    for (const shardIndex of [0, 1] as const) {
      const { witness } = await noir.execute(input.build.circuitInputs[shardIndex]);
      witnessToErase = witness;
      input.build.circuitInputs[shardIndex] = {};
      const proofData = await backend.generateProof(witness, { keccakZK: true });
      witness.fill(0);
      witnessToErase = undefined;
      if (!await backend.verifyProof(proofData, { keccakZK: true })) {
        throw new Error(`VestingBook proof shard ${shardIndex} failed local verification.`);
      }
      const shardIndexPosition = PAYO_VESTING_TRANSITION_PUBLIC_INPUT_COUNT - 1;
      if (proofData.publicInputs.length !== PAYO_VESTING_TRANSITION_PUBLIC_INPUT_COUNT
        || BigInt(proofData.publicInputs[shardIndexPosition]) !== BigInt(shardIndex)) {
        throw new Error(`VestingBook proof shard ${shardIndex} returned an invalid public ABI.`);
      }
      if (commonPublicInputs) {
        for (let index = 0; index < shardIndexPosition; index += 1) {
          if (BigInt(commonPublicInputs[index]) !== BigInt(proofData.publicInputs[index])) {
            throw new Error("VestingBook proof shards returned different state bindings.");
          }
        }
      } else {
        commonPublicInputs = proofData.publicInputs;
      }
      const publicInputs = mapVestingTransitionPublicInputs(proofData.publicInputs);
      const proofCalldata = normalizeGaragaProofCalldata(getZKHonkCallData(
        proofData.proof,
        serializeVestingTransitionPublicInputs(proofData.publicInputs),
        input.assets.verificationKey,
      ));
      if (proofCalldata.length > PAYO_MAX_PROOF_CALLDATA_FELTS) {
        throw new Error(
          `VestingBook proof shard ${shardIndex} has ${proofCalldata.length} calldata felts; Starknet submissions permit at most ${PAYO_MAX_PROOF_CALLDATA_FELTS}.`,
        );
      }
      shards.push({
        shardIndex,
        proof: proofData.proof,
        proofCalldata,
        calldataHash: hashProofCalldata(proofCalldata),
        publicInputs,
      });
    }
    return {
      proofVersion: 3,
      entryKind: input.build.entryKind,
      circuitSha256: input.assets.circuitSha256,
      verificationKeySha256: VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
      provingTimeMs: Math.round(performance.now() - startedAt),
      scheduleId: input.build.scheduleId,
      previousStateCommitment: input.build.previousStateCommitment,
      nextStateCommitment: input.build.nextStateCommitment,
      releaseNullifier: input.build.releaseNullifier,
      bookEntry: input.build.bookEntry,
      bookEntryCommitment: input.build.bookEntryCommitment,
      shards: shards as [VestingTransitionShardProof, VestingTransitionShardProof],
    };
  } finally {
    witnessToErase?.fill(0);
    input.build.circuitInputs[0] = {};
    input.build.circuitInputs[1] = {};
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

export async function proveSettlementMatchOnSelfHostedNode(input: {
  requestId: string;
  encryptedPayrollWitness: EncryptedVaultRecord;
  encryptedSettlementWitness: EncryptedVaultRecord;
  principal: VaultPrincipalKeyPair;
}): Promise<SettlementMatchProofWorkerSuccess> {
  if (
    input.encryptedPayrollWitness.aad.organizationId
      !== input.encryptedSettlementWitness.aad.organizationId
    || input.encryptedSettlementWitness.aad.recordType
      !== "settlement-match-proof-request"
  ) {
    throw new Error("SettlementMatch proof envelopes cross an organization or record boundary.");
  }
  let settlementPayload = settlementMatchWitnessSchema.parse(
    decryptVaultRecord<unknown>(input.encryptedSettlementWitness, input.principal),
  );
  if (settlementPayload.executionId !== input.requestId) {
    throw new Error("SettlementMatch witness belongs to another execution.");
  }
  let payrollPayload = decryptVaultRecord<EncryptedPayrollWitness>(
    input.encryptedPayrollWitness,
    input.principal,
  );
  const payroll = "advancedBuildInput" in payrollPayload
    ? await buildPayrollIntegrityInputsFromSerialized(payrollPayload.advancedBuildInput.payroll)
    : "buildInput" in payrollPayload
      ? await buildPayrollIntegrityInputsFromSerialized(payrollPayload.buildInput)
      : undefined;
  payrollPayload = { circuitInputs: [{}, {}] };
  if (!payroll) {
    throw new Error(
      "SettlementMatch requires a serialized payroll build, not opaque circuit inputs.",
    );
  }
  payroll.witness.circuitInputs = [{}, {}];
  const transactionReference = settlementTransactionReference({
    chainId: settlementPayload.chainId,
    policyAccountAddress: settlementPayload.policyAccountAddress,
    poolAddress: settlementPayload.poolAddress,
    poolCalldata: settlementPayload.poolCalldata,
  });
  const built = buildSettlementMatchInputs({
    payroll,
    senderAddress: settlementPayload.policyAccountAddress,
    viewingKey: settlementPayload.viewingKey,
    transactionReference,
    payrollNotes: settlementPayload.payrollNotes as SettlementPayrollNote[],
    emittedNotes: settlementPayload.emittedNotes as SettlementEmittedNote[],
  });
  settlementPayload = {
    ...settlementPayload,
    viewingKey: "0x0",
    payrollNotes: settlementPayload.payrollNotes.map((note) => ({
      ...note,
      amountAtomic: "0",
      salt: "0",
    })),
  };

  garagaReady ??= initGaraga();
  const [assets, bbPath] = await Promise.all([
    loadSettlementPinnedAssets(),
    loadPinnedSettlementBb(),
    garagaReady,
  ]).then(([pinnedAssets, pinnedBb]) => [pinnedAssets, pinnedBb] as const);
  const threads = parseProverThreadCount(process.env.PAYO_PROVER_THREADS);
  const noir = new Noir(assets.circuit);
  const startedAt = performance.now();
  let witnessToErase: Uint8Array | undefined;
  const jobDirectory = await mkdtemp(resolve(tmpdir(), "payo-settlement-"));
  try {
    await chmod(jobDirectory, 0o700);
    const circuitPath = resolve(process.cwd(), "public/circuits/settlement_match-v8.json");
    const circuitText = await readFile(circuitPath, "utf8");
    if (sha256(circuitText) !== SETTLEMENT_MATCH_CIRCUIT_SHA256) {
      throw new Error("The native SettlementMatch circuit changed after its pinned hash check.");
    }
    const verificationKeyPath = resolve(jobDirectory, "vk");
    await writeFile(verificationKeyPath, assets.verificationKey, { mode: 0o600 });
    const configuredCrsPath = process.env.PAYO_BB_CRS_PATH?.trim();
    const crsPath = configuredCrsPath || resolve(jobDirectory, "crs");
    if (!isAbsolute(crsPath)) {
      throw new Error("PAYO_BB_CRS_PATH must be absolute when configured.");
    }
    await mkdir(crsPath, { recursive: true, mode: 0o700 });
    const slowLowMemory = process.env.PAYO_BB_SLOW_LOW_MEMORY === "true";
    const chunks: SettlementMatchProofWorkerSuccess["chunks"] = [];
    for (let chunkIndex = 0; chunkIndex < built.circuitInputs.length; chunkIndex += 1) {
      const circuitInput = built.circuitInputs[chunkIndex];
      const { witness } = await noir.execute(circuitInput);
      witnessToErase = witness;
      built.circuitInputs[chunkIndex] = {};
      const chunkDirectory = resolve(jobDirectory, `chunk-${chunkIndex}`);
      await mkdir(chunkDirectory, { mode: 0o700 });
      const witnessPath = resolve(chunkDirectory, "witness.gz");
      const proofPath = resolve(chunkDirectory, "proof");
      const publicInputsPath = resolve(chunkDirectory, "public_inputs");
      await writeFile(witnessPath, witness, { mode: 0o600 });
      witness.fill(0);
      witnessToErase = undefined;
      try {
        await runPinnedBb({
          bbPath,
          threads,
          args: [
            "prove",
            "--scheme", "ultra_honk",
            "--oracle_hash", "keccak",
            "--bytecode_path", circuitPath,
            "--witness_path", witnessPath,
            "--output_path", chunkDirectory,
            "--vk_path", verificationKeyPath,
            "--crs_path", crsPath,
            ...(slowLowMemory ? ["--slow_low_memory"] : []),
          ],
        });
        await rm(witnessPath, { force: true });
        const proof = await readFile(proofPath);
        const publicInputBytes = await readFile(publicInputsPath);
        try {
          const publicInputs = decodeBbFieldVector(
            publicInputBytes,
            `SettlementMatch chunk ${chunkIndex} public inputs`,
          );
          const expectedPublicInputs = built.publicInputs[chunkIndex];
          assertSettlementPublicInputs(publicInputs, expectedPublicInputs);
          await runPinnedBb({
            bbPath,
            threads,
            args: [
              "verify",
              "--scheme", "ultra_honk",
              "--oracle_hash", "keccak",
              "--vk_path", verificationKeyPath,
              "--proof_path", proofPath,
              "--public_inputs_path", publicInputsPath,
              "--crs_path", crsPath,
            ],
          });
          const proofCalldata = normalizeGaragaProofCalldata(getZKHonkCallData(
            proof,
            serializeSettlementMatchPublicInputs(publicInputs),
            assets.verificationKey,
          ));
          if (proofCalldata.length > PAYO_MAX_PROOF_CALLDATA_FELTS) {
            throw new Error(
              "SettlementMatch chunk " + chunkIndex + " has " + proofCalldata.length
                + " calldata felts; Starknet submissions permit at most "
                + PAYO_MAX_PROOF_CALLDATA_FELTS + ".",
            );
          }
          chunks.push({
            chunkIndex,
            chunkCount: built.circuitInputs.length,
            proofCalldata,
            calldataHash: hashProofCalldata(proofCalldata),
            publicInputs: expectedPublicInputs,
          });
        } finally {
          proof.fill(0);
          publicInputBytes.fill(0);
        }
      } finally {
        await rm(chunkDirectory, { recursive: true, force: true, maxRetries: 3 });
      }
    }
    return {
      version: 8,
      type: "settlement-proof-complete",
      requestId: input.requestId,
      scheme: "ultra_keccak_zk_honk",
      circuitSha256: assets.circuitSha256,
      verificationKeySha256: SETTLEMENT_MATCH_VERIFICATION_KEY_SHA256,
      settlementRoot: built.settlementRoot,
      transactionReference: built.transactionReference,
      provingTimeMs: Math.round(performance.now() - startedAt),
      chunks,
    };
  } finally {
    witnessToErase?.fill(0);
    built.circuitInputs.fill({});
    await rm(jobDirectory, { recursive: true, force: true, maxRetries: 3 });
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
  const exceptionBookBuild = payload.exceptionBookBuild;
  if (exceptionBookBuild && profile === "obligation_snapshot_v5") {
    throw new Error("An obligation snapshot cannot append a payroll-book entry.");
  }
  payload = { circuitInputs: [{}, {}] };
  const result = await proveExceptionCircuit({
    assets: await loadExceptionPinnedAssets(profile),
    circuitInput,
    profile,
  });
  const vestingBook = exceptionBookBuild
    ? await proveVestingBookCircuit({
        assets: await loadPinnedAssets("vesting"),
        build: exceptionBookBuild,
      })
    : undefined;
  if (vestingBook) {
    const source = result.proof.publicInputs;
    const book = vestingBook.shards[0].publicInputs;
    const expectedKind = profile === "wage_claim_v6" ? 3n : 4n;
    const pairs: Array<[string, string]> = [
      [book.agreementRootHigh, source.agreementRootHigh],
      [book.agreementRootLow, source.agreementRootLow],
      [book.manifestRootHigh, source.manifestRootHigh],
      [book.manifestRootLow, source.manifestRootLow],
      [book.policyRootHigh, source.policyRootHigh],
      [book.policyRootLow, source.policyRootLow],
      [book.fxRootHigh, source.fxRootHigh],
      [book.fxRootLow, source.fxRootLow],
      [book.subjectNullifierHigh, source.subjectNullifierHigh],
      [book.subjectNullifierLow, source.subjectNullifierLow],
      [book.parentFactHigh, source.parentFactCommitmentHigh],
      [book.parentFactLow, source.parentFactCommitmentLow],
      [book.factHigh, source.factCommitmentHigh],
      [book.factLow, source.factCommitmentLow],
      [book.sourceSealAddress, source.sealAddress],
      [book.sourceProofVersion, source.proofVersion],
      [book.validityStart, source.validityStart],
      [book.validityExpiry, source.validityExpiry],
    ];
    if (BigInt(book.entryKind) !== expectedKind
      || pairs.some(([left, right]) => BigInt(left) !== BigInt(right))) {
      throw new Error("The generated payroll-book proof is not bound to its exception proof.");
    }
  }
  return {
    version: 2,
    type: "exception-proof-complete",
    requestId: input.requestId,
    scheme: "ultra_keccak_zk_honk",
    ...result,
    ...(vestingBook ? { vestingBook } : {}),
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
    const request = payload.advancedBuildInput;
    const payroll = await buildPayrollIntegrityInputsFromSerialized(request.payroll);
    const advanced = buildAdvancedObligationInputs({
      payroll,
      agreements: request.agreements,
    });
    let vestingBuild: VestingTransitionInputBuild | undefined;
    if (request.vestingBook) {
      const privateVesting = request.agreements.filter((agreement) =>
        agreement.agreementVersion === "payo-agreement-v2"
          && agreement.paymentPlan.kind === "private_vesting");
      if (privateVesting.length > 1) {
        throw new Error("A stateful vesting payroll can release exactly one private schedule per run.");
      }
      const periodStart = BigInt(request.vestingBook.periodStart);
      const periodEnd = BigInt(request.vestingBook.periodEnd);
      const totalsSalt = derivePayrollBookTotalsSalt({
        organizationSecret: request.payroll.organizationSecret,
        runNullifier: payroll.runNullifier,
      });
      vestingBuild = privateVesting.length === 1
        ? await buildVestingTransitionInputs({
            payroll,
            agreement: privateVesting[0],
            ownerAddress: request.vestingBook.ownerAddress,
            bookSealAddress: request.vestingBook.bookSealAddress,
            periodStart,
            periodEnd,
            previousStateSalt: request.vestingBook.previousStateSalt,
            nextStateSalt: request.vestingBook.nextStateSalt,
            totalsSalt,
            ...(request.vestingBook.attestation
              ? { attestation: request.vestingBook.attestation }
              : {}),
          })
        : await buildPayrollBookEntryInputs({
            payroll,
            ownerAddress: request.vestingBook.ownerAddress,
            bookSealAddress: request.vestingBook.bookSealAddress,
            periodStart,
            periodEnd,
            entryKind: request.vestingBook.entryKind ?? "ordinary",
            totalsSalt,
            ...(request.vestingBook.attestation
              ? { attestation: request.vestingBook.attestation }
              : {}),
          });
    }
    payload = { circuitInputs: [{}, {}] };
    payroll.witness.circuitInputs = [{}, {}];
    const mergedProof = await proveLinkedCircuit({
      assets: await loadPinnedAssets("advanced"),
      circuitInputs: advanced.witness.circuitInputs,
      label: "AdvancedPayrollIntegrity",
    });
    const vestingBook = vestingBuild
      ? await proveVestingBookCircuit({
          assets: await loadPinnedAssets("vesting"),
          build: vestingBuild,
        })
      : undefined;
    return {
      version: 1,
      type: "proof-complete",
      requestId: input.requestId,
      scheme: "ultra_keccak_zk_honk",
      shards: mergedProof.shards,
      circuitSha256: ADVANCED_OBLIGATION_CIRCUIT_SHA256,
      provingTimeMs: mergedProof.provingTimeMs + (vestingBook?.provingTimeMs ?? 0),
      ...(vestingBook ? { vestingBook } : {}),
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
