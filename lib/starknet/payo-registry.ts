import { validateAndParseAddress, type Call } from "starknet";
import { splitHashToU128 } from "@/lib/crypto/commitments";

export const PAYO_REGISTRY_MIN_DELAY_SECONDS = 0;
export const PAYO_REGISTRY_ACTIVATION_BUFFER_SECONDS = 0;
export const PAYO_OBLIGATION_ROOT_LIFETIME_SECONDS = 45 * 24 * 60 * 60;
export const PAYO_BASELINE_LIFETIME_SECONDS = 365 * 24 * 60 * 60;

export type ObligationRootSchedule = {
  call: Call;
  validAfter: number;
  expiresAt: number;
};

export type PayoBaselineSchedule = {
  calls: [Call, Call];
  validAfter: number;
  expiresAt: number;
};

export function rootLimbs(root: string): { high: bigint; low: bigint } {
  if (!/^0x[0-9a-fA-F]{64}$/.test(root)) {
    throw new Error("The registry root must be a canonical 32-byte value.");
  }
  return splitHashToU128(root);
}

export function prepareObligationRootSchedule(input: {
  registryAddress: string;
  agreementRoot: string;
  blockTimestamp: number;
}): ObligationRootSchedule {
  const registryAddress = validateAndParseAddress(input.registryAddress);
  if (!Number.isSafeInteger(input.blockTimestamp) || input.blockTimestamp < 0) {
    throw new Error("The Starknet block timestamp is invalid.");
  }
  const { high, low } = rootLimbs(input.agreementRoot);
  const validAfter = input.blockTimestamp
    + PAYO_REGISTRY_MIN_DELAY_SECONDS
    + PAYO_REGISTRY_ACTIVATION_BUFFER_SECONDS;
  const expiresAt = validAfter + PAYO_OBLIGATION_ROOT_LIFETIME_SECONDS;
  return {
    call: {
      contractAddress: registryAddress,
      entrypoint: "schedule_obligation_root",
      calldata: [high.toString(), low.toString(), validAfter.toString(), expiresAt.toString()],
    },
    validAfter,
    expiresAt,
  };
}

export function preparePayoBaselineSchedule(input: {
  registryAddress: string;
  bundleVerifierAddress: string;
  policyRoot: string;
  blockTimestamp: number;
}): PayoBaselineSchedule {
  const registryAddress = validateAndParseAddress(input.registryAddress);
  const bundleVerifierAddress = validateAndParseAddress(input.bundleVerifierAddress);
  if (BigInt(bundleVerifierAddress) === 0n) {
    throw new Error("The PAYO bundle verifier address cannot be zero.");
  }
  if (!Number.isSafeInteger(input.blockTimestamp) || input.blockTimestamp < 0) {
    throw new Error("The Starknet block timestamp is invalid.");
  }
  const { high, low } = rootLimbs(input.policyRoot);
  const validAfter = input.blockTimestamp
    + PAYO_REGISTRY_MIN_DELAY_SECONDS
    + PAYO_REGISTRY_ACTIVATION_BUFFER_SECONDS;
  const expiresAt = validAfter + PAYO_BASELINE_LIFETIME_SECONDS;
  return {
    calls: [
      {
        contractAddress: registryAddress,
        entrypoint: "schedule_policy_root",
        calldata: [high.toString(), low.toString(), validAfter.toString(), expiresAt.toString()],
      },
      {
        contractAddress: registryAddress,
        entrypoint: "schedule_verifier",
        calldata: ["0", "1", bundleVerifierAddress, validAfter.toString(), expiresAt.toString()],
      },
    ],
    validAfter,
    expiresAt,
  };
}


export function prepareFxRootPublication(input: {
  registryAddress: string;
  fxRoot: string;
  observedAt: number;
  maximumAgeSeconds: number;
  blockTimestamp: number;
}): Call {
  const registryAddress = validateAndParseAddress(input.registryAddress);
  const { high, low } = rootLimbs(input.fxRoot);
  for (const [label, value] of [
    ["FX observation timestamp", input.observedAt],
    ["FX maximum age", input.maximumAgeSeconds],
    ["Starknet block timestamp", input.blockTimestamp],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} is invalid.`);
  }
  if (input.maximumAgeSeconds < 1 || input.maximumAgeSeconds > 3_600) {
    throw new Error("The FX root lifetime must be between 1 and 3,600 seconds.");
  }
  if (
    input.observedAt > input.blockTimestamp
    || input.blockTimestamp > input.observedAt + input.maximumAgeSeconds
  ) {
    throw new Error("The FX root is stale or future-dated at the latest Starknet block.");
  }
  return {
    contractAddress: registryAddress,
    entrypoint: "publish_fx_root",
    calldata: [
      high.toString(),
      low.toString(),
      input.observedAt.toString(),
      input.maximumAgeSeconds.toString(),
    ],
  };
}
