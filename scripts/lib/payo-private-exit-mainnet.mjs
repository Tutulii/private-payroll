import { hash, num, validateAndParseAddress } from "starknet";

export const PAYO_PRIVATE_EXIT_MAINNET_PLAN_VERSION =
  "payo-private-exit-mainnet-plan-v1";
export const PAYO_PRIVATE_EXIT_MAINNET_CHAIN_ID = "0x534e5f4d41494e";
export const PAYO_PRIVATE_EXIT_ANONYMIZER_CLASS_HASH =
  "0x2a4ac595283d4d64b9952f5ef5c0da1775bfdb7c9d92237524a21dd8d19ebd7";
export const PAYO_PRIVATE_EXIT_ANONYMIZER_SALT =
  "0x7061796f2d707269766174652d657869742d656b75626f2d7631";
export const PAYO_PRIVATE_EXIT_ANONYMIZER_ADDRESS =
  "0x6737a6cdde0e0c4f39d88ec7301e1db8d7c46ffed35ade0ee9a56ed87ab784";
export const PAYO_PRIVATE_EXIT_UPSTREAM = Object.freeze({
  repository: "https://github.com/starkware-libs/starknet-privacy",
  commit: "bc75e4bac71ad0ce10c6e63effc33b5b25131a4f",
  contract: "EkuboSwapAnonymizer",
});

function canonicalFelt(value, label) {
  try {
    const parsed = BigInt(value);
    if (parsed <= 0n) throw new Error("zero");
    return num.toHex(parsed);
  } catch {
    throw new Error(`${label} must be a non-zero Starknet felt.`);
  }
}

function canonicalAddress(value, label) {
  try {
    const parsed = validateAndParseAddress(value);
    if (BigInt(parsed) === 0n) throw new Error("zero");
    return num.toHex(BigInt(parsed));
  } catch {
    throw new Error(`${label} must be a non-zero Starknet address.`);
  }
}

export function calculatePayoPrivateExitAddress({
  classHash = PAYO_PRIVATE_EXIT_ANONYMIZER_CLASS_HASH,
  salt = PAYO_PRIVATE_EXIT_ANONYMIZER_SALT,
} = {}) {
  return num.toHex(BigInt(hash.calculateContractAddressFromHash(
    canonicalFelt(salt, "Private-exit deployment salt"),
    canonicalFelt(classHash, "Private-exit class hash"),
    [],
    0,
  )));
}

export function buildPayoPrivateExitMainnetPlan({
  deployerAddress,
  upstreamEvidence,
  generatedAt = new Date().toISOString(),
}) {
  const address = calculatePayoPrivateExitAddress();
  if (BigInt(address) !== BigInt(PAYO_PRIVATE_EXIT_ANONYMIZER_ADDRESS)) {
    throw new Error("The private-exit deterministic address no longer matches its reviewed lock.");
  }
  if (
    upstreamEvidence?.schemaVersion !== "payo.block5.private-exit.upstream.v1"
    || upstreamEvidence?.upstream?.commit !== PAYO_PRIVATE_EXIT_UPSTREAM.commit
    || BigInt(upstreamEvidence?.reviewedContract?.classHash ?? 0)
      !== BigInt(PAYO_PRIVATE_EXIT_ANONYMIZER_CLASS_HASH)
    || upstreamEvidence?.checks?.pinnedUpstreamRevision !== true
    || upstreamEvidence?.checks?.releaseClassHashReproduced !== true
    || upstreamEvidence?.checks?.anonymizerAssertions?.passed !== 3
    || upstreamEvidence?.checks?.anonymizerAssertions?.failed !== 0
    || upstreamEvidence?.checks?.strk20OpenNoteSwapComposition?.passed !== 1
    || upstreamEvidence?.checks?.strk20OpenNoteSwapComposition?.failed !== 0
  ) {
    throw new Error("Passing pinned upstream anonymizer evidence is required.");
  }
  return {
    schemaVersion: PAYO_PRIVATE_EXIT_MAINNET_PLAN_VERSION,
    generatedAt,
    network: "starknet-mainnet",
    chainId: PAYO_PRIVATE_EXIT_MAINNET_CHAIN_ID,
    deployerAddress: canonicalAddress(deployerAddress, "Private-exit deployer address"),
    upstream: PAYO_PRIVATE_EXIT_UPSTREAM,
    deployment: {
      address,
      classHash: PAYO_PRIVATE_EXIT_ANONYMIZER_CLASS_HASH,
      salt: PAYO_PRIVATE_EXIT_ANONYMIZER_SALT,
      constructorCalldata: [],
      unique: false,
    },
    evidence: {
      path: "evidence/block5-private-exit-upstream.json",
      upstreamLockSha256: upstreamEvidence.upstream.lockfileSha256,
      anonymizerSourceSha256: upstreamEvidence.upstream.anonymizerSourceSha256,
      integrationSourceSha256: upstreamEvidence.upstream.privacyIntegrationSourceSha256,
      releaseArtifactSha256: upstreamEvidence.reviewedContract.releaseArtifactSha256,
    },
    releaseRequirements: {
      classDeclared: true,
      emptyConstructor: true,
      exactPrivacyInvokeAbi: true,
      deployedClassHashReadback: true,
      configureOnlyAfterReadback: true,
      tinyReadyWalletCanaryRequired: true,
    },
  };
}

export function assertPayoPrivateExitMainnetPlan(plan, context) {
  const expected = buildPayoPrivateExitMainnetPlan({
    ...context,
    generatedAt: plan?.generatedAt,
  });
  if (JSON.stringify(plan) !== JSON.stringify(expected)) {
    throw new Error("The reviewed private-exit Mainnet plan is stale or modified.");
  }
  return plan;
}

export function privateExitDeploymentPayload(plan) {
  return {
    classHash: plan.deployment.classHash,
    constructorCalldata: [],
    salt: plan.deployment.salt,
    unique: false,
  };
}

export function assertPayoAnonymizerAbi(input) {
  const abi = typeof input === "string" ? JSON.parse(input) : input;
  if (!Array.isArray(abi)) throw new Error("The anonymizer class returned no ABI.");
  const constructor = abi.find((entry) => entry?.type === "constructor");
  if (!constructor || constructor.name !== "constructor" || constructor.inputs?.length !== 0) {
    throw new Error("The reviewed anonymizer must have an empty constructor.");
  }
  const contractInterface = abi.find((entry) =>
    entry?.type === "interface"
    && entry.name === "ekubo_swap_anonymizer::ekubo_swap_anonymizer::IEkuboSwapAnonymizer");
  const privacyInvoke = contractInterface?.items?.find((entry) =>
    entry?.type === "function" && entry.name === "privacy_invoke");
  const expectedInputs = [
    "core::starknet::contract_address::ContractAddress",
    "ekubo::interfaces::router::TokenAmount",
    "ekubo::types::keys::PoolKey",
    "core::integer::u256",
    "core::integer::u128",
    "core::felt252",
  ];
  if (
    privacyInvoke?.state_mutability !== "external"
    || privacyInvoke?.inputs?.length !== expectedInputs.length
    || privacyInvoke.inputs.some((item, index) => item.type !== expectedInputs[index])
    || privacyInvoke?.outputs?.length !== 1
    || privacyInvoke.outputs[0]?.type !== "core::array::Span::<privacy::objects::OpenNoteDeposit>"
  ) {
    throw new Error("The Mainnet class does not expose the reviewed privacy_invoke ABI.");
  }
  return true;
}
