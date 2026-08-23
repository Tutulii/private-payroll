import { num } from "starknet";

export const NATIVE_USDC_ADDRESS =
  "0x033068f6539f8e6e6b131e6b2b814e6c34a5224bc66947c47dab9dfee93b35fb";
export const STRK20_MAINNET_POOL_ADDRESS =
  "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a";
export const STRK20_EVENT_SELECTORS = {
  deposit: "0x09149d2123147c5f43d258257fef0b7b969db78269369ebcf5ebb9eef8592f2",
  encryptedNoteCreated: "0x023c20207be8b1ef4430c25eef8ce779c9745ebe04139555ae81bd4f8fdd6ec5",
  noteUsed: "0x0247fc60d782e0094e7f98c47f277d92a3345d07a436f1f56b27a9b62be2322e",
  withdrawal: "0x02eed7e29b3502a726faf503ac4316b7101f3da813654e8df02c13449e03da8",
};

export function atomic(value, label) {
  if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value)) {
    throw new Error(`${label} must be an atomic-unit integer string.`);
  }
  return BigInt(value);
}

export function normalized(value) {
  return num.toHex(num.toBigInt(value)).toLowerCase();
}

export function versionAtLeast(version, minimum) {
  if (typeof version !== "string" || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
    return false;
  }
  const parts = (value) => value.split(/[+-]/, 1)[0].split(".").map(Number);
  const left = parts(version);
  const right = parts(minimum);
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    if ((left[index] ?? 0) !== (right[index] ?? 0)) return (left[index] ?? 0) > (right[index] ?? 0);
  }
  return true;
}

function assertFelt(value, label) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) {
    throw new Error(`${label} must be a 0x-prefixed Starknet value.`);
  }
  normalized(value);
}

export function validateEvidence(evidence) {
  if (evidence.evidenceVersion !== "payo-usdc-mainnet-v1") {
    throw new Error("Unsupported USDC evidence version.");
  }
  if (evidence.network !== "SN_MAIN") throw new Error("USDC evidence must use Starknet Mainnet.");
  if (evidence.wallet?.name !== "Ready") throw new Error("The compatibility wallet must be Ready.");
  if (!versionAtLeast(evidence.wallet.walletApiVersion, "0.10.3")) {
    throw new Error("Ready Wallet API is older than 0.10.3 or invalid.");
  }
  assertFelt(evidence.wallet.accountAddress, "Wallet account address");
  if (normalized(evidence.token?.address) !== normalized(NATIVE_USDC_ADDRESS) || evidence.token.decimals !== 6) {
    throw new Error("Evidence must use six-decimal Circle native USDC.");
  }
  if (normalized(evidence.poolAddress) !== normalized(STRK20_MAINNET_POOL_ADDRESS)) {
    throw new Error("Evidence uses the wrong STRK20 pool.");
  }
  assertFelt(evidence.shield?.transactionHash, "Shield transaction hash");
  assertFelt(evidence.privateTransfer?.transactionHash, "Private-transfer transaction hash");
  if (
    evidence.privateTransfer?.attestation?.source !== "ready_wallet_ui_and_user_confirmation"
    || evidence.privateTransfer.attestation.asset !== "USDC"
    || evidence.privateTransfer.attestation.recipientRelationship !== "cross-account"
    || evidence.privateTransfer.attestation.publicSettlementProof !== "unavailable_by_design"
  ) {
    throw new Error("Private transfer requires an explicit privacy-bounded Ready/user attestation.");
  }
  if (!Number.isFinite(Date.parse(evidence.observedAt))) throw new Error("Evidence observedAt is invalid.");

  const gross = atomic(evidence.shield.grossAtomic, "Shield gross");
  const transferred = evidence.privateTransfer.amountAtomic === undefined
    ? null
    : atomic(evidence.privateTransfer.amountAtomic, "Private transfer amount");

  if (gross <= 0n || (transferred !== null && (transferred <= 0n || transferred >= gross))) {
    throw new Error("The shield must be positive and any disclosed transfer must use only part of it.");
  }

  return { gross, transferred };
}

export function receiptFee(receipt, label) {
  if (receipt.actual_fee?.unit !== "FRI") {
    throw new Error(`${label} was not paid in STRK FRI.`);
  }
  return num.toBigInt(receipt.actual_fee.amount);
}

function poolEvents(receipt) {
  return (receipt.events ?? []).filter(
    (event) => normalized(event.from_address) === normalized(STRK20_MAINNET_POOL_ADDRESS),
  );
}

function eventHasSelector(event, selector) {
  return normalized(event.keys?.[0] ?? "0x0") === normalized(selector);
}

export function tokenWithdrawalFee(receipt, tokenAddress, label) {
  const withdrawal = poolEvents(receipt).find(
    (event) =>
      eventHasSelector(event, STRK20_EVENT_SELECTORS.withdrawal)
      && normalized(event.keys?.[2] ?? "0x0") === normalized(tokenAddress),
  );
  if (!withdrawal || withdrawal.data.length === 0) {
    throw new Error(`${label} has no ${normalized(tokenAddress)} fee withdrawal.`);
  }
  return num.toBigInt(withdrawal.data.at(-1));
}

export function assertReceipt(receipt, label) {
  if (receipt.execution_status !== "SUCCEEDED") throw new Error(`${label} did not succeed.`);
  if (!["ACCEPTED_ON_L2", "ACCEPTED_ON_L1"].includes(receipt.finality_status)) {
    throw new Error(`${label} is not accepted on Starknet.`);
  }
  if (poolEvents(receipt).length === 0) {
    throw new Error(`${label} has no live STRK20 pool event.`);
  }
}

export function assertUsdcShieldReceipt(receipt, label) {
  assertReceipt(receipt, label);
  const events = poolEvents(receipt);
  const requiredSelectors = [
    STRK20_EVENT_SELECTORS.deposit,
    STRK20_EVENT_SELECTORS.encryptedNoteCreated,
  ];
  for (const selector of requiredSelectors) {
    if (!events.some((event) => eventHasSelector(event, selector))) {
      throw new Error(`${label} is missing required STRK20 event ${selector}.`);
    }
  }
  tokenWithdrawalFee(receipt, NATIVE_USDC_ADDRESS, label);
}

export function assertPrivateTransferReceipt(receipt, label) {
  assertReceipt(receipt, label);
  const events = poolEvents(receipt);
  for (const selector of [STRK20_EVENT_SELECTORS.noteUsed, STRK20_EVENT_SELECTORS.encryptedNoteCreated]) {
    if (!events.some((event) => eventHasSelector(event, selector))) {
      throw new Error(`${label} is missing required private-note event ${selector}.`);
    }
  }
  // The transferred asset, recipient, and amount are intentionally absent from
  // public events. A visible Withdrawal can be fee recovery in another token.
}
