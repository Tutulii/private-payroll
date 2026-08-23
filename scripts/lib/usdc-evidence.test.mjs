import { describe, expect, it } from "vitest";
import {
  assertReceipt,
  assertPrivateTransferReceipt,
  assertUsdcShieldReceipt,
  NATIVE_USDC_ADDRESS,
  receiptFee,
  STRK20_EVENT_SELECTORS,
  STRK20_MAINNET_POOL_ADDRESS,
  tokenWithdrawalFee,
  validateEvidence,
  versionAtLeast,
} from "./usdc-evidence.mjs";

function validEvidence() {
  return {
    evidenceVersion: "payo-usdc-mainnet-v1",
    network: "SN_MAIN",
    wallet: {
      name: "Ready",
      walletApiVersion: "0.10.3",
      accountAddress: "0x123",
    },
    token: { symbol: "USDC", address: NATIVE_USDC_ADDRESS, decimals: 6 },
    poolAddress: STRK20_MAINNET_POOL_ADDRESS,
    shield: {
      transactionHash: "0x456",
      grossAtomic: "10000",
    },
    privateTransfer: {
      transactionHash: "0x789",
      amountAtomic: "5000",
      attestation: {
        source: "ready_wallet_ui_and_user_confirmation",
        asset: "USDC",
        recipientRelationship: "cross-account",
        publicSettlementProof: "unavailable_by_design",
      },
    },
    observedAt: "2026-08-24T00:00:00.000Z",
  };
}

describe("native-USDC Mainnet evidence", () => {
  it("accepts the minimal non-sensitive Ready compatibility record", () => {
    expect(validateEvidence(validEvidence())).toEqual({ gross: 10000n, transferred: 5000n });
  });

  it("rejects a transfer that does not use only part of the test shield", () => {
    const evidence = validEvidence();
    evidence.privateTransfer.amountAtomic = "10000";
    expect(() => validateEvidence(evidence)).toThrow(
      "disclosed transfer must use only part",
    );
  });

  it("rejects invalid or old Wallet API versions", () => {
    expect(versionAtLeast("0.10.3", "0.10.3")).toBe(true);
    expect(versionAtLeast("0.11.0-rc.1", "0.10.3")).toBe(true);
    expect(versionAtLeast("0.10.2", "0.10.3")).toBe(false);
    expect(versionAtLeast("Ready", "0.10.3")).toBe(false);
  });

  it("requires successful USDC shield receipts from the pool", () => {
    const receipt = {
      execution_status: "SUCCEEDED",
      finality_status: "ACCEPTED_ON_L2",
      actual_fee: { amount: "0x3e8", unit: "FRI" },
      events: [
        {
          from_address: STRK20_MAINNET_POOL_ADDRESS,
          keys: [STRK20_EVENT_SELECTORS.deposit, "0x123", NATIVE_USDC_ADDRESS],
          data: ["0x2710"],
        },
        {
          from_address: STRK20_MAINNET_POOL_ADDRESS,
          keys: [STRK20_EVENT_SELECTORS.encryptedNoteCreated, "0x456"],
          data: ["0x789"],
        },
        {
          from_address: STRK20_MAINNET_POOL_ADDRESS,
          keys: [STRK20_EVENT_SELECTORS.withdrawal, "0xabc", NATIVE_USDC_ADDRESS],
          data: ["0x3e8"],
        },
      ],
    };
    expect(() => assertReceipt(receipt, "Shield transaction")).not.toThrow();
    expect(() => assertUsdcShieldReceipt(receipt, "Shield transaction")).not.toThrow();
    expect(tokenWithdrawalFee(receipt, NATIVE_USDC_ADDRESS, "Shield transaction")).toBe(1000n);
    expect(receiptFee(receipt, "Shield transaction")).toBe(1000n);
    expect(() => assertReceipt({ ...receipt, events: [] }, "Shield transaction")).toThrow(
      "no live STRK20 pool event",
    );
  });

  it("does not mistake a visible STRK fee withdrawal for the hidden transfer asset", () => {
    const strk = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
    const receipt = {
      execution_status: "SUCCEEDED",
      finality_status: "ACCEPTED_ON_L2",
      actual_fee: { amount: "0x3e8", unit: "FRI" },
      events: [
        { from_address: STRK20_MAINNET_POOL_ADDRESS, keys: [STRK20_EVENT_SELECTORS.noteUsed], data: [] },
        { from_address: STRK20_MAINNET_POOL_ADDRESS, keys: [STRK20_EVENT_SELECTORS.encryptedNoteCreated], data: [] },
        {
          from_address: STRK20_MAINNET_POOL_ADDRESS,
          keys: [STRK20_EVENT_SELECTORS.withdrawal, "0xabc", strk],
          data: ["0x3e8"],
        },
      ],
    };
    expect(() => assertPrivateTransferReceipt(receipt, "Private transfer")).not.toThrow();
  });
});
