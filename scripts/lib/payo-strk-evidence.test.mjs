import { describe, expect, it } from "vitest";
import evidence from "../../evidence/payo-strk-mainnet.json" with { type: "json" };
import {
  assertAcceptedReceipt,
  PAYO_PAYROLL_SEAL_ADDRESS,
  receiptHasEmitter,
  STRK20_MAINNET_POOL_ADDRESS,
  validatePayoStrkEvidence,
} from "./payo-strk-evidence.mjs";

function cloneEvidence() {
  return structuredClone(evidence);
}

describe("proof-bound PAYO STRK Mainnet evidence", () => {
  it("accepts the checked-in privacy-bounded record", () => {
    const result = validatePayoStrkEvidence(cloneEvidence());
    expect(result.orderedShards.map((shard) => shard.index)).toEqual([0, 1]);
  });

  it("rejects missing or duplicate proof shards", () => {
    const missing = cloneEvidence();
    missing.verifierShards.pop();
    expect(() => validatePayoStrkEvidence(missing)).toThrow("exactly two");

    const duplicate = cloneEvidence();
    duplicate.verifierShards[1].index = 0;
    expect(() => validatePayoStrkEvidence(duplicate)).toThrow("exactly 0 and 1");
  });

  it("rejects unproven or failed evidence", () => {
    const unproven = cloneEvidence();
    unproven.run.onchainStatus = 1;
    expect(() => validatePayoStrkEvidence(unproven)).toThrow("proven status");

    const failed = cloneEvidence();
    failed.payroll.executionStatus = "REVERTED";
    expect(() => validatePayoStrkEvidence(failed)).toThrow("did not succeed");
  });

  it("fails closed if recipient or salary privacy is not withheld", () => {
    const disclosed = cloneEvidence();
    disclosed.privacy.recipient = "0x123";
    expect(() => validatePayoStrkEvidence(disclosed)).toThrow("must remain withheld");
  });

  it("checks receipt status, block, and required event emitters", () => {
    const expected = evidence.payroll;
    const receipt = {
      transaction_hash: expected.transactionHash,
      block_number: expected.blockNumber,
      execution_status: "SUCCEEDED",
      finality_status: "ACCEPTED_ON_L2",
      events: [
        { from_address: STRK20_MAINNET_POOL_ADDRESS },
        { from_address: PAYO_PAYROLL_SEAL_ADDRESS },
      ],
    };
    expect(() => assertAcceptedReceipt(receipt, expected, "Payroll transaction")).not.toThrow();
    expect(receiptHasEmitter(receipt, STRK20_MAINNET_POOL_ADDRESS)).toBe(true);
    expect(receiptHasEmitter(receipt, PAYO_PAYROLL_SEAL_ADDRESS)).toBe(true);
    expect(() => assertAcceptedReceipt({ ...receipt, block_number: 1 }, expected, "Payroll transaction"))
      .toThrow("block number differs");
    expect(() => assertAcceptedReceipt(
      { ...receipt, finality_status: "ACCEPTED_ON_L1" },
      expected,
      "Payroll transaction",
    )).not.toThrow();
  });
});
