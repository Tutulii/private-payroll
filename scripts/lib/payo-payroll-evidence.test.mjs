import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { assertAcceptedReceipt, validatePayoPayrollEvidence } from "./payo-payroll-evidence.mjs";

const root = resolve(import.meta.dirname, "../..");

async function fixture(name) {
  return JSON.parse(await readFile(resolve(root, "evidence", name), "utf8"));
}

describe("proof-bound dual-token Mainnet evidence", () => {
  it.each([
    ["payo-usdc-mainnet.json", ["USDC"]],
    ["payo-mixed-mainnet.json", ["STRK", "USDC"]],
  ])("validates %s", async (name, expectedSymbols) => {
    expect(validatePayoPayrollEvidence(await fixture(name)).symbols).toEqual(expectedSymbols);
  });

  it("rejects an asset claim that does not match the batch kind", async () => {
    const evidence = await fixture("payo-usdc-mainnet.json");
    evidence.privateFlowAttestation.assets = ["STRK"];
    expect(() => validatePayoPayrollEvidence(evidence)).toThrow(/attestation/i);
  });

  it("rejects duplicated verifier transactions", async () => {
    const evidence = await fixture("payo-mixed-mainnet.json");
    evidence.verifierShards[1].transactionHash = evidence.verifierShards[0].transactionHash;
    expect(() => validatePayoPayrollEvidence(evidence)).toThrow(/distinct/i);
  });

  it("rejects evidence that leaks a recipient", async () => {
    const evidence = await fixture("payo-usdc-mainnet.json");
    evidence.privacy.recipient = "0x123";
    expect(() => validatePayoPayrollEvidence(evidence)).toThrow(/withheld/i);
  });

  it("accepts a receipt that advances from recorded L2 to L1 finality", async () => {
    const evidence = await fixture("payo-usdc-mainnet.json");
    expect(() => assertAcceptedReceipt({
      transaction_hash: evidence.payroll.transactionHash,
      block_number: evidence.payroll.blockNumber,
      execution_status: evidence.payroll.executionStatus,
      finality_status: "ACCEPTED_ON_L1",
    }, evidence.payroll, "Payroll transaction")).not.toThrow();
  });
});
