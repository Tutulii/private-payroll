import { describe, expect, it } from "vitest";
import { hash } from "starknet";
import { extractDirectPrivacySettlementEvidence } from "./privacy-invocation";

const pool = "0x456";
const policyAccount = "0x123";
const viewingKey = "0x789";
const chainId = "0x534e5f4d41494e";
const selector = hash.getSelectorFromName("compile_actions");

const clientActions = [
  "0x3",
  "0x6", "0x44", "0x555", "0x2",
  "0x3", "0x111", "0x222", "0x555", "0x64", "0x5", "0x77",
  "0x3", policyAccount, "0x333", "0x555", "0x9", "0x6", "0x88",
];

function invocation(inner = [policyAccount, viewingKey, ...clientActions]) {
  return {
    invocation: {
      sender_address: pool,
      calldata: ["0x1", pool, selector, "0x" + inner.length.toString(16), ...inner],
    },
  };
}

const poolCalldata = [
  "0x5",
  "0x0", "0x900", "0x1", "0x901",
  "0x9", "0x902",
  "0x8", "0xaaa", "0xbbb",
  "0x8", "0xccc", "0xddd",
  "0x1", "0x444", "0x555", "0x666", "0x777",
  "0x1",
];

function parse(overrides: Partial<Parameters<typeof extractDirectPrivacySettlementEvidence>[0]> = {}) {
  return extractDirectPrivacySettlementEvidence({
    invocation: invocation(),
    poolAddress: pool,
    policyAccountAddress: policyAccount,
    viewingKey,
    chainId,
    poolCalldata,
    payrollLineCount: 1,
    ...overrides,
  });
}

describe("pinned Privacy SDK settlement evidence", () => {
  it("joins the first payroll note to exact prover output and keeps change in the root", () => {
    const evidence = parse();
    expect(evidence.senderAddress).toBe(policyAccount);
    expect(evidence.viewingKey).toBe(viewingKey);
    expect(evidence.payrollNotes).toEqual([{
      position: 0,
      recipientAddress: "0x111",
      recipientPublicKey: "0x222",
      tokenAddress: "0x555",
      amountAtomic: "100",
      noteIndex: 5,
      salt: "119",
      noteId: "0x" + "0".repeat(61) + "aaa",
      packedValue: "0x" + "0".repeat(61) + "bbb",
    }]);
    expect(evidence.emittedNotes).toHaveLength(2);
    expect(evidence.transactionReference).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("rejects a substituted sender, truncated action input and output-note omission", () => {
    const replaced = invocation(["0x124", viewingKey, ...clientActions]);
    expect(() => parse({ invocation: replaced })).toThrow("payroll sender was substituted");

    const truncated = invocation().invocation.calldata.slice(0, -1);
    expect(() => parse({ invocation: { invocation: {
      ...invocation().invocation,
      calldata: truncated,
    } } })).toThrow("trailing or truncated");

    const missingSecondNote = [
      "0x4",
      "0x0", "0x900", "0x1", "0x901",
      "0x9", "0x902",
      "0x8", "0xaaa", "0xbbb",
      "0x1", "0x444", "0x555", "0x666", "0x777",
      "0x1",
    ];
    expect(() => parse({ poolCalldata: missingSecondNote })).toThrow(
      "does not cover every encrypted note",
    );
  });

  it("rejects public server actions, screening data and any external invoke", () => {
    expect(() => parse({ poolCalldata: ["0x1", "0x3", "0x1", "0x2", "0x3", "0x1"] }))
      .toThrow("forbidden public");
    expect(() => parse({ poolCalldata: [...poolCalldata.slice(0, -1), "0x0"] }))
      .toThrow("empty screening");
    expect(() => parse({
      poolCalldata: ["0x1", "0xa", "0x999", "0x1", "0xabc", "0x1"],
    })).toThrow("forbids external pool invocations");
  });
});
