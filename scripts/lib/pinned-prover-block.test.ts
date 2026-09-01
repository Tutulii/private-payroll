import { describe, expect, it } from "vitest";
import {
  STARKNET_PROOF_MATURITY_BLOCKS,
  proofMaturityBlock,
  pinnedProverBlockHash,
} from "./pinned-prover-block";

describe("proofMaturityBlock", () => {
  it("adds a submission margin after Starknet's ten-block stored-hash buffer", () => {
    expect(STARKNET_PROOF_MATURITY_BLOCKS).toBe(12);
    expect(proofMaturityBlock(["0x1", "0x2", "0x3", "0x4", "0x64", "0xabc"])).toBe(112);
  });

  it("rejects incomplete proof facts", () => {
    expect(() => proofMaturityBlock([])).toThrow(/incomplete proof facts/);
  });

  it("rejects an invalid proof block number", () => {
    expect(() => proofMaturityBlock(["0", "0", "0", "0", "bad", "0xabc"]))
      .toThrow(/invalid proof block number/);
  });
});

describe("pinnedProverBlockHash", () => {
  it("wraps a canonical discovery hash in the Starknet RPC block-id variant", () => {
    expect(pinnedProverBlockHash("0x00AbC")).toEqual({ block_hash: "0xabc" });
  });

  it.each([
    "latest",
    "123",
    "0x",
    "0xnot-a-felt",
    null,
  ])("rejects malformed discovery hash %j", (value) => {
    expect(() => pinnedProverBlockHash(value)).toThrow(/malformed Starknet block hash/);
  });

  it.each([
    "0x0",
    `0x${(1n << 252n).toString(16)}`,
  ])("rejects out-of-range discovery hash %s", (value) => {
    expect(() => pinnedProverBlockHash(value)).toThrow(/out-of-range Starknet block hash/);
  });
});
