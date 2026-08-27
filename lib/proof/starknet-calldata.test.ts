import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { mapPayrollPublicInputs } from "./protocol";
import {
  STARKNET_FIELD_PRIME,
  decodeVerificationKeyHex,
  hashProofCalldata,
  normalizeGaragaProofCalldata,
  orderedPayrollPublicInputs,
  parsePayrollPublicInputsFromGaragaCalldata,
  serializePayrollPublicInputs,
} from "./starknet-calldata";

describe("PayrollIntegrity Starknet calldata", () => {
  it("serializes all 17 public inputs as canonical 32-byte big-endian values", () => {
    const values = Array.from({ length: 17 }, (_, index) => `0x${(index + 1).toString(16)}`);
    const mapped = mapPayrollPublicInputs(values);
    expect(orderedPayrollPublicInputs(mapped)).toEqual(values);

    const serialized = serializePayrollPublicInputs(values);
    expect(serialized).toHaveLength(17 * 32);
    expect(serialized.slice(0, 31)).toEqual(new Uint8Array(31));
    expect(serialized[31]).toBe(1);
    expect(serialized[serialized.length - 1]).toBe(17);
  });

  it("rejects malformed verification keys and non-canonical public inputs", () => {
    expect(() => decodeVerificationKeyHex("0xz1")).toThrow("canonical hexadecimal");
    expect(() => serializePayrollPublicInputs(["0x1"])).toThrow("Expected 17");
    expect(() => serializePayrollPublicInputs([
      ...Array.from({ length: 16 }, () => "0"),
      (1n << 256n).toString(),
    ])).toThrow("canonical range");
  });

  it("removes exactly one Garaga Span length and rejects malformed felts", () => {
    expect(normalizeGaragaProofCalldata([2n, 1n, 2n])).toEqual(["0x1", "0x2"]);
    expect(() => normalizeGaragaProofCalldata([1n, 1n, 2n])).toThrow("declared 1");
    expect(() => normalizeGaragaProofCalldata([1n, STARKNET_FIELD_PRIME])).toThrow(
      "canonical range",
    );
  });

  it("matches Cairo poseidon_hash_span for both real Garaga proof fixtures", () => {
    const readProof = (shard: 0 | 1) => readFileSync(
      new URL(
        `../../contracts/integrity_verifier/tests/proof_calldata-shard-${shard}.txt`,
        import.meta.url,
      ),
      "utf8",
    ).trim().split(/\s+/);

    expect(hashProofCalldata(readProof(0))).toBe(
      "0x43e808ebc10232b8b641d1599fa83fa8b525f457767a4f70e697708fecbcbf9",
    );
    expect(hashProofCalldata(readProof(1))).toBe(
      "0x75174b257e0a37e992dbdae96d61d58b3d2feadcb3809e7dee01f9010bff51a",
    );
    const shardZero = parsePayrollPublicInputsFromGaragaCalldata(readProof(0));
    const shardOne = parsePayrollPublicInputsFromGaragaCalldata(readProof(1));
    expect(shardZero).toMatchObject({
      chainId: "1",
      sealAddress: "74565",
      proofVersion: "1",
      schemaVersion: "1",
      validityStart: "1010",
      validityExpiry: "2000",
      shardIndex: "0",
    });
    expect(shardOne).toMatchObject({ ...shardZero, shardIndex: "1" });
  });

  it("extracts and validates the v2 inputs from PAYO's linked advanced envelope", () => {
    const base = readFileSync(
      new URL(
        "../../contracts/integrity_verifier/tests/proof_calldata-shard-0.txt",
        import.meta.url,
      ),
      "utf8",
    ).trim().split(/\s+/);
    const advanced = [...base];
    advanced[5] = "0x2";
    const wrapped = [`0x${base.length.toString(16)}`, ...base, ...advanced];

    expect(parsePayrollPublicInputsFromGaragaCalldata(wrapped)).toMatchObject({
      chainId: "1",
      sealAddress: "74565",
      proofVersion: "2",
      schemaVersion: "1",
      validityStart: "1010",
      validityExpiry: "2000",
      shardIndex: "0",
    });
  });

  it("rejects malformed linked advanced calldata", () => {
    const malformed = ["0xc73", "0x10", ...Array.from({ length: 34 }, () => "0x0")];
    expect(() => parsePayrollPublicInputsFromGaragaCalldata(malformed)).toThrow(
      "invalid composite packing",
    );

    const base = [
      "0x11",
      ...Array.from({ length: 34 }, (_, index) => index === 4 ? "0x1" : "0x0"),
    ];
    const advanced = [...base];
    advanced[5] = "0x2";
    advanced[1] = "0x99";
    expect(() => parsePayrollPublicInputsFromGaragaCalldata([
      `0x${base.length.toString(16)}`,
      ...base,
      ...advanced,
    ])).toThrow("not linked at public input chainId");
  });
});
