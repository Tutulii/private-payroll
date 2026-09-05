import { describe, expect, it } from "vitest";
import { vestingTransitionPublicInputsSchema } from "@/lib/domain/proof-bundle";
import { mapVestingTransitionPublicInputs } from "./vesting-transition-input";
import { remoteVestingTransitionPublicInputsSchema } from "./remote-prover";

describe("Vesting transition public-input serialization", () => {
  it("canonicalizes fixed-width bb.js fields before remote response validation", () => {
    const fields = Array.from({ length: 58 }, (_, index) =>
      `0x${BigInt(index + 1).toString(16).padStart(64, "0")}`);
    fields[2] = `0x${"0".repeat(63)}3`;
    fields[3] = `0x${"0".repeat(63)}1`;
    fields[4] = `0x${"0".repeat(64)}`;
    fields[28] = `0x${"0".repeat(64)}`;
    fields[57] = `0x${"0".repeat(64)}`;

    const publicInputs = mapVestingTransitionPublicInputs(fields);

    expect(publicInputs.chainId).toBe("0x1");
    expect(publicInputs.sealAddress).toBe("0x2");
    expect(publicInputs.agreementRootHigh).toBe("6");
    expect(publicInputs.ownerAddress).toBe("22");
    expect(publicInputs.shardIndex).toBe("0");
    expect(() => vestingTransitionPublicInputsSchema.parse(publicInputs)).not.toThrow();

    const rollingResponse = remoteVestingTransitionPublicInputsSchema.parse(
      Object.fromEntries(Object.entries(publicInputs).map(([key], index) => [key, fields[index]])),
    );
    expect(rollingResponse).toEqual(publicInputs);
  });

  it("keeps already canonical decimal values stable", () => {
    const fields = Array.from({ length: 58 }, (_, index) => String(index + 1));
    fields[2] = "3"; fields[3] = "1"; fields[4] = "0"; fields[28] = "1"; fields[57] = "1";
    expect(mapVestingTransitionPublicInputs(fields).shardIndex).toBe("1");
  });
});
