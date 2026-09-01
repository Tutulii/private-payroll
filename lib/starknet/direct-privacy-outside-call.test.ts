import { describe, expect, it } from "vitest";
import { OutsideExecutionVersion, hash, outsideExecution, type Call } from "starknet";
import { directPrivacyPreparationSchema } from "@/lib/domain/direct-privacy";
import { assertDirectPrivacyOutsideCall } from "./direct-privacy-outside-call";

const policyCall: Call = {
  contractAddress: "0x789",
  entrypoint: "execute_policy_intent",
  calldata: ["0x1", "0x2", "0x3"],
};

function outsideCall(): Call {
  return outsideExecution.buildExecuteFromOutsideCall({
    outsideExecution: {
      caller: "0x123",
      nonce: "0x456",
      execute_after: 500,
      execute_before: 600,
      calls: [{
        to: policyCall.contractAddress,
        selector: hash.getSelectorFromName(policyCall.entrypoint),
        calldata: policyCall.calldata!,
      }],
    },
    signature: ["0xabc", "0xdef"],
    signerAddress: policyCall.contractAddress,
    version: OutsideExecutionVersion.V2,
  })[0];
}

function calldata(call: Call): string[] {
  if (!Array.isArray(call.calldata)) throw new Error("Test call calldata is not flattened.");
  return call.calldata as string[];
}

function verify(call: Call, currentBlockTimestamp = 550): void {
  assertDirectPrivacyOutsideCall({
    outsideCall: call,
    policyCall,
    relayerAddress: "0x123",
    proofValidAfterUnix: "499",
    proofValidBeforeUnix: "601",
    currentBlockTimestamp,
  });
}

describe("direct private SNIP-9 authorization binding", () => {
  it("accepts the exact Starknet.js V2 wire call and decimal calldata", () => {
    const call = outsideCall();
    expect(calldata(call).every((value) => /^\d+$/.test(value))).toBe(true);
    expect(() => verify(call)).not.toThrow();
  });

  it.each([
    ["caller", 0, "0x124", /caller.*substituted/i],
    ["window", 3, "0x999", /time window/i],
    ["call count", 4, "0x2", /exactly one call/i],
    ["target", 5, "0x788", /policy account.*substituted/i],
    ["selector", 6, "0x1", /selector.*substituted/i],
    ["calldata length", 7, "0x2", /calldata length.*substituted/i],
    ["calldata", 8, "0x9", /calldata 0.*substituted/i],
    ["signature length", 11, "0x1", /exactly two/i],
  ])("rejects substituted %s", (_label, index, value, message) => {
    const call = outsideCall();
    calldata(call)[index as number] = value as string;
    expect(() => verify(call)).toThrow(message as RegExp);
  });

  it("rejects an expired, future, trailing, or wrong outer authorization", () => {
    expect(() => verify(outsideCall(), 600)).toThrow(/not valid at the current/i);
    expect(() => verify(outsideCall(), 500)).toThrow(/not valid at the current/i);
    const trailing = outsideCall();
    calldata(trailing).push("0x1");
    expect(() => verify(trailing)).toThrow(/trailing/i);
    const wrongOuter = { ...outsideCall(), contractAddress: "0x788" };
    expect(() => verify(wrongOuter)).toThrow(/policy account.*substituted/i);
  });

  it("normalizes decimal Starknet.js calldata before encrypted persistence", () => {
    const call = outsideCall();
    const parsed = directPrivacyPreparationSchema.shape.outsideCall.parse(call);
    expect(parsed.calldata.every((value) => /^0x[0-9a-f]+$/.test(value))).toBe(true);
    expect(parsed.calldata.map(BigInt)).toEqual(calldata(call).map((value) => BigInt(value)));
  });
});
