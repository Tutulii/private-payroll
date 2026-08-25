import { describe, expect, it } from "vitest";
import { parseProverThreadCount } from "./prover-runtime";

describe("self-hosted prover runtime", () => {
  it("uses one thread unless an explicit bounded value is configured", () => {
    expect(parseProverThreadCount(undefined)).toBe(1);
    expect(parseProverThreadCount("2")).toBe(2);
    expect(parseProverThreadCount("4")).toBe(4);
  });

  it("rejects unsafe or ambiguous thread counts", () => {
    for (const value of ["0", "5", "1.5", "two"]) {
      expect(() => parseProverThreadCount(value)).toThrow("integer from 1 to 4");
    }
  });
});
