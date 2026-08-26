import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { validatePhase3DisclosureEvidence } from "./phase3-disclosure-evidence.mjs";

const root = resolve(import.meta.dirname, "../..");

async function fixture(name) {
  return JSON.parse(await readFile(resolve(root, "evidence", name), "utf8"));
}

describe("Phase 3 recipient disclosure evidence", () => {
  it("validates every workflow worker plus employer, auditor, and tax packages", async () => {
    const result = await validatePhase3DisclosureEvidence({
      evidence: await fixture("phase3-matrix-disclosure.json"),
      matrixEvidence: await fixture("phase3-private-settlement-devnet.json"),
    }, { root });
    expect(result).toMatchObject({ packageCount: 10, scopes: ["auditor", "employer", "tax"] });
    expect(result.workflows).toHaveLength(7);
  });

  it("rejects missing workflow coverage", async () => {
    const evidence = await fixture("phase3-matrix-disclosure.json");
    evidence.packages = evidence.packages.filter(({ workflow }) => workflow !== "vesting");
    await expect(validatePhase3DisclosureEvidence({
      evidence,
      matrixEvidence: await fixture("phase3-private-settlement-devnet.json"),
    }, { root })).rejects.toThrow(/seven worker|coverage/i);
  });

  it("rejects a package whose encrypted envelope differs from the evidence record", async () => {
    const evidence = await fixture("phase3-matrix-disclosure.json");
    evidence.packages[0].grantId = "phase3-matrix-tampered-grant-v1";
    await expect(validatePhase3DisclosureEvidence({
      evidence,
      matrixEvidence: await fixture("phase3-private-settlement-devnet.json"),
    }, { root })).rejects.toThrow(/does not match evidence/i);
  });
});
