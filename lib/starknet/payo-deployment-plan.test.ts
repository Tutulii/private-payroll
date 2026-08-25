import { describe, expect, it } from "vitest";
import type { PayoBrowserDeploymentPackage } from "./payo-deployment-plan";
import { buildPayoMainnetTopologyPlan } from "./payo-deployment-plan";

const artifact = (classHash: string, compiledClassHash = "0x1") => ({
  contract: {} as PayoBrowserDeploymentPackage["artifacts"]["payrollSeal"]["contract"],
  casm: {} as PayoBrowserDeploymentPackage["artifacts"]["payrollSeal"]["casm"],
  classHash,
  compiledClassHash,
  sierraSha256: "11".repeat(32),
  casmSha256: "22".repeat(32),
});

const artifacts = {
  generatedVerifier: artifact("0x601776a0980ab1b8e3d629d456dccc5eace85ba6f47a015d2e3c3448a758bb9"),
  bundleVerifier: artifact("0x451e59b2f2e454a5a53914ca317069d84faf504498e1d56609a78fb626da2bc"),
  policyRegistry: artifact("0x7327c47bcc044b6147fbd1360478d167079e30cb5604895a7f5fd62b227d135"),
  obligationRegistry: artifact("0x8e10e268903e759d275a7d84ab0f7c5b4ce5d188c327d527377250915e3378"),
  payrollSeal: artifact("0x4c1dc6a699f310964bad2380adf2b0f9bdcb14825a0f19fb20fd4c13458fc40"),
} satisfies PayoBrowserDeploymentPackage["artifacts"];

describe("PAYO Mainnet topology plan", () => {
  it("reproduces the reviewed deterministic addresses and canonical pool binding", () => {
    const plan = buildPayoMainnetTopologyPlan({
      adminAddress: "0x038c1d4E372a3cdF605A0C06D944b046c7f4d7923922001f9366b5d000Aa3871",
      artifacts,
    });
    expect(plan.contracts.generatedVerifier.address).toBe(
      "0x475cc47caf5d8b5b3a719915ceef5ae3e959f8754f2c0faa634d2e8c73d06db",
    );
    expect(plan.contracts.bundleVerifier.address).toBe(
      "0x2755c2260220f44c319249402887ca50c8b968ab43364e90de54f5afd66759",
    );
    expect(plan.contracts.policyRegistry.address).toBe(
      "0x43a1434aba81aacec7e5bdc70ac781fdfe0111cb2b8d2b8e920ec029dac1c5f",
    );
    expect(plan.contracts.obligationRegistry.address).toBe(
      "0x453bb12e0220afa8959216306d844d97d06b1f850171388b92c671110956999",
    );
    expect(plan.contracts.payrollSeal.address).toBe(
      "0x5180b634fab279c2146572676d879e664c265825ba496e60535896f770a3359",
    );
    expect(plan.contracts.payrollSeal.constructorCalldata).toEqual([
      "0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a",
      plan.contracts.policyRegistry.address,
      plan.contracts.obligationRegistry.address,
      "0x534e5f4d41494e",
    ]);
  });

  it("fails closed on a zero administrator or malformed class hash", () => {
    expect(() => buildPayoMainnetTopologyPlan({ adminAddress: "0x0", artifacts })).toThrow(
      /non-zero/,
    );
    expect(() => buildPayoMainnetTopologyPlan({
      adminAddress: "0x123",
      artifacts: { ...artifacts, payrollSeal: artifact("not-a-hash") },
    })).toThrow(/class hash is invalid/);
  });
});
