import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getPayoPayrollProofDeployments } from "./payo-deployment";

const MANAGED_ENV = [
  "PAYO_CHAIN_ID",
  "PAYO_SEAL_ADDRESS",
  "NEXT_PUBLIC_PAYO_SEAL_ADDRESS",
  "PAYO_AGENT_SEAL_ADDRESS",
  "NEXT_PUBLIC_PAYO_AGENT_SEAL_ADDRESS",
  "PAYO_VESTING_BOOK_SEAL_ADDRESS",
  "NEXT_PUBLIC_PAYO_VESTING_BOOK_SEAL_ADDRESS",
] as const;
const original = Object.fromEntries(MANAGED_ENV.map((name) => [name, process.env[name]]));

beforeEach(() => {
  for (const name of MANAGED_ENV) delete process.env[name];
  process.env.PAYO_CHAIN_ID = "0x534e5f4d41494e";
  process.env.PAYO_SEAL_ADDRESS = "0x101";
  process.env.NEXT_PUBLIC_PAYO_SEAL_ADDRESS = "0x101";
});

afterEach(() => {
  for (const name of MANAGED_ENV) {
    const value = original[name];
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

describe("PAYO proof deployment allowlist", () => {
  it("includes independently attested human, agent, and VestingBook seals", () => {
    process.env.PAYO_AGENT_SEAL_ADDRESS = "0x202";
    process.env.NEXT_PUBLIC_PAYO_AGENT_SEAL_ADDRESS = "0x202";
    process.env.PAYO_VESTING_BOOK_SEAL_ADDRESS = "0x303";
    process.env.NEXT_PUBLIC_PAYO_VESTING_BOOK_SEAL_ADDRESS = "0x303";

    expect(getPayoPayrollProofDeployments().map(({ sealAddress }) => BigInt(sealAddress))).toEqual([
      0x101n,
      0x202n,
      0x303n,
    ]);
  });

  it("deduplicates a seal and fails closed on partial VestingBook configuration", () => {
    process.env.PAYO_VESTING_BOOK_SEAL_ADDRESS = "0x101";
    process.env.NEXT_PUBLIC_PAYO_VESTING_BOOK_SEAL_ADDRESS = "0x101";
    expect(getPayoPayrollProofDeployments()).toHaveLength(1);

    delete process.env.NEXT_PUBLIC_PAYO_VESTING_BOOK_SEAL_ADDRESS;
    expect(() => getPayoPayrollProofDeployments()).toThrow(/configuration is incomplete/);
  });
});
