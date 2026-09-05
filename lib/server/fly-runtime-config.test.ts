import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function configuredAudience(source: string): string | undefined {
  return source.match(/^\s*PAYO_AUTH_AUDIENCE\s*=\s*"([^"]+)"\s*$/m)?.[1];
}

function configuredValues(source: string, name: string): string[] {
  const pattern = new RegExp(`^\\s*${name}\\s*=\\s*"([^"]+)"\\s*$`, "gm");
  return Array.from(source.matchAll(pattern), (match) => match[1]);
}

describe("Fly Ready authentication configuration", () => {
  it("uses the same explicit audience in the web and prover runtimes", () => {
    const web = readFileSync("fly.web.toml", "utf8");
    const prover = readFileSync("fly.prover.toml", "utf8");

    const webAudience = configuredAudience(web);
    expect(webAudience).toBe("https://private-payroll.fly.dev");
    expect(configuredAudience(prover)).toBe(webAudience);
    expect(prover).toContain(`PAYO_PROVER_ALLOWED_ORIGINS = "${webAudience}`);
  });

  it("pins the verified Mainnet VestingBook seal at build time and runtime", () => {
    const web = readFileSync("fly.web.toml", "utf8");
    const prover = readFileSync("fly.prover.toml", "utf8");
    const dockerfile = readFileSync("Dockerfile.prover", "utf8");
    const deployment = JSON.parse(readFileSync("evidence/vesting-tax-mainnet.json", "utf8"));
    const sealAddress = deployment.plan.contracts.vestingBookSeal.address as string;

    expect(deployment.activation.profile.matches).toBe(true);
    expect(deployment.verification.passed).toBe(true);
    expect(sealAddress).toBe(
      "0x5208cc07cb4153235ab5c6ecd1936ee77f9be7a2ea09f6cc69518a6362493f",
    );
    for (const source of [web, prover]) {
      expect(configuredValues(source, "NEXT_PUBLIC_PAYO_VESTING_BOOK_SEAL_ADDRESS"))
        .toEqual([sealAddress, sealAddress]);
      expect(configuredValues(source, "PAYO_VESTING_BOOK_SEAL_ADDRESS"))
        .toEqual([sealAddress]);
    }
    expect(dockerfile).toContain("ARG NEXT_PUBLIC_PAYO_VESTING_BOOK_SEAL_ADDRESS");
    expect(dockerfile).toContain(
      "ENV NEXT_PUBLIC_PAYO_VESTING_BOOK_SEAL_ADDRESS=${NEXT_PUBLIC_PAYO_VESTING_BOOK_SEAL_ADDRESS}",
    );
  });
});
