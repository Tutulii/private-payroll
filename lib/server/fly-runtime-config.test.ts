import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function configuredAudience(source: string): string | undefined {
  return source.match(/^\s*PAYO_AUTH_AUDIENCE\s*=\s*"([^"]+)"\s*$/m)?.[1];
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
});
