import { spawn } from "node:child_process";
import { once } from "node:events";
import { describe, expect, it } from "vitest";

describe("PAYO MCP stdio entrypoint", () => {
  it("starts from the repository script without a module-format failure", async () => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "packages/mcp/src/server.ts"],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          PAYO_API_URL: "https://private-payroll.fly.dev",
          PAYO_API_ACCESS_TOKEN: "not-a-real-token",
          PAYO_CAPABILITY_ID: "00000000-test",
          PAYO_CAPABILITY_ISSUER_PUBLIC_KEY: "test",
        },
        stdio: ["pipe", "ignore", "pipe"],
      },
    );
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.stdin.end();

    const [exitCode, signal] = await once(child, "close") as [
      number | null,
      NodeJS.Signals | null,
    ];
    expect(signal).toBeNull();
    expect(exitCode).toBe(0);
    expect(stderr).toContain("PAYO MCP server running over stdio.");
  });
});
