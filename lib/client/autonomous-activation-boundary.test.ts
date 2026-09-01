import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("autonomous Mainnet activation boundary", () => {
  it("keeps proof preparation read-only until a separate reviewed activation", () => {
    const executionSource = readFileSync(
      new URL("./payroll-execution.ts", import.meta.url),
      "utf8",
    );
    const pageSource = readFileSync(
      new URL("../../app/payroll/page.tsx", import.meta.url),
      "utf8",
    );
    const teamSource = readFileSync(
      new URL("../../app/team/page.tsx", import.meta.url),
      "utf8",
    );
    expect(executionSource).not.toContain("activateDirectPrivacyAccount(");
    expect(pageSource).toContain("estimateDirectPrivacyAccountActivation");
    expect(pageSource).toContain("Approve & activate");
    expect(pageSource.indexOf("loadAutonomousActivationReview"))
      .toBeLessThan(pageSource.indexOf("activateAutonomousPolicy"));
    expect(teamSource).toContain("Review activation");
    expect(teamSource).toContain("estimateDirectPrivacyAccountActivation");
    expect(teamSource.indexOf("reviewDirectAccountActivation"))
      .toBeLessThan(teamSource.indexOf("activateDirectAccount"));
  });

  it("exposes fee review as GET and mutation as POST on one authenticated route", () => {
    const routeSource = readFileSync(
      new URL("../../app/api/v1/direct-privacy-accounts/[id]/activation/route.ts", import.meta.url),
      "utf8",
    );
    expect(routeSource).toContain("export async function GET");
    expect(routeSource).toContain("estimateDirectPrivacyAccountActivation");
    expect(routeSource).toContain("export async function POST");
    expect(routeSource).toContain("configureAndActivateDirectPrivacyAccount");
  });
});
