import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { createPayoPublicIdentity } from "@/lib/client/proof-package-files";
import { generateVaultPrincipal } from "@/lib/crypto/vault";

const RUN_ID = "018f2000-0000-7000-8000-000000000001";
const APPROVAL_EXECUTION_ID = "018f2000-0000-7000-8000-000000000002";
const AUTONOMOUS_EXECUTION_ID = "018f2000-0000-7000-8000-000000000003";

type ExportedState = ReturnType<NonNullable<Window["__PAYO_BROWSER_EVIDENCE__"]>["exportState"]>;

async function exportedState(page: Page): Promise<ExportedState> {
  return page.evaluate(() => {
    if (!window.__PAYO_BROWSER_EVIDENCE__) throw new Error("Browser evidence is unavailable.");
    return window.__PAYO_BROWSER_EVIDENCE__.exportState();
  });
}

async function addAgent(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Add contributor", exact: true }).click();
  const form = page.locator("form.team-add-form");
  await form.getByLabel("Display name").fill("Payroll Scout");
  await form.getByLabel("Kind").selectOption("agent");
  await form.getByLabel("Registered Starknet address").fill("0x599");
  await form.getByLabel("Private token").selectOption("STRK");
  await form.getByLabel("Jurisdiction").fill("US");
  const identity = createPayoPublicIdentity(generateVaultPrincipal("phase4-browser-agent"));
  await form.locator("input.proof-package-file-input").setInputFiles({
    name: "payo-agent-identity.json",
    mimeType: "application/json",
    buffer: Buffer.from(`${JSON.stringify(identity)}\n`),
  });
  await expect(form.getByText(/Claim identity verified/)).toBeVisible();
  await form.getByRole("button", { name: "Encrypt contributor" }).click();

  const card = page.locator(".member-card").filter({ hasText: "Payroll Scout" });
  await card.getByRole("button", { name: "Add encrypted agreement" }).click();
  const agreement = page.locator("form.team-add-form");
  await agreement.getByLabel("Payment plan").selectOption({ label: "Recurring payroll" });
  await agreement.getByLabel("Private amount").fill("1");
  await agreement.getByRole("button", { name: "Encrypt proof-bound agreement" }).click();
  await expect(card.getByRole("button", { name: "Update encrypted agreement" })).toBeVisible();
}

function activeCapability(state: ExportedState) {
  const records = state.records.filter(({ recordType }) => recordType === "agent-capability");
  const record = records.find(({ plaintext }) => !(plaintext as { revokedAt?: string }).revokedAt);
  if (!record) throw new Error("An active browser capability was not stored.");
  return record.plaintext as {
    id: string;
    signedCapability: { capability: { executionMode: string } };
  };
}

test("Phase 4 renders approval, bounded autonomy, limits and redacted agent evidence", async ({ page }, testInfo) => {
  await page.goto("/payo-browser-evidence/team");
  await expect(page.getByRole("heading", { name: /People and agents/ })).toBeVisible();
  await page.evaluate(() => window.__PAYO_BROWSER_EVIDENCE__?.reset());
  await page.reload();
  await addAgent(page);

  const card = page.locator(".member-card").filter({ hasText: "Payroll Scout" });
  await card.getByRole("button", { name: "Issue approval capability" }).click();
  let state = await exportedState(page);
  const approvalCapability = activeCapability(state);
  expect(approvalCapability.signedCapability.capability.executionMode).toBe("request_approval");

  const now = new Date().toISOString();
  await page.evaluate(({ capabilityId, now }) => {
    window.__PAYO_BROWSER_EVIDENCE__?.setAgentExecutions([{
      executionId: "018f2000-0000-7000-8000-000000000002",
      capabilityId,
      runId: "018f2000-0000-7000-8000-000000000001",
      settlementId: null,
      state: "approval_pending",
      requiresApproval: true,
      requestCommitment: `0x${"91".repeat(32)}`,
      transactionHash: null,
      errorCode: null,
      replayed: false,
      createdAt: now,
      updatedAt: now,
    }]);
  }, { capabilityId: approvalCapability.id, now });
  await page.reload();

  const approvalRow = page.locator(".agent-approval-row").filter({ hasText: "APPROVAL PENDING" });
  await expect(approvalRow).toContainText(RUN_ID.slice(0, 8));
  await expect(approvalRow.getByRole("link", { name: "Review in Payroll" })).toHaveAttribute(
    "href",
    new RegExp(APPROVAL_EXECUTION_ID),
  );
  const approvalPolicy = page.locator(".agent-capability-row").filter({ hasText: "READY APPROVAL" });
  await expect(approvalPolicy).toContainText("1 STRK");
  await expect(approvalPolicy).toContainText("max 100 calls");
  await approvalPolicy.getByRole("button", { name: "Issue MCP key" }).click();
  await expect(page.getByRole("button", { name: "Copy scoped MCP configuration" })).toBeEnabled();
  await approvalPolicy.getByRole("button", { name: "Revoke MCP keys" }).click();
  await approvalPolicy.getByRole("button", { name: "Revoke capability" }).click();

  await card.getByRole("button", { name: "Issue one-run autonomy" }).click();
  state = await exportedState(page);
  const autonomousCapability = activeCapability(state);
  expect(autonomousCapability.signedCapability.capability.executionMode).toBe("autonomous_bounded");
  const later = new Date(Date.now() + 1_000).toISOString();
  await page.evaluate(({ capabilityId, later }) => {
    window.__PAYO_BROWSER_EVIDENCE__?.setAgentExecutions([{
      executionId: "018f2000-0000-7000-8000-000000000003",
      capabilityId,
      runId: "018f2000-0000-7000-8000-000000000001",
      settlementId: "018f2000-0000-7000-8000-000000000005",
      state: "reconciled",
      requiresApproval: false,
      requestCommitment: `0x${"91".repeat(32)}`,
      transactionHash: "0xabc",
      errorCode: null,
      replayed: false,
      createdAt: later,
      updatedAt: later,
    }]);
    window.__PAYO_BROWSER_EVIDENCE__?.setDirectPrivacyAccounts([{
      id: "018f2000-0000-7000-8000-000000000004",
      capabilityId,
      stateVersion: 4,
      authorizedRunCount: 1,
      activationState: "active",
      activeExecutionId: null,
      activeLeaseExpiresAt: null,
      createdAt: later,
      updatedAt: later,
      config: {
        policyAccountAddress: "0x456",
        policyId: "0x789",
        validBeforeUnix: "2000000000",
        maxCallsPerPeriod: 1,
        maxCallCount: 1,
      },
    }]);
    window.__PAYO_BROWSER_EVIDENCE__?.setAuditEvents([{
      id: "018f2000-0000-7000-8000-000000000006",
      actorId: "agent:payroll-scout",
      action: "direct_privacy_reconciled",
      subjectId: "018f2000-0000-7000-8000-000000000003",
      metadata: {
        transactionHash: "0xabc",
        recipientAddress: "0xprivate-recipient-must-not-render",
        amountAtomic: "1000000000000000000",
      },
      createdAt: later,
    }]);
  }, { capabilityId: autonomousCapability.id, later });
  await page.reload();

  const autonomousPolicy = page.locator(".agent-capability-row").filter({ hasText: "AUTONOMY ACTIVE" });
  await expect(autonomousPolicy).toContainText("1 STRK");
  await expect(autonomousPolicy).toContainText("max 1 calls");
  await expect(autonomousPolicy).toContainText("1 exact runs");
  await expect(page.locator(".agent-approval-row").filter({ hasText: "RECONCILED" }))
    .toContainText(AUTONOMOUS_EXECUTION_ID.slice(0, 8));

  await page.goto("/payo-browser-evidence/activity");
  await expect(page.getByText("Agent policy events").locator("..")).toContainText("1");
  await page.getByRole("tab", { name: "Agent" }).click();
  const audit = page.locator(".timeline-event").filter({ hasText: "Direct privacy reconciled" });
  await expect(audit).toContainText("Policy-scoped");
  await expect(audit).toContainText(AUTONOMOUS_EXECUTION_ID.slice(0, 8));
  await expect(page.locator("body")).not.toContainText("0xprivate-recipient-must-not-render");
  await expect(page.locator("body")).not.toContainText("1000000000000000000");

  const finalState = await exportedState(page);
  const capabilityModes = finalState.records
    .filter(({ recordType }) => recordType === "agent-capability")
    .map(({ plaintext }) => (plaintext as {
      signedCapability: { capability: { executionMode: string } };
    }).signedCapability.capability.executionMode);
  const artifact = {
    schemaVersion: "payo.phase4.rendered-browser-origin.v2",
    generatedAt: new Date().toISOString(),
    routeGuard: "PAYO_BROWSER_EVIDENCE_MODE=1",
    renderedProductionPages: ["app/team/page.tsx", "app/activity/page.tsx"],
    checks: {
      readyApprovalIsDefault: true,
      humanApprovalReviewRendered: true,
      boundedAutonomyRendered: true,
      exactOneRunLimitRendered: true,
      activeDirectAccountRendered: true,
      oneTimeMcpCredentialIssuedAndRevoked: true,
      agentAuditRendered: true,
      privateAuditMetadataRedacted: true,
    },
    evidenceSummary: {
      encryptedRecordTypes: finalState.records.map(({ recordType }) => recordType).sort(),
      capabilityModes: [...new Set(capabilityModes)].sort(),
      executionStates: finalState.agentExecutions.map(({ state }) => state).sort(),
      directAccounts: finalState.directPrivacyAccounts.map((account) => ({
        activationState: account.activationState,
        authorizedRunCount: account.authorizedRunCount,
        maxCallCount: account.config.maxCallCount,
        maxCallsPerPeriod: account.config.maxCallsPerPeriod,
      })),
      auditActions: finalState.auditEvents.map(({ action }) => action).sort(),
    },
  };
  const outputPath = testInfo.outputPath("phase4-rendered-browser-origin.json");
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600 });
  await testInfo.attach("phase4-rendered-browser-origin", {
    path: outputPath,
    contentType: "application/json",
  });
  if (process.env.PAYO_BROWSER_EVIDENCE_WRITE === "1") {
    const committedPath = resolve("evidence/phase4-rendered-browser-ui-origin.json");
    await mkdir(dirname(committedPath), { recursive: true });
    await writeFile(committedPath, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600 });
  }
});
