import { expect, test } from "playwright/test";
import { encryptVaultRecord, type VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import type { PendingPayrollSubmission } from "@/lib/client/payroll-execution";

const organizationId = "018f1000-0000-7000-8000-000000000030";
const runId = "018f1000-0000-7000-8000-000000000041";
const proofBundleId = "018f1000-0000-7000-8000-000000000042";
const settlementId = "018f1000-0000-7000-8000-000000000043";
const walletRequestId = "018f1000-0000-7000-8000-000000000044";
const principal: VaultPrincipalKeyPair = {
  principalId: "phase3-browser-evidence",
  publicKey: "KsD1+YKrizU8vEyTJQ2MrSbRreOHGeXtvoaLYUXVoF8=",
  secretKey: "pT60QxIT6W8XlFM5ejV1bLRKfjGqc4vEXQuJFgpiEQU=",
};

const pending: PendingPayrollSubmission = {
  version: 5,
  authorizationMode: "vesting_book_v3",
  organizationId,
  runId,
  proofBundleId,
  settlementId,
  walletRequestId,
  idempotencyKey: `browser-recovery:${settlementId}`,
  tokenTotalsCommitment: `0x${"42".repeat(32)}`,
  settlementEnvelope: encryptVaultRecord(
    { workflowType: "payroll", runId },
    { schemaVersion: 1, organizationId, recordType: "settlement", recordId: settlementId, revision: 1 },
    [principal],
  ),
  proofShards: [["0x1"], ["0x2"]],
  createdAt: "2026-09-07T12:00:00.000Z",
};

for (const viewport of [
  { name: "desktop", width: 1280, height: 900 },
  { name: "phone", width: 390, height: 844 },
]) {
  test(`payroll recovery stays readable on ${viewport.name}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto("/payo-browser-evidence/payroll");
    await page.evaluate(({ organizationId, pending }) => {
      window.__PAYO_BROWSER_EVIDENCE__?.reset();
      localStorage.setItem(
        `payo:pending-settlement:v1:${organizationId}`,
        JSON.stringify(pending),
      );
    }, { organizationId, pending });
    await page.reload();

    const recovery = page.locator(".runner-recovery").filter({ hasText: "Payment confirmation needs attention" });
    await expect(recovery).toBeVisible();
    await expect(recovery).toContainText("checking Mainnet automatically");
    await recovery.getByRole("button", { name: "I see a submitted transaction" }).click();
    await expect(recovery.getByLabel("Ready payroll transaction hash")).toBeVisible();
    await expect(recovery.getByRole("button", { name: "Record submitted hash" })).toBeVisible();
    await expect(recovery.getByRole("button", { name: "No transaction · cancel" })).toBeVisible();

    const geometry = await recovery.evaluate((element) => {
      const box = element.getBoundingClientRect();
      const descendants = [...element.querySelectorAll("button, input")].map((child) => {
        const childBox = child.getBoundingClientRect();
        return {
          left: childBox.left,
          right: childBox.right,
          width: childBox.width,
          scrollWidth: child.scrollWidth,
          clientWidth: child.clientWidth,
        };
      });
      return {
        panel: { left: box.left, right: box.right, scrollWidth: element.scrollWidth, clientWidth: element.clientWidth },
        descendants,
      };
    });
    expect(geometry.panel.scrollWidth).toBeLessThanOrEqual(geometry.panel.clientWidth + 1);
    for (const control of geometry.descendants) {
      expect(control.left).toBeGreaterThanOrEqual(geometry.panel.left - 1);
      expect(control.right).toBeLessThanOrEqual(geometry.panel.right + 1);
      expect(control.scrollWidth).toBeLessThanOrEqual(control.clientWidth + 1);
      expect(control.width).toBeGreaterThan(80);
    }

    await page.screenshot({
      path: testInfo.outputPath(`payroll-recovery-${viewport.name}.png`),
      fullPage: true,
    });
  });
}
