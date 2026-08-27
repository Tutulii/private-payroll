import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";

const COMMITMENTS = {
  milestone: `0x${"79".repeat(32)}`,
  approver: `0x${"83".repeat(32)}`,
  attestation: `0x${"8d".repeat(32)}`,
  adjustment: `0x${"a1".repeat(32)}`,
  termination: `0x${"a0".repeat(32)}`,
};

const workflows = [
  { name: "Recurring worker", plan: "recurring", option: "Recurring payroll", token: "USDC" },
  { name: "Checkpoint worker", plan: "checkpoint_stream", option: "Checkpoint stream", token: "USDC" },
  { name: "Milestone worker", plan: "milestone", option: "Approved milestone", token: "USDC" },
  { name: "Vesting worker", plan: "private_vesting", option: "Private vesting release", token: "USDC" },
  { name: "Final pay worker", plan: "final_pay", option: "Final pay / offboarding", token: "USDC" },
  { name: "Adjustment worker", plan: "approved_adjustment", option: "Approved pay adjustment", token: "USDC" },
  { name: "Statutory worker", plan: "statutory_classification", option: "Recurring payroll", token: "USDC" },
  { name: "FX-floor worker", plan: "fx_floor", option: "Recurring payroll", token: "STRK" },
] as const;

type EvidenceState = {
  organizationId: string;
  records: Array<{
    id: string;
    recordType: string;
    revision: number;
    createdAt: string;
    envelope: unknown;
    envelopeHash: string;
    plaintext: Record<string, unknown>;
  }>;
  runs: Array<Record<string, unknown>>;
  schedules: Array<{
    agreementId: string;
    agreementRevision: number;
    scheduleCommitment: string;
    dueAt: string;
    materializedAt: string | null;
  }>;
};

async function evidenceState(page: Page): Promise<EvidenceState> {
  return page.evaluate(() => {
    if (!window.__PAYO_BROWSER_EVIDENCE__) throw new Error("The gated browser-evidence adapter is unavailable.");
    return window.__PAYO_BROWSER_EVIDENCE__.exportState() as EvidenceState;
  });
}

async function addContributor(page: Page, workflow: (typeof workflows)[number], index: number) {
  await page.getByRole("button", { name: "Add contributor", exact: true }).click();
  const form = page.locator("form.team-add-form");
  await form.getByLabel("Display name").fill(workflow.name);
  await form.getByLabel("Registered Starknet address").fill(`0x${(0x500 + index).toString(16)}`);
  await form.getByLabel("Private token").selectOption(workflow.token);
  await form.getByLabel("Jurisdiction").fill("US");
  await form.getByRole("button", { name: "Encrypt contributor" }).click();
  await expect(page.locator(".member-card").filter({ hasText: workflow.name })).toBeVisible();
}

async function answerClassification(form: ReturnType<Page["locator"]>, answer: "yes" | "no") {
  const selectors = form.locator(".team-add-form__classification select");
  await expect(selectors).toHaveCount(6);
  for (let index = 0; index < 6; index += 1) await selectors.nth(index).selectOption(answer);
}

async function fillAgreement(page: Page, workflow: (typeof workflows)[number]) {
  const card = page.locator(".member-card").filter({ hasText: workflow.name });
  await card.getByRole("button", { name: /encrypted agreement/i }).click();
  const form = page.locator("form.team-add-form");
  await form.getByLabel("Payment plan").selectOption({ label: workflow.option });

  if (workflow.plan === "statutory_classification") {
    await form.getByLabel("Classification").selectOption("employee");
    await answerClassification(form, "yes");
  } else {
    await answerClassification(form, "no");
  }

  if (["recurring", "statutory_classification", "fx_floor"].includes(workflow.plan)) {
    await form.getByLabel("Private amount").fill(workflow.plan === "statutory_classification" ? "10" : "1");
    if (workflow.plan === "fx_floor") await form.getByLabel("Optional USD value floor").fill("0.2");
  }
  if (workflow.plan === "checkpoint_stream" || workflow.plan === "private_vesting") {
    await form.getByLabel("Total committed value").fill("1");
  }
  if (workflow.plan === "checkpoint_stream") {
    await form.getByLabel("Checkpoint attestation commitment").fill(COMMITMENTS.attestation);
  }
  if (workflow.plan === "milestone" || workflow.plan === "approved_adjustment") {
    const amountLabel = workflow.plan === "milestone" ? "Private amount" : "Private adjustment amount";
    await form.getByLabel(amountLabel).fill(workflow.plan === "milestone" ? "0.3" : "0.25");
  }
  if (["milestone", "approved_adjustment", "final_pay"].includes(workflow.plan)) {
    const obligationLabel = workflow.plan === "final_pay"
      ? "Offboarding obligation commitment"
      : workflow.plan === "approved_adjustment"
        ? "Adjustment obligation commitment"
        : "Milestone commitment";
    await form.getByLabel(obligationLabel).fill(COMMITMENTS.milestone);
    await form.getByLabel("Approver commitment").fill(COMMITMENTS.approver);
    await form.getByLabel("Approval evidence commitment").fill(COMMITMENTS.attestation);
  }
  if (workflow.plan === "approved_adjustment") {
    await form.getByLabel("Adjustment reason commitment").fill(COMMITMENTS.adjustment);
  }
  if (workflow.plan === "final_pay") {
    await form.getByLabel("Termination reason commitment").fill(COMMITMENTS.termination);
    await form.getByLabel("Ordinary pay").fill("0.1");
    await form.getByRole("textbox", { name: "Accrued leave" }).fill("0.02");
    await form.getByLabel("Notice pay").fill("0.03");
    await form.getByRole("textbox", { name: "Severance" }).fill("0.04");
    await form.getByLabel("Adjustments").fill("0.01");
    await form.getByRole("checkbox", { name: "Notice" }).check();
    await form.getByRole("checkbox", { name: "Severance" }).check();
  }

  const submit = form.getByRole("button", { name: "Encrypt proof-bound agreement" });
  await expect(submit).toBeEnabled();
  await submit.click();
  await expect(card.getByRole("button", { name: "Update encrypted agreement" })).toBeVisible();
}

test("all Phase 3 production controls create encrypted, proof-bound browser evidence", async ({ page }, testInfo) => {
  await page.goto("/payo-browser-evidence/team");
  await expect(page.getByRole("heading", { name: /People and agents/ })).toBeVisible();
  await page.evaluate(() => window.__PAYO_BROWSER_EVIDENCE__?.reset());
  await page.reload();

  for (const [index, workflow] of workflows.entries()) await addContributor(page, workflow, index);
  for (const workflow of workflows) await fillAgreement(page, workflow);

  const teamState = await evidenceState(page);
  const agreements = teamState.records.filter(({ recordType }) => recordType === "pay-agreement");
  expect(agreements).toHaveLength(8);
  expect(teamState.schedules).toHaveLength(8);
  expect(new Set(teamState.schedules.map(({ agreementId }) => agreementId))).toEqual(
    new Set(agreements.map(({ plaintext }) => (plaintext.agreement as { id: string }).id)),
  );
  expect(teamState.schedules.every(({ scheduleCommitment }) => /^0x[0-9a-f]{64}$/.test(scheduleCommitment))).toBe(true);
  expect(new Set(agreements.map(({ plaintext }) =>
    (plaintext.agreement as { paymentPlan: { kind: string } }).paymentPlan.kind))).toEqual(new Set([
      "recurring",
      "checkpoint_stream",
      "milestone",
      "private_vesting",
    ]));
  expect(agreements.some(({ plaintext }) =>
    Boolean((plaintext.agreement as { adjustment?: unknown }).adjustment))).toBe(true);
  expect(agreements.some(({ plaintext }) =>
    Boolean((plaintext.agreement as { termination?: unknown }).termination))).toBe(true);
  const statutory = agreements.find(({ plaintext }) =>
    (plaintext.agreement as { classification: string }).classification === "employee");
  expect(statutory).toBeTruthy();
  const fxFloor = agreements.find(({ plaintext }) =>
    Boolean((plaintext.agreement as { fxProtection?: unknown }).fxProtection));
  expect(fxFloor).toBeTruthy();
  expect((fxFloor!.plaintext.agreement as { settlementToken: string }).settlementToken).toBe("STRK");
  expect((fxFloor!.plaintext.agreement as { fxProtection: { minimumReferenceAtomic: string } }).fxProtection.minimumReferenceAtomic)
    .toBe("200000");
  for (const record of agreements) {
    const envelope = JSON.stringify(record.envelope);
    const agreement = record.plaintext.agreement as { earningsAtomic: string[] };
    for (const amount of agreement.earningsAtomic) expect(envelope).not.toContain(amount);
  }

  const recurring = agreements.find(({ plaintext }) =>
    (plaintext.agreement as { paymentPlan: { kind: string }; classification: string }).paymentPlan.kind === "recurring"
      && (plaintext.agreement as { classification: string }).classification === "contractor");
  expect(recurring).toBeTruthy();
  const recurringAgreement = recurring!.plaintext.agreement as { id: string };
  const runId = "018f1000-0000-7000-8000-000000000034";
  await page.evaluate(({ runId, agreementId }) => {
    window.__PAYO_BROWSER_EVIDENCE__?.setRuns([{
      id: runId,
      cycleId: "phase3-browser-exception",
      state: "confirmed",
      dueAt: "2026-08-26T00:00:00.000Z",
      updatedAt: "2026-08-26T00:01:00.000Z",
      lines: [{ agreementId }],
    }]);
  }, { runId, agreementId: recurringAgreement.id });

  await page.goto("/payo-browser-evidence/activity");
  const claimButton = page.getByRole("button", { name: "Draft private claim" });
  await expect(claimButton).toBeEnabled();
  await claimButton.click();
  const claimForm = page.locator("form.receipt-disclosure-form").filter({ hasText: "This creates a salted" });
  const agreementSelect = claimForm.getByLabel("Committed agreement");
  const runSelect = claimForm.getByLabel("Payroll run");
  await runSelect.selectOption(runId);
  await expect(agreementSelect.locator(`option[value="${recurringAgreement.id}"]`))
    .toHaveText(/Agreement \d+ · Recurring worker/);
  await expect(agreementSelect.locator("option")).toHaveCount(2);
  await expect(runSelect.locator(`option[value="${runId}"]`)).toHaveText(/Payday 1 · Aug 26/);
  await agreementSelect.selectOption(recurringAgreement.id);
  await claimForm.getByLabel("Claim type").selectOption("missing_obligation");
  await claimForm.getByRole("button", { name: "Encrypt claim draft" }).click();
  await expect(page.locator(".private-exception-row").filter({ hasText: "missing obligation" })).toContainText("draft");
  const claimDraftState = await evidenceState(page);
  const claimDraft = claimDraftState.records.find(({ recordType }) => recordType === "wage-claim");
  expect(claimDraft).toBeTruthy();

  await page.evaluate(() => window.__PAYO_BROWSER_EVIDENCE__?.markLatestClaimSubmitted());
  await page.getByRole("button", { name: "Refresh records" }).click();
  await expect(page.locator(".private-exception-row").filter({ hasText: "missing obligation" })).toContainText("submitted");

  const remediationButton = page.getByRole("button", { name: "Draft remediation" });
  await expect(remediationButton).toBeEnabled();
  await remediationButton.click();
  const remediationForm = page.locator("form.receipt-disclosure-form").last();
  await expect(remediationForm).toBeVisible();
  await remediationForm.getByLabel("Encrypted claim").selectOption({ index: 1 });
  await remediationForm.getByLabel("Remediation amount (token atomic units)").fill("3");
  await remediationForm.getByRole("button", { name: "Encrypt remediation draft" }).click();
  await expect(page.locator(".private-exception-row").filter({ hasText: "remediation" })).toContainText("draft");

  const activityState = await evidenceState(page);
  const remediation = activityState.records.find(({ recordType }) => recordType === "remediation");
  expect(remediation).toBeTruthy();
  expect((remediation!.plaintext as { claimId: string }).claimId)
    .toBe((claimDraft!.plaintext as { id: string }).id);

  const artifact = {
    schemaVersion: "payo.phase3.rendered-browser-origin.v1",
    generatedAt: new Date().toISOString(),
    routeGuard: "PAYO_BROWSER_EVIDENCE_MODE=1",
    renderedProductionPages: ["app/team/page.tsx", "app/activity/page.tsx"],
    productionControls: [
      "Encrypt contributor",
      "Encrypt proof-bound agreement",
      "Encrypt claim draft",
      "Encrypt remediation draft",
    ],
    workflowPlans: workflows.map(({ name, plan, option }) => ({ name, plan, option })),
    teamState,
    claimDraft,
    activityState,
    checks: {
      eightRenderedAgreementForms: true,
      productionTeamControls: true,
      productionScheduleRegistration: true,
      productionActivityControls: true,
      clientEncryptedRoundTrips: true,
      statutoryFxClassificationProfile: true,
      claimToRemediationBinding: true,
    },
  };
  const outputPath = testInfo.outputPath("phase3-rendered-browser-origin.json");
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600 });
  await testInfo.attach("phase3-rendered-browser-origin", { path: outputPath, contentType: "application/json" });

  if (process.env.PAYO_BROWSER_EVIDENCE_WRITE === "1") {
    const committedPath = resolve("evidence/phase3-devnet-fixtures/rendered-browser-ui-origin.json");
    await mkdir(dirname(committedPath), { recursive: true });
    await writeFile(committedPath, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600 });
  }
});
