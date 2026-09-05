import { ed25519 } from "@noble/curves/ed25519.js";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { createPayoPublicIdentity } from "@/lib/client/proof-package-files";
import { generateVaultPrincipal } from "@/lib/crypto/vault";
import {
  buildExternalAttestationCatalog,
  createExternalAttestationProofPackage,
  externalAttestationFactMask,
  jurisdictionCommitment,
  PAYO_EXTERNAL_ATTESTATION_ACTIVE_STATUS,
  signExternalAttestation,
} from "@/lib/domain/external-attestation";

const hex = (byte: string): `0x${string}` => `0x${byte.repeat(32)}`;

async function addDueAdvancedAgreement(page: Page) {
  await page.getByRole("button", { name: "Add contributor", exact: true }).click();
  const payeeForm = page.locator("form.team-add-form");
  await payeeForm.getByLabel("Display name").fill("Attested engineer");
  await payeeForm.getByLabel("Kind").selectOption("human");
  await payeeForm.getByLabel("Registered Starknet address").fill("0x744");
  await payeeForm.getByLabel("Private token").selectOption("STRK");
  await payeeForm.getByLabel("Jurisdiction").fill("US");
  const identity = createPayoPublicIdentity(generateVaultPrincipal("block4-browser-worker"));
  await payeeForm.locator("input.proof-package-file-input").setInputFiles({
    name: "payo-attested-engineer.json",
    mimeType: "application/json",
    buffer: Buffer.from(`${JSON.stringify(identity)}\n`),
  });
  await payeeForm.getByRole("button", { name: "Encrypt contributor" }).click();

  const card = page.locator(".member-card").filter({ hasText: "Attested engineer" });
  await card.getByRole("button", { name: "Add encrypted agreement" }).click();
  const agreementForm = page.locator("form.team-add-form");
  await agreementForm.getByLabel("Payment plan").selectOption({ label: "Recurring payroll" });
  await agreementForm.getByLabel("Private amount").fill("1");
  const answers = agreementForm.locator(".team-add-form__classification select");
  await expect(answers).toHaveCount(6);
  for (let index = 0; index < 6; index += 1) await answers.nth(index).selectOption("no");
  const submit = agreementForm.getByRole("button", { name: "Encrypt proof-bound agreement" });
  await expect(submit).toBeEnabled({ timeout: 30_000 });
  await submit.click();
  await expect(card.getByRole("button", { name: "Update encrypted agreement" })).toBeVisible();
}

test("Block 4 imports and binds an issuer-signed private fact package", async ({ page }, testInfo) => {
  await page.goto("/payo-browser-evidence/team");
  await page.evaluate(() => window.__PAYO_BROWSER_EVIDENCE__?.reset());
  await page.reload();
  await addDueAdvancedAgreement(page);

  const record = await page.evaluate(() => window.__PAYO_BROWSER_EVIDENCE__
    ?.exportState().records.find(({ recordType }) => recordType === "pay-agreement")?.plaintext);
  if (!record || typeof record !== "object") throw new Error("Browser agreement fixture is missing.");
  const agreement = record as {
    recipientCommitment: string;
    agreement: { id: string; statutoryPolicy: { catalogRoot: string } };
  };
  const issuer = ed25519.keygen();
  const now = Math.floor(Date.now() / 1_000);
  const signForSubject = (subjectCommitment: string, nonce: `0x${string}`) =>
    signExternalAttestation({
      attestationVersion: "payo-external-attestation-v1",
      subjectCommitment,
      factMask: externalAttestationFactMask.residency
        | externalAttestationFactMask.employment_status
        | externalAttestationFactMask.tax_status,
      jurisdictionCode: "US-CA",
      jurisdictionCommitment: jurisdictionCommitment("US-CA"),
      policyRoot: agreement.agreement.statutoryPolicy.catalogRoot,
      statusCommitment: PAYO_EXTERNAL_ATTESTATION_ACTIVE_STATUS,
      validFrom: String(now - 300),
      validUntil: String(now + 7_200),
      nonce,
    }, issuer.secretKey);
  const correctSigned = signForSubject(agreement.recipientCommitment, hex("71"));
  const correctCatalog = await buildExternalAttestationCatalog({
    attestations: [correctSigned],
    trustedIssuerPublicKeys: [correctSigned.attestation.issuerPublicKey],
  });
  const correct = createExternalAttestationProofPackage({
    agreementId: agreement.agreement.id,
    catalog: correctCatalog,
    entryIndex: 0,
  });
  const wrongSubjectSigned = signForSubject(hex("99"), hex("72"));
  const wrongSubjectCatalog = await buildExternalAttestationCatalog({
    attestations: [wrongSubjectSigned],
    trustedIssuerPublicKeys: [wrongSubjectSigned.attestation.issuerPublicKey],
  });
  const wrongSubject = createExternalAttestationProofPackage({
    agreementId: agreement.agreement.id,
    catalog: wrongSubjectCatalog,
    entryIndex: 0,
  });

  await page.goto("/payo-browser-evidence/payroll");
  const facts = page.locator(".external-facts-card");
  await expect(facts).toContainText("Attach one private fact package");

  await facts.getByLabel("Import external facts package").setInputFiles({
    name: "wrong-worker-facts.json",
    mimeType: "application/json",
    buffer: Buffer.from(`${JSON.stringify(wrongSubject)}\n`),
  });
  await expect(facts).toContainText("Package does not match this payroll");
  await expect(facts).toContainText("another private subject");

  await facts.getByLabel("Import external facts package").setInputFiles({
    name: "attested-engineer-facts.json",
    mimeType: "application/json",
    buffer: Buffer.from(`${JSON.stringify(correct)}\n`),
  });
  await expect(facts).toContainText("Residency, employment and tax facts verified");
  await expect(facts).toContainText("Jurisdiction US-CA");
  await expect(facts).toContainText(`catalog ${correct.catalogRoot.slice(0, 10)}…`);
  await expect(page.locator("body")).not.toContainText(correct.signed.signature);

  const artifact = {
    schemaVersion: "payo.block4.external-attestation.browser.v1",
    generatedAt: new Date().toISOString(),
    routeGuard: "PAYO_BROWSER_EVIDENCE_MODE=1",
    productionPage: "app/payroll/page.tsx",
    checks: {
      portablePackageImported: true,
      issuerSignatureVerified: true,
      catalogMembershipVerified: true,
      wrongSubjectRejected: true,
      exactAgreementAndPolicyBound: true,
      readableVerifiedStateRendered: true,
      signatureNotRendered: true,
    },
  };
  const outputPath = testInfo.outputPath("block4-external-attestation-browser.json");
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600 });
  await testInfo.attach("block4-external-attestation-browser", {
    path: outputPath,
    contentType: "application/json",
  });
  if (process.env.PAYO_BROWSER_EVIDENCE_WRITE === "1") {
    const committed = resolve("evidence/block4-external-attestation-browser.json");
    await mkdir(dirname(committed), { recursive: true });
    await writeFile(committed, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600 });
  }
});
