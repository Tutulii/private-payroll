import { writePhase3ExceptionUiFixture } from "./lib/phase3-exception-ui-fixture";

void writePhase3ExceptionUiFixture().then((fixture) => {
  process.stdout.write(`${JSON.stringify({
    valid: true,
    artifact: "evidence/phase3-devnet-fixtures/claim-remediation-ui-origin.json",
    agreementId: fixture.agreementRecord.agreement.id,
    claimId: fixture.claimDraft.id,
    remediationId: fixture.remediationDraft.id,
    shortfallAtomic: fixture.submittedClaim.shortfallAtomic,
    token: fixture.submittedClaim.token,
    formInputCommitments: fixture.formInputCommitments,
    checks: fixture.checks,
  }, null, 2)}\n`);
}).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
