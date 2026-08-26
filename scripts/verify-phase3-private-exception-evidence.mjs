import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const [evidence, linkage, uiOrigin, claimProof, remediationProof] = await Promise.all([
  "evidence/phase3-private-exceptions-devnet.json",
  "evidence/phase3-devnet-fixtures/claim-remediation-linkage.json",
  "evidence/phase3-devnet-fixtures/claim-remediation-ui-origin.json",
  "evidence/phase3-devnet-fixtures/claim-proof.json",
  "evidence/phase3-devnet-fixtures/remediation-proof.json",
].map(async (path) => JSON.parse(await readFile(resolve(root, path), "utf8"))));
const expectedPoolClassHash =
  "0x52107fadffab71bdcbb6b2ccb68ba3e1b5558d94036538053e159d3076ad633";
const expectedStrkAddress =
  "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const feltPattern = /^0x[0-9a-f]+$/i;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertFelt(value, label) {
  assert(typeof value === "string" && feltPattern.test(value), `${label} is not a felt.`);
}

function assertVerifierReceipts(receipts, profile) {
  assert(Array.isArray(receipts) && receipts.length === 2, `${profile} needs two verifier receipts.`);
  receipts.forEach((receipt, index) => {
    assert(receipt.shardIndex === index, `${profile} shard ${index} index mismatch.`);
    assertFelt(receipt.transactionHash, `${profile} shard ${index} transaction hash`);
    assert(Number.isInteger(receipt.blockNumber) && receipt.blockNumber >= 0, `${profile} shard ${index} block is invalid.`);
  });
}

function joinedRoot(limbs) {
  assert(Array.isArray(limbs) && limbs.length === 2, "A linked root must contain two limbs.");
  return `0x${((BigInt(limbs[0]) << 128n) | BigInt(limbs[1])).toString(16).padStart(64, "0")}`;
}

function publicRoot(proof, prefix) {
  const inputs = proof?.shards?.[0]?.publicInputs;
  assert(inputs, `The ${prefix} proof manifest is missing public inputs.`);
  const key = prefix === "claim" ? "runNullifier" : prefix;
  return `0x${((BigInt(inputs[`${key}High`]) << 128n) | BigInt(inputs[`${key}Low`])).toString(16).padStart(64, "0")}`;
}

assert(evidence.schemaVersion === "payo.phase3.private-exceptions.v1", "Unexpected evidence schema.");
assert(evidence.passed === true, "Private exception evidence did not pass.");
assert(evidence.rpcVersion === "0.10.2", "Evidence uses an unexpected RPC version.");
assert(evidence.privacySdkRevision === "PRIVACY-0.14.3-RC.2", "Unexpected Privacy SDK revision.");
assert(evidence.privacyPoolRevision === "PRIVACY-0.14.3-RC.0", "Unexpected privacy-pool revision.");
assert(evidence.privacyPoolClassHash === expectedPoolClassHash, "Official privacy-pool class hash mismatch.");
assertFelt(evidence.privacyPoolAddress, "Privacy-pool address");
assertFelt(evidence.payoSealAddress, "PAYO seal address");
assert(
  Array.isArray(evidence.sharedClaimNullifier) && evidence.sharedClaimNullifier.length === 2,
  "Shared claim nullifier is missing.",
);
evidence.sharedClaimNullifier.forEach((felt, index) => assertFelt(felt, `Claim nullifier limb ${index}`));
const evidenceClaimNullifier = joinedRoot(evidence.sharedClaimNullifier);

assert(uiOrigin.schemaVersion === "payo.phase3.exception-ui-origin.v1", "Unexpected exception UI-origin schema.");
assert(uiOrigin.checks?.teamProductionCommand === "storeEncryptedAgreementFromForm", "UI agreement did not use the production command.");
assert(uiOrigin.checks?.claimProductionCommand === "createEncryptedWageClaimDraft", "UI claim did not use the production command.");
assert(uiOrigin.checks?.remediationProductionCommand === "createEncryptedRemediationDraft", "UI remediation did not use the production command.");
assert(uiOrigin.checks?.encryptedRoundTrips === true, "Exception UI records did not round-trip through encryption.");
assert(uiOrigin.checks?.plaintextAbsentFromEnvelopes === true, "Exception UI envelopes failed their plaintext check.");
assert(linkage.sourceArtifact === "evidence/phase3-devnet-fixtures/claim-remediation-ui-origin.json", "Proof linkage names another UI source.");
assert(linkage.agreementId === uiOrigin.agreementRecord?.agreement?.id, "Claim proof uses another UI agreement.");
assert(linkage.claimId === uiOrigin.claimDraft?.id, "Claim proof uses another Activity claim draft.");
assert(linkage.remediationId === uiOrigin.remediationDraft?.id, "Remediation proof uses another Activity draft.");
assert(
  JSON.stringify(linkage.formInputCommitments) === JSON.stringify(uiOrigin.formInputCommitments),
  "Exception proof form commitments do not match their UI-origin artifact.",
);
for (const [name, commitment] of Object.entries(uiOrigin.formInputCommitments ?? {})) {
  assert(typeof commitment === "string" && /^0x[0-9a-f]{64}$/.test(commitment), `${name} form commitment is invalid.`);
}
assert(BigInt(linkage.claimNullifier) === BigInt(evidenceClaimNullifier), "UI claim nullifier differs from official-pool evidence.");
assert(BigInt(uiOrigin.submittedClaim?.claimNullifier) === BigInt(evidenceClaimNullifier), "Submitted UI claim has another nullifier.");
assert(BigInt(publicRoot(claimProof, "claim")) === BigInt(evidenceClaimNullifier), "Claim proof public nullifier differs from official-pool evidence.");
assert(BigInt(publicRoot(remediationProof, "claim")) === BigInt(evidenceClaimNullifier), "Remediation proof is not linked to the UI claim nullifier.");

assert(evidence.committedClaim?.token === "STRK", "Committed claim token is not STRK.");
assertFelt(evidence.committedClaim?.recipientAddress, "Committed claim recipient");
assertFelt(evidence.committedClaim?.disputedManifestRoot, "Disputed manifest root");
assertFelt(evidence.committedClaim?.remediationManifestRoot, "Remediation manifest root");
assert(BigInt(evidence.committedClaim.disputedManifestRoot) === BigInt(linkage.disputedManifestRoot), "Disputed manifest root differs from the UI proof linkage.");
assert(BigInt(evidence.committedClaim.remediationManifestRoot) === BigInt(linkage.remediationManifestRoot), "Remediation manifest root differs from the UI proof linkage.");
assert(BigInt(publicRoot(remediationProof, "manifestRoot")) === BigInt(linkage.remediationManifestRoot), "Remediation proof exposes another manifest root.");
assert(BigInt(evidence.committedClaim.recipientAddress) === BigInt(linkage.recipientAddress), "UI claim recipient differs from official-pool evidence.");
assert(BigInt(evidence.committedClaim.recipientAddress) === BigInt(uiOrigin.recipientAddress), "Activity-origin recipient differs from settlement evidence.");
assert(evidence.remediation?.tokenAddress === expectedStrkAddress, "Remediation token address is not STRK.");
assert(
  evidence.remediation?.recipientAddress === evidence.committedClaim.recipientAddress,
  "Private remediation recipient differs from the committed claim recipient.",
);
const shortfall = BigInt(evidence.committedClaim.shortfallAtomic);
const remediationAmount = BigInt(evidence.remediation.amountAtomic);
assert(shortfall > 0n && remediationAmount === shortfall, "Private remediation amount differs from the committed shortfall.");
assert(shortfall === BigInt(linkage.shortfallAtomic), "UI proof linkage has another shortfall.");
assert(shortfall === BigInt(uiOrigin.remediationDraft?.amountAtomic), "Activity remediation draft has another amount.");
assert(evidence.committedClaim.token === linkage.token && linkage.token === uiOrigin.remediationDraft?.token, "Activity token differs from private remediation evidence.");

assertFelt(evidence.claim?.privateInvocationTransactionHash, "Private claim transaction hash");
assertVerifierReceipts(evidence.claim?.verifierShards, "Claim");
assert(evidence.claim?.finalStatus === 4, "Claim did not reach disputed status 4.");
const claimBeforeAlice = BigInt(evidence.claim.balancesBeforeAtomic.alice);
const claimBeforeBob = BigInt(evidence.claim.balancesBeforeAtomic.bob);
const claimAfterAlice = BigInt(evidence.claim.balancesAfterAtomic.alice);
const claimAfterBob = BigInt(evidence.claim.balancesAfterAtomic.bob);
assert(
  claimBeforeAlice === claimAfterAlice && claimBeforeBob === claimAfterBob,
  "No-payment wage-claim invocation changed private balances.",
);

assertFelt(evidence.remediation?.privatePaymentAndSealTransactionHash, "Private remediation transaction hash");
assertVerifierReceipts(evidence.remediation?.verifierShards, "Remediation");
assert(evidence.remediation?.finalStatus === 5, "Remediation did not reach reconciled status 5.");
const remediationBeforeAlice = BigInt(evidence.remediation.balancesBeforeAtomic.alice);
const remediationBeforeBob = BigInt(evidence.remediation.balancesBeforeAtomic.bob);
const remediationAfterAlice = BigInt(evidence.remediation.balancesAfterAtomic.alice);
const remediationAfterBob = BigInt(evidence.remediation.balancesAfterAtomic.bob);
assert(remediationBeforeAlice === claimAfterAlice, "Remediation sender start balance is not linked to claim completion.");
assert(remediationBeforeBob === claimAfterBob, "Remediation recipient start balance is not linked to claim completion.");
assert(remediationAfterAlice === remediationBeforeAlice - shortfall, "Sender balance delta differs from shortfall.");
assert(remediationAfterBob === remediationBeforeBob + shortfall, "Recipient balance delta differs from shortfall.");
assertFelt(evidence.transactions?.schedule, "Exception registry schedule transaction hash");

const requiredChecks = [
  "officialPoolClassMatched",
  "sealConfiguredForOfficialPool",
  "claimAndRemediationNullifierLinked",
  "remediationMatchesCommittedClaimFields",
  "claimReachedDisputedStatus",
  "remediationPaymentAndSealAtomic",
  "remediationReachedReconciledStatus",
  "recipientDiscoveredPrivateRemediation",
  "claimTamperRejected",
  "remediationTamperRejected",
  "poolOriginatedReplayRejected",
  "replayPreservedPrivateBalances",
];
for (const check of requiredChecks) {
  assert(evidence.checks?.[check] === true, `Required check ${check} did not pass.`);
}
assert(evidence.checks?.fullTransactionProofVerification === false, "Unsupported full transaction-proof verification was claimed.");
assert(
  evidence.checks?.directPrivateAmountToManifestReconciliation === false,
  "Phase 4 SettlementMatch was claimed by Phase 3 exception evidence.",
);
assert(Array.isArray(evidence.limitations) && evidence.limitations.length >= 2, "Evidence limitations are missing.");

process.stdout.write(
  "Phase 3 private claim/remediation evidence is internally consistent; its explicit Devnet proof-mode and Phase 4 limitations remain non-completion blockers.\n",
);
