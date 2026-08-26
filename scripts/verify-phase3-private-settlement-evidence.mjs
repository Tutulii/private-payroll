import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const evidencePath = resolve(root, "evidence/phase3-private-settlement-devnet.json");
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

const evidence = JSON.parse(await readFile(evidencePath, "utf8"));
assert(evidence.schemaVersion === "payo.phase3.private-settlement.v1", "Unexpected evidence schema.");
assert(evidence.passed === true, "Integrated private-settlement evidence did not pass.");
assert(evidence.rpcVersion === "0.10.2", "Evidence uses an unexpected RPC version.");
assert(evidence.privacySdkRevision === "PRIVACY-0.14.3-RC.2", "Unexpected Privacy SDK revision.");
assert(evidence.privacyPoolRevision === "PRIVACY-0.14.3-RC.0", "Unexpected privacy-pool revision.");
assert(evidence.privacyPoolClassHash === expectedPoolClassHash, "Official privacy-pool class hash mismatch.");
assertFelt(evidence.privacyPoolAddress, "Privacy-pool address");
assertFelt(evidence.payoSealAddress, "PAYO seal address");
assert(evidence.privateSettlement?.tokenAddress === expectedStrkAddress, "Settlement token is not STRK.");
assertFelt(evidence.privateSettlement?.recipientAddress, "Settlement recipient");
assertFelt(evidence.privateSettlement?.transactionHash, "Private settlement transaction hash");
assert(
  evidence.transactions?.privateSettlementAndSeal === evidence.privateSettlement.transactionHash,
  "Private value movement and PAYO seal are not evidenced by the same transaction.",
);
assertFelt(evidence.transactions?.schedule, "Registry schedule transaction hash");
assert(Array.isArray(evidence.transactions?.verifierShards), "Verifier shard receipts are missing.");
assert(evidence.transactions.verifierShards.length === 2, "Exactly two verifier shard receipts are required.");
for (const [index, receipt] of evidence.transactions.verifierShards.entries()) {
  assert(receipt.shardIndex === index, `Verifier shard ${index} index mismatch.`);
  assertFelt(receipt.transactionHash, `Verifier shard ${index} transaction hash`);
  assert(Number.isInteger(receipt.blockNumber) && receipt.blockNumber >= 0, `Verifier shard ${index} block is invalid.`);
}

const amount = BigInt(evidence.privateSettlement.amountAtomic);
assert(
  Array.isArray(evidence.privateSettlement.workflowOutputs)
    && evidence.privateSettlement.workflowOutputs.length === 7,
  "Seven workflow-specific private outputs are required.",
);
const outputTotal = evidence.privateSettlement.workflowOutputs.reduce((total, output, index) => {
  assert(typeof output.workflow === "string" && output.workflow.length > 0, `Workflow output ${index} has no profile.`);
  assertFelt(output.recipientAddress, `Workflow output ${index} recipient`);
  const outputAmount = BigInt(output.amountAtomic);
  assert(outputAmount > 0n, `Workflow output ${index} amount must be positive.`);
  return total + outputAmount;
}, 0n);
assert(outputTotal === amount, "Workflow-specific private outputs do not sum to the settlement amount.");
const beforeAlice = BigInt(evidence.privateSettlement.balancesBeforeAtomic.alice);
const beforeBob = BigInt(evidence.privateSettlement.balancesBeforeAtomic.bob);
const afterAlice = BigInt(evidence.privateSettlement.balancesAfterAtomic.alice);
const afterBob = BigInt(evidence.privateSettlement.balancesAfterAtomic.bob);
assert(amount > 0n, "Private settlement amount must be positive.");
assert(afterAlice === beforeAlice - amount, "Sender private balance did not decrease by the settlement amount.");
assert(afterBob === beforeBob + amount, "Recipient private balance did not increase by the settlement amount.");
assert(evidence.finalStatus === 2, "PAYO did not reach verified payroll status.");
assert(Array.isArray(evidence.workflowCoverage) && evidence.workflowCoverage.length === 7, "Seven-workflow coverage is missing.");
assert(Array.isArray(evidence.proofBindings?.proofHashes) && evidence.proofBindings.proofHashes.length === 2, "Proof hashes are missing.");
for (const [index, proofHash] of evidence.proofBindings.proofHashes.entries()) {
  assertFelt(proofHash, `Proof hash ${index}`);
}

const requiredChecks = [
  "officialPoolClassMatched",
  "sealConfiguredForOfficialPool",
  "privateTransferAndPayoSealAtomic",
  "recipientDiscoveredPrivateNote",
  "payoProofVerifiedOnchain",
  "tamperedProofRejected",
  "poolOriginatedReplayRejected",
  "replayPreservedPrivateBalances",
];
for (const check of requiredChecks) {
  assert(evidence.checks?.[check] === true, `Required check ${check} did not pass.`);
}
assert(evidence.checks?.fullTransactionProofVerification === false, "Unsupported full transaction-proof verification was claimed.");
assert(
  evidence.checks?.directPrivateAmountToManifestReconciliation === false,
  "Phase 4 private amount-to-manifest reconciliation was claimed by Phase 3 evidence.",
);
assert(Array.isArray(evidence.limitations) && evidence.limitations.length >= 2, "Evidence limitations are missing.");

process.stdout.write(
  "Phase 3 private STRK settlement evidence is internally consistent; its explicit Devnet proof-mode and Phase 4 limitations remain non-completion blockers.\n",
);
