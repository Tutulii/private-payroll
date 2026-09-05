import { createHash } from "node:crypto";
import { access, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const MAINNET_CHAIN_ID = "0x534e5f4d41494e";
const ANONYMIZER_CLASS_HASH =
  "0x2a4ac595283d4d64b9952f5ef5c0da1775bfdb7c9d92237524a21dd8d19ebd7";
const ANONYMIZER_ADDRESS =
  "0x6737a6cdde0e0c4f39d88ec7301e1db8d7c46ffed35ade0ee9a56ed87ab784";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function readJson(path) {
  return JSON.parse(await readFile(resolve(root, path), "utf8"));
}

function assertEveryBooleanTrue(value, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} is missing.`);
  for (const [name, passed] of Object.entries(value)) {
    assert(passed === true, `${label}.${name} did not pass.`);
  }
}

function sha256Hex(bytes) {
  return `0x${createHash("sha256").update(bytes).digest("hex")}`;
}

async function optionalJson(path) {
  try {
    return await readJson(path);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

const [
  vestingDevnet,
  privateBookDevnet,
  attestationBrowser,
  exitBrowser,
  exitUpstream,
  vestingPlan,
  exitPlanRecord,
  vestingDeployment,
  exitDeployment,
] = await Promise.all([
  readJson("evidence/vesting-tax-devnet.json"),
  readJson("evidence/universal-payroll-book-private-devnet.json"),
  readJson("evidence/block4-external-attestation-browser.json"),
  readJson("evidence/block5-private-exit-browser.json"),
  readJson("evidence/block5-private-exit-upstream.json"),
  readJson("evidence/vesting-tax-mainnet-plan.json"),
  readJson("evidence/private-exit-mainnet-plan.json"),
  optionalJson("evidence/vesting-tax-mainnet.json"),
  optionalJson("evidence/private-exit-mainnet.json"),
]);

assert(vestingDevnet.passed === true, "Vesting/tax Devnet lifecycle did not pass.");
assert(vestingDevnet.realProofVerification?.passed === true,
  "The real generated VestingBook verifier was not exercised on Devnet.");
assertEveryBooleanTrue(vestingDevnet.negativeTests, "vestingDevnet.negativeTests");
assert(vestingDevnet.externalAttestation?.activeCatalogAccepted === true,
  "An active external-attestation catalog was not accepted.");
assert(vestingDevnet.externalAttestation?.revokedCatalogRejected === true,
  "A revoked external-attestation catalog was not rejected.");
assert(vestingDevnet.publicState?.releaseConsumed === true,
  "The vesting release nullifier was not consumed.");
assert(vestingDevnet.publicState?.bookEntryCount === 1,
  "The Devnet vesting transition did not append exactly one book entry.");

assertEveryBooleanTrue(privateBookDevnet.checks, "privateBookDevnet.checks");
const privateDelta = BigInt(privateBookDevnet.privateBalanceEvidenceAtomic?.delta);
assert(privateDelta > 0n, "The private-payment balance delta is not positive.");
assert(
  BigInt(privateBookDevnet.privateBalanceEvidenceAtomic?.recipientAfter)
    - BigInt(privateBookDevnet.privateBalanceEvidenceAtomic?.recipientBefore)
    === privateDelta,
  "The private-payment balance delta does not reconcile.",
);
assert(privateBookDevnet.universalPayrollBook?.entryCount === 1,
  "The universal private payroll book did not append exactly one entry.");

assertEveryBooleanTrue(attestationBrowser.checks, "attestationBrowser.checks");
assertEveryBooleanTrue(exitBrowser.checks, "exitBrowser.checks");
assert(exitUpstream.checks?.pinnedUpstreamRevision === true,
  "The private-exit upstream revision is not pinned.");
assert(exitUpstream.checks?.releaseClassHashReproduced === true,
  "The private-exit release class hash was not reproduced.");
assert(exitUpstream.checks?.anonymizerAssertions?.passed === 3
  && exitUpstream.checks?.anonymizerAssertions?.failed === 0,
"The upstream anonymizer contract tests did not pass 3/3.");
assert(exitUpstream.checks?.strk20OpenNoteSwapComposition?.passed === 1
  && exitUpstream.checks?.strk20OpenNoteSwapComposition?.failed === 0,
"The upstream STRK20 open-note composition did not pass.");

assert(vestingPlan.network === "starknet-mainnet" && vestingPlan.chainId === MAINNET_CHAIN_ID,
  "The VestingBook plan is not bound to Starknet Mainnet.");
assert(vestingPlan.mutationSubmitted === false,
  "The reviewed VestingBook plan unexpectedly records a mutation.");
assert(vestingPlan.circuit?.proofVersion === 3
  && vestingPlan.circuit?.publicInputCount === 58,
"The VestingBook plan is not bound to the final 58-input v3 statement.");
assert(vestingPlan.circuit?.measuredProofCalldataFelts <= vestingPlan.circuit?.maximumProofCalldataFelts,
  "The measured VestingBook proof exceeds the planned calldata ceiling.");

const circuitBytes = await readFile(resolve(root, "public/circuits/vesting_transition-v3.json"));
const vkHex = (await readFile(
  resolve(root, "public/circuits/vesting_transition-v3.vk.hex"),
  "utf8",
)).replace(/\s/g, "");
assert(/^[0-9a-f]+$/i.test(vkHex) && vkHex.length % 2 === 0,
  "The published VestingBook verification key is malformed.");
assert(sha256Hex(circuitBytes) === vestingPlan.circuit.circuitSha256,
  "The reviewed VestingBook plan is not bound to the published circuit.");
assert(sha256Hex(Buffer.from(vkHex, "hex")) === vestingPlan.circuit.verificationKeySha256,
  "The reviewed VestingBook plan is not bound to the published verification key.");

const classBindings = [
  ["realVerifier", "vestingVerifier"],
  ["realBundle", "vestingBundle"],
  ["vestingBookSeal", "vestingBookSeal"],
];
for (const [devnetName, planName] of classBindings) {
  assert(
    vestingDevnet.classes?.[devnetName]?.classHash === vestingPlan.contracts?.[planName]?.classHash,
    `${planName} Mainnet plan differs from the class exercised on Devnet.`,
  );
  assert(
    vestingDevnet.classes?.[devnetName]?.artifactSha256
      === vestingPlan.contracts?.[planName]?.sierraSha256,
    `${planName} Mainnet plan differs from the artifact exercised on Devnet.`,
  );
}
assert(vestingPlan.contracts?.vestingBookSeal?.constructorCalldata?.length === 5,
  "The VestingBook seal does not have the reviewed five-field immutable wiring.");
assert(
  vestingPlan.contracts.vestingBookSeal.constructorCalldata[3]
    === vestingPlan.reusedTopology?.exceptionSeal?.address,
  "The VestingBook seal is not bound to the reviewed exception seal.",
);

const vestingEstimate = vestingPlan.feeEstimate;
assert(vestingEstimate && BigInt(vestingEstimate.totalFeeFri) > 0n,
  "The VestingBook Mainnet fee simulation is missing.");
assert(Array.isArray(vestingEstimate.pendingDeployments),
  "The VestingBook Mainnet pending-deployment status is missing.");

const exitPlan = exitPlanRecord.plan;
assert(exitPlan?.network === "starknet-mainnet" && exitPlan.chainId === MAINNET_CHAIN_ID,
  "The private-exit plan is not bound to Starknet Mainnet.");
assert(exitPlanRecord.mutationSubmitted === false
  && exitPlanRecord.feeEstimate?.mutationSubmitted === false,
"The reviewed private-exit plan unexpectedly records a mutation.");
assert(exitPlan.deployment?.classHash === ANONYMIZER_CLASS_HASH
  && exitPlan.deployment?.address === ANONYMIZER_ADDRESS,
"The private-exit deployment does not match the reviewed class and address.");
assert(Array.isArray(exitPlan.deployment?.constructorCalldata)
  && exitPlan.deployment.constructorCalldata.length === 0,
"The private-exit deployment no longer has an empty constructor.");
assert(exitPlanRecord.reviewedClass?.classHash === ANONYMIZER_CLASS_HASH
  && exitPlanRecord.reviewedClass?.exactPrivacyInvokeAbi === true,
"The Mainnet anonymizer class or privacy_invoke ABI was not read back exactly.");
assert(BigInt(exitPlanRecord.feeEstimate?.feeFri) > 0n,
  "The private-exit Mainnet fee simulation is missing.");

const vestingMainnetPassed = vestingDeployment?.verification?.passed === true
  && vestingDeployment?.canary?.passed === true;
const exitMainnetPassed = exitDeployment?.verification?.passed === true
  && exitDeployment?.canary?.passed === true;
const totalFeeFri = BigInt(vestingEstimate.totalFeeFri)
  + BigInt(exitPlanRecord.feeEstimate.feeFri);
const balanceFri = BigInt(vestingEstimate.balanceFri);
const shortfallFri = totalFeeFri > balanceFri ? totalFeeFri - balanceFri : 0n;

const result = {
  schemaVersion: "payo-pre-hackathon-release-gate-v1",
  localAndDevnetEvidencePassed: true,
  mutationSubmitted: false,
  mainnet: {
    vestingBook: vestingMainnetPassed ? "verified" : "pending",
    privateExit: exitMainnetPassed ? "verified" : "pending",
    totalEstimatedFeeFri: totalFeeFri.toString(),
    observedBalanceFri: balanceFri.toString(),
    bareShortfallFri: shortfallFri.toString(),
  },
  block6Complete: vestingMainnetPassed && exitMainnetPassed,
};

process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
