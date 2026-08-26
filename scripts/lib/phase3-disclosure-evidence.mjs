import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

export const PHASE3_DISCLOSURE_WORKFLOWS = [
  "recurring",
  "checkpoint",
  "milestone",
  "vesting",
  "final-pay",
  "approved-adjustment",
  "statutory-fx-classification",
];

const commitmentPattern = /^0x[0-9a-fA-F]{64}$/;

function assertCommitment(value, label) {
  if (typeof value !== "string" || !commitmentPattern.test(value)) {
    throw new Error(`${label} must be a 32-byte commitment.`);
  }
}

function rootFromLimbs(limbs) {
  if (!Array.isArray(limbs) || limbs.length !== 2) throw new Error("Matrix manifest root limbs are invalid.");
  const high = BigInt(limbs[0]);
  const low = BigInt(limbs[1]);
  if (high < 0n || high >= 1n << 128n || low < 0n || low >= 1n << 128n) {
    throw new Error("Matrix manifest root limbs exceed u128.");
  }
  return `0x${((high << 128n) | low).toString(16).padStart(64, "0")}`;
}

function assertUnique(values, label) {
  if (new Set(values).size !== values.length) throw new Error(`${label} must be unique.`);
}

function assertPackageResult(entry) {
  if (
    entry.recipientPrivateKeyPersisted !== false
    || entry.wrongRecipientRejected !== true
    || entry.expiredGrantRejected !== true
    || entry.revokedGrantRejected !== true
  ) throw new Error(`Disclosure package ${entry.grantId ?? "unknown"} did not pass its privacy checks.`);
  assertCommitment(entry.packageCommitment, "Disclosure package commitment");
  if (entry.verified?.scope !== entry.scope) throw new Error("Disclosure verification scope differs from its grant scope.");
  const files = entry.verified?.fileNames;
  if (!Array.isArray(files) || !files.includes("manifest.json") || !files.includes("journal.csv")) {
    throw new Error("Disclosure verification is missing its manifest or balanced journal.");
  }
  if ((entry.scope === "worker") !== files.includes("line-opening.json")) {
    throw new Error("Only worker disclosure packages may contain a line opening.");
  }
}

export async function validatePhase3DisclosureEvidence(input, options = {}) {
  const { evidence, matrixEvidence } = input;
  const root = options.root ?? process.cwd();
  if (evidence?.schemaVersion !== 1 || evidence.passed !== true) {
    throw new Error("Phase 3 disclosure evidence is not a passing schema-v1 record.");
  }
  if (matrixEvidence?.passed !== true) throw new Error("The source Phase 3 matrix did not pass.");
  assertCommitment(evidence.manifestRoot, "Disclosure manifest root");
  const matrixManifestRoot = rootFromLimbs(
    matrixEvidence.publicBindings?.manifestRoot ?? matrixEvidence.proofBindings?.manifestRoot,
  );
  if (BigInt(evidence.manifestRoot) !== BigInt(matrixManifestRoot)) {
    throw new Error("Disclosure evidence does not open the on-chain matrix manifest root.");
  }
  if (evidence.workflowWorkerPackageCount !== PHASE3_DISCLOSURE_WORKFLOWS.length) {
    throw new Error("Disclosure evidence does not declare all workflow worker packages.");
  }
  if (!Array.isArray(evidence.packages) || evidence.packages.length !== 10) {
    throw new Error("Phase 3 requires seven worker and three organization-scope packages.");
  }

  const workers = evidence.packages.filter(({ scope }) => scope === "worker");
  const organizationScopes = evidence.packages.filter(({ scope }) => scope !== "worker");
  const workflows = workers.map(({ workflow }) => workflow).sort();
  if (JSON.stringify(workflows) !== JSON.stringify([...PHASE3_DISCLOSURE_WORKFLOWS].sort())) {
    throw new Error("Worker disclosure workflow coverage is incomplete or duplicated.");
  }
  const workerIndices = workers.map(({ lineIndex }) => lineIndex).sort((left, right) => left - right);
  if (JSON.stringify(workerIndices) !== JSON.stringify([0, 1, 2, 3, 4, 5, 6])) {
    throw new Error("Worker disclosure line indices must cover the complete seven-line manifest once.");
  }
  const scopes = organizationScopes.map(({ scope }) => scope).sort();
  if (JSON.stringify(scopes) !== JSON.stringify(["auditor", "employer", "tax"])) {
    throw new Error("Employer, auditor, and tax disclosure coverage is required exactly once.");
  }

  for (const entry of evidence.packages) assertPackageResult(entry);
  assertUnique(evidence.packages.map(({ grantId }) => grantId), "Disclosure grant IDs");
  assertUnique(evidence.packages.map(({ recipientPrincipalId }) => recipientPrincipalId), "Disclosure recipients");
  assertUnique(evidence.packages.map(({ packageCommitment }) => packageCommitment), "Disclosure package commitments");
  assertUnique(evidence.packages.map(({ encryptedPackagePath }) => encryptedPackagePath), "Disclosure evidence paths");

  const fixtureRoot = resolve(root, "evidence/phase3-devnet-fixtures");
  for (const entry of evidence.packages) {
    if (typeof entry.encryptedPackagePath !== "string") throw new Error("Disclosure package path is missing.");
    const packagePath = resolve(root, entry.encryptedPackagePath);
    if (packagePath !== fixtureRoot && !packagePath.startsWith(`${fixtureRoot}${sep}`)) {
      throw new Error("Disclosure package path escapes the Phase 3 fixture directory.");
    }
    const encrypted = JSON.parse(await readFile(packagePath, "utf8"));
    if (
      encrypted.packageVersion !== "payo-encrypted-proof-package-v1"
      || encrypted.grantId !== entry.grantId
      || encrypted.envelope?.aad?.recordId !== entry.grantId
      || encrypted.packageCommitment !== entry.packageCommitment
      || encrypted.envelope?.wrappedKeys?.length !== 1
      || encrypted.envelope.wrappedKeys[0]?.principalId !== entry.recipientPrincipalId
    ) throw new Error(`Encrypted disclosure envelope does not match evidence for ${entry.grantId}.`);
  }
  return { matrixManifestRoot, workflows, scopes, packageCount: evidence.packages.length };
}
