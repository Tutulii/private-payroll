import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { hash } from "starknet";
import { agreementProofScheduleCommitment } from "@/lib/client/agreement-directory";
import { hashRecipientCommitment } from "@/lib/crypto/commitments";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { toHex } from "@/lib/crypto/encoding";
import { buildPhase3MatrixFixture } from "./generate-phase3-matrix-fixture";
import { loadPhase3UiWorkflowFixture } from "./lib/phase3-ui-workflow-fixture";

const root = process.cwd();

interface ProofCoverageEntry {
  agreementId: string;
  formInputCommitment: string;
  workflow: string;
}

interface ProofShard {
  calldataHash: string;
  publicInputs: Record<string, string>;
}

interface ProofManifest {
  coverage: ProofCoverageEntry[];
  shards: ProofShard[];
}

interface SettlementEvidence {
  checks?: Record<string, boolean>;
  coverage?: ProofCoverageEntry[];
  finalStatus: number;
  passed: boolean;
  workflowCoverage?: ProofCoverageEntry[];
}

async function readJson<T>(relativePath: string): Promise<T> {
  return JSON.parse(await readFile(resolve(root, relativePath), "utf8")) as T;
}

function normalized(value: unknown): string {
  return `0x${BigInt(String(value)).toString(16)}`;
}

function joinedRoot(high: unknown, low: unknown): `0x${string}` {
  const value = (BigInt(String(high)) << 128n) | BigInt(String(low));
  return `0x${value.toString(16).padStart(64, "0")}`;
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function main() {
  const [ui, matrix, proof, privateEvidence, shard0, shard1] = await Promise.all([
    loadPhase3UiWorkflowFixture(),
    buildPhase3MatrixFixture(),
    readJson<ProofManifest>("evidence/phase3-devnet-fixtures/advanced-matrix-proof.json"),
    readJson<SettlementEvidence>("evidence/phase3-private-settlement-devnet.json"),
    readFile(resolve(root, "evidence/phase3-devnet-fixtures/advanced-matrix-shard-0.txt"), "utf8"),
    readFile(resolve(root, "evidence/phase3-devnet-fixtures/advanced-matrix-shard-1.txt"), "utf8"),
  ]);
  assert(ui.entries.length === 7, "The UI-origin artifact must contain seven proof profiles/workflows.");
  assert(new Set(ui.entries.map(({ workflow }) => workflow)).size === 7, "UI workflow names must be unique.");

  for (const entry of ui.entries) {
    const { agreementRecord: record, encryptedEnvelope: envelope, payee } = entry;
    assert(record.agreement.agreementVersion === "payo-agreement-v2", `${entry.workflow} is not an advanced v2 agreement.`);
    assert(record.organizationId === ui.organizationId && payee.organizationId === ui.organizationId,
      `${entry.workflow} belongs to another organization.`);
    assert(record.payeeId === payee.id, `${entry.workflow} is not bound to its UI-selected contributor.`);
    assert(envelope.aad.organizationId === record.organizationId
      && envelope.aad.recordId === record.id
      && envelope.aad.recordType === "pay-agreement"
      && envelope.aad.revision === record.revision,
    `${entry.workflow} ciphertext AAD does not match its stored identity.`);
    const recipientCommitment = toHex(hashRecipientCommitment(payee.recipientAddress, record.recipientSalt));
    assert(BigInt(recipientCommitment) === BigInt(record.recipientCommitment),
      `${entry.workflow} recipient commitment does not match the UI contributor.`);
    const agreementCommitment = hashCanonicalJson({
      domain: "PAYO_ENCRYPTED_AGREEMENT_V1",
      agreement: record.agreement,
      recipientCommitment: record.recipientCommitment,
      agreementSalt: record.agreementSalt,
    });
    assert(BigInt(agreementCommitment) === BigInt(record.agreementCommitment),
      `${entry.workflow} encrypted agreement commitment is invalid.`);
    const storedProofScheduleCommitment = record.proofScheduleCommitment;
    assert(storedProofScheduleCommitment, `${entry.workflow} has no stored proof schedule commitment.`);
    assert(BigInt(await agreementProofScheduleCommitment(record.agreement)) === BigInt(storedProofScheduleCommitment),
      `${entry.workflow} proof schedule is not bound to the stored advanced plan.`);
    const ciphertext = JSON.stringify(envelope);
    assert(![payee.displayName, payee.recipientAddress, ...record.agreement.earningsAtomic]
      .some((privateValue) => ciphertext.includes(privateValue)),
    `${entry.workflow} ciphertext serialization contains a private form value.`);
  }

  const expectedCoverage = matrix.entries.map(({ workflow, agreement, formInputCommitment }) => ({
    workflow,
    agreementId: agreement.id,
    formInputCommitment: normalized(formInputCommitment),
  }));
  assert(Array.isArray(proof.coverage) && proof.coverage.length === expectedCoverage.length,
    "The real proof manifest does not cover every UI workflow.");
  for (const expected of expectedCoverage) {
    const actual = proof.coverage.find((candidate) => candidate.workflow === expected.workflow);
    assert(actual, `The real proof manifest omits ${expected.workflow}.`);
    assert(actual.agreementId === expected.agreementId, `${expected.workflow} proof uses another agreement.`);
    assert(normalized(actual.formInputCommitment) === expected.formInputCommitment,
      `${expected.workflow} proof is not bound to its UI form commitment.`);
  }

  assert(Array.isArray(proof.shards) && proof.shards.length === 2, "The UI workflow proof requires two shards.");
  const [first, second] = proof.shards.map((shard) => shard.publicInputs);
  for (const field of ["agreementRoot", "manifestRoot", "policyRoot", "fxRoot", "runNullifier"] as const) {
    const upper = `${field}High`;
    const lower = `${field}Low`;
    assert(joinedRoot(first[upper], first[lower]) === matrix.payroll[field], `Proof ${field} does not match the UI matrix.`);
    assert(joinedRoot(second[upper], second[lower]) === matrix.payroll[field], `Proof shard 1 ${field} is not linked.`);
  }
  const calldata = [shard0, shard1].map((source) => source.trim().split(/\s+/));
  for (const [index, values] of calldata.entries()) {
    const calldataHash = normalized(hash.computePoseidonHashOnElements(values));
    assert(calldataHash === normalized(proof.shards[index].calldataHash),
      `Proof shard ${index} calldata hash does not match its manifest.`);
  }

  assert(privateEvidence.passed === true && privateEvidence.finalStatus === 2,
    "Official-pool UI-workflow settlement evidence is not terminal.");
  for (const evidence of [privateEvidence]) {
    const coverage = evidence.coverage ?? evidence.workflowCoverage;
    assert(Array.isArray(coverage) && coverage.length === expectedCoverage.length,
      "A settlement evidence file omits a UI workflow.");
    for (const expected of expectedCoverage) {
      const actual = coverage.find((candidate) => candidate.workflow === expected.workflow);
      assert(actual?.agreementId === expected.agreementId, `${expected.workflow} settlement uses another agreement.`);
      assert(normalized(actual.formInputCommitment) === expected.formInputCommitment,
        `${expected.workflow} settlement is not traceable to the UI form.`);
    }
  }
  assert(privateEvidence.checks?.privateTransferAndPayoSealAtomic === true,
    "The UI workflows were not settled through the official pool and PAYO atomically.");
  assert(privateEvidence.checks?.tamperedProofRejected === true
    && privateEvidence.checks?.poolOriginatedReplayRejected === true,
  "UI workflow negative settlement checks did not pass.");

  process.stdout.write(`${JSON.stringify({
    valid: true,
    workflows: expectedCoverage,
    agreementRoot: matrix.payroll.agreementRoot,
    manifestRoot: matrix.payroll.manifestRoot,
    runNullifier: matrix.payroll.runNullifier,
    proofHashes: proof.shards.map((shard) => shard.calldataHash),
    officialPoolFinalStatus: privateEvidence.finalStatus,
  }, null, 2)}\n`);
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
