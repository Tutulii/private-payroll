import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { CompiledCircuit, InputMap } from "@noir-lang/noir_js";
import { Noir } from "@noir-lang/noir_js";
import { encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { buildFxSnapshot } from "@/lib/domain/fx";
import type { EmploymentAgreement } from "@/lib/domain/obligations";
import { calculatePolicyDeductions } from "@/lib/policy/execution-catalog";
import type { PolicyPack } from "@/lib/policy/engine";
import { US_2026_SUPPLEMENTAL_FLAT } from "@/lib/policy/reference-packs";
import { advancedPlanProofCommitment } from "@/lib/proof/advanced-plan-commitment";
import { buildAdvancedObligationInputs } from "@/lib/proof/advanced-obligation-input";
import {
  buildPayrollIntegrityInputsFromSerialized,
  PAYO_NET_INVOICE_POLICY,
  serializePayrollIntegrityBuildRequest,
  type PayrollIntegrityLineInput,
} from "@/lib/proof/input-builder";
import { provePayrollOnSelfHostedNode } from "@/lib/proof/server-prover";
import {
  loadPhase3UiWorkflowFixture,
  phase3UiOrganizationId,
  phase3UiValidityStart,
} from "./lib/phase3-ui-workflow-fixture";

const outputDirectory = resolve(
  process.cwd(),
  process.env.PAYO_PHASE3_OUTPUT_DIRECTORY ?? "evidence/phase3-devnet-fixtures",
);
const organizationId = phase3UiOrganizationId;
const validityStart = phase3UiValidityStart;
const validityExpiry = validityStart + 3_600n;

function iso(seconds: bigint): string {
  return new Date(Number(seconds) * 1_000).toISOString();
}

function commitment(byte: number): `0x${string}` {
  return `0x${byte.toString(16).padStart(2, "0").repeat(32)}`;
}

function componentMask(components: { accruedLeave: boolean; notice: boolean; severance: boolean }): number {
  return (components.accruedLeave ? 1 : 0)
    | (components.notice ? 2 : 0)
    | (components.severance ? 4 : 0);
}

type MatrixEntry = {
  workflow: string;
  agreement: EmploymentAgreement;
  policy: PolicyPack;
  recipientAddress: string;
  recipientSalt: `0x${string}`;
  agreementSalt: `0x${string}`;
  formInputCommitment: `0x${string}`;
};

async function matrixEntries(): Promise<MatrixEntry[]> {
  const fixture = await loadPhase3UiWorkflowFixture();
  if (fixture.organizationId !== organizationId || BigInt(fixture.validityStart) !== validityStart) {
    throw new Error("The UI workflow artifact is bound to another Phase 3 matrix context.");
  }
  const policies: readonly PolicyPack[] = [PAYO_NET_INVOICE_POLICY, US_2026_SUPPLEMENTAL_FLAT.pack];
  return fixture.entries.map((entry) => {
    const agreement = entry.agreementRecord.agreement;
    if (agreement.agreementVersion !== "payo-agreement-v2") {
      throw new Error(`UI workflow ${entry.workflow} is not an advanced v2 obligation.`);
    }
    const policy = policies.find((candidate) =>
      candidate.id === agreement.statutoryPolicy.policyId
      && candidate.revision === agreement.statutoryPolicy.policyVersion);
    if (!policy) throw new Error(`UI workflow ${entry.workflow} selects an unknown policy.`);
    return {
      workflow: entry.workflow,
      agreement,
      policy,
      recipientAddress: entry.payee.recipientAddress,
      recipientSalt: entry.agreementRecord.recipientSalt as `0x${string}`,
      agreementSalt: entry.agreementRecord.agreementSalt as `0x${string}`,
      formInputCommitment: entry.formInputCommitment as `0x${string}`,
    };
  });
}

export async function buildPhase3MatrixFixture() {
  const entries = await matrixEntries();
  const policies = [PAYO_NET_INVOICE_POLICY, US_2026_SUPPLEMENTAL_FLAT.pack];
  const snapshot = buildFxSnapshot({
    baseToken: "USDC",
    referenceCurrency: "USD",
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 300,
    minimumSources: 3,
    aggregatedSourceCount: 5,
    feedId: "pragma-protected-v2:USDC/USD:phase3-matrix-pinned-block",
    quotes: [{
      source: "pragma-protected-v2:usdc/usd",
      priceAtomic: "1000000",
      observedAt: iso(validityStart - 30n),
    }],
    now: new Date(Number(validityStart) * 1_000),
  });
  const lines: PayrollIntegrityLineInput[] = [];
  for (const [index, entry] of entries.entries()) {
    const gross = entry.agreement.earningsAtomic;
    lines.push({
      agreementId: entry.agreement.id,
      recipientAddress: entry.recipientAddress,
      recipientSalt: entry.recipientSalt,
      agreementSalt: entry.agreementSalt,
      lineSalt: commitment(190 + index),
      token: entry.agreement.settlementToken,
      earningsAtomic: gross,
      deductionsAtomic: calculatePolicyDeductions(entry.policy, gross),
      policyId: entry.policy.id,
      scheduleCommitment: await advancedPlanProofCommitment(entry.agreement),
      dueAt: validityStart,
      validUntil: validityExpiry,
      classification: entry.agreement.classification === "employee"
        ? {
            declared: 1,
            score: entry.agreement.classificationAssessment?.score ?? 5,
            employeeThreshold: entry.agreement.classificationAssessment?.employeeThreshold ?? 5,
          }
        : {
            declared: 2,
            score: entry.agreement.classificationAssessment?.score ?? 2,
            employeeThreshold: entry.agreement.classificationAssessment?.employeeThreshold ?? 5,
          },
      ...(entry.agreement.agreementVersion === "payo-agreement-v2" && entry.agreement.termination ? {
        finalPay: {
          requiredMask: componentMask(entry.agreement.termination.pay.requiredComponents),
          includedMask: componentMask(entry.agreement.termination.pay.includedComponents),
          componentsAtomic: [
            entry.agreement.termination.pay.ordinaryPayAtomic,
            entry.agreement.termination.pay.accruedLeaveAtomic,
            entry.agreement.termination.pay.noticeAtomic,
            entry.agreement.termination.pay.severanceAtomic,
            entry.agreement.termination.pay.adjustmentsAtomic,
          ],
        },
      } : {}),
      fxFloorAtomic: entry.agreement.fxProtection?.minimumReferenceAtomic ?? "0",
      referenceCurrency: "USD",
    });
  }
  const serialized = serializePayrollIntegrityBuildRequest({
    chainId: process.env.PAYO_PHASE3_CHAIN_ID ?? "0x1",
    sealAddress: process.env.PAYO_PHASE3_SEAL_ADDRESS ?? "0x12345",
    organizationSecret: commitment(200),
    cycleId: "phase3-advanced-workflow-matrix",
    // Revision 1 belongs to the earlier hand-authored matrix. UI-originated
    // obligations are a new authorization and must never reuse its nullifier.
    revision: 2,
    validityStart,
    validityExpiry,
    policies,
    fxSnapshots: [snapshot],
    lines,
  });
  return {
    entries,
    payroll: await buildPayrollIntegrityInputsFromSerialized(serialized),
    serialized,
  };
}

async function validateCircuit(circuitPath: string, inputs: [InputMap, InputMap]) {
  const circuit = JSON.parse(await readFile(resolve(process.cwd(), circuitPath), "utf8")) as CompiledCircuit;
  const noir = new Noir(circuit);
  for (const shard of inputs) {
    const { witness } = await noir.execute(shard);
    witness.fill(0);
  }
}

async function main() {
  const fixture = await buildPhase3MatrixFixture();
  const advanced = buildAdvancedObligationInputs({
    payroll: fixture.payroll,
    agreements: fixture.entries.map(({ agreement }) => agreement),
  });
  if (process.env.PAYO_PHASE3_MATRIX_WITNESS_ONLY === "1") {
    const circuit = JSON.parse(await readFile(
      resolve(process.cwd(), "public/circuits/advanced_obligation-v2.json"),
      "utf8",
    )) as CompiledCircuit;
    const noir = new Noir(circuit);
    const targetDirectory = resolve(process.cwd(), "circuits/advanced_obligation/target");
    await mkdir(targetDirectory, { recursive: true });
    const witnesses: string[] = [];
    for (const shardIndex of [0, 1] as const) {
      const { witness } = await noir.execute(advanced.witness.circuitInputs[shardIndex]);
      const witnessPath = resolve(targetDirectory, `witness-v2-merged-shard-${shardIndex}.gz`);
      await writeFile(witnessPath, witness);
      witnesses.push(witnessPath);
      witness.fill(0);
    }
    console.log(JSON.stringify({ generated: true, witnesses }, null, 2));
    return;
  }
  if (process.env.PAYO_PHASE3_MATRIX_VALIDATE_ONLY === "1") {
    await validateCircuit("public/circuits/payroll_integrity-v1.json", fixture.payroll.witness.circuitInputs);
    await validateCircuit("public/circuits/advanced_obligation-v2.json", advanced.witness.circuitInputs);
    console.log(JSON.stringify({
      valid: true,
      workflows: fixture.entries.map(({ workflow }) => workflow),
      agreementRoot: fixture.payroll.agreementRoot,
      manifestRoot: fixture.payroll.manifestRoot,
      policyRoot: fixture.payroll.policyRoot,
      fxRoot: fixture.payroll.fxRoot,
    }, null, 2));
    return;
  }
  const principal = generateVaultPrincipal("phase3-matrix-prover");
  const encryptedWitness = encryptVaultRecord(
    { advancedBuildInput: { payroll: fixture.serialized, agreements: fixture.entries.map(({ agreement }) => agreement) } },
    {
      schemaVersion: 1,
      organizationId,
      recordType: "payroll-proof-request",
      recordId: "phase3-matrix-proof-request",
      revision: 1,
    },
    [principal],
  );
  const proof = await provePayrollOnSelfHostedNode({
    requestId: "phase3-matrix-proof-request",
    encryptedWitness,
    principal,
  });
  await mkdir(outputDirectory, { recursive: true });
  const summary = {
    generatedAt: new Date().toISOString(),
    circuitSha256: proof.circuitSha256,
    provingTimeMs: proof.provingTimeMs,
    coverage: fixture.entries.map(({ workflow, agreement, formInputCommitment }) => ({
      workflow,
      formInputCommitment,
      agreementId: agreement.id,
      policyId: agreement.statutoryPolicy.policyId,
      fxFloorAtomic: agreement.fxProtection?.minimumReferenceAtomic ?? "0",
      classification: agreement.classification,
    })),
    shards: proof.shards.map((shard) => ({
      shardIndex: shard.shardIndex,
      calldataHash: shard.calldataHash,
      publicInputs: shard.publicInputs,
      packedCalldataFelts: shard.proofCalldata.length,
    })),
  };
  await writeFile(resolve(outputDirectory, "advanced-matrix-proof.json"), `${JSON.stringify(summary, null, 2)}\n`);
  await Promise.all(proof.shards.map((shard) => writeFile(
    resolve(outputDirectory, `advanced-matrix-shard-${shard.shardIndex}.txt`),
    `${shard.proofCalldata.join("\n")}\n`,
  )));
  console.log(JSON.stringify(summary, null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
