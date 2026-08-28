import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { z } from "zod";
import { generateVaultPrincipal } from "@/lib/crypto/vault";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { stableJson } from "@/lib/crypto/encoding";
import { buildProofPackage } from "@/lib/domain/payroll";
import {
  createRecipientEncryptedProofPackage,
  verifyRecipientProofPackageOffline,
  type ProofPackageGrant,
  type RecipientProofPackagePayload,
} from "@/lib/disclosure/proof-package";
import { createProofCommitter } from "@/lib/proof/commitments";
import { buildPhase3MatrixFixture } from "./generate-phase3-matrix-fixture";
import { phase3UiOrganizationId } from "./lib/phase3-ui-workflow-fixture";

const root = process.cwd();
const matrixEvidencePath = resolve(root, "evidence/phase3-private-settlement-devnet.json");
const deploymentPath = resolve(root, "evidence/phase3-devnet-deployment.json");
const outputPath = resolve(root, "evidence/phase3-matrix-disclosure.json");

const transactionSchema = z.object({
  shardIndex: z.number().int().min(0).max(1).optional(),
  transactionHash: z.string().regex(/^0x[0-9a-fA-F]+$/),
  blockNumber: z.number().int().nonnegative(),
}).strict();

const matrixEvidenceSchema = z.object({
  generatedAt: z.string().datetime(),
  passed: z.literal(true),
  chainId: z.string().min(1),
  payoSealAddress: z.string().regex(/^0x[0-9a-fA-F]+$/),
  proofBindings: z.object({
    manifestRoot: z.tuple([
      z.string().regex(/^0x[0-9a-fA-F]{1,32}$/),
      z.string().regex(/^0x[0-9a-fA-F]{1,32}$/),
    ]),
    proofHashes: z.tuple([
      z.string().regex(/^0x[0-9a-fA-F]{1,64}$/),
      z.string().regex(/^0x[0-9a-fA-F]{1,64}$/),
    ]),
  }).passthrough(),
  finalStatus: z.literal(2),
  transactions: z.object({
    schedule: z.string().regex(/^0x[0-9a-fA-F]+$/),
    privateSettlementAndSeal: z.string().regex(/^0x[0-9a-fA-F]+$/),
    verifierShards: z.tuple([transactionSchema, transactionSchema]),
  }).passthrough(),
}).passthrough();

const deploymentSchema = z.object({
  classes: z.object({
    payrollSeal: z.object({ classHash: z.string().regex(/^0x[0-9a-fA-F]+$/) }).passthrough(),
  }).passthrough(),
}).passthrough();

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8"));
}

async function rejected(operation: () => Promise<unknown>): Promise<boolean> {
  try {
    await operation();
    return false;
  } catch {
    return true;
  }
}

async function main() {
  const [matrixEvidence, deployment, fixture] = await Promise.all([
    readJson(matrixEvidencePath).then(matrixEvidenceSchema.parse),
    readJson(deploymentPath).then(deploymentSchema.parse),
    buildPhase3MatrixFixture(),
  ]);
  const source = fixture.payroll.witness.circuitInputs[0] as Record<string, unknown>;
  if (!Array.isArray(source.payroll_leaves) || source.payroll_leaves.some((leaf) => typeof leaf !== "string")) {
    throw new Error("The matrix witness does not contain canonical payroll leaves.");
  }
  const leaves = (source.payroll_leaves as string[])
    .slice(0, fixture.payroll.calculatedLines.length)
    .map((leaf) => `0x${BigInt(leaf).toString(16).padStart(64, "0")}` as `0x${string}`);
  const proofCommitter = await createProofCommitter();

  const now = new Date();
  const verificationTransaction = matrixEvidence.transactions.verifierShards[1];
  const proofHashes = matrixEvidence.proofBindings.proofHashes;
  const proofPackage = buildProofPackage({
    runId: "phase3-advanced-workflow-matrix",
    organizationId,
    proofType: "payroll_integrity",
    proofVersion: "2",
    verifier: {
      chainId: matrixEvidence.chainId,
      contractAddress: matrixEvidence.payoSealAddress,
      classHash: deployment.classes.payrollSeal.classHash,
    },
    publicInputs: {
      agreementRoot: fixture.payroll.agreementRoot,
      manifestRoot: fixture.payroll.manifestRoot,
      policyRoot: fixture.payroll.policyRoot,
      fxRoot: fixture.payroll.fxRoot,
      runNullifier: fixture.payroll.runNullifier,
      shard0CalldataHash: proofHashes[0],
      shard1CalldataHash: proofHashes[1],
    },
    proof: stableJson({
      scheme: "ultra_keccak_zk_honk",
      calldataHashes: proofHashes,
      verifierTransactions: matrixEvidence.transactions.verifierShards,
    }),
    transactionHash: verificationTransaction.transactionHash,
  });
  type PackageScope = ProofPackageGrant["scope"];
  type DisclosureField = ProofPackageGrant["fieldScope"][number];
  const scopeFields: Record<PackageScope, DisclosureField[]> = {
    worker: ["identity", "gross", "deductions", "net", "token", "schedule", "classification", "settlement"],
    employer: ["identity", "gross", "deductions", "net", "token", "schedule", "classification", "aggregate", "settlement"],
    auditor: ["gross", "deductions", "net", "token", "schedule", "classification", "aggregate", "settlement"],
    tax: ["gross", "deductions", "net", "token", "aggregate", "settlement"],
  };
  const agreements = new Map(fixture.entries.map((entry) => [entry.agreement.id, entry] as const));
  const workerPackages = fixture.payroll.calculatedLines.map((workerLine, workerLineIndex) => {
    const workerEntry = agreements.get(workerLine.agreementId);
    const workerAgreement = workerEntry?.agreement;
    if (!workerEntry || !workerAgreement || workerAgreement.agreementVersion !== "payo-agreement-v2") {
      throw new Error(`The matrix worker agreement ${workerLine.agreementId} is missing or not advanced.`);
    }
    const workflow = workerEntry.workflow;
    return {
      scope: "worker" as const,
      packageKey: `worker-${workflow}`,
      outputStem: workflow === "statutory-fx-classification" ? "worker" : `worker-${workflow}`,
      scopedLines: [workerLine],
      lineIndex: workerLineIndex,
      workflow,
    };
  });
  const packageRequests = [
    ...workerPackages,
    ...(["employer", "auditor", "tax"] as const).map((scope) => ({
      scope,
      packageKey: scope,
      outputStem: scope,
      scopedLines: fixture.payroll.calculatedLines,
      lineIndex: undefined,
      workflow: undefined,
    })),
  ];
  const packageEvidence = [];
  for (const request of packageRequests) {
    const { scope, packageKey, outputStem, scopedLines, lineIndex, workflow } = request;
    const recipient = generateVaultPrincipal(`phase3-matrix-${packageKey}-recipient`);
    const stranger = generateVaultPrincipal(`phase3-matrix-${packageKey}-stranger`);
    const grant: ProofPackageGrant = {
      grantVersion: "payo-proof-package-grant-v1",
      id: `phase3-matrix-${packageKey}-grant-v1`,
      organizationId,
      runId: "phase3-advanced-workflow-matrix",
      scope,
      granteePrincipalId: recipient.principalId,
      fieldScope: scopeFields[scope],
      recipientEncryptionKey: recipient.publicKey,
      validAfter: new Date(now.getTime() - 60_000).toISOString(),
      expiresAt: new Date(now.getTime() + 86_400_000).toISOString(),
    };
    const totals = new Map<"STRK" | "USDC", bigint>();
    for (const scopedLine of scopedLines) {
      totals.set(scopedLine.token, (totals.get(scopedLine.token) ?? 0n) + BigInt(scopedLine.netAtomic));
    }
    const journal: RecipientProofPackagePayload["journal"] = [...totals.entries()].flatMap(([token, total]) => [{
      date: now.toISOString().slice(0, 10),
      accountCode: "PRIVATE_PAYROLL_EXPENSE",
      debitAtomic: total.toString(),
      creditAtomic: "0",
      token,
      memo: `${scope}-scoped private payroll expense`,
    }, {
      date: now.toISOString().slice(0, 10),
      accountCode: "PRIVATE_TREASURY",
      debitAtomic: "0",
      creditAtomic: total.toString(),
      token,
      memo: `${scope}-scoped private settlement`,
    }]);
    const availableFields: Record<DisclosureField, unknown> = {
      identity: scopedLines.map(({ agreementId: id }) => ({ agreementId: id })),
      gross: scopedLines.map(({ agreementId: id, grossAtomic }) => ({ agreementId: id, grossAtomic })),
      deductions: scopedLines.map(({ agreementId: id, deductionsTotalAtomic }) => ({ agreementId: id, deductionsTotalAtomic })),
      net: scopedLines.map(({ agreementId: id, netAtomic }) => ({ agreementId: id, netAtomic })),
      token: [...new Set(scopedLines.map(({ token }) => token))],
      schedule: scopedLines.map(({ agreementId: id }) => {
        const scopedAgreement = agreements.get(id)?.agreement;
        return {
          agreementId: id,
          schedule: scopedAgreement?.agreementVersion === "payo-agreement-v2"
            ? scopedAgreement.paymentPlan
            : scopedAgreement?.schedule,
        };
      }),
      classification: scopedLines.map(({ agreementId: id }) => {
        const scopedAgreement = agreements.get(id)?.agreement;
        return {
          agreementId: id,
          declared: scopedAgreement?.classification,
          factsCommitment: scopedAgreement?.classificationFactsCommitment,
        };
      }),
      aggregate: [...totals.entries()].map(([token, total]) => ({ token, netAtomic: total.toString(), lineCount: scopedLines.length })),
      settlement: {
        state: "onchain_verified",
        transactionHash: verificationTransaction.transactionHash,
        blockNumber: verificationTransaction.blockNumber,
      },
      exception: undefined,
    };
    const disclosedFields = Object.fromEntries(
      grant.fieldScope.map((field) => [field, availableFields[field]]),
    ) as RecipientProofPackagePayload["disclosedFields"];
    const opening = lineIndex === undefined
      ? undefined
      : proofCommitter.buildProofFixedMerkleMembership(leaves, lineIndex);
    if (opening && BigInt(opening.root) !== BigInt(fixture.payroll.manifestRoot)) {
      throw new Error(`The ${packageKey} line opening does not reconstruct the on-chain matrix manifest root.`);
    }
    const payload: RecipientProofPackagePayload = {
      packageVersion: "payo-recipient-proof-package-v1",
      grant,
      journal,
      proofPackage,
      verification: {
        verified: true,
        verificationState: "onchain_verified",
        verifierAddress: matrixEvidence.payoSealAddress,
        proofVersion: "2",
        publicInputsHash: hashCanonicalJson(proofPackage.publicInputs),
        verificationTransactionHash: verificationTransaction.transactionHash,
        checkedAt: matrixEvidence.generatedAt,
      },
      starknetReceipt: {
        transactionHash: verificationTransaction.transactionHash,
        finalStatus: matrixEvidence.finalStatus,
        sealTransactionHash: matrixEvidence.transactions.privateSettlementAndSeal,
        verificationTransactionHash: verificationTransaction.transactionHash,
        verificationBlockNumber: verificationTransaction.blockNumber,
      },
      disclosedFields,
      ...(opening && lineIndex !== undefined ? {
        lineOpening: {
          manifestRoot: opening.root,
          lineCommitment: opening.leaf,
          lineIndex,
          siblings: opening.siblings,
          pathBits: opening.pathBits,
        },
      } : {}),
    };
    const encryptedPackage = createRecipientEncryptedProofPackage({ payload, recipient, at: now });
    const verified = await verifyRecipientProofPackageOffline({ encryptedPackage, recipient, currentGrant: grant, at: now });
    const [wrongRecipientRejected, expiredGrantRejected, revokedGrantRejected] = await Promise.all([
      rejected(() => verifyRecipientProofPackageOffline({ encryptedPackage, recipient: stranger, currentGrant: grant, at: now })),
      rejected(() => verifyRecipientProofPackageOffline({
        encryptedPackage,
        recipient,
        currentGrant: grant,
        at: new Date(new Date(grant.expiresAt).getTime() + 1),
      })),
      rejected(() => verifyRecipientProofPackageOffline({
        encryptedPackage,
        recipient,
        currentGrant: { ...grant, revokedAt: now.toISOString() },
        at: now,
      })),
    ]);
    if (!wrongRecipientRejected || !expiredGrantRejected || !revokedGrantRejected) {
      throw new Error(`A ${scope} proof-package negative check unexpectedly succeeded.`);
    }
    const relativePackagePath = `evidence/phase3-devnet-fixtures/advanced-matrix-${outputStem}-package.json`;
    const encryptedPackagePath = resolve(root, relativePackagePath);
    await writeFile(encryptedPackagePath, `${JSON.stringify(encryptedPackage, null, 2)}\n`, { mode: 0o600 });
    packageEvidence.push({
      scope,
      ...(workflow ? { workflow, agreementId: scopedLines[0].agreementId, lineIndex } : {}),
      grantId: grant.id,
      recipientPrincipalId: recipient.principalId,
      recipientPublicKey: recipient.publicKey,
      recipientPrivateKeyPersisted: false,
      packageCommitment: encryptedPackage.packageCommitment,
      verified,
      wrongRecipientRejected,
      expiredGrantRejected,
      revokedGrantRejected,
      encryptedPackagePath: relativePackagePath,
    });
  }
  const statutoryWorker = packageEvidence.find((entry) => entry.workflow === "statutory-fx-classification");
  if (!statutoryWorker || statutoryWorker.lineIndex === undefined) {
    throw new Error("The statutory worker disclosure evidence is missing.");
  }
  const evidence = {
    schemaVersion: 1,
    generatedAt: now.toISOString(),
    passed: true,
    sourceMatrixEvidence: "evidence/phase3-private-settlement-devnet.json",
    manifestRoot: fixture.payroll.manifestRoot,
    workerLineIndex: statutoryWorker.lineIndex,
    workflowWorkerPackageCount: workerPackages.length,
    packages: packageEvidence,
  };
  await writeFile(outputPath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  console.log(JSON.stringify(evidence, null, 2));
}

const organizationId = phase3UiOrganizationId;

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
