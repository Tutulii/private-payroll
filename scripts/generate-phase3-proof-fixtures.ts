import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { generateVaultPrincipal, encryptVaultRecord } from "@/lib/crypto/vault";
import { buildFxSnapshot } from "@/lib/domain/fx";
import type { EmploymentAgreement } from "@/lib/domain/obligations";
import { advancedPlanProofCommitment } from "@/lib/proof/advanced-plan-commitment";
import {
  PAYO_NET_INVOICE_POLICY,
  serializePayrollIntegrityBuildRequest,
} from "@/lib/proof/input-builder";
import { provePayrollOnSelfHostedNode } from "@/lib/proof/server-prover";

const outputDirectory = resolve(process.cwd(), "evidence/phase3-devnet-fixtures");

function checkpointAgreement(): Extract<EmploymentAgreement, { agreementVersion: "payo-agreement-v2" }> {
  return {
    agreementVersion: "payo-agreement-v2",
    id: "phase3-advanced-checkpoint",
    organizationId: "phase3-fixture-organization",
    principalKind: "human",
    classification: "contractor",
    classificationFactsCommitment: `0x${"12".repeat(32)}`,
    jurisdictionCode: "US",
    settlementToken: "USDC",
    earningsAtomic: ["500"],
    schedule: {
      kind: "stream",
      startsAt: "1970-01-01T00:00:00.000Z",
      endsAt: "1970-01-01T00:33:20.000Z",
      totalAtomic: "1000",
      claimedAtomic: "0",
    },
    statutoryPolicy: {
      catalogRoot: `0x${"11".repeat(32)}`,
      policyId: PAYO_NET_INVOICE_POLICY.id,
      policyVersion: PAYO_NET_INVOICE_POLICY.revision,
    },
    paymentPlan: {
      planVersion: "payo-payment-plan-v1",
      kind: "checkpoint_stream",
      startsAt: "1970-01-01T00:00:00.000Z",
      endsAt: "1970-01-01T00:33:20.000Z",
      totalAtomic: "1000",
      settledAtomic: "0",
      minimumCheckpointSeconds: 300,
      checkpoint: {
        sequence: 1,
        checkpointAt: "1970-01-01T00:16:40.000Z",
        cumulativeEntitlementAtomic: "500",
        attestationCommitment: `0x${"13".repeat(32)}`,
      },
    },
    planSalt: `0x${"14".repeat(32)}`,
  };
}

function snapshot() {
  return buildFxSnapshot({
    baseToken: "USDC",
    referenceCurrency: "USD",
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 300,
    minimumSources: 3,
    aggregatedSourceCount: 5,
    quotes: [{ source: "pragma-usdc", priceAtomic: "1000000", observedAt: "1970-01-01T00:16:30.000Z" }],
    now: new Date("1970-01-01T00:16:40.000Z"),
  });
}

function unpack(calldata: readonly string[]) {
  const baseLength = Number(BigInt(calldata[0]));
  if (!Number.isSafeInteger(baseLength) || baseLength <= 0 || baseLength + 1 >= calldata.length) {
    throw new Error("The advanced proof returned malformed composite calldata.");
  }
  return {
    base: calldata.slice(1, baseLength + 1),
    advanced: calldata.slice(baseLength + 1),
  };
}

async function main() {
  const agreement = checkpointAgreement();
  const scheduleCommitment = await advancedPlanProofCommitment(agreement);
  const payroll = serializePayrollIntegrityBuildRequest({
    chainId: process.env.PAYO_PHASE3_CHAIN_ID ?? "0x1",
    sealAddress: process.env.PAYO_PHASE3_SEAL_ADDRESS ?? "0x12345",
    organizationSecret: `0x${"15".repeat(32)}`,
    cycleId: "phase3-advanced-checkpoint-proof",
    revision: 1,
    validityStart: 1_000n,
    validityExpiry: 2_000n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: [snapshot()],
    lines: [{
      agreementId: agreement.id,
      recipientAddress: "0x456",
      recipientSalt: `0x${"16".repeat(32)}`,
      agreementSalt: `0x${"17".repeat(32)}`,
      lineSalt: `0x${"18".repeat(32)}`,
      token: "USDC",
      earningsAtomic: agreement.earningsAtomic,
      deductionsAtomic: [],
      policyId: PAYO_NET_INVOICE_POLICY.id,
      scheduleCommitment,
      dueAt: 1_000n,
      validUntil: 2_000n,
      classification: { declared: 2, score: 2, employeeThreshold: 5 },
      fxFloorAtomic: "0",
      referenceCurrency: "USD",
    }],
  });
  const principal = generateVaultPrincipal("phase3-fixture-prover");
  const encryptedWitness = encryptVaultRecord(
    { advancedBuildInput: { payroll, agreements: [agreement] } },
    {
      schemaVersion: 1,
      organizationId: agreement.organizationId,
      recordType: "payroll-proof-request",
      recordId: "phase3-fixture-request",
      revision: 1,
    },
    [principal],
  );
  const proof = await provePayrollOnSelfHostedNode({
    requestId: "phase3-fixture-request",
    encryptedWitness,
    principal,
  });
  await mkdir(outputDirectory, { recursive: true });
  const summary = {
    generatedAt: new Date().toISOString(),
    circuitSha256: proof.circuitSha256,
    provingTimeMs: proof.provingTimeMs,
    shards: proof.shards.map((shard) => ({
      shardIndex: shard.shardIndex,
      calldataHash: shard.calldataHash,
      publicInputs: shard.publicInputs,
      packedCalldataFelts: shard.proofCalldata.length,
      baseCalldataFelts: unpack(shard.proofCalldata).base.length,
      advancedCalldataFelts: unpack(shard.proofCalldata).advanced.length,
    })),
  };
  await writeFile(resolve(outputDirectory, "advanced-proof.json"), `${JSON.stringify(summary, null, 2)}\n`);
  for (const shard of proof.shards) {
    const parts = unpack(shard.proofCalldata);
    await Promise.all([
      writeFile(resolve(outputDirectory, `advanced-packed-shard-${shard.shardIndex}.txt`), `${shard.proofCalldata.join("\n")}\n`),
      writeFile(resolve(outputDirectory, `payroll-base-shard-${shard.shardIndex}.txt`), `${parts.base.join("\n")}\n`),
      writeFile(resolve(outputDirectory, `advanced-only-shard-${shard.shardIndex}.txt`), `${parts.advanced.join("\n")}\n`),
    ]);
  }
  console.log(JSON.stringify(summary, null, 2));
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
