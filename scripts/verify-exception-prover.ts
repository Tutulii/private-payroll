import { encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import type { InputMap } from "@noir-lang/noir_js";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { claimCapabilityCommitmentV2 } from "@/lib/domain/exception-protocol";
import { buildFxSnapshot } from "@/lib/domain/fx";
import {
  buildObligationSnapshotLinkInputs,
  buildWageClaimV2Inputs,
  buildWageRemediationV2Inputs,
} from "@/lib/proof/exception-input-builder";
import {
  buildPayrollIntegrityInputs,
  PAYO_NET_INVOICE_POLICY,
} from "@/lib/proof/input-builder";
import {
  provePayoExceptionOnSelfHostedNode,
} from "@/lib/proof/server-prover";
import type {
  EncryptedPayrollWitness,
  ExceptionCircuitProfile,
} from "@/lib/proof/protocol";

const organizationId = "018f1000-0000-7000-8000-000000000001";
const chainId = "0x1";
const sealAddress = "0x12345";
const capabilitySecret = `0x${"91".repeat(32)}`;
const principal = generateVaultPrincipal("exception-prover:fixture");

function fx(
  token: "STRK" | "USDC",
  priceAtomic: string,
  observedAtSeconds: number,
) {
  const observedAt = new Date(observedAtSeconds * 1_000).toISOString();
  return buildFxSnapshot({
    baseToken: token,
    referenceCurrency: "USD",
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 300,
    minimumSources: 3,
    feedId: `pragma:${token}/USD:${observedAtSeconds}`,
    quotes: ["a", "b", "c"].map((source) => ({
      source: `pragma-${token.toLowerCase()}-${source}`,
      priceAtomic,
      observedAt,
    })),
    now: new Date((observedAtSeconds + 1) * 1_000),
  });
}

async function prove(
  profile: ExceptionCircuitProfile,
  circuitInput: InputMap,
  suffix: string,
  fixtureName: string = profile,
) {
  const requestId = `018f1000-000${suffix}-7000-8000-000000000001`;
  const payload: EncryptedPayrollWitness = { exceptionCircuitProfile: profile, circuitInput };
  const encryptedWitness = encryptVaultRecord(payload, {
    schemaVersion: 1,
    organizationId,
    recordType: "payroll-proof-request",
    recordId: requestId,
    revision: 1,
  }, [principal]);
  const result = await provePayoExceptionOnSelfHostedNode({
    requestId,
    encryptedWitness,
    principal,
  });
  if (result.profile !== profile || result.proof.proofCalldata.length === 0) {
    throw new Error(`${profile} did not produce canonical Starknet calldata.`);
  }
  return {
    profile,
    fixtureName,
    circuitSha256: result.circuitSha256,
    provingTimeMs: result.provingTimeMs,
    calldataFelts: result.proof.proofCalldata.length,
    calldataHash: result.proof.calldataHash,
    proofCalldata: result.proof.proofCalldata,
  };
}

async function main() {
const payroll = await buildPayrollIntegrityInputs({
  chainId,
  sealAddress,
  organizationSecret: `0x${"55".repeat(32)}`,
  cycleId: "exception-real-prover-fixture",
  revision: 1,
  validityStart: 1_000n,
  validityExpiry: 1_100n,
  policies: [PAYO_NET_INVOICE_POLICY],
  fxSnapshots: [fx("USDC", "1000000", 990)],
  lines: [{
    agreementId: "missing-usdc",
    recipientAddress: "0x456",
    recipientSalt: `0x${"11".repeat(32)}`,
    agreementSalt: `0x${"22".repeat(32)}`,
    lineSalt: `0x${"33".repeat(32)}`,
    token: "USDC",
    earningsAtomic: ["1000000"],
    deductionsAtomic: [],
    policyId: PAYO_NET_INVOICE_POLICY.id,
    scheduleCommitment: `0x${"44".repeat(32)}`,
    dueAt: 1_000n,
    validUntil: 2_000n,
    classification: { declared: 2, score: 2, employeeThreshold: 5 },
    fxFloorAtomic: "0",
    referenceCurrency: "USD",
  }],
});
const snapshot = await buildObligationSnapshotLinkInputs({
  chainId,
  sealAddress,
  ownerAddress: "0xabc",
  payroll,
  claimCapabilityCommitments: {
    "missing-usdc": claimCapabilityCommitmentV2(capabilitySecret),
  },
  graceEndsAt: 1_100n,
  claimEndsAt: 1_500n,
  validityStart: 999n,
  validityExpiry: 1_000n,
});
const claim = await buildWageClaimV2Inputs({
  chainId,
  sealAddress,
  snapshot,
  agreementId: "missing-usdc",
  claimCapabilitySecret: capabilitySecret,
  claimKind: "missing_obligation",
  evidence: { source: "unsettled_period" },
  validityStart: 1_150n,
  validityExpiry: 1_200n,
});
const remediation = await buildWageRemediationV2Inputs({
  chainId,
  sealAddress,
  claim,
  remediationSecret: `0x${"92".repeat(32)}`,
  actionSalt: `0x${"93".repeat(32)}`,
  amountAtomic: "1000000",
  token: "USDC",
  validityStart: 1_201n,
  validityExpiry: 1_250n,
});



const fxCapabilitySecret = `0x${"94".repeat(32)}`;
const fxPayroll = await buildPayrollIntegrityInputs({
  chainId,
  sealAddress,
  organizationSecret: `0x${"56".repeat(32)}`,
  cycleId: "exception-fx-floor-prover-fixture",
  revision: 1,
  validityStart: 1_000n,
  validityExpiry: 1_100n,
  policies: [PAYO_NET_INVOICE_POLICY],
  fxSnapshots: [fx("STRK", "2000000", 990)],
  lines: [{
    agreementId: "fx-strk",
    recipientAddress: "0x457",
    recipientSalt: `0x${"12".repeat(32)}`,
    agreementSalt: `0x${"23".repeat(32)}`,
    lineSalt: `0x${"34".repeat(32)}`,
    token: "STRK",
    earningsAtomic: ["1000000000000000000"],
    deductionsAtomic: [],
    policyId: PAYO_NET_INVOICE_POLICY.id,
    scheduleCommitment: `0x${"45".repeat(32)}`,
    dueAt: 1_000n,
    validUntil: 2_000n,
    classification: { declared: 2, score: 2, employeeThreshold: 5 },
    fxFloorAtomic: "1500000",
    referenceCurrency: "USD",
  }],
});
const fxSnapshotPlan = await buildObligationSnapshotLinkInputs({
  chainId,
  sealAddress,
  ownerAddress: "0xabc",
  payroll: fxPayroll,
  claimCapabilityCommitments: {
    "fx-strk": claimCapabilityCommitmentV2(fxCapabilitySecret),
  },
  graceEndsAt: 1_100n,
  claimEndsAt: 1_500n,
  validityStart: 999n,
  validityExpiry: 1_000n,
});
const fxClaim = await buildWageClaimV2Inputs({
  chainId,
  sealAddress,
  snapshot: fxSnapshotPlan,
  agreementId: "fx-strk",
  claimCapabilitySecret: fxCapabilitySecret,
  claimKind: "below_committed_floor",
  evidence: {
    source: "employer_statement",
    observedAt: 1_150n,
    availabilityCommitment: `0x${"77".repeat(32)}`,
    target: {
      kind: "line",
      deductionsAtomic: [],
      lineSalt: `0x${"66".repeat(32)}`,
      classificationTreatment: 2,
      finalIncludedMask: 0,
      referenceValueAtomic: "1000000",
    },
    fxSnapshots: [fx("STRK", "1000000", 1_140)],
  },
  validityStart: 1_150n,
  validityExpiry: 1_200n,
});
const fxRemediation = await buildWageRemediationV2Inputs({
  chainId,
  sealAddress,
  claim: fxClaim,
  remediationSecret: `0x${"95".repeat(32)}`,
  actionSalt: `0x${"96".repeat(32)}`,
  amountAtomic: "500000000000000000",
  token: "STRK",
  fxSnapshots: [fx("STRK", "1000000", 1_200)],
  selectedFxIndex: 0,
  validityStart: 1_201n,
  validityExpiry: 1_250n,
});

const finalCapabilitySecret = `0x${"97".repeat(32)}`;
const finalPayroll = await buildPayrollIntegrityInputs({
  chainId,
  sealAddress,
  organizationSecret: `0x${"57".repeat(32)}`,
  cycleId: "exception-final-pay-prover-fixture",
  revision: 1,
  validityStart: 1_000n,
  validityExpiry: 1_100n,
  policies: [PAYO_NET_INVOICE_POLICY],
  fxSnapshots: [fx("USDC", "1000000", 990)],
  lines: [{
    agreementId: "final-usdc",
    recipientAddress: "0x458",
    recipientSalt: `0x${"13".repeat(32)}`,
    agreementSalt: `0x${"24".repeat(32)}`,
    lineSalt: `0x${"35".repeat(32)}`,
    token: "USDC",
    earningsAtomic: ["1000000"],
    deductionsAtomic: [],
    policyId: PAYO_NET_INVOICE_POLICY.id,
    scheduleCommitment: `0x${"46".repeat(32)}`,
    dueAt: 1_000n,
    validUntil: 2_000n,
    classification: { declared: 2, score: 2, employeeThreshold: 5 },
    finalPay: {
      requiredMask: 3,
      includedMask: 3,
      componentsAtomic: ["800000", "200000"],
    },
    fxFloorAtomic: "0",
    referenceCurrency: "USD",
  }],
});
const finalSnapshotPlan = await buildObligationSnapshotLinkInputs({
  chainId,
  sealAddress,
  ownerAddress: "0xabc",
  payroll: finalPayroll,
  claimCapabilityCommitments: {
    "final-usdc": claimCapabilityCommitmentV2(finalCapabilitySecret),
  },
  graceEndsAt: 1_100n,
  claimEndsAt: 1_500n,
  validityStart: 999n,
  validityExpiry: 1_000n,
});
const finalClaim = await buildWageClaimV2Inputs({
  chainId,
  sealAddress,
  snapshot: finalSnapshotPlan,
  agreementId: "final-usdc",
  claimCapabilitySecret: finalCapabilitySecret,
  claimKind: "incomplete_final_pay",
  evidence: {
    source: "employer_statement",
    observedAt: 1_150n,
    availabilityCommitment: `0x${"76".repeat(32)}`,
    target: {
      kind: "line",
      deductionsAtomic: [],
      lineSalt: `0x${"65".repeat(32)}`,
      classificationTreatment: 2,
      finalIncludedMask: 1,
      referenceValueAtomic: "0",
    },
  },
  validityStart: 1_150n,
  validityExpiry: 1_200n,
});

const results = [];
results.push(await prove("obligation_snapshot_v5", snapshot.circuitInputs, "1"));
results.push(await prove("wage_claim_v6", claim.circuitInputs, "2"));
results.push(await prove("wage_remediation_v7", remediation.circuitInputs, "3"));
results.push(await prove(
  "wage_claim_v6",
  fxClaim.circuitInputs,
  "4",
  "wage_claim_v6_fx_floor",
));
results.push(await prove(
  "wage_remediation_v7",
  fxRemediation.circuitInputs,
  "5",
  "wage_remediation_v7_fx_floor",
));
results.push(await prove(
  "wage_claim_v6",
  finalClaim.circuitInputs,
  "6",
  "wage_claim_v6_final_pay",
));
const resultSummaries = results.map((result) => ({
  profile: result.profile,
  fixtureName: result.fixtureName,
  circuitSha256: result.circuitSha256,
  provingTimeMs: result.provingTimeMs,
  calldataFelts: result.calldataFelts,
  calldataHash: result.calldataHash,
}));
const fixtureDirectory = process.env.PAYO_EXCEPTION_PROOF_FIXTURE_DIR?.trim();
if (fixtureDirectory) {
  const outputDirectory = resolve(fixtureDirectory);
  await mkdir(outputDirectory, { recursive: true });
  for (const result of results) {
    await writeFile(
      resolve(outputDirectory, `${result.fixtureName}.txt`),
      `${result.proofCalldata.join("\n")}\n`,
      "utf8",
    );
  }
  await writeFile(
    resolve(outputDirectory, "manifest.json"),
    `${JSON.stringify({
      generatedBy: "scripts/verify-exception-prover.ts",
      chainId,
      sealAddress,
      fixtures: resultSummaries,
    }, null, 2)}\n`,
    "utf8",
  );
}
process.stdout.write(`${JSON.stringify({
  passed: true,
  fixturesWrittenTo: fixtureDirectory ? resolve(fixtureDirectory) : null,
  results: resultSummaries,
}, null, 2)}\n`);
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
