import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { InputMap } from "@noir-lang/noir_js";
import { encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { buildPayrollIntegrityInputsFromSerialized } from "@/lib/proof/input-builder";
import { provePayrollOnSelfHostedNode } from "@/lib/proof/server-prover";
import { buildWageClaimInputs, buildWageRemediationInputs } from "@/lib/proof/wage-claim-input";
import { loadPhase3ExceptionUiFixture } from "./lib/phase3-exception-ui-fixture";

const outputDirectory = resolve(process.cwd(), "evidence/phase3-devnet-fixtures");
let organizationId = "";

async function proveProfile(input: {
  profile: "wage_claim" | "wage_remediation";
  circuitInputs: [InputMap, InputMap];
}) {
  const principal = generateVaultPrincipal(`phase3-${input.profile}-fixture`);
  const requestId = `phase3-${input.profile}-fixture`;
  const encryptedWitness = encryptVaultRecord(
    { circuitProfile: input.profile, circuitInputs: input.circuitInputs },
    {
      schemaVersion: 1,
      organizationId,
      recordType: "payroll-proof-request",
      recordId: requestId,
      revision: 1,
    },
    [principal],
  );
  return provePayrollOnSelfHostedNode({ requestId, encryptedWitness, principal });
}

async function writeProof(profile: "claim" | "remediation", proof: Awaited<ReturnType<typeof provePayrollOnSelfHostedNode>>) {
  const summary = {
    generatedAt: new Date().toISOString(),
    circuitSha256: proof.circuitSha256,
    provingTimeMs: proof.provingTimeMs,
    shards: proof.shards.map((shard) => ({
      shardIndex: shard.shardIndex,
      calldataHash: shard.calldataHash,
      publicInputs: shard.publicInputs,
      calldataFelts: shard.proofCalldata.length,
    })),
  };
  await writeFile(resolve(outputDirectory, `${profile}-proof.json`), `${JSON.stringify(summary, null, 2)}\n`);
  await Promise.all(proof.shards.map((shard) =>
    writeFile(resolve(outputDirectory, `${profile}-shard-${shard.shardIndex}.txt`), `${shard.proofCalldata.join("\n")}\n`)));
  return summary;
}

async function main() {
  const origin = await loadPhase3ExceptionUiFixture();
  organizationId = origin.organizationId;
  const payroll = await buildPayrollIntegrityInputsFromSerialized(origin.payrollRequest);
  const validityStart = BigInt(origin.payrollRequest.validityStart);
  const validityExpiry = BigInt(origin.payrollRequest.validityExpiry);
  const claim = await buildWageClaimInputs({
    payroll,
    agreementId: origin.claimDraft.agreementId,
    claimKind: origin.claimDraft.claimKind,
    claimSalt: origin.claimDraft.claimSalt as `0x${string}`,
    validityStart,
    validityExpiry,
    disputedReferenceValueAtomic: origin.claimDraft.disputedReferenceValueAtomic,
    disputedFinalIncludedMask: origin.claimDraft.disputedFinalIncludedMask,
  });
  if (
    BigInt(claim.claimNullifier) !== BigInt(origin.submittedClaim.claimNullifier ?? "0")
    || claim.shortfallAtomic !== origin.submittedClaim.shortfallAtomic
    || claim.token !== origin.submittedClaim.token
  ) throw new Error("The Activity-originated proved claim fields do not match the rebuilt witness.");
  const remediation = await buildWageRemediationInputs({
    claim,
    amountAtomic: origin.remediationDraft.amountAtomic ?? "0",
    token: origin.remediationDraft.token ?? claim.token,
    remediationSalt: origin.remediationDraft.remediationSalt as `0x${string}`,
    validityStart,
    validityExpiry,
  });
  await mkdir(outputDirectory, { recursive: true });
  const claimProof = await proveProfile({
    profile: "wage_claim",
    circuitInputs: claim.witness.circuitInputs,
  });
  const remediationProof = await proveProfile({
    profile: "wage_remediation",
    circuitInputs: remediation.witness.circuitInputs,
  });
  const summary = {
    claim: await writeProof("claim", claimProof),
    remediation: await writeProof("remediation", remediationProof),
    linkage: {
      claimNullifier: claim.claimNullifier,
      disputedManifestRoot: claim.disputedManifestRoot,
      remediationManifestRoot: remediation.remediationManifestRoot,
      shortfallAtomic: claim.shortfallAtomic,
      token: claim.token,
      recipientAddress: origin.recipientAddress,
      agreementId: origin.agreementRecord.agreement.id,
      claimId: origin.claimDraft.id,
      remediationId: origin.remediationDraft.id,
      formInputCommitments: origin.formInputCommitments,
      sourceArtifact: "evidence/phase3-devnet-fixtures/claim-remediation-ui-origin.json",
    },
  };
  await writeFile(resolve(outputDirectory, "claim-remediation-linkage.json"), `${JSON.stringify(summary.linkage, null, 2)}\n`);
  console.log(JSON.stringify(summary, null, 2));
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
