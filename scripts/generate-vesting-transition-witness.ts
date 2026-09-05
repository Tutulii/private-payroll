import { readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { buildFxSnapshot } from "@/lib/domain/fx";
import {
  buildExternalAttestationCatalog,
  externalAttestationFactMask,
  jurisdictionCommitment,
  PAYO_EXTERNAL_ATTESTATION_ACTIVE_STATUS,
  signExternalAttestation,
} from "@/lib/domain/external-attestation";
import type { EmploymentAgreement } from "@/lib/domain/obligations";
import { toBase64, toHex } from "@/lib/crypto/encoding";
import { ed25519 } from "@noble/curves/ed25519.js";
import { advancedPlanProofCommitment } from "@/lib/proof/advanced-plan-commitment";
import { buildPayrollIntegrityInputs, PAYO_NET_INVOICE_POLICY } from "@/lib/proof/input-builder";
import { orderedVestingTransitionPublicInputs } from "@/lib/proof/starknet-calldata";
import { buildVestingTransitionInputs } from "@/lib/proof/vesting-transition-input";

const hex = (byte: string): `0x${string}` => `0x${byte.repeat(64)}`;

function vestingAgreement(): Extract<EmploymentAgreement, { agreementVersion: "payo-agreement-v2" }> {
  return {
    agreementVersion: "payo-agreement-v2",
    id: "private-vesting-v3-real-proof",
    organizationId: "organization-vesting-v3",
    principalKind: "human",
    classification: "contractor",
    classificationFactsCommitment: hex("1"),
    jurisdictionCode: "US",
    settlementToken: "STRK",
    earningsAtomic: ["500"],
    schedule: {
      kind: "vesting",
      startsAt: "1970-01-01T00:01:40.000Z",
      cliffAt: "1970-01-01T00:03:20.000Z",
      endsAt: "1970-01-01T00:18:20.000Z",
      totalAtomic: "1000",
      releasedAtomic: "0",
    },
    statutoryPolicy: {
      catalogRoot: hex("2"),
      policyId: PAYO_NET_INVOICE_POLICY.id,
      policyVersion: PAYO_NET_INVOICE_POLICY.revision,
    },
    paymentPlan: {
      planVersion: "payo-payment-plan-v1",
      kind: "private_vesting",
      startsAt: "1970-01-01T00:01:40.000Z",
      cliffAt: "1970-01-01T00:03:20.000Z",
      releaseAt: "1970-01-01T00:10:00.000Z",
      endsAt: "1970-01-01T00:18:20.000Z",
      totalAtomic: "1000",
      releasedAtomic: "0",
      releaseSequence: 0,
    },
    planSalt: hex("3"),
  };
}

function orderedPublicInputs(
  input: Awaited<ReturnType<typeof buildVestingTransitionInputs>>["publicInputs"][number],
): string[] {
  return orderedVestingTransitionPublicInputs(input);
}

async function main() {
  const root = resolve(import.meta.dirname, "..");
  const circuitPath = resolve(root, "public/circuits/vesting_transition-v3.json");
  const circuit = JSON.parse(readFileSync(circuitPath, "utf8")) as CompiledCircuit;
  const agreement = vestingAgreement();
  const scheduleCommitment = await advancedPlanProofCommitment(agreement);
  const fx = buildFxSnapshot({
    baseToken: "STRK",
    referenceCurrency: "USD",
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 300,
    minimumSources: 3,
    aggregatedSourceCount: 3,
    quotes: [{
      source: "pragma-strk",
      priceAtomic: "100000",
      observedAt: "1970-01-01T00:09:50.000Z",
    }],
    now: new Date("1970-01-01T00:10:00.000Z"),
  });
  const payroll = await buildPayrollIntegrityInputs({
    chainId: "0x534e5f4d41494e",
    sealAddress: "0x456",
    organizationSecret: hex("4"),
    cycleId: "vesting-v3-real-proof",
    revision: 1,
    validityStart: 600n,
    validityExpiry: 900n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: [fx],
    lines: [{
      agreementId: agreement.id,
      recipientAddress: "0x789",
      recipientSalt: hex("5"),
      agreementSalt: hex("6"),
      lineSalt: hex("7"),
      token: "STRK",
      earningsAtomic: agreement.earningsAtomic,
      deductionsAtomic: [],
      policyId: PAYO_NET_INVOICE_POLICY.id,
      scheduleCommitment,
      dueAt: 600n,
      validUntil: 900n,
      classification: { declared: 2, score: 2, employeeThreshold: 5 },
      fxFloorAtomic: "0",
      referenceCurrency: "USD",
    }],
  });
  const issuerSecretKey = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const subjectCommitment = toHex(Uint8Array.from(
    payroll.proofBindings[0].agreement.recipient_commitment,
  ));
  const signedAttestation = signExternalAttestation({
    attestationVersion: "payo-external-attestation-v1",
    subjectCommitment,
    factMask: externalAttestationFactMask.residency
      | externalAttestationFactMask.employment_status
      | externalAttestationFactMask.tax_status,
    jurisdictionCode: "US",
    jurisdictionCommitment: jurisdictionCommitment("US"),
    policyRoot: payroll.policyRoot,
    statusCommitment: PAYO_EXTERNAL_ATTESTATION_ACTIVE_STATUS,
    validFrom: "500",
    validUntil: "1000",
    nonce: hex("b"),
  }, issuerSecretKey);
  const attestationCatalog = await buildExternalAttestationCatalog({
    attestations: [signedAttestation],
    trustedIssuerPublicKeys: [toBase64(ed25519.getPublicKey(issuerSecretKey))],
  });
  const built = await buildVestingTransitionInputs({
    payroll,
    agreement,
    ownerAddress: "0x123",
    periodStart: 1n,
    periodEnd: 1_000n,
    previousStateSalt: hex("8"),
    nextStateSalt: hex("9"),
    totalsSalt: hex("a"),
    attestation: {
      agreementId: agreement.id,
      catalogRoot: attestationCatalog.root,
      signed: attestationCatalog.entries[0].signed,
      siblings: attestationCatalog.entries[0].siblings,
      pathBits: attestationCatalog.entries[0].pathBits,
    },
  });
  const outputDirectory = resolve(root, "circuits/vesting_transition/target/real-proof-fixture");
  await mkdir(outputDirectory, { recursive: true, mode: 0o700 });
  const noir = new Noir(circuit);
  for (let shard = 0; shard < built.circuitInputs.length; shard += 1) {
    const { witness } = await noir.execute(built.circuitInputs[shard]);
    if (witness.byteLength === 0) throw new Error(`Vesting shard ${shard} produced an empty witness.`);
    await writeFile(resolve(outputDirectory, `witness-${shard}.gz`), witness, { mode: 0o600 });
    witness.fill(0);
  }
  await writeFile(
    resolve(outputDirectory, "bindings.json"),
    JSON.stringify({
      proofVersion: 3,
      entryKind: built.entryKind,
      scheduleId: built.scheduleId,
      previousStateCommitment: built.previousStateCommitment,
      nextStateCommitment: built.nextStateCommitment,
      releaseNullifier: built.releaseNullifier,
      bookEntryCommitment: built.bookEntryCommitment,
      attestationRoot: built.bookEntry.attestationRoot,
      publicInputs: built.publicInputs.map(orderedPublicInputs),
    }, null, 2) + "\n",
    { mode: 0o600 },
  );
  process.stdout.write(JSON.stringify({
    generated: true,
    shards: built.circuitInputs.length,
    scheduleId: built.scheduleId,
    bookEntryCommitment: built.bookEntryCommitment,
    outputDirectory,
  }, null, 2) + "\n");
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
