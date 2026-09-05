import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519.js";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { describe, expect, it } from "vitest";
import { buildFxSnapshot } from "@/lib/domain/fx";
import {
  buildExternalAttestationCatalog,
  externalAttestationFactMask,
  jurisdictionCommitment,
  PAYO_EXTERNAL_ATTESTATION_ACTIVE_STATUS,
  signExternalAttestation,
} from "@/lib/domain/external-attestation";
import { toBase64, toHex } from "@/lib/crypto/encoding";
import { buildPayrollIntegrityInputs, PAYO_NET_INVOICE_POLICY } from "./input-builder";
import { buildUniversalPayrollBookInput } from "./universal-payroll-book-input";

const hex = (byte: string): `0x${string}` => `0x${byte.repeat(64)}`;

async function payroll(lineCount = 26) {
  const now = 1_800_000_000n;
  const fx = buildFxSnapshot({
    baseToken: "STRK",
    referenceCurrency: "USD",
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 300,
    minimumSources: 3,
    aggregatedSourceCount: 3,
    quotes: [{ source: "pragma", priceAtomic: "100000", observedAt: new Date(Number(now - 10n) * 1_000).toISOString() }],
    now: new Date(Number(now) * 1_000),
  });
  return buildPayrollIntegrityInputs({
    chainId: "0x534e5f4d41494e",
    sealAddress: "0x456",
    organizationSecret: hex("1"),
    cycleId: "universal-book-test",
    revision: 1,
    validityStart: now,
    validityExpiry: now + 300n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: [fx],
    lines: Array.from({ length: lineCount }, (_, index) => ({
      agreementId: `agreement-${index.toString().padStart(2, "0")}`,
      recipientAddress: `0x${(index + 100).toString(16)}`,
      recipientSalt: hex("2"),
      agreementSalt: `0x${(10_000 + index).toString(16).padStart(64, "0")}` as `0x${string}`,
      lineSalt: `0x${(20_000 + index).toString(16).padStart(64, "0")}` as `0x${string}`,
      token: "STRK" as const,
      earningsAtomic: [(100 + index).toString()],
      deductionsAtomic: [],
      policyId: PAYO_NET_INVOICE_POLICY.id,
      scheduleCommitment: hex("3"),
      dueAt: now,
      validUntil: now + 300n,
      classification: { declared: 2 as const, score: 2, employeeThreshold: 5 },
      referenceCurrency: "USD" as const,
    })),
  });
}

async function externalAttestationFor(
  subjectCommitment: string,
  policyRoot: string,
  options?: { agreementId?: string; factMask?: number },
) {
  const issuer = ed25519.keygen();
  const signed = signExternalAttestation({
    attestationVersion: "payo-external-attestation-v1",
    subjectCommitment: subjectCommitment as `0x${string}`,
    factMask: options?.factMask ?? (externalAttestationFactMask.residency
      | externalAttestationFactMask.employment_status
      | externalAttestationFactMask.tax_status),
    jurisdictionCode: "US",
    jurisdictionCommitment: jurisdictionCommitment("US"),
    policyRoot,
    statusCommitment: PAYO_EXTERNAL_ATTESTATION_ACTIVE_STATUS,
    validFrom: "1799999000",
    validUntil: "1800000600",
    nonce: hex("6"),
  }, issuer.secretKey);
  const catalog = await buildExternalAttestationCatalog({
    attestations: [signed],
    trustedIssuerPublicKeys: [toBase64(issuer.publicKey)],
  });
  return {
    agreementId: options?.agreementId ?? "agreement-00",
    catalogRoot: catalog.root,
    signed: catalog.entries[0].signed,
    siblings: catalog.entries[0].siblings,
    pathBits: catalog.entries[0].pathBits,
  };
}

describe("universal payroll-book proof input", () => {
  it("splits 26 contributors into two root-bound aggregate witnesses", async () => {
    const source = await payroll();
    const build = buildUniversalPayrollBookInput({
      payroll: source,
      entryKind: "ordinary",
      ownerAddress: "0x123",
      sourceSealAddress: "0x456",
      periodStart: 1_799_000_000n,
      periodEnd: 1_900_000_000n,
      totalsDisclosure: "public",
      totalsSalt: hex("5"),
      attestationRoot: hex("4"),
    });
    expect(build.shards.map(({ aggregate }) => aggregate.contributorCount)).toEqual([25, 1]);
    expect(build.entry.contributorCount).toBe(26);
    expect(build.entry.totals.STRK.grossAtomic).toBe(
      Array.from({ length: 26 }, (_, index) => 100n + BigInt(index)).reduce((sum, value) => sum + value, 0n).toString(),
    );
    expect(build.shards[0].agreementLeaves).toEqual(build.shards[1].agreementLeaves);
    expect(build.shards[1].lines.filter(({ active }) => active)).toHaveLength(1);

    const circuit = JSON.parse(readFileSync(
      new URL("../../circuits/vesting_transition/target/payo_vesting_transition.json", import.meta.url),
      "utf8",
    )) as CompiledCircuit;
    const noir = new Noir(circuit);
    const vestingInputs = await (await import("./vesting-transition-input")).buildPayrollBookEntryInputs({
      payroll: source,
      ownerAddress: "0x123",
      periodStart: 1_799_000_000n,
      periodEnd: 1_900_000_000n,
      totalsDisclosure: "public",
      totalsSalt: hex("5"),
    });
    for (const circuitInput of vestingInputs.circuitInputs) {
      const { witness } = await noir.execute(circuitInput);
      expect(witness.byteLength).toBeGreaterThan(0);
      witness.fill(0);
    }
    await expect(noir.execute({
      ...vestingInputs.circuitInputs[0],
      shard_0_contributor_count: "24",
    })).rejects.toThrow(/contributor count mismatch/);
    await expect(noir.execute({
      ...vestingInputs.circuitInputs[0],
      shard_0_strk_net: (
        BigInt(String(vestingInputs.circuitInputs[0].shard_0_strk_net)) + 1n
      ).toString(),
    })).rejects.toThrow(/STRK net mismatch/);
  }, 120_000);

  it("can publish only the count while keeping public token totals zero", async () => {
    const source = await payroll(1);
    const attestation = await externalAttestationFor(
      toHex(Uint8Array.from(source.proofBindings[0].agreement.recipient_commitment)),
      source.policyRoot,
    );
    const build = buildUniversalPayrollBookInput({
      payroll: source,
      entryKind: "agent",
      ownerAddress: "0x123",
      sourceSealAddress: "0x456",
      periodStart: 1_799_000_000n,
      periodEnd: 1_900_000_000n,
      totalsDisclosure: "hidden",
      totalsSalt: hex("5"),
      attestationRoot: attestation.catalogRoot,
    });
    expect(build.entry.contributorCount).toBe(1);
    expect(build.entry.totals.STRK.netAtomic).toBe("0");
    expect(build.shards[0].aggregate.STRK.netAtomic).toBe("100");
    expect(BigInt(build.entry.totalsCommitment)).not.toBe(0n);

    const circuit = JSON.parse(readFileSync(
      new URL("../../circuits/vesting_transition/target/payo_vesting_transition.json", import.meta.url),
      "utf8",
    )) as CompiledCircuit;
    const noir = new Noir(circuit);
    const proof = await (await import("./vesting-transition-input")).buildPayrollBookEntryInputs({
      payroll: source,
      entryKind: "agent",
      ownerAddress: "0x123",
      periodStart: 1_799_000_000n,
      periodEnd: 1_900_000_000n,
      totalsDisclosure: "hidden",
      totalsSalt: hex("5"),
      attestation,
    });
    for (const circuitInput of proof.circuitInputs) {
      const { witness } = await noir.execute(circuitInput);
      witness.fill(0);
    }
    const emptyEnabledFacts = structuredClone(proof.circuitInputs[0]);
    (emptyEnabledFacts.external_attestation as Record<string, unknown>).fact_mask = "0";
    await expect(noir.execute(emptyEnabledFacts)).rejects.toThrow(/does not cover every required fact/);
    const wrongMembership = structuredClone(proof.circuitInputs[0]);
    (wrongMembership.external_attestation_membership as Record<string, unknown>).siblings = Array(6).fill("1");
    await expect(noir.execute(wrongMembership)).rejects.toThrow(/root .* limb mismatch/);
    const wrongCircuitSubject = structuredClone(proof.circuitInputs[0]);
    (wrongCircuitSubject.external_attestation as Record<string, unknown>).subject_commitment = Array(32).fill(9);
    await expect(noir.execute(wrongCircuitSubject)).rejects.toThrow(/attestation subject mismatch/);
    const wrongCircuitPolicy = structuredClone(proof.circuitInputs[0]);
    (wrongCircuitPolicy.external_attestation as Record<string, unknown>).policy_root = Array(32).fill(9);
    await expect(noir.execute(wrongCircuitPolicy)).rejects.toThrow(/attestation policy root mismatch/);

    const buildBook = (candidate: Awaited<ReturnType<typeof externalAttestationFor>>) =>
      (import("./vesting-transition-input")).then(({ buildPayrollBookEntryInputs }) =>
        buildPayrollBookEntryInputs({
          payroll: source,
          entryKind: "agent",
          ownerAddress: "0x123",
          periodStart: 1_799_000_000n,
          periodEnd: 1_900_000_000n,
          totalsDisclosure: "hidden",
          totalsSalt: hex("5"),
          attestation: candidate,
        }));
    await expect(buildBook(await externalAttestationFor(hex("9"), source.policyRoot)))
      .rejects.toThrow(/another private recipient/);
    await expect(buildBook(await externalAttestationFor(
      toHex(Uint8Array.from(source.proofBindings[0].agreement.recipient_commitment)),
      hex("8"),
    ))).rejects.toThrow(/another payroll policy catalog/);
    await expect(buildBook(await externalAttestationFor(
      toHex(Uint8Array.from(source.proofBindings[0].agreement.recipient_commitment)),
      source.policyRoot,
      { factMask: externalAttestationFactMask.tax_status },
    ))).rejects.toThrow(/residency, employment and tax status/);
    const withoutAttestation = await (await import("./vesting-transition-input")).buildPayrollBookEntryInputs({
      payroll: source,
      entryKind: "agent",
      ownerAddress: "0x123",
      bookSealAddress: "0x789",
      periodStart: 1_799_000_000n,
      periodEnd: 1_900_000_000n,
      totalsDisclosure: "hidden",
      totalsSalt: hex("5"),
    });
    expect(withoutAttestation.publicInputs[0].sourceSealAddress).toBe(BigInt(source.publicInputs[0].sealAddress).toString());
    expect(withoutAttestation.publicInputs[0].sealAddress).toBe(BigInt("0x789").toString());
    for (const circuitInput of withoutAttestation.circuitInputs) {
      const { witness } = await noir.execute(circuitInput);
      witness.fill(0);
    }
    await expect(noir.execute({
      ...proof.circuitInputs[0],
      private_shard_0_strk_net: "99",
    })).rejects.toThrow(/private shard zero STRK net mismatch/);
    await expect(noir.execute({
      ...proof.circuitInputs[0],
      totals_commitment_low: (
        BigInt(String(proof.circuitInputs[0].totals_commitment_low)) + 1n
      ).toString(),
    })).rejects.toThrow(/root low limb mismatch/);
  }, 120_000);

  it("rejects a reporting period that does not contain the proved payroll", async () => {
    const source = await payroll(1);
    expect(() => buildUniversalPayrollBookInput({
      payroll: source,
      entryKind: "ordinary",
      ownerAddress: "0x123",
      sourceSealAddress: "0x456",
      periodStart: 1n,
      periodEnd: 2n,
      totalsDisclosure: "public",
      totalsSalt: hex("5"),
    })).toThrow(/outside the reporting period/);
  });
});
