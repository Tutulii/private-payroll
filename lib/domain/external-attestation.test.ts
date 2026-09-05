import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { toBase64 } from "@/lib/crypto/encoding";
import {
  assertExternalAttestationUsable,
  buildExternalAttestationCatalog,
  createExternalAttestationProofPackage,
  externalAttestationCommitment,
  externalAttestationFactMask,
  jurisdictionCommitment,
  openExternalAttestationProofPackage,
  PAYO_EXTERNAL_ATTESTATION_ACTIVE_STATUS,
  signExternalAttestation,
  verifySignedExternalAttestation,
} from "./external-attestation";

const hex = (byte: string): `0x${string}` => `0x${byte.repeat(32)}`;

function signedFixture(secretKey: Uint8Array, nonce = hex("44")) {
  return signExternalAttestation({
    attestationVersion: "payo-external-attestation-v1",
    subjectCommitment: hex("11"),
    factMask: externalAttestationFactMask.residency
      | externalAttestationFactMask.employment_status
      | externalAttestationFactMask.tax_status,
    jurisdictionCode: "US-CA",
    jurisdictionCommitment: jurisdictionCommitment("US-CA"),
    policyRoot: hex("22"),
    statusCommitment: PAYO_EXTERNAL_ATTESTATION_ACTIVE_STATUS,
    validFrom: "100",
    validUntil: "200",
    nonce,
  }, secretKey);
}

describe("issuer-signed external payroll attestations", () => {
  it("binds issuer, private subject, facts, jurisdiction, validity and nonce", () => {
    const issuer = ed25519.keygen();
    const signed = signedFixture(issuer.secretKey);
    expect(verifySignedExternalAttestation(signed, {
      trustedIssuerPublicKeys: [toBase64(issuer.publicKey)],
    })).toEqual(signed);
    expect(externalAttestationCommitment(signed.attestation)).toBe(signed.commitment);
    expect(assertExternalAttestationUsable(signed, {
      subjectCommitment: hex("11"),
      policyRoot: hex("22"),
      requiredFactMask: externalAttestationFactMask.employment_status
        | externalAttestationFactMask.tax_status,
      at: 150n,
    })).toEqual(signed);
  });

  it("rejects mutation, an unapproved issuer, expiry and revocation", () => {
    const issuer = ed25519.keygen();
    const signed = signedFixture(issuer.secretKey);
    const changed = structuredClone(signed);
    changed.attestation.validUntil = "199";
    expect(() => verifySignedExternalAttestation(changed)).toThrow("commitment");
    expect(() => verifySignedExternalAttestation(signed, {
      trustedIssuerPublicKeys: [toBase64(ed25519.keygen().publicKey)],
    })).toThrow("not approved");
    expect(() => assertExternalAttestationUsable(signed, {
      subjectCommitment: hex("11"),
      policyRoot: hex("22"),
      requiredFactMask: externalAttestationFactMask.tax_status,
      at: 201n,
    })).toThrow("validity");
    expect(() => assertExternalAttestationUsable(signed, {
      subjectCommitment: hex("11"),
      policyRoot: hex("22"),
      requiredFactMask: externalAttestationFactMask.tax_status,
      at: 150n,
      revokedNonces: new Set([signed.attestation.nonce]),
    })).toThrow("revoked");
    expect(() => assertExternalAttestationUsable(signed, {
      subjectCommitment: hex("11"),
      policyRoot: hex("23"),
      requiredFactMask: externalAttestationFactMask.tax_status,
      at: 150n,
    })).toThrow("policy catalog");
  });

  it("builds a proof catalog only from signed, approved and non-revoked entries", async () => {
    const issuer = ed25519.keygen();
    const first = signedFixture(issuer.secretKey, hex("44"));
    const second = signedFixture(issuer.secretKey, hex("45"));
    const catalog = await buildExternalAttestationCatalog({
      attestations: [first, second],
      trustedIssuerPublicKeys: [toBase64(issuer.publicKey)],
      revokedNonces: new Set([first.attestation.nonce]),
    });
    expect(catalog.entries).toHaveLength(1);
    expect(catalog.entries[0].signed.commitment).toBe(second.commitment);
    expect(catalog.entries[0].siblings).toHaveLength(6);
    expect(catalog.entries[0].pathBits).toHaveLength(6);
    expect(BigInt(catalog.root)).toBeGreaterThan(0n);
  });

  it("exports a portable package and rejects a substituted catalog opening", async () => {
    const issuer = ed25519.keygen();
    const catalog = await buildExternalAttestationCatalog({
      attestations: [
        signedFixture(issuer.secretKey, hex("44")),
        signedFixture(issuer.secretKey, hex("45")),
      ],
      trustedIssuerPublicKeys: [toBase64(issuer.publicKey)],
    });
    const portable = createExternalAttestationProofPackage({
      agreementId: "018f1000-0000-7000-8000-000000000001",
      catalog,
      entryIndex: 1,
    });
    await expect(openExternalAttestationProofPackage(portable)).resolves.toEqual(portable);

    const substituted = structuredClone(portable);
    substituted.siblings[0] = hex("99");
    await expect(openExternalAttestationProofPackage(substituted))
      .rejects.toThrow("does not reconstruct");
  });
});
