import { describe, expect, it, vi } from "vitest";
import {
  generateVaultPrincipal,
} from "@/lib/crypto/vault";
import { generateUuidV7 } from "@/lib/domain/records";
import { prepareEncryptedExceptionProofBundle } from "./proof-bundle";
import {
  WAGE_CLAIM_VNEXT_CIRCUIT_SHA256,
  WAGE_REMEDIATION_VNEXT_CIRCUIT_SHA256,
} from "@/lib/proof/protocol";
import { hashProofCalldata } from "@/lib/proof/starknet-calldata";
import { mockExceptionBookProof } from "@/lib/proof/vesting-transition-test-support";
import {
  authorizeStoredExceptionProof,
  openStoredExceptionProof,
  waitForExceptionAuthorization,
} from "./exception-proof-recovery";

const organizationId = "0198ddf0-9c00-7000-8000-0000000000d1";
const runId = "0198ddf0-9c00-7000-8000-0000000000d2";
const subjectRecordId = "0198ddf0-9c00-7000-8000-0000000000d3";
const principal = generateVaultPrincipal("exception-proof-recovery");
const outsider = generateVaultPrincipal("exception-proof-recovery-outsider");

function publicInputs(proofVersion: "6" | "7") {
  return {
    chainId: "0x1",
    sealAddress: "0x12345",
    proofVersion,
    schemaVersion: "2",
    agreementRootHigh: "1",
    agreementRootLow: "2",
    manifestRootHigh: "3",
    manifestRootLow: "4",
    policyRootHigh: "5",
    policyRootLow: "6",
    fxRootHigh: "7",
    fxRootLow: "8",
    subjectNullifierHigh: "9",
    subjectNullifierLow: "10",
    parentNullifierHigh: "11",
    parentNullifierLow: "12",
    factCommitmentHigh: "13",
    factCommitmentLow: "14",
    parentFactCommitmentHigh: "15",
    parentFactCommitmentLow: "16",
    validityStart: "17",
    validityExpiry: "18",
    shardIndex: "0",
  };
}

function storedProofFixture(
  profile: "wage_claim_v6" | "wage_remediation_v7",
) {
  const proofVersion = profile === "wage_claim_v6" ? "6" : "7";
  const proofType = profile === "wage_claim_v6"
    ? "wage_claim"
    : "wage_remediation";
  const circuitSha256 = profile === "wage_claim_v6"
    ? WAGE_CLAIM_VNEXT_CIRCUIT_SHA256
    : WAGE_REMEDIATION_VNEXT_CIRCUIT_SHA256;
  const proofCalldata = Array.from(
    { length: 35 },
    (_, index) => "0x" + (index + 1).toString(16),
  );
  const proof = {
    version: 2 as const,
    type: "exception-proof-complete" as const,
    requestId: generateUuidV7(),
    profile,
    scheme: "ultra_keccak_zk_honk" as const,
    circuitSha256,
    provingTimeMs: 42,
    proof: {
      proof: Uint8Array.of(1, 2, 3),
      proofCalldata,
      calldataHash: hashProofCalldata(proofCalldata),
      publicInputs: publicInputs(proofVersion),
    },
    vestingBook: mockExceptionBookProof({
      source: publicInputs(proofVersion),
      entryKind: profile === "wage_claim_v6" ? "claim" : "remediation",
      bookSealAddress: "0x456",
      sourceSealAddress: "0x12345",
      ownerAddress: "0xabc",
    }),
  };
  const bundle = prepareEncryptedExceptionProofBundle({
    id: generateUuidV7(),
    organizationId,
    runId,
    revision: 1,
    proof: proof as never,
    subjectRecordId,
    principals: [principal],
  });
  const metadata = {
    schemaVersion: 2 as const,
    envelopeRecordId: bundle.id,
    envelopeRevision: bundle.revision,
    proofType: bundle.proofType,
    subjectRecordId: bundle.subjectRecordId,
    proofVersion: bundle.proofVersion,
    circuitSha256: bundle.circuitSha256,
    verificationKeySha256: bundle.verificationKeySha256,
    publicInputsHash: bundle.publicInputsHash,
    publicInputs: bundle.publicInputs,
    proofCalldataHash: bundle.proofCalldataHash,
  };
  const stored = {
    id: bundle.id,
    organizationId,
    runId,
    proofType,
    proofVersion,
    subjectRecordId,
    proofPackage: metadata,
    verificationState: "pending",
    verificationTransactionHash: null,
    createdAt: new Date().toISOString(),
    revision: 1,
    envelope: bundle.envelope,
  };
  return { bundle, metadata, proofCalldata, stored };
}

function authorization(state: "pending" | "leased" | "complete" | "dead") {
  const now = new Date().toISOString();
  return {
    id: generateUuidV7(),
    organizationId,
    runId,
    proofBundleId: generateUuidV7(),
    workflowType: "wage_claim" as const,
    subjectRecordId,
    state,
    transactionHash: state === "complete" ? "0xabc" : null,
    attempts: 1,
    lastErrorCode: state === "dead" ? "PROOF_FAILED" : null,
    lastErrorMessage: state === "dead" ? "Verifier rejected the proof." : null,
    authorizedAt: state === "complete" ? now : null,
    createdAt: now,
    updatedAt: now,
  };
}

describe("stored vNext exception proof recovery", () => {
  it.each([
    "wage_claim_v6",
    "wage_remediation_v7",
  ] as const)("opens and requeues an exact %s proof", async (profile) => {
    const fixture = storedProofFixture(profile);
    const enqueue = vi.fn().mockResolvedValue({
      authorization: authorization("pending"),
    });
    const client = {
      getEncryptedProofBundle: vi.fn().mockResolvedValue({
        proofBundle: fixture.stored,
      }),
      enqueueExceptionAuthorization: enqueue,
    };
    const opened = await openStoredExceptionProof({
      client,
      proofBundleId: fixture.bundle.id,
      principal,
    });
    expect(opened.payload.profile).toBe(profile);
    expect(opened.payload.proof.proofCalldata).toEqual(fixture.proofCalldata);

    const authorized = await authorizeStoredExceptionProof({
      client,
      proofBundleId: fixture.bundle.id,
      principal,
    });
    expect(enqueue).toHaveBeenCalledOnce();
    expect(enqueue).toHaveBeenCalledWith({
      proofBundleId: fixture.bundle.id,
      request: {
        proofCalldata: fixture.proofCalldata,
        vestingBook: authorized.payload.vestingBook,
      },
    });
  });

  it("rejects the wrong recipient and altered durable proof commitments", async () => {
    const fixture = storedProofFixture("wage_claim_v6");
    const client = {
      getEncryptedProofBundle: vi.fn().mockResolvedValue({
        proofBundle: fixture.stored,
      }),
    };
    await expect(openStoredExceptionProof({
      client,
      proofBundleId: fixture.bundle.id,
      principal: outsider,
    })).rejects.toThrow(/not authorized/i);

    client.getEncryptedProofBundle.mockResolvedValueOnce({
      proofBundle: {
        ...fixture.stored,
        proofPackage: {
          ...fixture.metadata,
          proofCalldataHash: "0x123",
        },
      },
    });
    await expect(openStoredExceptionProof({
      client,
      proofBundleId: fixture.bundle.id,
      principal,
    })).rejects.toThrow(/public commitments/i);
  });

  it("polls to completion and fails closed on terminal or timed-out jobs", async () => {
    const pending = authorization("pending");
    const complete = authorization("complete");
    const getComplete = vi.fn()
      .mockResolvedValueOnce({ authorization: pending })
      .mockResolvedValueOnce({ authorization: complete });
    let clock = 0;
    await expect(waitForExceptionAuthorization({
      client: { getExceptionAuthorization: getComplete } as never,
      proofBundleId: pending.proofBundleId,
      timeoutMs: 500,
      pollIntervalMs: 100,
      now: () => clock,
      wait: async (milliseconds) => { clock += milliseconds; },
    })).resolves.toMatchObject({ state: "complete", transactionHash: "0xabc" });

    const dead = authorization("dead");
    await expect(waitForExceptionAuthorization({
      client: {
        getExceptionAuthorization: vi.fn().mockResolvedValue({
          authorization: dead,
        }),
      } as never,
      proofBundleId: dead.proofBundleId,
      timeoutMs: 500,
      pollIntervalMs: 100,
    })).rejects.toThrow(/Verifier rejected/i);

    clock = 0;
    await expect(waitForExceptionAuthorization({
      client: {
        getExceptionAuthorization: vi.fn().mockResolvedValue({
          authorization: pending,
        }),
      } as never,
      proofBundleId: pending.proofBundleId,
      timeoutMs: 200,
      pollIntervalMs: 100,
      now: () => clock,
      wait: async (milliseconds) => { clock += milliseconds; },
    })).rejects.toThrow(/safe to leave.*resume later/i);
  });
});
