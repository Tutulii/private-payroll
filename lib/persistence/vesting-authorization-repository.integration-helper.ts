import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import { encryptVaultRecord, generateVaultPrincipal } from "@/lib/crypto/vault";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  hiddenPayrollBookTotals,
  payrollBookTotalsCommitment,
  universalPayrollBookEntryCommitment,
  type UniversalPayrollBookEntry,
} from "@/lib/domain/universal-payroll-book";
import {
  ADVANCED_OBLIGATION_CIRCUIT_SHA256,
  ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
  VESTING_TRANSITION_CIRCUIT_SHA256,
  VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
} from "@/lib/proof/protocol";
import {
  hashProofCalldata,
  parsePayrollPublicInputsFromGaragaCalldata,
  parseVestingTransitionPublicInputsFromGaragaCalldata,
} from "@/lib/proof/starknet-calldata";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { getDatabase } from "./db";
import { listPayrollBookReportSources } from "./payroll-book-report-repository";
import {
  advanceVestingAuthorizationJob,
  completeVestingAuthorizationJob,
  enqueueVestingAuthorization,
  leaseVestingAuthorizationJobs,
  recordVestingAuthorizationSubmission,
  type VestingAuthorizationStep,
} from "./vesting-authorization-repository";
import {
  organizationMembers,
  organizations,
  payrollRuns,
  proofBundles,
  settlements,
  vaultRecords,
  vestingAuthorizationJobs,
} from "./schema";

const principal: AuthenticatedPrincipal = {
  principalId: "admin:vesting-integration",
  sessionId: "session:vesting-integration",
};
const U128_MASK = (1n << 128n) - 1n;
const ZERO = `0x${"00".repeat(32)}` as const;

function setU256PublicInput(
  calldata: string[],
  inputIndex: number,
  value: string | bigint,
): void {
  const parsed = BigInt(value);
  calldata[1 + inputIndex * 2] = `0x${(parsed & U128_MASK).toString(16)}`;
  calldata[2 + inputIndex * 2] = `0x${(parsed >> 128n).toString(16)}`;
}

function setLinkedPayrollPublicInput(
  calldata: string[],
  inputIndex: number,
  value: string | bigint,
): void {
  const firstHeader = Number(BigInt(calldata[0]));
  if (firstHeader === 17) {
    setU256PublicInput(calldata, inputIndex, value);
    return;
  }
  const write = (offset: number) => {
    const parsed = BigInt(value);
    calldata[offset + 1 + inputIndex * 2] = `0x${(parsed & U128_MASK).toString(16)}`;
    calldata[offset + 2 + inputIndex * 2] = `0x${(parsed >> 128n).toString(16)}`;
  };
  write(1);
  write(firstHeader + 1);
}

function combine(high: string, low: string): `0x${string}` {
  return `0x${((BigInt(high) << 128n) | BigInt(low)).toString(16).padStart(64, "0")}`;
}

function address(value: string): `0x${string}` {
  return `0x${BigInt(value).toString(16)}`;
}

/**
 * Persistence-only vector. Public inputs in real Garaga calldata are rewritten
 * to a current validity window so transaction durability can be tested without
 * pretending the modified proof is cryptographically valid. Noir/Garaga/Cairo
 * tests retain the untouched real proof and verify its cryptography.
 */
function fixture() {
  const nowSeconds = Math.floor(Date.now() / 1_000);
  const validityStart = String(nowSeconds - 30);
  const validityExpiry = String(nowSeconds + 1_800);
  const periodStart = String(nowSeconds - 86_400);
  const periodEnd = String(nowSeconds + 86_400);
  const payrollShards = ([0, 1] as const).map((shardIndex) => {
    const calldata = readFileSync(
      new URL(`../../evidence/phase3-devnet-fixtures/advanced-shard-${shardIndex}.txt`, import.meta.url),
      "utf8",
    ).trim().split(/\s+/);
    setLinkedPayrollPublicInput(calldata, 14, validityStart);
    setLinkedPayrollPublicInput(calldata, 15, validityExpiry);
    return calldata;
  }) as [string[], string[]];
  const payrollInputs = payrollShards.map(parsePayrollPublicInputsFromGaragaCalldata);
  const payroll = payrollInputs[0];
  const runNullifier = combine(payroll.runNullifierHigh, payroll.runNullifierLow);
  const totals = hiddenPayrollBookTotals();
  const totalsCommitment = payrollBookTotalsCommitment({
    subjectNullifier: runNullifier,
    contributorCount: 2,
    totals,
    salt: `0x${"a2".repeat(32)}`,
  });
  const scheduleId = `0x${"21".repeat(32)}` as const;
  const previousStateCommitment = `0x${"22".repeat(32)}` as const;
  const nextStateCommitment = `0x${"23".repeat(32)}` as const;
  const releaseNullifier = `0x${"24".repeat(32)}` as const;
  const bookEntry: UniversalPayrollBookEntry = {
    entryVersion: "payo-payroll-book-entry-v2",
    entryKind: "vesting",
    chainId: address(payroll.chainId),
    sealAddress: address(payroll.sealAddress),
    sourceSealAddress: address(payroll.sealAddress),
    ownerAddress: "0x789",
    periodStart,
    periodEnd,
    agreementRoot: combine(payroll.agreementRootHigh, payroll.agreementRootLow),
    manifestRoot: combine(payroll.manifestRootHigh, payroll.manifestRootLow),
    policyRoot: combine(payroll.policyRootHigh, payroll.policyRootLow),
    fxRoot: combine(payroll.fxRootHigh, payroll.fxRootLow),
    runNullifier,
    subjectNullifier: runNullifier,
    parentFactCommitment: ZERO,
    factCommitment: ZERO,
    sourceProofVersion: 2,
    attestationRoot: ZERO,
    contributorCount: 2,
    totalsDisclosure: "hidden",
    totalsCommitment,
    totals,
    vestingScheduleId: scheduleId,
    vestingStateCommitment: nextStateCommitment,
  };
  const bookEntryCommitment = universalPayrollBookEntryCommitment(bookEntry);
  const split = (value: string): [string, string] => {
    const parsed = BigInt(value);
    return [(parsed >> 128n).toString(), (parsed & U128_MASK).toString()];
  };
  const [totalsHigh, totalsLow] = split(totalsCommitment);
  const [scheduleHigh, scheduleLow] = split(scheduleId);
  const [previousHigh, previousLow] = split(previousStateCommitment);
  const [nextHigh, nextLow] = split(nextStateCommitment);
  const [releaseHigh, releaseLow] = split(releaseNullifier);
  const [entryHigh, entryLow] = split(bookEntryCommitment);
  const makeTransitionCalldata = (shardIndex: 0 | 1): string[] => {
    const values = [
      payroll.chainId, payroll.sealAddress, "3", "1", "1",
      payroll.agreementRootHigh, payroll.agreementRootLow,
      payroll.manifestRootHigh, payroll.manifestRootLow,
      payroll.policyRootHigh, payroll.policyRootLow,
      payroll.fxRootHigh, payroll.fxRootLow,
      payroll.runNullifierHigh, payroll.runNullifierLow,
      payroll.runNullifierHigh, payroll.runNullifierLow,
      "0", "0", "0", "0", "0x789", payroll.sealAddress, "2",
      "0", "0", "1", "1", "0", totalsHigh, totalsLow,
      ...Array(12).fill("0"),
      scheduleHigh, scheduleLow, previousHigh, previousLow, nextHigh, nextLow,
      releaseHigh, releaseLow, entryHigh, entryLow,
      periodStart, periodEnd, validityStart, validityExpiry, String(shardIndex),
    ];
    if (values.length !== 58) throw new Error("Persistence vector must contain 58 public inputs.");
    const calldata = ["0x3a"];
    for (const value of values) {
      const parsed = BigInt(value);
      calldata.push(`0x${(parsed & U128_MASK).toString(16)}`);
      calldata.push(`0x${(parsed >> 128n).toString(16)}`);
    }
    return calldata;
  };
  const transitionShards = [makeTransitionCalldata(0), makeTransitionCalldata(1)] as [string[], string[]];
  const transitionInputs = transitionShards.map((calldata) => {
    const parsed = parseVestingTransitionPublicInputsFromGaragaCalldata(calldata);
    return {
      ...parsed,
      chainId: address(parsed.chainId),
      sealAddress: address(parsed.sealAddress),
    };
  }) as [
    ReturnType<typeof parseVestingTransitionPublicInputsFromGaragaCalldata>,
    ReturnType<typeof parseVestingTransitionPublicInputsFromGaragaCalldata>,
  ];
  const { shardIndex: ignoredShard, chainId, sealAddress, ...decimalCommon } = payrollInputs[0];
  void ignoredShard;
  const commonInputs = { chainId: address(chainId), sealAddress: address(sealAddress), ...decimalCommon };
  const payrollProofBundleId = generateUuidV7();
  const runId = generateUuidV7();
  const payrollMetadata = {
    schemaVersion: 1 as const,
    envelopeRecordId: payrollProofBundleId,
    envelopeRevision: 1,
    proofType: "payroll_integrity" as const,
    subjectRecordId: runId,
    proofVersion: "2",
    circuitSha256: ADVANCED_OBLIGATION_CIRCUIT_SHA256,
    verificationKeySha256: ADVANCED_OBLIGATION_VERIFICATION_KEY_SHA256,
    publicInputsHash: hashCanonicalJson([
      { ...commonInputs, shardIndex: "0" },
      { ...commonInputs, shardIndex: "1" },
    ]),
    commonInputs,
    shardCalldataHashes: payrollShards.map(hashProofCalldata) as [string, string],
  };
  return {
    nowSeconds,
    runId,
    payrollProofBundleId,
    payrollShards,
    commonInputs,
    payrollMetadata,
    request: {
      payrollProofBundleId,
      payrollShards,
      vestingBook: {
        proofVersion: 3 as const,
        entryKind: "vesting" as const,
        circuitSha256: VESTING_TRANSITION_CIRCUIT_SHA256 as typeof VESTING_TRANSITION_CIRCUIT_SHA256,
        verificationKeySha256: VESTING_TRANSITION_VERIFICATION_KEY_SHA256 as typeof VESTING_TRANSITION_VERIFICATION_KEY_SHA256,
        scheduleId: combine(transitionInputs[0].scheduleIdHigh, transitionInputs[0].scheduleIdLow),
        previousStateCommitment: combine(transitionInputs[0].previousStateHigh, transitionInputs[0].previousStateLow),
        nextStateCommitment: combine(transitionInputs[0].nextStateHigh, transitionInputs[0].nextStateLow),
        releaseNullifier: combine(transitionInputs[0].releaseNullifierHigh, transitionInputs[0].releaseNullifierLow),
        bookEntry,
        bookEntryCommitment,
        shards: transitionShards.map((proofCalldata, shardIndex) => ({
          shardIndex: shardIndex as 0 | 1,
          proofCalldata,
          calldataHash: hashProofCalldata(proofCalldata),
          publicInputs: transitionInputs[shardIndex],
        })) as [
          { shardIndex: 0; proofCalldata: string[]; calldataHash: string; publicInputs: typeof transitionInputs[0] },
          { shardIndex: 1; proofCalldata: string[]; calldataHash: string; publicInputs: typeof transitionInputs[1] },
        ],
      },
    },
  };
}

async function seed() {
  const organizationId = generateUuidV7();
  await getDatabase().insert(organizations).values({
    id: organizationId,
    encryptedProfile: { ciphertext: "vesting-integration" },
    recoveryState: "package_downloaded",
  });
  await getDatabase().insert(organizationMembers).values({
    organizationId,
    principalId: principal.principalId,
    role: "admin",
    vaultPublicKey: "vesting-integration-public-key",
  });
  return organizationId;
}

export function registerVestingAuthorizationRepositoryIntegrationTests(): void {
  it("serializes four-proof vesting authorization and recovers all five relay steps", async () => {
    const organizationId = await seed();
    const value = fixture();
    await getDatabase().insert(payrollRuns).values({
      id: value.runId,
      organizationId,
      cycleId: "vesting-authorization",
      revision: 1,
      state: "proven",
      dueAt: new Date(),
      agreementRoot: combine(value.commonInputs.agreementRootHigh, value.commonInputs.agreementRootLow),
      manifestRoot: combine(value.commonInputs.manifestRootHigh, value.commonInputs.manifestRootLow),
      policyRoot: combine(value.commonInputs.policyRootHigh, value.commonInputs.policyRootLow),
      fxRoot: combine(value.commonInputs.fxRootHigh, value.commonInputs.fxRootLow),
      runNullifier: combine(value.commonInputs.runNullifierHigh, value.commonInputs.runNullifierLow),
    });
    await getDatabase().insert(proofBundles).values({
      id: value.payrollProofBundleId,
      organizationId,
      runId: value.runId,
      proofType: "payroll_integrity",
      proofVersion: "2",
      subjectRecordId: value.runId,
      proofPackage: value.payrollMetadata,
      proofHash: `0x${"91".repeat(32)}`,
      verificationState: "locally_verified",
    });

    await expect(enqueueVestingAuthorization({
      runId: value.runId,
      request: value.request,
      principal: { principalId: "admin:other", sessionId: "other" },
      chainId: value.commonInputs.chainId,
      sealAddress: value.commonInputs.sealAddress,
    })).rejects.toMatchObject({ code: "ORG_FORBIDDEN" });
    const tampered = structuredClone(value.request);
    tampered.vestingBook.shards[0].publicInputs.bookEntryLow = "1";
    await expect(enqueueVestingAuthorization({
      runId: value.runId,
      request: tampered,
      principal,
      chainId: value.commonInputs.chainId,
      sealAddress: value.commonInputs.sealAddress,
    })).rejects.toMatchObject({ code: "PROOF_PUBLIC_INPUT_MISMATCH" });

    const queued = await Promise.all([
      enqueueVestingAuthorization({
        runId: value.runId,
        request: value.request,
        principal,
        chainId: value.commonInputs.chainId,
        sealAddress: value.commonInputs.sealAddress,
      }),
      enqueueVestingAuthorization({
        runId: value.runId,
        request: value.request,
        principal,
        chainId: value.commonInputs.chainId,
        sealAddress: value.commonInputs.sealAddress,
      }),
    ]);
    expect(queued.filter(({ replayed }) => replayed)).toHaveLength(1);
    expect(await getDatabase().select().from(vestingAuthorizationJobs)).toHaveLength(1);

    const startedAt = new Date();
    const concurrent = await Promise.all([
      leaseVestingAuthorizationJobs("vesting-worker-a", 1, startedAt),
      leaseVestingAuthorizationJobs("vesting-worker-b", 1, startedAt),
    ]);
    expect(concurrent.flat()).toHaveLength(1);
    await expect(leaseVestingAuthorizationJobs(
      "vesting-worker-before-expiry",
      1,
      new Date(startedAt.getTime() + 119_000),
    )).resolves.toEqual([]);
    let [job] = await leaseVestingAuthorizationJobs(
      "vesting-worker-after-restart",
      1,
      new Date(startedAt.getTime() + 120_001),
    );
    expect(job).toMatchObject({ activeStep: "begin", transactionHash: null });

    const steps: VestingAuthorizationStep[] = ["begin", "payroll0", "payroll1", "transition0", "transition1"];
    let stepTime = new Date(startedAt.getTime() + 120_001);
    for (let index = 0; index < steps.length; index += 1) {
      const current = steps[index];
      await recordVestingAuthorizationSubmission(job, current, `0x${(100 + index).toString(16)}`, stepTime);
      stepTime = new Date(stepTime.getTime() + 1_501);
      [job] = await leaseVestingAuthorizationJobs(`vesting-worker-confirm-${current}`, 1, stepTime);
      expect(job).toMatchObject({ activeStep: current, transactionHash: `0x${(100 + index).toString(16)}` });
      if (index < steps.length - 1) {
        await advanceVestingAuthorizationJob(job, steps[index + 1], stepTime);
        stepTime = new Date(stepTime.getTime() + 1);
        [job] = await leaseVestingAuthorizationJobs(`vesting-worker-${steps[index + 1]}`, 1, stepTime);
      }
    }
    await completeVestingAuthorizationJob(job, stepTime);

    expect((await getDatabase().select().from(vestingAuthorizationJobs))[0]).toMatchObject({
      state: "complete",
      beginTransactionHash: "0x64",
      payrollShard0TransactionHash: "0x65",
      payrollShard1TransactionHash: "0x66",
      transitionShard0TransactionHash: "0x67",
      transitionShard1TransactionHash: "0x68",
      transactionHash: "0x68",
      authorizedAt: expect.any(Date),
    });
    expect((await getDatabase().select().from(proofBundles))[0]).toMatchObject({
      verificationState: "onchain_verified",
      verificationTransactionHash: "0x68",
    });
    await expect(leaseVestingAuthorizationJobs(
      "vesting-worker-after-completion",
      1,
      new Date(stepTime.getTime() + 300_000),
    )).resolves.toEqual([]);

    const reportPrincipal = generateVaultPrincipal(principal.principalId);
    const runEnvelope = encryptVaultRecord({ encrypted: "report-source" }, {
      schemaVersion: 1,
      organizationId,
      recordType: "payroll-run",
      recordId: value.runId,
      revision: 1,
    }, [reportPrincipal]);
    await getDatabase().insert(vaultRecords).values({
      id: value.runId,
      organizationId,
      recordType: "payroll-run",
      revision: 1,
      ciphertext: runEnvelope.ciphertext,
      envelope: runEnvelope,
      envelopeHash: hashCanonicalJson(runEnvelope),
      createdBy: principal.principalId,
    });
    await getDatabase().insert(settlements).values({
      id: generateUuidV7(),
      organizationId,
      runId: value.runId,
      workflowType: "payroll",
      subjectRecordId: value.runId,
      walletRequestId: generateUuidV7(),
      idempotencyKey: `report-source:${value.runId}`,
      state: "confirmed",
      tokenTotalsCommitment: `0x${"92".repeat(32)}`,
      transactionHash: "0xabc",
      submittedAt: stepTime,
      confirmedAt: stepTime,
    });
    const reportSources = await listPayrollBookReportSources({
      organizationId,
      ownerAddress: value.request.vestingBook.bookEntry.ownerAddress,
      periodStart: value.request.vestingBook.bookEntry.periodStart,
      periodEnd: value.request.vestingBook.bookEntry.periodEnd,
      principal,
    });
    expect(reportSources).toEqual([expect.objectContaining({
      runId: value.runId,
      runRevision: 1,
      entryKind: "vesting",
      bookEntryCommitment: value.request.vestingBook.bookEntryCommitment,
      integrityVerificationTransactionHash: "0x68",
      settlementTransactionHash: "0xabc",
      runEnvelope,
    })]);
    await expect(listPayrollBookReportSources({
      organizationId,
      ownerAddress: value.request.vestingBook.bookEntry.ownerAddress,
      periodStart: value.request.vestingBook.bookEntry.periodStart,
      periodEnd: value.request.vestingBook.bookEntry.periodEnd,
      principal: { principalId: "admin:other", sessionId: "other" },
    })).rejects.toMatchObject({ code: "ORG_FORBIDDEN" });
    await expect(listPayrollBookReportSources({
      organizationId,
      ownerAddress: value.request.vestingBook.bookEntry.ownerAddress,
      periodStart: String(BigInt(value.request.vestingBook.bookEntry.periodStart) - 1n),
      periodEnd: value.request.vestingBook.bookEntry.periodEnd,
      principal,
    })).resolves.toEqual([]);
  }, 120_000);
}
