import { describe, expect, it, vi } from "vitest";
import { buildFxSnapshot } from "@/lib/domain/fx";
import { claimCapabilityCommitmentV2 } from "@/lib/domain/exception-protocol";
import {
  obligationClaimAccessPrivateSchema,
  obligationSnapshotPlanPrivateSchema,
} from "@/lib/domain/obligation-snapshot-plan";
import { generateUuidV7 } from "@/lib/domain/records";
import {
  decryptVaultRecord,
  encryptVaultRecord,
  generateVaultPrincipal,
} from "@/lib/crypto/vault";
import {
  buildObligationSnapshotPlanInputs,
  buildWageClaimV2Inputs,
} from "@/lib/proof/exception-input-builder";
import {
  buildPayrollAgreementSnapshot,
  buildPayrollIntegrityInputs,
  PAYO_NET_INVOICE_POLICY,
  serializePayrollIntegrityBuildRequest,
  type PayrollIntegrityLineInput,
} from "@/lib/proof/input-builder";
import {
  openPayrollStatementEvidence,
  prepareDurableEmployerStatementForPayroll,
  prepareEmployerStatements,
  registerDurableEmployerStatement,
} from "./employer-statement";
import { PayoApiError } from "./payo-client";

const organizationId = "0198ddf0-9c00-7000-8000-000000000091";
const owner = generateVaultPrincipal("owner:employer-statement-test");
const workerOne = generateVaultPrincipal("worker:employer-statement-one");
const workerTwo = generateVaultPrincipal("worker:employer-statement-two");
const ownerAddress = "0xabc";

function hex(value: string) {
  return ("0x" + value.repeat(32)) as PayrollIntegrityLineInput["lineSalt"];
}

function payrollLine(input: {
  agreementId: string;
  token: "STRK" | "USDC";
  amount: string;
  lineSalt: string;
  fxFloorAtomic?: string;
  finalPay?: PayrollIntegrityLineInput["finalPay"];
}): PayrollIntegrityLineInput {
  return {
    agreementId: input.agreementId,
    recipientAddress: input.token === "STRK" ? "0x111" : "0x222",
    recipientSalt: hex("11"),
    agreementSalt: hex("22"),
    lineSalt: input.lineSalt as ReturnType<typeof hex>,
    token: input.token,
    earningsAtomic: [input.amount],
    deductionsAtomic: [],
    policyId: PAYO_NET_INVOICE_POLICY.id,
    scheduleCommitment: hex("44"),
    dueAt: 1_000n,
    validUntil: 2_000n,
    classification: { declared: 2, score: 2, employeeThreshold: 5 },
    finalPay: input.finalPay,
    fxFloorAtomic: input.fxFloorAtomic ?? "0",
    referenceCurrency: "USD",
  };
}

function fxSnapshot(
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
    feedId: "pragma:" + token + "/USD:" + observedAtSeconds,
    quotes: ["a", "b", "c"].map((source) => ({
      source: "pragma-" + token.toLowerCase() + "-" + source,
      priceAtomic,
      observedAt,
    })),
    now: new Date((observedAtSeconds + 1) * 1_000),
  });
}

async function fixture() {
  const secretOne = hex("81");
  const secretTwo = hex("82");
  const lines = [
    payrollLine({
      agreementId: "statement-strk",
      token: "STRK",
      amount: "1000000000000000000",
      lineSalt: hex("31"),
      fxFloorAtomic: "1500000",
    }),
    payrollLine({
      agreementId: "statement-usdc",
      token: "USDC",
      amount: "1000000",
      lineSalt: hex("32"),
      finalPay: {
        requiredMask: 3,
        includedMask: 3,
        componentsAtomic: ["800000", "200000"],
      },
    }),
  ];
  const payroll = await buildPayrollAgreementSnapshot({
    organizationSecret: hex("55"),
    cycleId: "employer-statement-multi-worker",
    revision: 1,
    policies: [PAYO_NET_INVOICE_POLICY],
    lines,
  });
  const snapshot = await buildObligationSnapshotPlanInputs({
    ownerAddress,
    payroll,
    claimCapabilityCommitments: {
      "statement-strk": claimCapabilityCommitmentV2(secretOne),
      "statement-usdc": claimCapabilityCommitmentV2(secretTwo),
    },
    graceEndsAt: 1_100n,
    claimEndsAt: 2_000n,
  });
  const planId = generateUuidV7(900_000);
  const runId = generateUuidV7(900_001);
  const accessOneId = generateUuidV7(900_002);
  const accessTwoId = generateUuidV7(900_003);
  const payeeOne = generateUuidV7(900_004);
  const payeeTwo = generateUuidV7(900_005);
  const bindings = snapshot.lines.map((line) => {
    const isStrk = line.agreementId === "statement-strk";
    return {
    agreementId: line.agreementId,
    payeeId: isStrk ? payeeOne : payeeTwo,
    claimAccessGrantId: isStrk ? accessOneId : accessTwoId,
    claimantPrincipalId: isStrk
      ? workerOne.principalId
      : workerTwo.principalId,
    claimantPublicKey: isStrk
      ? workerOne.publicKey
      : workerTwo.publicKey,
    agreementCommitment: hex(isStrk ? "91" : "92"),
    recipientCommitment: hex(isStrk ? "93" : "94"),
    scheduleCommitment: hex("44"),
    claimCapabilityCommitment: line.claimCapabilityCommitment,
    };
  });
  const snapshotPlan = obligationSnapshotPlanPrivateSchema.parse({
    format: "payo-obligation-snapshot-plan-v1",
    planId,
    runId,
    organizationId,
    cycleId: "employer-statement-multi-worker",
    payrollRevision: 1,
    snapshot: snapshot.snapshot,
    snapshotCommitment: snapshot.snapshotCommitment,
    agreementBindings: bindings,
    claimWitness: {
      claimRoot: snapshot.claimRoot,
      lines: snapshot.lines,
    },
    createdAt: new Date(900_000).toISOString(),
  });
  const claimAccess = snapshot.lines.map((line, index) =>
    obligationClaimAccessPrivateSchema.parse({
      format: "payo-obligation-claim-access-v1",
      grantId: bindings[index]!.claimAccessGrantId,
      snapshotPlanId: planId,
      runId,
      organizationId,
      cycleId: snapshotPlan.cycleId,
      payrollRevision: 1,
      snapshot: snapshot.snapshot,
      snapshotCommitment: snapshot.snapshotCommitment,
      binding: bindings[index],
      witness: line,
      issuerPrincipal: {
        principalId: owner.principalId,
        publicKey: owner.publicKey,
      },
      createdAt: new Date(900_000).toISOString(),
    }),
  );
  return {
    snapshotPlan,
    snapshot,
    lines,
    payroll,
    claimAccess,
    secretOne,
    secretTwo,
    strkIndex: snapshot.lines.findIndex(({ agreementId }) => agreementId === "statement-strk"),
    usdcIndex: snapshot.lines.findIndex(({ agreementId }) => agreementId === "statement-usdc"),
  };
}

function publicGrant(input: {
  prepared: Awaited<ReturnType<typeof prepareEmployerStatements>>[number];
  evidenceIndex: number;
}) {
  const evidence = input.prepared.evidence[input.evidenceIndex]!;
  const grant = input.prepared.create.evidenceGrants[input.evidenceIndex]!;
  const statement = input.prepared.create;
  const observedAt = new Date(
    Number(statement.statement.observedAt) * 1_000,
  ).toISOString();
  return {
    id: grant.id,
    statementId: statement.id,
    claimAccessGrantId: grant.claimAccessGrantId,
    claimantPrincipalId: grant.claimantPrincipalId,
    revokedAt: null,
    statement: {
      id: statement.id,
      snapshotPlanId: statement.snapshotPlanId,
      organizationId: statement.organizationId,
      runId: statement.runId,
      ownerAddress: statement.ownerAddress,
      statementFact: statement.statementCommitment,
      manifestRoot: statement.statement.manifestRoot,
      fxRoot: statement.statement.fxRoot,
      availabilityCommitment: statement.statement.availabilityCommitment,
      observedAt,
      source: "employer_statement" as const,
      state: "registered" as const,
      registrationTransactionHash: "0x123",
      registeredAt: observedAt,
      createdAt: observedAt,
      updatedAt: observedAt,
    },
    envelope: grant.envelope,
    evidence,
  };
}


async function durablePayrollFixture() {
  const base = await fixture();
  const fxSnapshots = [
    fxSnapshot("STRK", "2000000", 1_140),
    fxSnapshot("USDC", "1000000", 1_140),
  ];
  const fullPayroll = await buildPayrollIntegrityInputs({
    chainId: "0x1",
    sealAddress: "0x12345",
    organizationSecret: hex("55"),
    cycleId: base.snapshotPlan.cycleId,
    revision: 1,
    validityStart: 1_150n,
    validityExpiry: 1_200n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots,
    lines: base.lines,
  });
  const buildInput = serializePayrollIntegrityBuildRequest({
    chainId: "0x1",
    sealAddress: "0x12345",
    organizationSecret: hex("55"),
    cycleId: base.snapshotPlan.cycleId,
    revision: 1,
    validityStart: 1_150n,
    validityExpiry: 1_200n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots,
    lines: base.lines,
  });
  const planEnvelope = encryptVaultRecord(
    base.snapshotPlan,
    {
      schemaVersion: 1,
      organizationId,
      recordType: "obligation-snapshot-plan",
      recordId: base.snapshotPlan.planId,
      revision: 1,
    },
    [owner],
  );
  const runEnvelope = encryptVaultRecord(
    {
      obligationSnapshotPlanId: base.snapshotPlan.planId,
      claimProofSource: { buildInput },
    },
    {
      schemaVersion: 1,
      organizationId,
      recordType: "payroll-run",
      recordId: base.snapshotPlan.runId,
      revision: 1,
    },
    [owner],
  );
  const plan = {
    id: base.snapshotPlan.planId,
    runId: base.snapshotPlan.runId,
    organizationId,
    cycleId: base.snapshotPlan.cycleId,
    revision: 1,
    ownerAddress: base.snapshotPlan.snapshot.ownerAddress,
    agreementRoot: base.snapshotPlan.snapshot.baseAgreementRoot,
    claimRoot: base.snapshotPlan.snapshot.obligationRoot,
    policyRoot: base.snapshotPlan.snapshot.policyRoot,
    runNullifier: base.snapshotPlan.snapshot.runNullifier,
    snapshotFact: base.snapshotPlan.snapshotCommitment,
    dueAt: new Date(Number(base.snapshotPlan.snapshot.dueAt) * 1_000).toISOString(),
    graceEndsAt: new Date(Number(base.snapshotPlan.snapshot.graceEndsAt) * 1_000).toISOString(),
    claimEndsAt: new Date(Number(base.snapshotPlan.snapshot.claimEndsAt) * 1_000).toISOString(),
    state: "consumed" as const,
    registrationTransactionHash: "0xsnapshot",
    registeredAt: new Date(900_000).toISOString(),
    consumedAt: new Date(1_150_000).toISOString(),
    createdAt: new Date(900_000).toISOString(),
    updatedAt: new Date(1_150_000).toISOString(),
    envelope: planEnvelope,
  };
  const run = {
    id: base.snapshotPlan.runId,
    organizationId,
    state: "confirmed" as const,
    agreementRoot: fullPayroll.agreementRoot,
    manifestRoot: fullPayroll.manifestRoot,
    policyRoot: fullPayroll.policyRoot,
    fxRoot: fullPayroll.fxRoot,
    runNullifier: fullPayroll.runNullifier,
    obligationSnapshotPlanId: base.snapshotPlan.planId,
    transactionHash: "0xpayroll",
    envelope: runEnvelope,
  };
  let created: Parameters<
    EmployerStatementPreparationClientForTest["createEmployerStatement"]
  >[0] | undefined;
  const statementSummary = () => {
    if (!created) throw new Error("No employer statement was prepared.");
    const observedAt = new Date(
      Number(created.statement.observedAt) * 1_000,
    ).toISOString();
    return {
      id: created.id,
      snapshotPlanId: created.snapshotPlanId,
      organizationId: created.organizationId,
      runId: created.runId,
      ownerAddress: created.ownerAddress,
      statementFact: created.statementCommitment,
      manifestRoot: created.statement.manifestRoot,
      fxRoot: created.statement.fxRoot,
      availabilityCommitment: created.statement.availabilityCommitment,
      observedAt,
      source: "employer_statement" as const,
      state: "prepared" as const,
      registrationTransactionHash: null,
      registeredAt: null,
      createdAt: observedAt,
      updatedAt: observedAt,
    };
  };
  const client = {
    getPayrollRun: vi.fn(async () => ({ run })),
    getObligationSnapshotPlan: vi.fn(async () => ({ plan })),
    listEmployerStatements: vi.fn(async () => ({
      statements: created ? [statementSummary()] : [],
    })),
    getEmployerStatement: vi.fn(async () => ({
      statement: { ...statementSummary(), envelope: created!.envelope },
    })),
    createEmployerStatement: vi.fn(async (input: NonNullable<typeof created>) => {
      created = input;
      return { statement: { ...statementSummary(), replayed: false } };
    }),
  };
  return { client, run, plan };
}

type EmployerStatementPreparationClientForTest = Pick<
  import("./payo-client").PayoClient,
  | "createEmployerStatement"
  | "getEmployerStatement"
  | "getObligationSnapshotPlan"
  | "getPayrollRun"
  | "listEmployerStatements"
>;

describe("worker-scoped employer statement evidence", () => {
  it("builds base and FX profiles without disclosing another worker's line", async () => {
    const preparedFixture = await fixture();
    const snapshots = [fxSnapshot("STRK", "1000000", 1_140)];
    const prepared = await prepareEmployerStatements({
      snapshotPlan: preparedFixture.snapshotPlan,
      lines: [{
        agreementId: "statement-strk",
        target: {
          kind: "line",
          deductionsAtomic: [],
          lineSalt: hex("61"),
          classificationTreatment: 2,
          finalIncludedMask: 0,
          referenceValueAtomic: "1000000",
        },
      }, {
        agreementId: "statement-usdc",
        target: { kind: "empty" },
      }],
      fxSnapshots: snapshots,
      principal: owner,
      now: new Date(1_150_000),
    });
    expect(prepared.map(({ profile }) => profile)).toEqual(["base", "fx"]);
    expect(prepared[0].create.statement.fxRoot).toBe(hex("00"));
    expect(prepared[1].create.statement.fxRoot).not.toBe(hex("00"));
    expect(prepared[0].evidence).toHaveLength(2);
    expect(prepared[1].evidence[preparedFixture.usdcIndex]).not.toHaveProperty(
      "selectedFxIndex",
    );
    expect(prepared[0].evidence[0].target).not.toHaveProperty(
      "otherManifestLeaves",
    );
    expect(prepared[0].evidence[preparedFixture.usdcIndex].target).toMatchObject({
      kind: "empty",
      manifestMembership: {
        siblings: expect.arrayContaining([expect.any(String)]),
        pathBits: [
          Boolean(preparedFixture.usdcIndex & 1),
          Boolean(preparedFixture.usdcIndex & 2),
          Boolean(preparedFixture.usdcIndex & 4),
          Boolean(preparedFixture.usdcIndex & 8),
          Boolean(preparedFixture.usdcIndex & 16),
          Boolean(preparedFixture.usdcIndex & 32),
        ],
      },
    });
    expect(decryptVaultRecord(
      prepared[0].create.evidenceGrants[preparedFixture.usdcIndex].envelope,
      workerTwo,
    )).toEqual(prepared[0].evidence[preparedFixture.usdcIndex]);
    expect(() => decryptVaultRecord(
      prepared[0].create.evidenceGrants[preparedFixture.usdcIndex].envelope,
      workerOne,
    )).toThrow(/not authorized/i);

    const baseGrant = publicGrant({ prepared: prepared[0], evidenceIndex: preparedFixture.usdcIndex });
    const openedMissing = await openPayrollStatementEvidence({
      grant: baseGrant,
      principal: workerTwo,
      claimAccess: preparedFixture.claimAccess[preparedFixture.usdcIndex],
    });
    const missingClaim = await buildWageClaimV2Inputs({
      chainId: "0x1",
      sealAddress: "0x12345",
      snapshot: {
        snapshot: preparedFixture.snapshot.snapshot,
        snapshotCommitment: preparedFixture.snapshot.snapshotCommitment,
        claimRoot: preparedFixture.snapshot.claimRoot,
        lines: [preparedFixture.snapshot.lines[preparedFixture.usdcIndex]],
      },
      agreementId: "statement-usdc",
      claimCapabilitySecret: preparedFixture.secretTwo,
      claimKind: "missing_obligation",
      evidence: {
        source: "employer_statement",
        observedAt: BigInt(openedMissing.statement.observedAt),
        availabilityCommitment:
          openedMissing.statement.availabilityCommitment,
        target: openedMissing.target,
      },
      validityStart: 1_150n,
      validityExpiry: 1_200n,
    });
    expect(missingClaim.statementCommitment)
      .toBe(openedMissing.statementCommitment);

    const fxGrant = publicGrant({ prepared: prepared[1], evidenceIndex: preparedFixture.strkIndex });
    const openedFx = await openPayrollStatementEvidence({
      grant: fxGrant,
      principal: workerOne,
      claimAccess: preparedFixture.claimAccess[preparedFixture.strkIndex],
    });
    const fxClaim = await buildWageClaimV2Inputs({
      chainId: "0x1",
      sealAddress: "0x12345",
      snapshot: {
        snapshot: preparedFixture.snapshot.snapshot,
        snapshotCommitment: preparedFixture.snapshot.snapshotCommitment,
        claimRoot: preparedFixture.snapshot.claimRoot,
        lines: [preparedFixture.snapshot.lines[preparedFixture.strkIndex]],
      },
      agreementId: "statement-strk",
      claimCapabilitySecret: preparedFixture.secretOne,
      claimKind: "below_committed_floor",
      evidence: {
        source: "employer_statement",
        observedAt: BigInt(openedFx.statement.observedAt),
        availabilityCommitment: openedFx.statement.availabilityCommitment,
        target: openedFx.target,
        fxSnapshots: openedFx.fxSnapshots,
        selectedFxIndex: openedFx.selectedFxIndex,
      },
      validityStart: 1_150n,
      validityExpiry: 1_200n,
    });
    expect(fxClaim.claimFact).toMatchObject({
      claimKind: "below_committed_floor",
      shortfallAtomic: "500000",
      evidenceSource: "employer_statement",
    });
    expect(fxClaim.statementCommitment).toBe(openedFx.statementCommitment);
  });

  it("rejects tampered public bindings and never resubmits a recorded transaction", async () => {
    const preparedFixture = await fixture();
    const [prepared] = await prepareEmployerStatements({
      snapshotPlan: preparedFixture.snapshotPlan,
      lines: [{
        agreementId: "statement-strk",
        target: {
          kind: "line",
          deductionsAtomic: [],
          lineSalt: hex("71"),
          classificationTreatment: 2,
          finalIncludedMask: 0,
          referenceValueAtomic: "1000000",
        },
      }, {
        agreementId: "statement-usdc",
        target: { kind: "empty" },
      }],
      principal: owner,
      now: new Date(1_150_000),
    });
    const validGrant = publicGrant({ prepared, evidenceIndex: preparedFixture.usdcIndex });
    await expect(openPayrollStatementEvidence({
      grant: {
        ...validGrant,
        statement: {
          ...validGrant.statement,
          manifestRoot: hex("ff"),
        },
      },
      principal: workerTwo,
      claimAccess: preparedFixture.claimAccess[preparedFixture.usdcIndex],
    })).rejects.toThrow(/differs from registered/i);

    const registerStatement = vi.fn().mockResolvedValue("0xabc");
    const record = vi.fn().mockResolvedValue({ statement: {} });
    const reconcile = vi.fn()
      .mockRejectedValueOnce(
        new PayoApiError("absent", "STATEMENT_NOT_REGISTERED", 409),
      )
      .mockResolvedValueOnce({
        statement: { id: prepared.create.id, state: "registered" },
        blockNumber: 9,
      });
    await expect(registerDurableEmployerStatement({
      client: {
        recordEmployerStatementSubmission: record,
        reconcileEmployerStatement: reconcile,
      } as never,
      stored: {
        id: prepared.create.id,
        state: "prepared",
        registrationTransactionHash: null,
      },
      statement: prepared.create.statement,
      statementCommitment: prepared.create.statementCommitment,
      registerStatement,
    })).resolves.toMatchObject({
      transactionHash: "0xabc",
      recovered: false,
    });
    expect(registerStatement).toHaveBeenCalledOnce();
    expect(record).toHaveBeenCalledWith({
      statementId: prepared.create.id,
      transactionHash: "0xabc",
    });

    await expect(registerDurableEmployerStatement({
      client: {
        recordEmployerStatementSubmission: vi.fn(),
        reconcileEmployerStatement: vi.fn().mockRejectedValue(
          new PayoApiError("absent", "STATEMENT_NOT_REGISTERED", 409),
        ),
      } as never,
      stored: {
        id: prepared.create.id,
        state: "submitted",
        registrationTransactionHash: "0xabc",
      },
      statement: prepared.create.statement,
      statementCommitment: prepared.create.statementCommitment,
      registerStatement: vi.fn(),
    })).rejects.toThrow(/do not submit it again/i);
  });
  it("derives one durable FX-bound statement from a confirmed payroll and recovers it after reload", async () => {
    const prepared = await durablePayrollFixture();
    const request = {
      client: prepared.client as never,
      organizationId,
      runId: prepared.run.id,
      snapshotPlanId: prepared.plan.id,
      principal: owner,
      now: new Date(1_150_000),
    };
    const first = await prepareDurableEmployerStatementForPayroll(request);
    expect(first).toMatchObject({
      recovered: false,
      stored: { state: "prepared", runId: prepared.run.id },
    });
    expect(BigInt(first.statement.manifestRoot)).toBe(
      BigInt(prepared.run.manifestRoot),
    );
    expect(BigInt(first.statement.fxRoot)).toBe(BigInt(prepared.run.fxRoot));
    expect(prepared.client.createEmployerStatement).toHaveBeenCalledOnce();

    const recovered = await prepareDurableEmployerStatementForPayroll(request);
    expect(recovered).toMatchObject({
      recovered: true,
      stored: { id: first.stored.id },
    });
    expect(prepared.client.createEmployerStatement).toHaveBeenCalledOnce();
  });

  it("rejects unconfirmed payrolls and altered encrypted proof roots before persistence", async () => {
    const prepared = await durablePayrollFixture();
    const request = {
      client: prepared.client as never,
      organizationId,
      runId: prepared.run.id,
      snapshotPlanId: prepared.plan.id,
      principal: owner,
      now: new Date(1_150_000),
    };
    prepared.client.getPayrollRun.mockResolvedValueOnce({
      run: { ...prepared.run, state: "submitted" },
    } as never);
    await expect(
      prepareDurableEmployerStatementForPayroll(request),
    ).rejects.toThrow(/canonically confirmed/i);
    expect(prepared.client.createEmployerStatement).not.toHaveBeenCalled();

    prepared.client.getPayrollRun.mockResolvedValueOnce({
      run: { ...prepared.run, manifestRoot: hex("ff") },
    } as never);
    await expect(
      prepareDurableEmployerStatementForPayroll(request),
    ).rejects.toThrow(/manifest root do not match/i);
    expect(prepared.client.createEmployerStatement).not.toHaveBeenCalled();
  });


});
