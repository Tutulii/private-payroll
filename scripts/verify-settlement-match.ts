import { readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { buildFxSnapshot } from "@/lib/domain/fx";
import { PAYROLL_TOKENS } from "@/lib/starknet/tokens";
import {
  buildPayrollIntegrityInputs,
  PAYO_NET_INVOICE_POLICY,
  type PayrollIntegrityLineInput,
} from "@/lib/proof/input-builder";
import {
  buildSettlementMatchInputs,
  deriveStrk20EncryptedNote,
  settlementTransactionReference,
  type SettlementPayrollNote,
} from "@/lib/proof/settlement-match";

type Hex = ReturnType<typeof deriveStrk20EncryptedNote>["noteId"];

function fxSnapshot() {
  return buildFxSnapshot({
    baseToken: "USDC",
    referenceCurrency: "USD",
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 30,
    minimumSources: 3,
    feedId: "pragma:USDC/USD:median",
    quotes: ["a", "b", "c"].map((source, index) => ({
      source: "pragma-usdc-" + source,
      priceAtomic: "1000000",
      observedAt: "1970-01-01T00:16:" + (40 + index) + ".000Z",
    })),
    now: new Date(1_010_000),
  });
}

function payrollLine(): PayrollIntegrityLineInput {
  return {
    agreementId: "settlement-match-real-main",
    recipientAddress: "0x111",
    recipientSalt: ("0x" + "66".repeat(32)) as Hex,
    agreementSalt: ("0x" + "22".repeat(32)) as Hex,
    lineSalt: ("0x" + "33".repeat(32)) as Hex,
    token: "USDC",
    earningsAtomic: ["1000000"],
    deductionsAtomic: [],
    policyId: PAYO_NET_INVOICE_POLICY.id,
    scheduleCommitment: ("0x" + "44".repeat(32)) as Hex,
    dueAt: 1_000n,
    validUntil: 2_000n,
    classification: { declared: 2, score: 2, employeeThreshold: 5 },
    fxFloorAtomic: "0",
    referenceCurrency: "USD",
  };
}

async function main() {
  const payroll = await buildPayrollIntegrityInputs({
    chainId: "0x1",
    sealAddress: "0x12345",
    organizationSecret: "0x" + "55".repeat(32),
    cycleId: "settlement-match-real-main",
    revision: 1,
    validityStart: 1_010n,
    validityExpiry: 2_000n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: [fxSnapshot()],
    lines: [payrollLine()],
  });
  const binding = payroll.proofBindings[0];
  const senderAddress = "0x123";
  const viewingKey = "0x456";
  const recipientPublicKey = "0x789";
  const noteIndex = 5;
  const salt = "22136";
  const encrypted = deriveStrk20EncryptedNote({
    senderAddress,
    viewingKey,
    recipientAddress: binding.source.recipientAddress,
    recipientPublicKey,
    tokenAddress: PAYROLL_TOKENS.USDC.address,
    noteIndex,
    salt,
    amountAtomic: binding.calculated.netAtomic,
  });
  const payrollNotes: SettlementPayrollNote[] = [{
    position: 0,
    recipientAddress: binding.source.recipientAddress as Hex,
    recipientPublicKey: recipientPublicKey as Hex,
    tokenAddress: PAYROLL_TOKENS.USDC.address as Hex,
    amountAtomic: binding.calculated.netAtomic,
    noteIndex,
    salt,
    noteId: encrypted.noteId,
    packedValue: encrypted.packedValue,
  }];
  const built = buildSettlementMatchInputs({
    payroll,
    senderAddress,
    viewingKey,
    transactionReference: settlementTransactionReference({
      chainId: "0x1",
      policyAccountAddress: senderAddress,
      poolAddress: "0x987",
      poolCalldata: ["0x1", "0x2", "0x3"],
    }),
    payrollNotes,
    emittedNotes: payrollNotes,
  });
  const artifact = JSON.parse(readFileSync(
    new URL("../circuits/settlement_match/target/payo_settlement_match.json", import.meta.url),
    "utf8",
  )) as CompiledCircuit;
  const noir = new Noir(artifact);
  const positive = await noir.execute(built.circuitInputs[0]);
  if (positive.witness.byteLength === 0) {
    throw new Error("SettlementMatch produced an empty witness.");
  }
  if (process.env.PAYO_PHASE4_WRITE_WITNESS === "1") {
    const witnessPath = resolve(
      process.cwd(),
      process.env.PAYO_PHASE4_SETTLEMENT_WITNESS_PATH
        ?? "circuits/settlement_match/target/witness-v8-fixture.gz",
    );
    const bindingsPath = resolve(
      process.cwd(),
      process.env.PAYO_PHASE4_SETTLEMENT_BINDINGS_PATH
        ?? "circuits/settlement_match/target/witness-v8-bindings.json",
    );
    await Promise.all([
      mkdir(dirname(witnessPath), { recursive: true }),
      mkdir(dirname(bindingsPath), { recursive: true }),
    ]);
    await Promise.all([
      writeFile(witnessPath, positive.witness, { mode: 0o600 }),
      writeFile(bindingsPath, JSON.stringify({
        proofVersion: 8,
        settlementRoot: built.settlementRoot,
        transactionReference: built.transactionReference,
        publicInputs: built.publicInputs[0],
      }, null, 2) + "\n", { mode: 0o600 }),
    ]);
  }
  positive.witness.fill(0);

  const tampered = structuredClone(built.circuitInputs[0]);
  const notes = tampered.notes as Array<{ packed_value: number[] }>;
  notes[0].packed_value[31] ^= 1;
  let rejected = false;
  try {
    const unexpected = await noir.execute(tampered);
    unexpected.witness.fill(0);
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error("SettlementMatch accepted a tampered encrypted note.");

  process.stdout.write(JSON.stringify({
    proofVersion: 8,
    chunks: built.circuitInputs.length,
    settlementRoot: built.settlementRoot,
    transactionReference: built.transactionReference,
    positiveWitness: "accepted",
    tamperedCiphertext: "rejected",
  }, null, 2) + "\n");
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
