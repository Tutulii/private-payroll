import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Noir, type CompiledCircuit } from "@noir-lang/noir_js";
import { buildFxSnapshot } from "@/lib/domain/fx";
import {
  buildPayrollIntegrityInputsFromSerialized,
  PAYO_NET_INVOICE_POLICY,
  serializePayrollIntegrityBuildRequest,
} from "@/lib/proof/input-builder";

const FELT = /^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})$/;
async function main(): Promise<void> {
const chainId = requiredFelt("PAYO_PHASE4_CHAIN_ID");
const sealAddress = requiredFelt("PAYO_PHASE4_SEAL_ADDRESS");
const recipientAddress = requiredFelt("PAYO_PHASE4_RECIPIENT_ADDRESS");
const validityStart = requiredTimestamp("PAYO_PHASE4_VALIDITY_START");
const validityExpiry = requiredTimestamp("PAYO_PHASE4_VALIDITY_EXPIRY");

if (
  validityStart < 30n
  || validityExpiry <= validityStart
  || validityExpiry - validityStart > 3_600n
) {
  throw new Error("Phase 4 PayrollIntegrity validity must be ordered, at most one hour, and start after 30.");
}

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function requiredFelt(name: string): `0x${string}` {
  const value = required(name);
  if (!FELT.test(value) || BigInt(value) === 0n) {
    throw new Error(`${name} must be a nonzero canonical Starknet felt.`);
  }
  return value as `0x${string}`;
}

function requiredTimestamp(name: string): bigint {
  const value = required(name);
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${name} must be an unsigned Unix timestamp.`);
  }
  const parsed = BigInt(value);
  if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${name} is outside JavaScript's safe timestamp range.`);
  }
  return parsed;
}

const snapshot = buildFxSnapshot({
  baseToken: "STRK",
  referenceCurrency: "USD",
  quoteDecimals: 6,
  haircutBps: 0,
  // Native SettlementMatch proving can take several minutes on constrained
  // runners. Keep the quote fresh for the whole proof/submission window while
  // still binding the exact observation time and bounded age into the proof.
  maximumAgeSeconds: 600,
  minimumSources: 3,
  feedId: "devnet:STRK/USD:median",
  quotes: [20n, 15n, 10n].map((age, index) => ({
    source: `phase4-devnet-source-${index + 1}`,
    priceAtomic: "1000000",
    observedAt: new Date(Number(validityStart - age) * 1_000).toISOString(),
  })),
  now: new Date(Number(validityStart) * 1_000),
});

const serializedBuild = serializePayrollIntegrityBuildRequest({
  chainId,
  sealAddress,
  organizationSecret: `0x${"41".repeat(32)}`,
  cycleId: "phase4-policy-account-devnet",
  revision: 1,
  validityStart,
  validityExpiry,
  policies: [PAYO_NET_INVOICE_POLICY],
  fxSnapshots: [snapshot],
  lines: [{
    agreementId: "phase4-bounded-agent-payroll",
    recipientAddress,
    recipientSalt: `0x${"42".repeat(32)}`,
    agreementSalt: `0x${"43".repeat(32)}`,
    lineSalt: `0x${"44".repeat(32)}`,
    token: "STRK",
    earningsAtomic: ["1000000000000000"],
    deductionsAtomic: [],
    policyId: PAYO_NET_INVOICE_POLICY.id,
    scheduleCommitment: `0x${"45".repeat(32)}`,
    dueAt: validityStart - 1n,
    validUntil: validityExpiry + 600n,
    classification: { declared: 2, score: 2, employeeThreshold: 5 },
    fxFloorAtomic: "0",
    referenceCurrency: "USD",
  }],
});
const payroll = await buildPayrollIntegrityInputsFromSerialized(serializedBuild);
const circuit = JSON.parse(await readFile(
  resolve(process.cwd(), "public/circuits/payroll_integrity-v1.json"),
  "utf8",
)) as CompiledCircuit;
const noir = new Noir(circuit);
const target = resolve(process.cwd(), "circuits/payroll_integrity/target");
for (const shardIndex of [0, 1] as const) {
  const { witness } = await noir.execute(payroll.witness.circuitInputs[shardIndex]);
  payroll.witness.circuitInputs[shardIndex] = {};
  await writeFile(
    resolve(target, `witness-phase4-devnet-shard-${shardIndex}.gz`),
    witness,
    { mode: 0o600 },
  );
  witness.fill(0);
}

const privateBuildPath = resolve(target, "phase4-devnet-payroll-build.json");
await writeFile(privateBuildPath, `${JSON.stringify({
  version: "payo-phase4-devnet-payroll-build-v1",
  serializedBuild,
}, null, 2)}\n`, { mode: 0o600 });

process.stdout.write(`${JSON.stringify({
  generated: true,
  chainId,
  sealAddress,
  recipientAddress,
  amountAtomic: payroll.calculatedLines[0].netAtomic,
  agreementRoot: payroll.agreementRoot,
  manifestRoot: payroll.manifestRoot,
  policyRoot: payroll.policyRoot,
  fxRoot: payroll.fxRoot,
  runNullifier: payroll.runNullifier,
  validityStart: validityStart.toString(),
  validityExpiry: validityExpiry.toString(),
  privateBuildPath,
}, null, 2)}\n`);
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
