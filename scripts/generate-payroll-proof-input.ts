import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  buildFixedMerkleRoot,
  deriveRunNullifier,
  hashAgreementTerms,
  hashMerkleNode,
  hashPayrollLeaf,
  hashRecipientCommitment,
  hashTextCommitment,
  PAYO_EMPTY_LEAF,
  splitHashToU128,
} from "../lib/crypto/commitments";
import { toHex } from "../lib/crypto/encoding";
import { encryptVaultRecord, generateVaultPrincipal } from "../lib/crypto/vault";
import { buildFxSnapshot, fxSnapshotCommitment, toCircuitFxSnapshot } from "../lib/domain/fx";
import { calculatePayrollLine } from "../lib/domain/payroll";
import { compilePolicyPack, policyPackCommitment } from "../lib/policy/engine";
import { US_2026_SUPPLEMENTAL_FLAT } from "../lib/policy/reference-packs";

const ZERO = `0x${"00".repeat(32)}`;
const byteArray = (hex: string) => Array.from(Buffer.from(hex.replace(/^0x/, "").padStart(64, "0"), "hex"));
const u128 = (value: bigint | number | string) => BigInt(value).toString();

function firstCatalogMembership() {
  const siblings: number[][] = [];
  let emptySubtree = PAYO_EMPTY_LEAF;
  for (let level = 0; level < 6; level += 1) {
    siblings.push(byteArray(emptySubtree));
    emptySubtree = hashMerkleNode(emptySubtree, emptySubtree);
  }
  return { siblings, path_bits: Array(6).fill(false) };
}

function catalogRoot(leaf: string): string {
  let current = leaf;
  for (const sibling of firstCatalogMembership().siblings) {
    current = hashMerkleNode(current, toHex(Uint8Array.from(sibling)));
  }
  return current;
}

function emptyProgram() {
  return {
    metadata_commitment: byteArray(ZERO), instruction_count: "0",
    opcodes: Array(16).fill("0"), left: Array(16).fill("0"), right: Array(16).fill("0"),
    immediate: Array(16).fill("0"), numerator: Array(16).fill("0"), denominator: Array(16).fill("0"),
    output_register: "0",
  };
}

function emptyAgreement() {
  return {
    enabled: false, id_commitment: byteArray(ZERO), recipient_commitment: byteArray(ZERO),
    earnings: Array(8).fill("0"), earnings_count: "0", token: "0",
    policy_commitment: byteArray(ZERO), schedule_commitment: byteArray(ZERO),
    due_at: "0", valid_until: "0", classification_declared: "0", classification_score: "0",
    classification_employee_threshold: "0", final_pay_mode: false, final_required_mask: "0",
    final_components: Array(5).fill("0"), fx_floor_atomic: "0", reference_currency: "0",
    salt: byteArray(ZERO),
  };
}

function emptyLine() {
  return {
    active: false, agreement_commitment: byteArray(ZERO), recipient_commitment: byteArray(ZERO),
    earnings: Array(8).fill("0"), earnings_count: "0", deductions: Array(8).fill("0"),
    deductions_count: "0", token: "0", policy_slot: "0", fx_slot: "0",
    schedule_commitment: byteArray(ZERO), salt: byteArray(ZERO), due_at: "0",
    classification_declared: "0", classification_treatment: "0", classification_score: "0",
    classification_employee_threshold: "0", final_pay_mode: false, final_required_mask: "0",
    final_included_mask: "0", final_components: Array(5).fill("0"), fx_floor_atomic: "0",
    reference_value_atomic: "0",
  };
}

function toml(value: unknown): string {
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number" && Number.isSafeInteger(value)) return value.toString();
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(toml).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value).map(([key, entry]) => `${key}=${toml(entry)}`).join(",")}}`;
  }
  throw new Error(`Unsupported TOML value: ${String(value)}`);
}

function rootLimbs(root: string) {
  const limbs = splitHashToU128(root);
  return { high: limbs.high.toString(), low: limbs.low.toString() };
}

const compiledPolicy = compilePolicyPack(US_2026_SUPPLEMENTAL_FLAT.pack);
const policyCommitment = policyPackCommitment(US_2026_SUPPLEMENTAL_FLAT.pack);
const agreementIdCommitment = toHex(hashTextCommitment("PAYO_AGREEMENT_ID_V1", "phase1-proof-agreement"));
const recipientCommitment = toHex(hashRecipientCommitment("0x123", `0x${"05".repeat(32)}`));
const scheduleCommitment = `0x${"04".repeat(32)}`;
const lineSalt = `0x${"05".repeat(32)}`;
const agreementSalt = `0x${"06".repeat(32)}`;
const validityStart = 1_010;
const validityExpiry = 2_000;
const dueAt = 1_000;
const validUntil = 3_000;

const calculatedLine = calculatePayrollLine({
  agreementId: "phase1-proof-agreement",
  recipientAddress: "0x123",
  token: "USDC",
  earningsAtomic: ["1000000"],
  deductionsAtomic: ["220000"],
  committedPolicyId: US_2026_SUPPLEMENTAL_FLAT.pack.id,
  scheduleCommitment,
  salt: lineSalt,
});
const payrollLeaf = hashPayrollLeaf(calculatedLine, 1, policyCommitment);

const fxSnapshot = buildFxSnapshot({
  baseToken: "USDC",
  referenceCurrency: "USD",
  quoteDecimals: 6,
  haircutBps: 0,
  maximumAgeSeconds: 30,
  minimumSources: 3,
  feedId: "pragma:USDC/USD:median",
  quotes: [
    { source: "pragma-source-a", priceAtomic: "1000000", observedAt: "1970-01-01T00:16:30.000Z" },
    { source: "pragma-source-b", priceAtomic: "1000000", observedAt: "1970-01-01T00:16:35.000Z" },
    { source: "pragma-source-c", priceAtomic: "1000000", observedAt: "1970-01-01T00:16:40.000Z" },
  ],
  now: new Date(validityStart * 1000),
});
const circuitFx = toCircuitFxSnapshot(fxSnapshot);
const fxCommitment = fxSnapshotCommitment(fxSnapshot);
const agreementTerms = hashAgreementTerms({
  agreementIdCommitment,
  recipientCommitment,
  earningsAtomic: calculatedLine.earningsAtomic,
  token: "USDC",
  policyCommitment,
  scheduleCommitment,
  dueAt: BigInt(dueAt),
  validUntil: BigInt(validUntil),
  classificationDeclared: 1,
  classificationScore: 10,
  classificationEmployeeThreshold: 5,
  finalPayMode: false,
  finalRequiredMask: 0,
  finalComponentsAtomic: [],
  fxFloorAtomic: "700000",
  referenceCurrency: "USD",
  salt: agreementSalt,
});

const agreementRoot = rootLimbs(buildFixedMerkleRoot([agreementTerms]));
const manifestRoot = rootLimbs(buildFixedMerkleRoot([payrollLeaf]));
const policyRoot = rootLimbs(catalogRoot(policyCommitment));
const fxRoot = rootLimbs(catalogRoot(fxCommitment));
const organizationSecret = `0x${"33".repeat(32)}`;
const cycleId = "phase1-real-proof";
const nullifier = rootLimbs(deriveRunNullifier({ organizationSecret, cycleId, revision: 1 }));

const agreement = {
  enabled: true,
  id_commitment: byteArray(agreementIdCommitment),
  recipient_commitment: byteArray(recipientCommitment),
  earnings: ["1000000", ...Array(7).fill("0")],
  earnings_count: "1",
  token: "1",
  policy_commitment: byteArray(policyCommitment),
  schedule_commitment: byteArray(scheduleCommitment),
  due_at: u128(dueAt),
  valid_until: u128(validUntil),
  classification_declared: "1",
  classification_score: "10",
  classification_employee_threshold: "5",
  final_pay_mode: false,
  final_required_mask: "0",
  final_components: Array(5).fill("0"),
  fx_floor_atomic: "700000",
  reference_currency: "0",
  salt: byteArray(agreementSalt),
};
const line = {
  active: true,
  agreement_commitment: byteArray(agreementIdCommitment),
  recipient_commitment: byteArray(recipientCommitment),
  earnings: ["1000000", ...Array(7).fill("0")], earnings_count: "1",
  deductions: ["220000", ...Array(7).fill("0")], deductions_count: "1",
  token: "1", policy_slot: "0", fx_slot: "0", schedule_commitment: byteArray(scheduleCommitment),
  salt: byteArray(lineSalt), due_at: u128(dueAt), classification_declared: "1",
  classification_treatment: "1", classification_score: "10", classification_employee_threshold: "5",
  final_pay_mode: false, final_required_mask: "0", final_included_mask: "0",
  final_components: Array(5).fill("0"), fx_floor_atomic: "700000", reference_value_atomic: "780000",
};
const policyProgram = {
  metadata_commitment: byteArray(compiledPolicy.metadataCommitment),
  instruction_count: u128(compiledPolicy.instructionCount),
  opcodes: compiledPolicy.opcodes.map(u128), left: compiledPolicy.left.map(u128), right: compiledPolicy.right.map(u128),
  immediate: [...compiledPolicy.immediate], numerator: [...compiledPolicy.numerator], denominator: [...compiledPolicy.denominator],
  output_register: u128(compiledPolicy.outputRegister),
};
const circuitSnapshot = {
  token: u128(circuitFx.token), token_decimals: u128(circuitFx.tokenDecimals),
  reference_currency: u128(circuitFx.referenceCurrency), quote_decimals: u128(circuitFx.quoteDecimals),
  feed_commitment: byteArray(circuitFx.feedCommitment),
  sources_commitment: byteArray(circuitFx.sourcesCommitment), price_numerator: circuitFx.priceNumerator,
  price_denominator: circuitFx.priceDenominator, observed_at: circuitFx.observedAt,
  source_count: u128(circuitFx.sourceCount), minimum_source_count: u128(circuitFx.minimumSourceCount),
  maximum_age_seconds: circuitFx.maximumAgeSeconds, haircut_bps: u128(circuitFx.haircutBps),
};
const emptyMembership = { siblings: Array.from({ length: 6 }, () => byteArray(ZERO)), path_bits: Array(6).fill(false) };
const emptySnapshot = {
  token: "0", token_decimals: "0", reference_currency: "0", quote_decimals: "0",
  feed_commitment: byteArray(ZERO),
  sources_commitment: byteArray(ZERO), price_numerator: "0", price_denominator: "0", observed_at: "0",
  source_count: "0", minimum_source_count: "0", maximum_age_seconds: "0", haircut_bps: "0",
};
const cycleBytes = [...new TextEncoder().encode(cycleId), ...Array(64 - cycleId.length).fill(0)];

const prover = {
  chain_id: "1",
  seal_address: "0x12345",
  proof_version: "1",
  schema_version: "1",
  agreement_root_high: agreementRoot.high,
  agreement_root_low: agreementRoot.low,
  manifest_root_high: manifestRoot.high,
  manifest_root_low: manifestRoot.low,
  policy_root_high: policyRoot.high,
  policy_root_low: policyRoot.low,
  fx_root_high: fxRoot.high,
  fx_root_low: fxRoot.low,
  run_nullifier_high: nullifier.high,
  run_nullifier_low: nullifier.low,
  validity_start: u128(validityStart),
  validity_expiry: u128(validityExpiry),
  organization_secret: byteArray(organizationSecret),
  cycle_id: cycleBytes,
  cycle_id_len: u128(cycleId.length),
  revision: "1",
  agreements: [agreement, ...Array.from({ length: 63 }, emptyAgreement)],
  lines: [line, ...Array.from({ length: 63 }, emptyLine)],
  policies: [
    { enabled: true, program: policyProgram, membership: firstCatalogMembership() },
    ...Array.from({ length: 3 }, () => ({ enabled: false, program: emptyProgram(), membership: emptyMembership })),
  ],
  fx_snapshots: [
    { enabled: true, snapshot: circuitSnapshot, membership: firstCatalogMembership() },
    { enabled: false, snapshot: emptySnapshot, membership: emptyMembership },
  ],
};

const output = `${Object.entries(prover).map(([key, value]) => `${key} = ${toml(value)}`).join("\n")}\n`;
const outputPath = resolve(process.cwd(), process.argv[2] ?? "circuits/payroll_integrity/Prover.toml");
async function writeProofInput() {
  await writeFile(outputPath, output, { encoding: "utf8", mode: 0o600 });
  if (process.env.PAYO_WRITE_BROWSER_PROOF_FIXTURE === "true") {
    const fixtureDirectory = resolve(process.cwd(), "public/fixtures");
    const fixturePath = resolve(fixtureDirectory, "encrypted-payroll-witness-v1.json");
    const principal = generateVaultPrincipal("phase1-browser-prover");
    const encryptedWitness = encryptVaultRecord(
      { circuitInput: prover },
      {
        schemaVersion: 1,
        organizationId: "phase1-proof-organization",
        recordType: "payroll-proof-witness",
        recordId: "phase1-browser-proof-witness",
        revision: 1,
      },
      [principal],
    );
    await mkdir(fixtureDirectory, { recursive: true });
    await writeFile(
      fixturePath,
      JSON.stringify({ syntheticFixture: true, principal, encryptedWitness }),
      { encoding: "utf8", mode: 0o600 },
    );
  }
  console.log(JSON.stringify({
    outputPath,
    publicInputs: {
      chainId: "1", sealAddress: "0x12345", proofVersion: "1", schemaVersion: "1",
      agreementRoot, manifestRoot, policyRoot, fxRoot, nullifier,
      validityStart: validityStart.toString(), validityExpiry: validityExpiry.toString(),
    },
  }, null, 2));
}

void writeProofInput();
