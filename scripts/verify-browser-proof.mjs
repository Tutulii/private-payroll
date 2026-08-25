import { writeFile } from "node:fs/promises";
import { chromium } from "playwright";

const baseUrl = process.env.PAYO_BROWSER_PROOF_URL ?? "http://127.0.0.1:3000";
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
const unexpectedErrors = [];
page.on("pageerror", (error) => unexpectedErrors.push(error.message));
await page.goto(`${baseUrl}/proof-benchmark`, { waitUntil: "networkidle" });
await page.locator('[data-proof-stage="ready"] button').click();
await page.locator('[data-proof-result="verified"]').waitFor({ timeout: 30 * 60_000 });
const result = await page.locator('[data-proof-result="verified"]').evaluate((node) => ({
  text: node.textContent,
  stage: node.closest("[data-proof-stage]")?.getAttribute("data-proof-stage"),
  calldataCounts: node.getAttribute("data-calldata-counts"),
  calldataHashes: node.getAttribute("data-calldata-hashes"),
}));
const calldataCounts = result.calldataCounts?.split(",").map(Number) ?? [];
const calldataHashes = result.calldataHashes?.split(",") ?? [];
const canonicalHash = /^0x[0-9a-f]{1,63}$/;
if (
  result.stage !== "complete"
  || unexpectedErrors.length > 0
  || calldataCounts.length !== 2
  || calldataCounts.some((count) => count !== 3_187)
  || calldataHashes.length !== 2
  || calldataHashes.some((value) => !canonicalHash.test(value) || BigInt(value) === 0n)
) {
  throw new Error(`Browser proof failed: ${JSON.stringify({ result, unexpectedErrors })}`);
}
const benchmark = {
  verified: true,
  starknetCalldataGenerated: true,
  calldataCounts,
  calldataHashes,
  browser: await browser.version(),
  result: result.text?.replace(/\s+/g, " ").trim(),
  recordedAt: new Date().toISOString(),
};
await writeFile("circuits/payroll_integrity/target/browser-proof-benchmark.json", JSON.stringify(benchmark, null, 2));
console.log(JSON.stringify(benchmark, null, 2));
await browser.close();
