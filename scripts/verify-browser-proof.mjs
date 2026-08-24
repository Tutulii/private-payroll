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
}));
if (result.stage !== "complete" || unexpectedErrors.length > 0) {
  throw new Error(`Browser proof failed: ${JSON.stringify({ result, unexpectedErrors })}`);
}
const benchmark = {
  verified: true,
  browser: await browser.version(),
  result: result.text?.replace(/\s+/g, " ").trim(),
  recordedAt: new Date().toISOString(),
};
await writeFile("circuits/payroll_integrity/target/browser-proof-benchmark.json", JSON.stringify(benchmark, null, 2));
console.log(JSON.stringify(benchmark, null, 2));
await browser.close();
