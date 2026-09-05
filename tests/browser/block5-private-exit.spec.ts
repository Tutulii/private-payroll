import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { expect, test } from "playwright/test";
import {
  sealPrivateExitQuote,
  type PrivateExitQuote,
} from "@/lib/domain/private-exit";
import {
  EKUBO_MAINNET_ROUTER_ADDRESS,
  PAYO_PRIVATE_STRK_USDC_POOL,
  STRK20_EKUBO_ANONYMIZER_CLASS_HASH,
} from "@/lib/starknet/private-exit";
import { STARKNET_MAINNET_CHAIN_ID } from "@/lib/starknet/deployment";

const EXECUTOR = "0x12345";
const BLOCK_HASH = `0x${"ab".repeat(32)}`;

function browserQuote(amountInAtomic = "1000000000000000000"): PrivateExitQuote {
  const quotedAt = Date.now();
  return sealPrivateExitQuote({
    version: "payo-private-exit-quote-v1",
    routeId: "ekubo-strk-usdc-single-hop-v1",
    chainId: STARKNET_MAINNET_CHAIN_ID,
    privacyMode: "anonymous-swap-to-open-private-note",
    fromToken: "STRK",
    toToken: "USDC",
    amountInAtomic,
    expectedOutAtomic: "27060",
    minimumOutAtomic: "26789",
    slippageBps: 100,
    priceImpact: 0.000535,
    quoteBlockNumber: 14_379_176,
    quoteBlockHash: BLOCK_HASH,
    quotedAt,
    expiresAt: quotedAt + 45_000,
    executorAddress: EXECUTOR,
    executorClassHash: STRK20_EKUBO_ANONYMIZER_CLASS_HASH,
    routerAddress: EKUBO_MAINNET_ROUTER_ADDRESS,
    pool: PAYO_PRIVATE_STRK_USDC_POOL,
    skipAhead: "0",
  });
}

test("Block 5 renders an honest private-exit boundary and rejects a tampered quote", async ({
  page,
}, testInfo) => {
  const requestedAmounts: string[] = [];
  let tamperNextQuote = false;

  await page.route("**/api/v1/private-exit/readiness", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        readiness: {
          enabled: true,
          code: "READY",
          message: "Reviewed STRK20 anonymizer verified.",
          routeId: "ekubo-strk-usdc-single-hop-v1",
          executorAddress: EXECUTOR,
          verifiedBlockNumber: 14_379_180,
        },
      }),
    });
  });
  await page.route("**/api/v1/private-exit/quote?**", async (route) => {
    const amount = new URL(route.request().url()).searchParams.get("amountAtomic") ?? "";
    requestedAmounts.push(amount);
    const quote = browserQuote(amount);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        quote: tamperNextQuote
          ? { ...quote, minimumOutAtomic: "1" }
          : quote,
      }),
    });
  });

  await page.goto("/wallet");
  const card = page.locator(".private-exit-card");
  await expect(card.getByRole("heading", { name: "Know where privacy ends." })).toBeVisible();
  await expect(card).toContainText("Official anonymizer class verified");
  await expect(card).toContainText("anonymous swap amount and Ekubo pool route remain visible");

  await card.getByLabel("Private swap amount").fill("1");
  await expect(card).toContainText("0.02706");
  await expect(card).toContainText("Minimum 0.026789 USDC");
  await expect(card.getByRole("button", { name: /Swap into private USDC/ })).toBeDisabled();
  expect(requestedAmounts).toEqual(["1000000000000000000"]);

  tamperNextQuote = true;
  await card.getByLabel("Private swap amount").fill("2");
  await expect(card).toContainText("quote commitment does not match");
  await expect(card.getByRole("button", { name: /Swap into private USDC/ })).toBeDisabled();

  await card.getByRole("tab", { name: "Public withdrawal" }).click();
  await expect(card).toContainText("permanently leaves PAYO’s privacy boundary");
  await expect(card).toContainText("destination address, token and amount become public");
  const publicButton = card.getByRole("button", { name: "Withdraw publicly" });
  await expect(publicButton).toBeDisabled();
  await card.getByLabel(/I understand this exact withdrawal/).check();
  await expect(publicButton).toBeDisabled();

  await card.getByRole("tab", { name: "Bridge / exchange" }).click();
  await expect(card).toContainText("Unsupported destinations are blocked");
  await expect(card).toContainText("will not wrap a bridge, centralized exchange or arbitrary contract call");

  const artifact = {
    schemaVersion: "payo.block5.private-exit.browser.v1",
    generatedAt: new Date().toISOString(),
    productionPage: "app/wallet/page.tsx",
    checks: {
      exactAtomicQuoteRequested: requestedAmounts[0] === "1000000000000000000",
      canonicalPrivateRouteRendered: true,
      privacyLeakageDisclosed: true,
      tamperedQuoteRejected: true,
      publicWithdrawalRequiresExplicitAcknowledgement: true,
      publicWithdrawalRemainsWalletGated: true,
      unsupportedBridgeAndExchangeBlocked: true,
    },
  };
  const outputPath = testInfo.outputPath("block5-private-exit-browser.json");
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600 });
  await testInfo.attach("block5-private-exit-browser", {
    path: outputPath,
    contentType: "application/json",
  });
  if (process.env.PAYO_BROWSER_EVIDENCE_WRITE === "1") {
    const committed = resolve("evidence/block5-private-exit-browser.json");
    await mkdir(dirname(committed), { recursive: true });
    await writeFile(committed, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600 });
  }
});
