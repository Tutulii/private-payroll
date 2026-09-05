import { defineConfig } from "playwright/test";

const port = 3105;

export default defineConfig({
  testDir: "./tests/browser",
  testMatch: "block4-external-attestation.spec.ts",
  fullyParallel: false,
  workers: 1,
  timeout: 180_000,
  expect: { timeout: 15_000 },
  outputDir: "test-results/block4-browser",
  reporter: process.env.CI
    ? [["line"], ["html", { outputFolder: "playwright-report-block4", open: "never" }]]
    : "line",
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    browserName: "chromium",
    headless: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: `node node_modules/next/dist/bin/next dev --webpack --hostname 127.0.0.1 --port ${port}`,
    url: `http://127.0.0.1:${port}/payo-browser-evidence/team`,
    timeout: 120_000,
    reuseExistingServer: false,
    env: {
      ...process.env,
      PAYO_BROWSER_EVIDENCE_MODE: "1",
      NEXT_PUBLIC_STARKNET_RPC_URL: `http://127.0.0.1:${port}/browser-rpc`,
      NEXT_PUBLIC_PAYO_SEAL_ADDRESS: "0x123",
      NEXT_PUBLIC_PAYO_VESTING_BOOK_SEAL_ADDRESS: "0x456",
      NEXT_PUBLIC_PAYO_POLICY_REGISTRY_ADDRESS: "0x789",
    },
  },
});
