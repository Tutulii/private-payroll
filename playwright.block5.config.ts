import { defineConfig } from "playwright/test";

const port = 3106;

export default defineConfig({
  testDir: "./tests/browser",
  testMatch: "block5-private-exit.spec.ts",
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  outputDir: "test-results/block5-browser",
  reporter: process.env.CI
    ? [["line"], ["html", { outputFolder: "playwright-report-block5", open: "never" }]]
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
    url: `http://127.0.0.1:${port}/wallet`,
    timeout: 120_000,
    reuseExistingServer: false,
    env: {
      ...process.env,
      NEXT_PUBLIC_STARKNET_RPC_URL: `http://127.0.0.1:${port}/browser-rpc`,
    },
  },
});
