import { defineConfig } from "playwright/test";

const port = 3103;

export default defineConfig({
  testDir: "./tests/browser",
  testMatch: "phase3-production-controls.spec.ts",
  fullyParallel: false,
  workers: 1,
  timeout: 300_000,
  expect: { timeout: 15_000 },
  outputDir: "test-results/phase3-browser",
  reporter: process.env.CI ? [["line"], ["html", { outputFolder: "playwright-report", open: "never" }]] : "line",
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
    },
  },
});
