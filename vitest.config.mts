import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["**/*.test.{ts,mjs}"],
  },
  resolve: {
    alias: {
      "@": new URL("./", import.meta.url).pathname,
    },
  },
});
