import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // These packages load WASM/runtime assets dynamically in the Node prover.
  // Keeping them external lets the container use their pinned npm layouts.
  serverExternalPackages: ["@aztec/bb.js", "@noir-lang/noir_js", "garaga"],
};

export default nextConfig;
