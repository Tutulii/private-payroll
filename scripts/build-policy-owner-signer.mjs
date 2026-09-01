import { build } from "esbuild";

await build({
  entryPoints: ["scripts/payo-policy-owner-signer.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node24",
  legalComments: "none",
  outfile: process.env.PAYO_POLICY_SIGNER_BUNDLE_OUTPUT
    ?? "dist/payo-policy-owner-signer.mjs",
});
