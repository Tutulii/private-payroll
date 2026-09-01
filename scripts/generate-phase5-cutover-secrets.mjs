import { mkdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { generatePhase5CutoverMaterial } from "./lib/phase5-cutover-material.mjs";

const POLICY_ACCOUNT = "0x656928a6f3aeb62c2e62ff7457d351a41ed987ceed07c514539165662ecb7e0";
const CURRENT_OWNER = "0x6e3e81271a762ead3ac1efc8c1193397882a7851f10ce7deea7ec83433da8ef";
const outputInput = process.env.PAYO_PHASE5_SECRET_DIR?.trim();
if (!outputInput || !isAbsolute(outputInput)) {
  throw new Error("PAYO_PHASE5_SECRET_DIR must be an absolute directory outside the repository.");
}
const outputDirectory = resolve(outputInput);
const repositoryRelative = relative(process.cwd(), outputDirectory);
if (!repositoryRelative.startsWith("..") || repositoryRelative === "") {
  throw new Error("Phase 5 secret material must never be written inside the repository.");
}

process.umask(0o077);
await mkdir(dirname(outputDirectory), { recursive: true, mode: 0o700 });
await mkdir(outputDirectory, { mode: 0o700 });
const material = generatePhase5CutoverMaterial({
  policyAccountAddress: POLICY_ACCOUNT,
  currentOwnerPublicKey: CURRENT_OWNER,
});
const envFile = (entries) => `${entries.map(([key, value]) => `${key}=${value}`).join("\n")}\n`;

const offlineOwnerPath = resolve(outputDirectory, "offline-owner-recovery.env");
const signerPath = resolve(outputDirectory, "signer-secrets.env");
const webPath = resolve(outputDirectory, "web-worker-secrets.env");
const publicPlanPath = resolve(outputDirectory, "public-cutover-plan.json");
await Promise.all([
  writeFile(offlineOwnerPath, envFile([
    ["PAYO_POLICY_OWNER_PRIVATE_KEY", material.ownerPrivateKey],
    ["PAYO_POLICY_OWNER_PUBLIC_KEY", material.ownerPublicKey],
    ["PAYO_POLICY_ROTATION_NEW_PUBLIC_KEY", material.ownerPublicKey],
    ["PAYO_POLICY_ROTATION_ACCEPTANCE_R", material.acceptanceSignature.r],
    ["PAYO_POLICY_ROTATION_ACCEPTANCE_S", material.acceptanceSignature.s],
  ]), { flag: "wx", mode: 0o600 }),
  writeFile(signerPath, envFile([
    ["PAYO_POLICY_OWNER_PRIVATE_KEY", material.ownerPrivateKey],
    ["PAYO_POLICY_OWNER_PUBLIC_KEY", material.ownerPublicKey],
    ["PAYO_POLICY_SIGNER_SECRET", material.signerSecret],
    ["PAYO_AGENT_POLICY_VIEWING_PUBLIC_KEY", material.viewingPublicKey],
  ]), { flag: "wx", mode: 0o600 }),
  writeFile(webPath, envFile([
    ["PAYO_POLICY_SIGNER_URL", "http://payo-policy-signer.internal:3000"],
    ["PAYO_POLICY_SIGNER_SECRET", material.signerSecret],
    ["PAYO_POLICY_SIGNER_PUBLIC_KEY", material.ownerPublicKey],
    ["PAYO_AGENT_POLICY_VIEWING_KEY", material.viewingKey],
  ]), { flag: "wx", mode: 0o600 }),
  writeFile(publicPlanPath, `${JSON.stringify({
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    policyAccountAddress: material.policyAccountAddress,
    currentOwnerPublicKey: material.currentOwnerPublicKey,
    newOwnerPublicKey: material.ownerPublicKey,
    treasuryViewingPublicKey: material.viewingPublicKey,
    ownerAcceptanceDigest: material.acceptanceDigest,
    ownerAcceptanceSignature: material.acceptanceSignature,
  }, null, 2)}\n`, { flag: "wx", mode: 0o600 }),
]);

process.stdout.write(`${JSON.stringify({
  generated: true,
  outputDirectory,
  files: { offlineOwnerPath, signerPath, webPath, publicPlanPath },
  public: {
    policyAccountAddress: material.policyAccountAddress,
    newOwnerPublicKey: material.ownerPublicKey,
    treasuryViewingPublicKey: material.viewingPublicKey,
  },
  nextGate: "Copy offline-owner-recovery.env to offline storage before any Mainnet owner rotation.",
}, null, 2)}\n`);
