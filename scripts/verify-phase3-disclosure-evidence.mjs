import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { validatePhase3DisclosureEvidence } from "./lib/phase3-disclosure-evidence.mjs";

const root = resolve(import.meta.dirname, "..");
const readJson = async (path) => JSON.parse(await readFile(resolve(root, path), "utf8"));
const result = await validatePhase3DisclosureEvidence({
  evidence: await readJson("evidence/phase3-matrix-disclosure.json"),
  matrixEvidence: await readJson("evidence/phase3-private-settlement-devnet.json"),
}, { root });
console.log(`Phase 3 disclosure evidence passed: ${result.packageCount} recipient-encrypted packages across seven workflows and three organization scopes.`);
