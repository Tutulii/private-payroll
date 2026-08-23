import { access, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const statusPath = resolve(root, "docs/implementation-status.json");
const allowedStatuses = new Set(["complete", "partial", "missing", "blocked"]);
const expectedRoadmapIds = [
  ...Array.from({ length: 5 }, (_, index) => `P0-${String(index + 1).padStart(2, "0")}`),
  ...Array.from({ length: 5 }, (_, index) => `P1-${String(index + 1).padStart(2, "0")}`),
  ...Array.from({ length: 5 }, (_, index) => `P2-${String(index + 1).padStart(2, "0")}`),
  ...Array.from({ length: 7 }, (_, index) => `P3-${String(index + 1).padStart(2, "0")}`),
  ...Array.from({ length: 5 }, (_, index) => `P4-${String(index + 1).padStart(2, "0")}`),
  ...Array.from({ length: 4 }, (_, index) => `P5-${String(index + 1).padStart(2, "0")}`),
];
const expectedArchitectureIds = Array.from(
  { length: 16 },
  (_, index) => `A${String(index + 1).padStart(2, "0")}`,
);
const requireComplete = process.argv.includes("--require-complete");
const errors = [];

const data = JSON.parse(await readFile(statusPath, "utf8"));

function validateIds(entries, expected, label) {
  const ids = entries.map(({ id }) => id);
  const unique = new Set(ids);
  if (unique.size !== ids.length) errors.push(`${label} contains duplicate IDs.`);
  for (const id of expected) {
    if (!unique.has(id)) errors.push(`${label} is missing ${id}.`);
  }
  for (const id of unique) {
    if (!expected.includes(id)) errors.push(`${label} contains unexpected ID ${id}.`);
  }
}

validateIds(data.roadmap, expectedRoadmapIds, "Roadmap matrix");
validateIds(data.architecture, expectedArchitectureIds, "Architecture matrix");

for (const entry of [...data.roadmap, ...data.architecture]) {
  if (!allowedStatuses.has(entry.status)) errors.push(`${entry.id} has invalid status ${entry.status}.`);
  if (!entry.requirement?.trim()) errors.push(`${entry.id} has no requirement text.`);
  if (entry.status === "complete" && (!Array.isArray(entry.evidence) || entry.evidence.length === 0)) {
    errors.push(`${entry.id} is complete without implementation evidence.`);
  }
  for (const evidence of entry.evidence ?? []) {
    if (evidence.startsWith("http") || evidence.includes(" ")) continue;
    try {
      await access(resolve(root, evidence));
    } catch {
      errors.push(`${entry.id} references missing evidence: ${evidence}.`);
    }
  }
  if (requireComplete && entry.status !== "complete") {
    errors.push(`${entry.id} remains ${entry.status}: ${entry.requirement}.`);
  }
}

const readme = await readFile(resolve(root, "README.md"), "utf8");
if (!readme.includes("## Master implementation roadmap")) errors.push("README roadmap heading is missing.");
if (!readme.includes("### Phase 5")) errors.push("README Phase 5 is missing.");
if (!readme.includes("[architecture.md](./architecture.md)")) errors.push("README architecture link is missing.");

const roadmapCounts = Object.groupBy(data.roadmap, ({ status }) => status);
const score = data.roadmap.reduce((total, entry) => total + data.scoring[entry.status], 0);
const percentage = Math.round((score / data.roadmap.length) * 1000) / 10;
const strictComplete = roadmapCounts.complete?.length ?? 0;

if (requireComplete) {
  const release = JSON.parse(await readFile(resolve(root, "strk20.json"), "utf8"));
  if (!Array.isArray(release.transactions) || release.transactions.length < 3) {
    errors.push("strk20.json requires at least three Mainnet transactions.");
  }
  if (!Array.isArray(release.contracts) || release.contracts.length === 0) {
    errors.push("strk20.json requires deployed PAYO contract addresses.");
  }
  if (!release.demo_video) errors.push("strk20.json requires a demo video.");
  if (!release.demo_url) errors.push("strk20.json requires a public demo URL.");
}

console.log(
  `PAYO roadmap: ${strictComplete}/${data.roadmap.length} complete; weighted implementation ${percentage}%.`,
);
console.log(
  `Architecture: ${data.architecture.filter(({ status }) => status === "complete").length}/${data.architecture.length} complete.`,
);

if (errors.length > 0) {
  console.error(errors.map((error) => `- ${error}`).join("\n"));
  process.exitCode = 1;
} else {
  console.log(requireComplete ? "PAYO completion gate passed." : "PAYO status matrix is structurally valid.");
}
