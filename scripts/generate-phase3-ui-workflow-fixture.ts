import { pathToFileURL } from "node:url";
import { writePhase3UiWorkflowFixture } from "./lib/phase3-ui-workflow-fixture";

async function main() {
  const fixture = await writePhase3UiWorkflowFixture();
  process.stdout.write(`${JSON.stringify({
    valid: true,
    artifact: "evidence/phase3-devnet-fixtures/advanced-matrix-ui-origin.json",
    organizationId: fixture.organizationId,
    workflows: fixture.entries.map(({ workflow }) => workflow),
    checks: fixture.entries.map(({ checks }) => checks),
  }, null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
