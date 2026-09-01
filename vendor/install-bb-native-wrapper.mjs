import { createHash } from "node:crypto";
import { chmod, copyFile, mkdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const packageRoot = resolve(root, "node_modules/@aztec/bb.js");
const packageJsonPath = resolve(packageRoot, "package.json");
const sourcePath = resolve(
  import.meta.dirname,
  "aztec-bb-3.0.0-nightly.20251104-kill-wrapper.sh",
);
const targetPaths = [
  resolve(packageRoot, "scripts/kill_wrapper.sh"),
  resolve(packageRoot, "dest/node-cjs/scripts/kill_wrapper.sh"),
];
const expectedVersion = "3.0.0-nightly.20251104";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

const packageJson = JSON.parse(await readFile(packageJsonPath, "utf8"));
if (packageJson.version !== expectedVersion) {
  throw new Error(
    `Refusing to repair @aztec/bb.js ${packageJson.version}; expected ${expectedVersion}.`,
  );
}

const source = await readFile(sourcePath);
for (const targetPath of targetPaths) {
  await mkdir(dirname(targetPath), { recursive: true });
  await copyFile(sourcePath, targetPath);
  await chmod(targetPath, 0o755);
  const installed = await readFile(targetPath);
  if (sha256(installed) !== sha256(source)) {
    throw new Error("The installed bb.js native wrapper does not match PAYO's vendored source.");
  }
}

process.stdout.write(
  `Installed pinned bb.js native wrappers for ${expectedVersion}.\n`,
);
