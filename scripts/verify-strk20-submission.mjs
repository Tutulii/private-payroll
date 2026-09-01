import { readFile } from "node:fs/promises";

const allowMissingVideo = process.argv.includes("--allow-missing-video");
const unknownArguments = process.argv.slice(2).filter(
  (argument) => argument !== "--allow-missing-video",
);
if (unknownArguments.length > 0) {
  throw new Error(`Unknown argument: ${unknownArguments.join(", ")}.`);
}

const submission = JSON.parse(await readFile("strk20.json", "utf8"));
const inventory = JSON.parse(
  await readFile("evidence/mainnet-contract-inventory.json", "utf8"),
);
const hashPattern = /^0x[0-9a-f]{1,64}$/i;

function requireUniqueHashes(values, label, minimum) {
  if (!Array.isArray(values) || values.length < minimum) {
    throw new Error(`${label} must contain at least ${minimum} entries.`);
  }
  if (values.some((value) => typeof value !== "string" || !hashPattern.test(value))) {
    throw new Error(`${label} contains a malformed Starknet hash/address.`);
  }
  const normalized = values.map((value) => BigInt(value).toString(16));
  if (new Set(normalized).size !== values.length) {
    throw new Error(`${label} contains a duplicate.`);
  }
}

function requireHttpsUrl(value, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid URL.`);
  }
  if (parsed.protocol !== "https:") {
    throw new Error(`${label} must use HTTPS.`);
  }
}

requireUniqueHashes(submission.transactions, "transactions", 3);
requireUniqueHashes(submission.contracts, "contracts", 1);
requireHttpsUrl(submission.demo_url, "demo_url");
if (!submission.demo_video) {
  if (!allowMissingVideo) {
    throw new Error("demo_video is required for the final STRK20 submission.");
  }
} else {
  requireHttpsUrl(submission.demo_video, "demo_video");
}

const submittedContracts = new Set(
  submission.contracts.map((address) => BigInt(address).toString(16)),
);
const missingOwnedContracts = inventory.contracts
  .filter((contract) => contract.payoOwned)
  .filter(
    (contract) =>
      !submittedContracts.has(BigInt(contract.address).toString(16)),
  )
  .map((contract) => contract.name);
if (missingOwnedContracts.length > 0) {
  throw new Error(
    `strk20.json omits active PAYO contracts: ${missingOwnedContracts.join(", ")}.`,
  );
}

process.stdout.write(
  `${JSON.stringify(
    {
      valid: true,
      final: Boolean(submission.demo_video),
      transactionCount: submission.transactions.length,
      contractCount: submission.contracts.length,
      demoUrl: submission.demo_url,
      videoStatus: submission.demo_video ? "configured" : "pending",
    },
    null,
    2,
  )}\n`,
);
