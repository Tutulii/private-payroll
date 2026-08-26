import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { RpcProvider } from "starknet";
import {
  fxSnapshotCommitment,
  pragmaProtectedFxSnapshotCommitment,
  protectedFxSnapshotToPayrollSnapshot,
} from "@/lib/domain/fx";
import {
  PRAGMA_MAINNET_ORACLE_ADDRESS,
  PRAGMA_MAINNET_SUMMARY_STATS_ADDRESS,
  readPragmaProtectedFxSnapshots,
} from "@/lib/server/pragma-fx";

const expectedChainId = "0x534e5f4d41494e";

async function main() {
  const rpcUrl = process.env.STARKNET_RPC_URL;
  if (!rpcUrl) throw new Error("STARKNET_RPC_URL is required for Pragma Mainnet verification.");
  const provider = new RpcProvider({ nodeUrl: rpcUrl });
  const chainId = await provider.getChainId();
  if (BigInt(chainId) !== BigInt(expectedChainId)) {
    throw new Error(`Refusing Pragma evidence on non-Mainnet chain ${chainId}.`);
  }
  const result = await readPragmaProtectedFxSnapshots({
    rpc: {
      getBlockNumber: () => provider.getBlockNumber(),
      getBlockTimestamp: async (blockNumber) => Number((await provider.getBlock(blockNumber)).timestamp),
      callContract: (call, blockIdentifier) => provider.callContract(call, blockIdentifier),
    },
    tokens: ["STRK"],
  });
  let usdcUnsupported = false;
  let usdcUnsupportedComponent: string | null = null;
  try {
    await readPragmaProtectedFxSnapshots({
      rpc: {
        getBlockNumber: () => provider.getBlockNumber(),
        getBlockTimestamp: async (blockNumber) => Number((await provider.getBlock(blockNumber)).timestamp),
        callContract: (call, blockIdentifier) => provider.callContract(call, blockIdentifier),
      },
      tokens: ["USDC"],
    });
  } catch (error) {
    usdcUnsupported = error instanceof Error
      && "pair" in error
      && error.pair === "USDC/USD"
      && "component" in error
      && error.component === "twap";
    usdcUnsupportedComponent = error instanceof Error && "component" in error
      ? String(error.component)
      : null;
  }
  if (!usdcUnsupported) {
    throw new Error("USDC/USD unexpectedly passed the protected profile without evidenced TWAP history.");
  }
  const snapshots = result.snapshots.map((protectedSnapshot) => {
    const payrollSnapshot = protectedFxSnapshotToPayrollSnapshot(protectedSnapshot);
    return {
      protectedSnapshot,
      protectedCommitment: pragmaProtectedFxSnapshotCommitment(protectedSnapshot),
      payrollSnapshot,
      payrollCommitment: fxSnapshotCommitment(payrollSnapshot),
    };
  });
  const evidence = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    passed: true,
    chainId,
    blockNumber: result.blockNumber,
    blockTimestamp: result.blockTimestamp,
    oracleAddress: PRAGMA_MAINNET_ORACLE_ADDRESS,
    summaryStatsAddress: PRAGMA_MAINNET_SUMMARY_STATS_ADDRESS,
    protectedPairs: ["STRK/USD"],
    unsupportedPairs: [{ pair: "USDC/USD", component: usdcUnsupportedComponent }],
    rpcCredentialPersisted: false,
    snapshots,
  };
  await writeFile(
    resolve(process.cwd(), "evidence/pragma-phase3-mainnet.json"),
    `${JSON.stringify(evidence, null, 2)}\n`,
    { mode: 0o600 },
  );
  console.log(JSON.stringify(evidence, null, 2));
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
