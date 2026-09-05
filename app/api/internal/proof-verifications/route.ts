import { Account, RpcProvider } from "starknet";
import { authorizeInternalWorker } from "@/lib/server/internal-auth";
import { getPayoDeploymentConfig, getPayoVestingBookConfig } from "@/lib/server/payo-deployment";
import { processExceptionAuthorizationBatch } from "@/lib/server/exception-authorization-relayer";
import { processPayrollAuthorizationBatch } from "@/lib/server/payroll-authorization-relayer";
import { processProofVerificationBatch } from "@/lib/server/proof-relayer";
import { processVestingAuthorizationBatch } from "@/lib/server/vesting-authorization-relayer";
import { withStarknetRelayerSubmissionLock } from "@/lib/persistence/relayer-lock";

export const runtime = "nodejs";

let verifiedChainIdAt = 0;
const CHAIN_ID_CACHE_MILLISECONDS = 5 * 60 * 1_000;

async function requireConfiguredChain(provider: RpcProvider, expectedChainId: string) {
  const now = Date.now();
  if (now - verifiedChainIdAt < CHAIN_ID_CACHE_MILLISECONDS) return true;
  const providerChainId = await provider.getChainId();
  if (BigInt(providerChainId) !== BigInt(expectedChainId)) return false;
  verifiedChainIdAt = now;
  return true;
}

export async function POST(request: Request) {
  if (!authorizeInternalWorker(request)) {
    return Response.json(
      { error: { code: "WORKER_UNAUTHORIZED", message: "Worker authorization failed." } },
      { status: 401 },
    );
  }
  const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
  const relayerAddress = process.env.PAYO_PROOF_RELAYER_ADDRESS;
  const relayerPrivateKey = process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY;
  if (!rpcUrl || !relayerAddress || !relayerPrivateKey) {
    return Response.json({
      error: {
        code: "PROOF_RELAYER_NOT_CONFIGURED",
        message: "The Starknet proof relayer is not configured.",
      },
    }, { status: 503 });
  }

  try {
    const deployment = getPayoDeploymentConfig();
    const provider = new RpcProvider({ nodeUrl: rpcUrl });
    if (!(await requireConfiguredChain(provider, deployment.chainId))) {
      return Response.json({
        error: { code: "PROOF_RELAYER_CHAIN_MISMATCH", message: "The relayer RPC is on the wrong chain." },
      }, { status: 503 });
    }
    const account = new Account({
      provider,
      address: relayerAddress,
      signer: relayerPrivateKey,
    });
    const rpc = {
      callContract: (call: Parameters<typeof provider.callContract>[0], blockIdentifier?: number) =>
        provider.callContract(call, blockIdentifier),
      getTransactionReceipt: (transactionHash: string) => provider.getTransactionReceipt(transactionHash),
      getBlockNumber: () => provider.getBlockNumber(),
      getBlockWithTxHashes: (blockNumber: number) => provider.getBlockWithTxHashes(blockNumber),
    };
    const submitter = {
      submit: (call: Parameters<typeof account.execute>[0]) =>
        withStarknetRelayerSubmissionLock(relayerAddress, async () => {
          // PAYO relays large deterministic verifier payloads. Do not depend on
          // Starknet.js tip sampling: sparse recent V3 blocks can make that
          // heuristic fail before the RPC receives an otherwise valid invoke.
          const response = await account.execute(call, { tip: 0 });
          return { transactionHash: response.transaction_hash };
        }),
    };
    const workerId = request.headers.get("x-payo-worker-id") || "payo-proof-relayer";
    const proofVerifications = await processProofVerificationBatch({
      rpc: {
        ...rpc,
      },
      submitter,
      deployment,
      workerId,
      limit: 2,
    });
    const payrollAuthorizations = await processPayrollAuthorizationBatch({
      rpc,
      submitter,
      deployment,
      workerId,
      limit: 2,
    });
    const bookConfigured = Boolean(
      process.env.PAYO_VESTING_BOOK_SEAL_ADDRESS
      || process.env.NEXT_PUBLIC_PAYO_VESTING_BOOK_SEAL_ADDRESS,
    );
    const bookDeployment = bookConfigured ? getPayoVestingBookConfig() : null;
    const exceptionAuthorizations = bookDeployment
      ? await processExceptionAuthorizationBatch({
          rpc,
          submitter,
          deployment,
          bookDeployment,
          workerId,
          limit: 1,
        })
      : { leased: 0, results: [] };
    const vestingAuthorizations = bookConfigured
      || process.env.NEXT_PUBLIC_PAYO_VESTING_BOOK_SEAL_ADDRESS
      ? await processVestingAuthorizationBatch({
          rpc,
          submitter,
          deployment: getPayoVestingBookConfig(),
          workerId,
          limit: 1,
        })
      : { leased: 0, results: [] };
    return Response.json({
      leased: proofVerifications.leased + payrollAuthorizations.leased
        + exceptionAuthorizations.leased + vestingAuthorizations.leased,
      results: [
        ...proofVerifications.results.map((result) => ({ kind: "payroll_proof", ...result })),
        ...payrollAuthorizations.results.map((result) => ({ kind: "payroll_authorization", ...result })),
        ...exceptionAuthorizations.results.map((result) => ({ kind: "exception_authorization", ...result })),
        ...vestingAuthorizations.results.map((result) => ({ kind: "vesting_authorization", ...result })),
      ],
      proofVerifications,
      payrollAuthorizations,
      exceptionAuthorizations,
      vestingAuthorizations,
    });
  } catch {
    return Response.json({
      error: { code: "PROOF_RELAYER_FAILURE", message: "Proof relay processing failed closed." },
    }, { status: 500 });
  }
}
