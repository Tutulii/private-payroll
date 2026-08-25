import { RpcProvider } from "starknet";
import { processConfirmationBatch } from "@/lib/server/confirmation-worker";
import { authorizeInternalWorker } from "@/lib/server/internal-auth";

export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!authorizeInternalWorker(request)) {
    return Response.json({ error: { code: "WORKER_UNAUTHORIZED", message: "Worker authorization failed." } }, { status: 401 });
  }
  const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
  if (!rpcUrl) {
    return Response.json({ error: { code: "RPC_NOT_CONFIGURED", message: "Starknet RPC is not configured." } }, { status: 503 });
  }
  try {
    const workerId = request.headers.get("x-payo-worker-id") || "payo-confirmation-worker";
    const result = await processConfirmationBatch({
      rpc: new RpcProvider({ nodeUrl: rpcUrl }),
      workerId,
      limit: 20,
    });
    return Response.json(result);
  } catch {
    return Response.json({ error: { code: "WORKER_FAILURE", message: "Confirmation processing failed." } }, { status: 500 });
  }
}
