import { z } from "zod";
import {
  enqueueFxPublication,
  getFxPublicationJob,
} from "@/lib/persistence/fx-publication-repository";
import { requireOrganizationRole } from "@/lib/persistence/repository";
import { PAYO_MAX_PROOF_CALLDATA_FELTS } from "@/lib/proof/protocol";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { verifyFxPublicationTicket } from "@/lib/server/fx-publication-ticket";
import { apiFailure, readJson } from "@/lib/server/http";
import { getPayoDeploymentConfig, getPayoRegistryConfig } from "@/lib/server/payo-deployment";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const proofFeltSchema = z.string().regex(/^0x[0-9a-fA-F]+$/);
const requestSchema = z.object({
  organizationId: z.string().uuid(),
  catalogRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  publicationTicket: z.string().min(32).max(8_000),
  proofVersion: z.union([z.literal(1), z.literal(2)]),
  shards: z.tuple([
    z.array(proofFeltSchema).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
    z.array(proofFeltSchema).min(1).max(PAYO_MAX_PROOF_CALLDATA_FELTS),
  ]),
}).strict();

const querySchema = z.object({
  organizationId: z.string().uuid(),
  catalogRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
}).strict();

function requireConfiguredPublisher() {
  const rpcUrl = process.env.STARKNET_RPC_URL ?? process.env.NEXT_PUBLIC_STARKNET_RPC_URL;
  if (!rpcUrl || !process.env.PAYO_PROOF_RELAYER_ADDRESS || !process.env.PAYO_PROOF_RELAYER_PRIVATE_KEY) {
    throw new ApiError(503, "The trusted PAYO FX publisher is not configured.", "FX_PUBLISHER_NOT_CONFIGURED");
  }
}

export async function POST(request: Request) {
  try {
    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > 2_500_000) {
      throw new ApiError(413, "The FX proof request is too large.", "FX_PROOF_TOO_LARGE");
    }
    const authenticated = await requirePrincipal(request);
    const input = requestSchema.parse(await readJson(request));
    await requireOrganizationRole(input.organizationId, authenticated, ["admin", "operator"]);
    requireConfiguredPublisher();
    const deployment = getPayoDeploymentConfig();
    const registries = getPayoRegistryConfig();
    const ticket = verifyFxPublicationTicket(input.publicationTicket, {
      organizationId: input.organizationId,
      principalId: authenticated.principalId,
      chainId: deployment.chainId,
      registryAddress: registries.policyRegistryAddress,
      catalogRoot: input.catalogRoot,
    });
    const job = await enqueueFxPublication({
      organizationId: input.organizationId,
      catalogRoot: input.catalogRoot,
      proofVersion: input.proofVersion,
      shards: input.shards,
      observedAt: ticket.observedAt,
      maximumAgeSeconds: ticket.maximumAgeSeconds,
      principal: authenticated,
    });
    return Response.json({ job }, { status: job.state === "complete" ? 200 : 202 });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function GET(request: Request) {
  try {
    const authenticated = await requirePrincipal(request);
    const url = new URL(request.url);
    const input = querySchema.parse({
      organizationId: url.searchParams.get("organizationId"),
      catalogRoot: url.searchParams.get("catalogRoot"),
    });
    const job = await getFxPublicationJob({ ...input, principal: authenticated });
    return Response.json({ job });
  } catch (error) {
    return apiFailure(error);
  }
}
