import { z } from "zod";
import { uuidV7Schema } from "@/lib/domain/records";
import { provisionDirectPrivacyAccountFromRuns } from "@/lib/persistence/direct-privacy-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import {
  getDirectPrivacyAuthorizedRunsPublic,
  getDirectPrivacyAccountPublic,
  getDirectPrivacyProvisioningReplay,
  listDirectPrivacyAccountsPublic,
} from "@/lib/server/direct-privacy-account-view";
import { getDirectPrivacyDeploymentConfig } from "@/lib/server/direct-privacy-deployment";
import { apiFailure, readJson } from "@/lib/server/http";
import { buildConfigurePolicyCall } from "@/lib/starknet/policy-account-configuration";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const feltInputSchema = z.string().regex(/^0x[0-9a-fA-F]{1,64}$/);
const provisionSchema = z.object({
  organizationId: uuidV7Schema,
  capabilityId: uuidV7Schema,
  runIds: z.array(uuidV7Schema).min(1).max(256),
  policyAccountAddress: feltInputSchema,
  policyId: feltInputSchema,
  validForSeconds: z.number().int().positive().max(366 * 24 * 60 * 60),
  periodSeconds: z.number().int().positive().max(366 * 24 * 60 * 60),
  maxCallsPerPeriod: z.number().int().positive().max(4_294_967_295),
  maxCallCount: z.number().int().positive().max(4_294_967_295),
}).strict();

const noStore = { "cache-control": "private, no-store, max-age=0" };

export async function GET(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const search = new URL(request.url).searchParams;
    const accountIdInput = search.get("accountId");
    const organizationIdInput = search.get("organizationId");
    if (accountIdInput && organizationIdInput) {
      throw new ApiError(400, "Choose accountId or organizationId, not both.", "DIRECT_ACCOUNT_QUERY_INVALID");
    }
    if (organizationIdInput) {
      const accounts = await listDirectPrivacyAccountsPublic({
        organizationId: uuidV7Schema.parse(organizationIdInput),
        principal,
      });
      return Response.json({ accounts }, { headers: noStore });
    }
    if (!accountIdInput) {
      throw new ApiError(400, "accountId or organizationId is required.", "DIRECT_ACCOUNT_QUERY_REQUIRED");
    }
    const accountId = uuidV7Schema.parse(accountIdInput);
    const account = await getDirectPrivacyAccountPublic({ accountId, principal });
    return Response.json({ account, configurationCall: buildConfigurePolicyCall(account.config) }, {
      headers: noStore,
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function POST(request: Request) {
  try {
    const principal = await requirePrincipal(request);
    const input = provisionSchema.parse(await readJson(request));
    const replayInput = {
      organizationId: input.organizationId,
      capabilityId: input.capabilityId,
      runIds: input.runIds,
      policyAccountAddress: input.policyAccountAddress,
      policyId: input.policyId,
      periodSeconds: input.periodSeconds,
      maxCallsPerPeriod: input.maxCallsPerPeriod,
      maxCallCount: input.maxCallCount,
      principal,
    };
    const existing = await getDirectPrivacyProvisioningReplay(replayInput);
    if (existing) {
      const authorizedRuns = await getDirectPrivacyAuthorizedRunsPublic({ accountId: existing.id, principal });
      return Response.json({
        account: existing,
        authorizedRuns,
        configurationCall: buildConfigurePolicyCall(existing.config),
        replayed: true,
      }, { headers: noStore });
    }
    let account;
    try {
      account = await provisionDirectPrivacyAccountFromRuns({
      organizationId: input.organizationId,
      capabilityId: input.capabilityId,
      runIds: input.runIds,
      request: {
        policyAccountAddress: input.policyAccountAddress,
        policyId: input.policyId,
        validForSeconds: input.validForSeconds,
        periodSeconds: input.periodSeconds,
        maxCallsPerPeriod: input.maxCallsPerPeriod,
        maxCallCount: input.maxCallCount,
      },
      deployment: getDirectPrivacyDeploymentConfig(),
      principal,
    });
    } catch (error) {
      if (!(error instanceof ApiError) || error.code !== "DIRECT_ACCOUNT_EXISTS") throw error;
      const replay = await getDirectPrivacyProvisioningReplay(replayInput);
      if (!replay) throw error;
      const authorizedRuns = await getDirectPrivacyAuthorizedRunsPublic({ accountId: replay.id, principal });
      return Response.json({
        account: replay,
        authorizedRuns,
        configurationCall: buildConfigurePolicyCall(replay.config),
        replayed: true,
      }, { headers: noStore });
    }
    const authorizedRuns = await getDirectPrivacyAuthorizedRunsPublic({ accountId: account.id, principal });
    return Response.json({ account, authorizedRuns, configurationCall: buildConfigurePolicyCall(account.config) }, {
      status: 201,
      headers: noStore,
    });
  } catch (error) {
    return apiFailure(error);
  }
}
