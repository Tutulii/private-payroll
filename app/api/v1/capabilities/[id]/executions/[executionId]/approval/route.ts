import { z } from "zod";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  cancelUnlinkedAgentExecutionApproval,
  linkAgentExecutionToHumanSettlement,
} from "@/lib/persistence/agent-execution-approval-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const linkSchema = z.object({ settlementId: uuidV7Schema }).strict();

type ApprovalContext = {
  params: Promise<{ id: string; executionId: string }>;
};

export async function POST(request: Request, context: ApprovalContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id: capabilityId, executionId } = await context.params;
    const { settlementId } = linkSchema.parse(await readJson(request));
    return Response.json({
      execution: await linkAgentExecutionToHumanSettlement({
        capabilityId: uuidV7Schema.parse(capabilityId),
        executionId: uuidV7Schema.parse(executionId),
        settlementId,
        principal,
      }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function DELETE(request: Request, context: ApprovalContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id: capabilityId, executionId } = await context.params;
    return Response.json({
      execution: await cancelUnlinkedAgentExecutionApproval({
        capabilityId: uuidV7Schema.parse(capabilityId),
        executionId: uuidV7Schema.parse(executionId),
        principal,
      }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}
