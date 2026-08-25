import { z } from "zod";
import { uuidV7Schema } from "@/lib/domain/records";
import {
  cancelSettlementApproval,
  getSettlement,
  recordSettlementSubmission,
} from "@/lib/persistence/settlement-repository";
import { requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const submissionSchema = z.object({
  transactionHash: z.string().regex(/^0x[0-9a-fA-F]{1,64}$/),
}).strict();

type SettlementContext = { params: Promise<{ id: string }> };

export async function GET(request: Request, context: SettlementContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    return Response.json({ settlement: await getSettlement(uuidV7Schema.parse(id), principal) });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function PATCH(request: Request, context: SettlementContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    const { transactionHash } = submissionSchema.parse(await readJson(request));
    return Response.json({
      settlement: await recordSettlementSubmission({
        settlementId: uuidV7Schema.parse(id),
        transactionHash,
        principal,
      }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function DELETE(request: Request, context: SettlementContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id } = await context.params;
    return Response.json({
      settlement: await cancelSettlementApproval({
        settlementId: uuidV7Schema.parse(id),
        principal,
      }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}
