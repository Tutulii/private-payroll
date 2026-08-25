import { z } from "zod";
import { paymentIntentBatchSchema } from "@/lib/domain/capability";
import {
  reserveCapabilityPayment,
  transitionCapabilityReservation,
} from "@/lib/persistence/capability-reservations";
import { ApiError, requirePrincipal } from "@/lib/server/auth";
import { apiFailure, readJson } from "@/lib/server/http";

const reserveSchema = z.object({ intents: paymentIntentBatchSchema }).strict();
const transitionSchema = z.object({
  reservationId: z.string().min(8).max(128),
  state: z.enum(["committed", "released"]),
}).strict();

type CapabilityContext = { params: Promise<{ id: string }> };

export async function POST(request: Request, context: CapabilityContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id: capabilityId } = await context.params;
    const idempotencyKey = request.headers.get("idempotency-key");
    if (!idempotencyKey) throw new ApiError(400, "Idempotency-Key is required.", "IDEMPOTENCY_KEY_REQUIRED");
    const { intents } = reserveSchema.parse(await readJson(request));
    return Response.json({
      reservation: await reserveCapabilityPayment({
        capabilityId,
        idempotencyKey,
        intents,
        principal,
      }),
    }, { status: 201 });
  } catch (error) {
    return apiFailure(error);
  }
}

export async function PATCH(request: Request, context: CapabilityContext) {
  try {
    const principal = await requirePrincipal(request);
    const { id: capabilityId } = await context.params;
    const input = transitionSchema.parse(await readJson(request));
    return Response.json({
      reservation: await transitionCapabilityReservation({ capabilityId, ...input, principal }),
    });
  } catch (error) {
    return apiFailure(error);
  }
}
