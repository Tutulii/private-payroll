import "server-only";

import { and, eq, gt, lte, or } from "drizzle-orm";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  agentCapabilitySchema,
  authorizePaymentBatch,
  paymentIntentBatchSchema,
  type PaymentIntent,
  type SignedCapability,
} from "@/lib/domain/capability";
import { generateUuidV7 } from "@/lib/domain/records";
import { tokenTotalsSchema, type TokenTotals } from "@/lib/domain/settlement";
import type { AuthenticatedPrincipal } from "@/lib/server/auth";
import { ApiError } from "@/lib/server/auth";
import { decryptCapabilityPolicy } from "@/lib/server/capability-policy-crypto";
import { getDatabase } from "./db";
import { requireOrganizationRoleWith } from "./repository";
import { agentCapabilities, auditEvents, capabilityReservations } from "./schema";

// A payment intent is deliberately short-lived at admission, but production
// payroll and settlement proofs can take several minutes each. Once admission
// succeeds, the durable reservation (plus capability/policy expiry) is the
// bounded authorization for preparation. Give that preparation enough room to
// finish without weakening the five-minute intent replay window.
const RESERVATION_TTL_MS = 30 * 60 * 1000;

function assertIdempotencyKey(key: string): void {
  if (!/^[A-Za-z0-9._:-]{16,256}$/.test(key)) {
    throw new ApiError(400, "A 16–256 character idempotency key is required.", "IDEMPOTENCY_KEY_INVALID");
  }
}

function totalsForIntents(intents: readonly PaymentIntent[]): TokenTotals {
  const totals: TokenTotals = { STRK: "0", USDC: "0" };
  for (const intent of intents) {
    totals[intent.token] = (BigInt(totals[intent.token]) + BigInt(intent.amountAtomic)).toString();
  }
  return tokenTotalsSchema.parse(totals);
}

function addReservationSpend(
  signedCapability: SignedCapability,
  reservations: Array<{ tokenTotals: unknown; callCount: number }>,
) {
  const capability = agentCapabilitySchema.parse(signedCapability.capability);
  const additional = { STRK: 0n, USDC: 0n };
  let additionalCalls = 0;
  for (const reservation of reservations) {
    const totals = tokenTotalsSchema.parse(reservation.tokenTotals);
    additional.STRK += BigInt(totals.STRK);
    additional.USDC += BigInt(totals.USDC);
    additionalCalls += reservation.callCount;
  }
  return {
    ...capability,
    usedCallCount: capability.usedCallCount + additionalCalls,
    limits: capability.limits.map((limit) => ({
      ...limit,
      spentThisPeriodAtomic: (
        BigInt(limit.spentThisPeriodAtomic) + additional[limit.token]
      ).toString(),
    })),
  };
}

function reservationPeriodKey(signedCapability: SignedCapability): string {
  return hashCanonicalJson(signedCapability.capability.limits.map((limit) => ({
    token: limit.token,
    startsAt: limit.periodStartsAt,
    endsAt: limit.periodEndsAt,
  })));
}

export async function reserveCapabilityPayment(input: {
  capabilityId: string;
  idempotencyKey: string;
  intents: readonly PaymentIntent[];
  principal: AuthenticatedPrincipal;
  now?: Date;
}) {
  assertIdempotencyKey(input.idempotencyKey);
  const intents = paymentIntentBatchSchema.parse(input.intents);
  const now = input.now ?? new Date();
  const requestHash = hashCanonicalJson({ capabilityId: input.capabilityId, intents });
  const database = getDatabase();

  return database.transaction(async (transaction) => {
    const [stored] = await transaction
      .select()
      .from(agentCapabilities)
      .where(eq(agentCapabilities.id, input.capabilityId))
      .for("update")
      .limit(1);
    if (!stored) throw new ApiError(404, "Agent capability not found.", "CAPABILITY_NOT_FOUND");
    await requireOrganizationRoleWith(transaction, stored.organizationId, input.principal, ["admin", "operator"]);
    const signedCapability = decryptCapabilityPolicy(stored.policy, {
      capabilityId: stored.id,
      organizationId: stored.organizationId,
      principalId: stored.principalId,
      capabilityHash: stored.capabilityHash,
    });
    if (signedCapability.capability.principalId !== input.principal.principalId) {
      throw new ApiError(403, "Only the capability principal can reserve its limits.", "CAPABILITY_PRINCIPAL_MISMATCH");
    }
    if (stored.revokedAt) throw new ApiError(410, "Agent capability was revoked.", "CAPABILITY_REVOKED");
    if (stored.expiresAt <= now) throw new ApiError(410, "Agent capability expired.", "CAPABILITY_EXPIRED");

    const [existing] = await transaction
      .select()
      .from(capabilityReservations)
      .where(and(
        eq(capabilityReservations.capabilityId, input.capabilityId),
        eq(capabilityReservations.idempotencyKey, input.idempotencyKey),
      ))
      .limit(1);
    if (existing) {
      if (existing.requestHash !== requestHash) {
        throw new ApiError(409, "This idempotency key was used with different payment intents.", "IDEMPOTENCY_MISMATCH");
      }
      return { ...existing, replayed: true };
    }

    await transaction
      .update(capabilityReservations)
      .set({ state: "expired", updatedAt: now })
      .where(and(
        eq(capabilityReservations.capabilityId, input.capabilityId),
        eq(capabilityReservations.state, "reserved"),
        // PostgreSQL compares timestamptz atomically inside the locked transaction.
        lte(capabilityReservations.expiresAt, now),
      ));
    const periodKey = reservationPeriodKey(signedCapability);
    const activeReservations = await transaction
      .select({
        tokenTotals: capabilityReservations.tokenTotals,
        callCount: capabilityReservations.callCount,
      })
      .from(capabilityReservations)
      .where(and(
        eq(capabilityReservations.capabilityId, input.capabilityId),
        eq(capabilityReservations.periodKey, periodKey),
        or(
          eq(capabilityReservations.state, "committed"),
          eq(capabilityReservations.state, "approval_linked"),
          and(eq(capabilityReservations.state, "reserved"), gt(capabilityReservations.expiresAt, now)),
        ),
      ));
    const effectiveCapability = addReservationSpend(signedCapability, activeReservations);
    const authorization = authorizePaymentBatch(effectiveCapability, intents, now);
    if (!authorization.allowed) {
      const denied = authorization.decisions.find((decision) => !decision.allowed);
      throw new ApiError(
        409,
        `Capability reservation denied: ${denied?.reasonCode ?? "CAPABILITY_DENIED"}.`,
        denied?.reasonCode ?? "CAPABILITY_DENIED",
      );
    }
    const tokenTotals = totalsForIntents(intents);
    const latestPeriodEnd = Math.min(
      stored.expiresAt.getTime(),
      ...effectiveCapability.limits.map((limit) => new Date(limit.periodEndsAt).getTime()),
    );
    // Human approvals remain reserved through the signed policy period. Once
    // linked to a Ready settlement they become `approval_linked` and cannot be
    // silently reused until submission or explicit cancellation. Autonomous
    // reservations keep the short preparation lease.
    const reservationHorizon = authorization.requiresApproval
      ? latestPeriodEnd
      : Math.min(now.getTime() + RESERVATION_TTL_MS, latestPeriodEnd);
    const expiresAt = new Date(reservationHorizon);
    const id = generateUuidV7(now.getTime());
    const [reservation] = await transaction
      .insert(capabilityReservations)
      .values({
        id,
        capabilityId: input.capabilityId,
        organizationId: stored.organizationId,
        idempotencyKey: input.idempotencyKey,
        requestHash,
        periodKey,
        tokenTotals,
        callCount: intents.length,
        requiresApproval: authorization.requiresApproval,
        expiresAt,
        createdAt: now,
        updatedAt: now,
      })
      .returning();
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: stored.organizationId,
      actorId: input.principal.principalId,
      action: "agent_capability.limit_reserved",
      subjectId: id,
      metadata: {
        capabilityHash: stored.capabilityHash,
        requestHash,
        tokenTotalsCommitment: hashCanonicalJson({ domain: "PAYO_AGENT_TOKEN_TOTALS_V1", tokenTotals }),
        callCount: intents.length,
      },
    });
    return { ...reservation, replayed: false, authorization };
  });
}

export async function transitionCapabilityReservation(input: {
  capabilityId: string;
  reservationId: string;
  state: "committed" | "released";
  principal: AuthenticatedPrincipal;
  now?: Date;
}) {
  const now = input.now ?? new Date();
  const database = getDatabase();
  return database.transaction(async (transaction) => {
    const [reservation] = await transaction
      .select()
      .from(capabilityReservations)
      .where(and(
        eq(capabilityReservations.id, input.reservationId),
        eq(capabilityReservations.capabilityId, input.capabilityId),
      ))
      .for("update")
      .limit(1);
    if (!reservation) throw new ApiError(404, "Capability reservation not found.", "RESERVATION_NOT_FOUND");
    await requireOrganizationRoleWith(transaction, reservation.organizationId, input.principal, ["admin", "operator"]);
    const [capability] = await transaction
      .select({ principalId: agentCapabilities.principalId })
      .from(agentCapabilities)
      .where(eq(agentCapabilities.id, input.capabilityId))
      .limit(1);
    if (!capability || capability.principalId !== input.principal.principalId) {
      throw new ApiError(403, "Only the capability principal can update its reservation.", "CAPABILITY_PRINCIPAL_MISMATCH");
    }
    if (reservation.state === input.state) return { ...reservation, replayed: true };
    if (reservation.state !== "reserved") {
      throw new ApiError(409, `A ${reservation.state} reservation cannot become ${input.state}.`, "RESERVATION_STATE_CONFLICT");
    }
    if (input.state === "committed" && reservation.expiresAt <= now) {
      await transaction
        .update(capabilityReservations)
        .set({ state: "expired", updatedAt: now })
        .where(eq(capabilityReservations.id, reservation.id));
      throw new ApiError(409, "The capability reservation expired before execution.", "RESERVATION_EXPIRED");
    }
    const [updated] = await transaction
      .update(capabilityReservations)
      .set({ state: input.state, updatedAt: now })
      .where(and(
        eq(capabilityReservations.id, reservation.id),
        eq(capabilityReservations.state, "reserved"),
      ))
      .returning();
    if (!updated) throw new ApiError(409, "Capability reservation changed; retry.", "RESERVATION_STATE_CONFLICT");
    await transaction.insert(auditEvents).values({
      id: generateUuidV7(),
      organizationId: reservation.organizationId,
      actorId: input.principal.principalId,
      action: `agent_capability.limit_${input.state}`,
      subjectId: reservation.id,
      metadata: { capabilityId: input.capabilityId },
    });
    return { ...updated, replayed: false };
  });
}
