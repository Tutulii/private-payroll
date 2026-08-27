import "server-only";

import { createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { ApiError } from "./auth";

const ticketPayloadSchema = z.object({
  version: z.literal(1),
  organizationId: z.string().uuid(),
  principalId: z.string().min(1).max(160),
  chainId: z.string().regex(/^0x[0-9a-fA-F]+$/),
  registryAddress: z.string().regex(/^0x[0-9a-fA-F]+$/),
  catalogRoot: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  observedAt: z.number().int().nonnegative(),
  maximumAgeSeconds: z.number().int().min(1).max(3_600),
  issuedAt: z.number().int().nonnegative(),
  expiresAt: z.number().int().positive(),
}).strict().superRefine((payload, context) => {
  if (payload.expiresAt <= payload.issuedAt) {
    context.addIssue({ code: "custom", path: ["expiresAt"], message: "FX ticket must expire after issuance." });
  }
  if (payload.expiresAt !== payload.observedAt + payload.maximumAgeSeconds) {
    context.addIssue({ code: "custom", path: ["expiresAt"], message: "FX ticket expiry does not match its publication window." });
  }
});

export type FxPublicationTicketPayload = z.infer<typeof ticketPayloadSchema>;

function signingSecret(): string {
  const secret = process.env.PAYO_WORKER_SECRET;
  if (!secret || secret.length < 32) {
    throw new ApiError(503, "PAYO's FX publication signer is not configured.", "FX_TICKET_NOT_CONFIGURED");
  }
  return secret;
}

function signature(payload: string): Buffer {
  return createHmac("sha256", signingSecret())
    .update("PAYO_FX_PUBLICATION_TICKET_V1\0", "utf8")
    .update(payload, "utf8")
    .digest();
}

export function issueFxPublicationTicket(
  input: Omit<FxPublicationTicketPayload, "version" | "issuedAt"> & { issuedAt?: number },
): string {
  const payload = ticketPayloadSchema.parse({
    ...input,
    version: 1,
    issuedAt: input.issuedAt ?? Math.floor(Date.now() / 1_000),
  });
  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${encoded}.${signature(encoded).toString("base64url")}`;
}

export function verifyFxPublicationTicket(
  ticket: string,
  input: {
    organizationId: string;
    principalId: string;
    chainId: string;
    registryAddress: string;
    catalogRoot: string;
    now?: number;
  },
): FxPublicationTicketPayload {
  const [encoded, encodedSignature, extra] = ticket.split(".");
  if (!encoded || !encodedSignature || extra) {
    throw new ApiError(403, "The FX publication ticket is malformed.", "FX_TICKET_INVALID");
  }
  let supplied: Buffer;
  try {
    supplied = Buffer.from(encodedSignature, "base64url");
  } catch {
    throw new ApiError(403, "The FX publication ticket is malformed.", "FX_TICKET_INVALID");
  }
  const expected = signature(encoded);
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new ApiError(403, "The FX publication ticket signature is invalid.", "FX_TICKET_INVALID");
  }
  let payload: FxPublicationTicketPayload;
  try {
    payload = ticketPayloadSchema.parse(JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")));
  } catch {
    throw new ApiError(403, "The FX publication ticket payload is invalid.", "FX_TICKET_INVALID");
  }
  if (
    payload.organizationId !== input.organizationId
    || payload.principalId !== input.principalId
    || BigInt(payload.chainId) !== BigInt(input.chainId)
    || BigInt(payload.registryAddress) !== BigInt(input.registryAddress)
    || BigInt(payload.catalogRoot) !== BigInt(input.catalogRoot)
  ) {
    throw new ApiError(403, "The FX publication ticket does not match this payroll.", "FX_TICKET_MISMATCH");
  }
  const now = input.now ?? Math.floor(Date.now() / 1_000);
  if (now < payload.issuedAt - 30 || now > payload.expiresAt) {
    throw new ApiError(409, "The FX publication ticket expired before proving finished.", "FX_TICKET_EXPIRED");
  }
  return payload;
}
