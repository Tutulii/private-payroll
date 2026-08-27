import { afterEach, describe, expect, it } from "vitest";
import { issueFxPublicationTicket, verifyFxPublicationTicket } from "./fx-publication-ticket";

const previousSecret = process.env.PAYO_WORKER_SECRET;
const base = {
  organizationId: "018f05d7-6af4-7c78-8f87-223fd7641b04",
  principalId: "starknet:mainnet:0x123",
  chainId: "0x534e5f4d41494e",
  registryAddress: "0x123",
  catalogRoot: `0x${"11".repeat(32)}`,
  observedAt: 1_000,
  maximumAgeSeconds: 900,
  expiresAt: 1_900,
  issuedAt: 1_100,
};

afterEach(() => {
  if (previousSecret === undefined) delete process.env.PAYO_WORKER_SECRET;
  else process.env.PAYO_WORKER_SECRET = previousSecret;
});

describe("FX publication tickets", () => {
  it("binds a canonical FX root to one organization and principal", () => {
    process.env.PAYO_WORKER_SECRET = "payo-test-worker-secret-that-is-long-enough";
    const ticket = issueFxPublicationTicket(base);
    expect(verifyFxPublicationTicket(ticket, { ...base, now: 1_200 })).toMatchObject(base);
  });

  it("rejects tampering, cross-tenant replay and expiry", () => {
    process.env.PAYO_WORKER_SECRET = "payo-test-worker-secret-that-is-long-enough";
    const ticket = issueFxPublicationTicket(base);
    const [payload, signature] = ticket.split(".");
    expect(() => verifyFxPublicationTicket(`${payload}x.${signature}`, { ...base, now: 1_200 }))
      .toThrow("signature is invalid");
    expect(() => verifyFxPublicationTicket(ticket, {
      ...base,
      organizationId: "018f05d7-6af4-7c78-8f87-223fd7641b05",
      now: 1_200,
    })).toThrow("does not match");
    expect(() => verifyFxPublicationTicket(ticket, { ...base, now: 1_901 }))
      .toThrow("expired");
  });
});
