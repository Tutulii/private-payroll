import { afterEach, describe, expect, it, vi } from "vitest";
import { PayoApiError, type PayrollAuthorizationStatus, type VestingAuthorizationStatus } from "./payo-client";
import { waitForPayrollAuthorization, waitForVestingAuthorization } from "./payroll-execution";

afterEach(() => vi.useRealTimers());

const runId = "0198ddf0-9c00-7000-8000-000000000001";
const complete = {
  runId, state: "complete", transactionHash: "0x123", authorizedAt: "2026-09-06T00:00:00Z",
} as VestingAuthorizationStatus & PayrollAuthorizationStatus;

describe.each(["payroll", "book"] as const)("%s durable authorization polling", (kind) => {
  const wait = (get: () => Promise<{ authorization: typeof complete }>, timeoutMs = 10_000) => kind === "book"
    ? waitForVestingAuthorization({ client: { getVestingAuthorization: get }, runId, timeoutMs, pollIntervalMs: 100 })
    : waitForPayrollAuthorization({ client: { getPayrollAuthorization: get }, runId, timeoutMs, pollIntervalMs: 100 });
  it("survives a timed-out status read and returns the durable completion", async () => {
    vi.useFakeTimers();
    const get = vi.fn().mockRejectedValueOnce(new PayoApiError("deadline", "PAYO_API_TIMEOUT", 504))
      .mockResolvedValueOnce({ authorization: complete });
    const assertion = expect(wait(get)).resolves.toMatchObject({ transactionHash: "0x123" });
    await vi.advanceTimersByTimeAsync(3_100);
    await assertion;
    expect(get).toHaveBeenCalledTimes(2);
  });
  it("does not retry a revoked session", async () => {
    const get = vi.fn().mockRejectedValue(new PayoApiError("revoked", "UNAUTHORIZED", 401));
    await expect(wait(get)).rejects.toMatchObject({ status: 401 });
    expect(get).toHaveBeenCalledTimes(1);
  });
  it("reports funding intervention without calling the job complete", async () => {
    const get = vi.fn().mockResolvedValue({ authorization: {
      ...complete, state: "pending", lastErrorCode: "PROOF_RELAYER_FUNDING_REQUIRED",
    } });
    await expect(wait(get)).rejects.toMatchObject({ code: "PROOF_RELAYER_FUNDING_REQUIRED" });
  });
  it("still requires transaction evidence after a connection recovers", async () => {
    const get = vi.fn().mockResolvedValue({ authorization: { ...complete, transactionHash: null } });
    await expect(wait(get)).rejects.toThrow("without finalized chain evidence");
  });
  it("retains a bounded overall wait through a sustained outage", async () => {
    vi.useFakeTimers();
    const get = vi.fn().mockRejectedValue(new PayoApiError("offline", "PAYO_API_NETWORK_ERROR", 503));
    const assertion = expect(wait(get, 1_000)).rejects.toThrow("proofs are saved");
    await vi.advanceTimersByTimeAsync(1_100);
    await assertion;
  });
});
