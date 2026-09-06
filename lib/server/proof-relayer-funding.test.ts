import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ProofRelayerFundingError, proofRelayerReserve, readProofRelayerBalance, submitFundedProofCall,
} from "./proof-relayer-funding";

afterEach(() => vi.unstubAllEnvs());

function setup(balance: bigint) {
  const resourceBounds = {
    l1_gas: { max_amount: 0n, max_price_per_unit: 1n },
    l2_gas: { max_amount: 100n, max_price_per_unit: 3n },
    l1_data_gas: { max_amount: 2n, max_price_per_unit: 5n },
  };
  const provider = { callContract: vi.fn().mockResolvedValue([balance.toString(), "0"]) };
  const account = {
    address: "0x123",
    estimateInvokeFee: vi.fn().mockResolvedValue({ overall_fee: 100n, resourceBounds }),
    execute: vi.fn().mockResolvedValue({ transaction_hash: "0xabc" }),
  };
  const call = { contractAddress: "0x456", entrypoint: "verify", calldata: ["0x1"] };
  return { provider, account, call, resourceBounds };
}

describe("proof relayer funding", () => {
  it("does not submit when balance covers the estimated fee but not maximum resource bounds", async () => {
    const input = setup(309n);
    await expect(submitFundedProofCall(input)).rejects.toBeInstanceOf(ProofRelayerFundingError);
    expect(input.account.execute).not.toHaveBeenCalled();
  });
  it("submits the exact estimated bounds once the balance covers every resource", async () => {
    const input = setup(310n);
    await expect(submitFundedProofCall(input)).resolves.toEqual({ transactionHash: "0xabc" });
    expect(input.account.estimateInvokeFee).toHaveBeenCalledTimes(1);
    expect(input.account.execute).toHaveBeenCalledExactlyOnceWith(input.call, {
      tip: 0, resourceBounds: input.resourceBounds,
    });
  });
  it("rejects a malformed balance before any submission", async () => {
    const input = setup(1n);
    input.provider.callContract.mockResolvedValue(["1"]);
    await expect(submitFundedProofCall(input)).rejects.toThrow("invalid gas balance");
    expect(input.account.execute).not.toHaveBeenCalled();
    input.provider.callContract.mockResolvedValue(["0", (1n << 128n).toString()]);
    await expect(readProofRelayerBalance(input.provider, "0x123")).rejects.toThrow("invalid gas balance");
  });
  it("fails closed on an invalid admission reserve", () => {
    vi.stubEnv("PAYO_PROOF_RELAYER_MIN_BALANCE_FRI", "0");
    expect(proofRelayerReserve).toThrow("Invalid proof service gas reserve");
  });
});
