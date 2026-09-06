import "server-only";

import type { Account, Call, RpcProvider } from "starknet";

const STRK_ADDRESS = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
export const PROOF_RELAYER_FUNDING_CODE = "PROOF_RELAYER_FUNDING_REQUIRED";
export const PROOF_RELAYER_FUNDING_MESSAGE =
  "PAYO's proof service needs gas funding before authorization can continue. Your saved proofs are retained; resume this payroll after the service is funded.";

export class ProofRelayerFundingError extends Error {
  readonly code = PROOF_RELAYER_FUNDING_CODE;
  constructor() { super(PROOF_RELAYER_FUNDING_MESSAGE); }
}

export async function readProofRelayerBalance(
  provider: Pick<RpcProvider, "callContract">,
  relayerAddress: string,
): Promise<bigint> {
  const result = await provider.callContract({
    contractAddress: STRK_ADDRESS,
    entrypoint: "balance_of",
    calldata: [relayerAddress],
  }, "latest");
  if (result.length !== 2) throw new Error("The proof service returned an invalid gas balance.");
  const limbs = result.map(BigInt);
  if (limbs.some((limb) => limb < 0n || limb >= 1n << 128n)) {
    throw new Error("The proof service returned an invalid gas balance.");
  }
  return limbs[0] + (limbs[1] << 128n);
}

/** Operational reserve for starting a new four-proof job, not a fee quote. */
export function proofRelayerReserve(): bigint {
  const configured = process.env.PAYO_PROOF_RELAYER_MIN_BALANCE_FRI ?? "100000000000000000000";
  if (!/^[1-9]\d{0,39}$/.test(configured)) throw new Error("Invalid proof service gas reserve.");
  return BigInt(configured);
}

/** Call under the shared nonce lock. Estimate once and submit those exact bounds. */
export async function submitFundedProofCall(input: {
  provider: Pick<RpcProvider, "callContract">;
  account: Pick<Account, "address" | "estimateInvokeFee" | "execute">;
  call: Call | Call[];
}) {
  const estimate = await input.account.estimateInvokeFee(input.call, { tip: 0 });
  const required = Object.values(estimate.resourceBounds).reduce(
    (sum, bound) => sum + BigInt(bound.max_amount) * BigInt(bound.max_price_per_unit), 0n,
  );
  if (required <= 0n) throw new Error("The proof service returned invalid fee bounds.");
  const balance = await readProofRelayerBalance(input.provider, input.account.address);
  if (balance < required) throw new ProofRelayerFundingError();
  const response = await input.account.execute(input.call, {
    tip: 0,
    resourceBounds: estimate.resourceBounds,
  });
  return { transactionHash: response.transaction_hash };
}
