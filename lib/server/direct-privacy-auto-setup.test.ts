import {
  AddressMap,
  Channel,
  SetupRequirement,
  Witness,
  createPrivateTransfers,
  type DiscoveryProviderInterface,
  type Note,
  type ExecuteOptions,
  type ProofProviderInterface,
} from "@starkware-libs/starknet-privacy-sdk";
import { ETransactionVersion, Signer, constants } from "starknet";
import { describe, expect, it } from "vitest";

const actionWidths = new Map([
  [1n, 4],
  [2n, 6],
  [3n, 6],
  [6n, 3],
]);

function actionVariants(calldata: readonly unknown[]): bigint[] {
  const count = Number(BigInt(String(calldata[2])));
  const variants: bigint[] = [];
  let cursor = 3;
  for (let index = 0; index < count; index += 1) {
    const variant = BigInt(String(calldata[cursor]));
    variants.push(variant);
    const width = actionWidths.get(variant);
    if (width === undefined) throw new Error(`Unexpected client action ${variant}.`);
    cursor += width + 1;
  }
  expect(cursor).toBe(calldata.length);
  return variants;
}

describe("direct private SDK atomic setup", () => {
  it("opens missing pinned channels and token subchannels in the payroll proof", async () => {
    const sender = 1n;
    const recipient = 2n;
    const token = 7n;
    const pinned = "0xabc" as const;
    const channels = new AddressMap<Channel>();
    channels.set(sender, new Channel(101n));
    channels.set(recipient, new Channel(202n));
    const notes = new AddressMap<Note[]>(() => []);
    notes.set(token, [{
      id: 999n,
      amount: 20n,
      witness: new Witness(555n, 0, 1n),
      sender: 3n,
    }]);
    let discoveryPin: unknown;
    let discoveryRecipients: readonly bigint[] = [];
    const transfers = createPrivateTransfers({
      account: { address: sender, signer: new Signer("0x123") },
      viewingKeyProvider: { getViewingKey: async () => 123n },
      provingProvider: {
        getDefaultDetails: async () => ({
          versions: [ETransactionVersion.V3],
          nonce: 0n,
          chainId: constants.StarknetChainId.SN_MAIN,
          version: ETransactionVersion.V3,
          skipValidate: true,
          resourceBounds: {
            l1_gas: { max_amount: 1n, max_price_per_unit: 0n },
            l2_gas: { max_amount: 100_000_000n, max_price_per_unit: 0n },
            l1_data_gas: { max_amount: 1n, max_price_per_unit: 0n },
          },
          tip: 0n,
          paymasterData: [],
          accountDeploymentData: [],
          nonceDataAvailabilityMode: "L1" as const,
          feeDataAvailabilityMode: "L1" as const,
        }),
        prove: async () => ({ data: "", output: [], proofFacts: [] }),
      } satisfies ProofProviderInterface,
      discoveryProvider: {
        discoverChannels: async (_address, _viewingKey, recipients, params) => {
          discoveryRecipients = recipients as bigint[];
          discoveryPin = params?.blockIdentifier;
          return { channels, total: 0, timestamp: pinned };
        },
        discoverNotes: async () => ({
          notes,
          cursor: { blockId: pinned, incomingChannels: new AddressMap() },
          timestamp: pinned,
        }),
        discoverRequirement: async () => SetupRequirement.Ready,
      } satisfies DiscoveryProviderInterface,
      poolContractAddress: 10n,
    });

    const options: ExecuteOptions = {
      autoRegister: false,
      autoSetup: true,
      autoDiscover: { channels: "refresh" },
      autoSelectNotes: "all",
      registry: {
        channels,
        notes,
        cursor: { blockId: pinned, incomingChannels: new AddressMap() },
      },
      registryConst: true,
      provingBlockId: pinned,
    };
    const result = await transfers.createProofInvocation({
      createNotes: [{ recipient, token, amount: 10n }],
      surpluses: [{ recipient: sender, token, withdraw: false }],
    }, options);
    const outerCalldata = result.invocation.calldata;
    if (!Array.isArray(outerCalldata)) throw new Error("Expected compiled calldata.");
    const innerLength = Number(BigInt(String(outerCalldata[3])));
    const signedCalldata = outerCalldata.slice(4, 4 + innerLength);
    expect(signedCalldata).toHaveLength(innerLength);


    expect(discoveryRecipients).toEqual([sender, recipient]);
    expect(discoveryPin).toEqual(pinned);
    expect(actionVariants(signedCalldata)).toEqual([1n, 1n, 2n, 2n, 6n, 3n, 3n]);
    expect(channels.get(sender)?.key).toBeUndefined();
    expect(channels.get(recipient)?.key).toBeUndefined();
  });
});
