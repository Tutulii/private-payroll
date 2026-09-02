import "server-only";

import {
  Account,
  EDAMode,
  OutsideExecutionVersion,
  RpcProvider,
  type SignerInterface,
  constants,
  hash,
  num,
  outsideExecution,
  type AccountInvocations,
  type Call,
  type ResourceBoundsBN,
} from "starknet";
import {
  directPrivacyAccountConfigSchema,
  directPrivacyFinalizationSubmissionSchema,
  directPrivacyPayrollAuthorizationSchema,
  directPrivacyPreparationSchema,
  directPrivacyProofDraftSchema,
  directPrivacyPreparedSubmissionSchema,
  type DirectPrivacyFinalizationSubmission,
  type DirectPrivacyProofDraft,
  type DirectPrivacyPayrollAuthorization,
  type DirectPrivacyPreparation,
  type DirectPrivacySignedTransaction,
} from "@/lib/domain/direct-privacy";
import {
  leaseDirectPrivacyExecutionContext,
  releaseDirectPrivacyExecution,
  type DirectPrivacyExecutionContext,
} from "@/lib/persistence/direct-privacy-repository";
import {
  abandonDirectPrivacyPreparation,
  findDirectPrivacyPreparation,
  loadDirectPrivacyPreparation,
  markDirectPrivacyPreparationSigned,
  storeDirectPrivacyPreparation,
} from "@/lib/persistence/direct-privacy-preparation-repository";
import {
  failDirectPrivacySubmission,
  finalizeDirectPrivacySubmission,
  findDirectPrivacySubmission,
  loadDirectPrivacySubmissionByExecution,
  markDirectPrivacySubmissionBroadcasting,
  recordDirectPrivacyBroadcast,
  storePreparedDirectPrivacySubmission,
} from "@/lib/persistence/direct-privacy-submission-repository";
import { withStarknetRelayerSubmissionLock } from "@/lib/persistence/relayer-lock";
import {
  AgentExecutionDriverError,
  type AgentExecutionObservation,
  type PreparedAgentExecution,
  type StructuredAgentExecutionDriver,
} from "./agent-execution-worker";
import { decryptDirectPrivacyPayload } from "./direct-privacy-crypto";
import {
  loadPinnedPrivacySdk,
  type PinnedPrivacySdk,
  type PrivacyDiscovery,
  type PrivacyTransfers,
} from "./privacy-sdk-loader";
import {
  deserializePrivacyHistoryCursor,
  mergePrivacyHistory,
  serializePrivacyHistoryCursor,
  serializePrivacyHistoryTransaction,
  serializePrivacyRegistry,
} from "./privacy-sdk-registry";
import {
  assertDirectPrivacySdkResult,
  buildDirectPrivacyPlan,
  buildDirectPrivacyPolicyCall,
} from "@/lib/starknet/direct-privacy-plan";
import type { LeasedAgentExecution } from "@/lib/persistence/agent-execution-worker-repository";
import { AgentProofClient } from "./agent-proof-client";
import { encryptVaultRecord } from "@/lib/crypto/vault";
import { buildSettlementRoot } from "@/lib/proof/settlement-match";
import type {
  ProofWorkerSuccess,
  SettlementMatchProofWorkerSuccess,
} from "@/lib/proof/protocol";
import { settlementMatchWitnessSchema } from "@/lib/proof/settlement-request";
import { extractDirectPrivacySettlementEvidence } from "@/lib/starknet/privacy-invocation";
import {
  completeDirectPrivacyFinalizationChunk,
  ensureDirectPrivacyReconciliation,
  loadDirectPrivacyReconciliation,
  markDirectPrivacyReconciled,
  recordDirectPrivacyFinalizationBroadcast,
  storeDirectPrivacyFinalization,
  storeDirectPrivacyReconciliationProof,
  storeDirectPrivacyProofDraft,
} from "@/lib/persistence/direct-privacy-reconciliation-repository";
import {
  loadDirectPrivacyPayrollAuthorization,
  recordDirectPrivacyPayrollAuthorizationProgress,
  storeDirectPrivacyPayrollAuthorization,
} from "@/lib/persistence/direct-privacy-payroll-authorization-repository";
import {
  buildDirectPayrollPrecommitCall,
  buildVerifySealedShardCalldataCall,
} from "@/lib/starknet/payo-seal";
import {
  PAYO_RUN_STATUS_PROVEN,
  PAYO_RUN_STATUS_SEALED,
  readProofSealState,
} from "./proof-relayer";
import { PolicyOwnerSignerClient } from "./policy-owner-signer-client";
import { assertDirectPrivacyOutsideCall } from "@/lib/starknet/direct-privacy-outside-call";
import {
  findDirectPrivacyReadinessFailure,
  isExactPinnedBlockReference,
  type DirectPrivacyDiscoveredChannel,
} from "./direct-privacy-discovery";

const HASH_PATTERN = /^0x[0-9a-fA-F]{1,64}$/;
const DEFAULT_INDEXER_MAX_LAG_SECONDS = 120;
const DEFAULT_FINALITY_BLOCKS = 3;
const OUTSIDE_WINDOW_SECONDS = 300n;
const PRIVATE_HISTORY_PAGE_SIZE = 100;
const PRIVATE_HISTORY_BACKFILL_PAGES = 4;

type DriverOpaque = {
  kind: "payo-direct-privacy-preparation";
  job: LeasedAgentExecution;
  preparationCommitment: string;
  simulated: true;
};

type AcceptedBlock = { number: number; hash: `0x${string}`; timestamp: number };
type PrivacyAddressMap<T> = {
  entries(): IterableIterator<[bigint, T]>;
  get(key: bigint): T | undefined;
};
type PrivacyDiscoverySnapshot = {
  registry: {
    channels: PrivacyAddressMap<DirectPrivacyDiscoveredChannel>;
    notes: PrivacyAddressMap<unknown[]>;
    cursor: unknown;
  };
  channelTotal: number | null;
  history: DirectPrivacyProofDraft["nextState"]["history"];
  historyCursor: DirectPrivacyProofDraft["nextState"]["historyCursor"];
  historyPinnedBlock: DirectPrivacyProofDraft["nextState"]["historyPinnedBlock"];
};
type DirectPrivacyPolicyAuthorization = Pick<
  DirectPrivacyPreparation,
  "policyCall" | "proofValidAfterUnix" | "proofValidBeforeUnix"
>;

type DirectPrivacyDriverRuntime = {
  rpcUrl: string;
  provingUrl: string;
  indexerUrl: string;
  provider: RpcProvider;
  relayer: Account;
  sdk: PinnedPrivacySdk;
  maxIndexerLagSeconds: number;
  finalityBlocks: number;
  now: () => Date;
  proofClient: AgentProofClient;
  policyOwnerSigner: SignerInterface;
  withRelayerLock: typeof withStarknetRelayerSubmissionLock;
};

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required for autonomous private payroll.`);
  return value;
}

function boundedInteger(name: string, fallback: number, minimum: number, maximum: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}.`);
  }
  return parsed;
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? value as Record<string, unknown> : {};
}

function acceptedBlock(value: unknown): AcceptedBlock {
  const block = record(value);
  const number = Number(block.block_number ?? block.blockNumber);
  const timestamp = Number(block.timestamp);
  const hashValue = String(block.block_hash ?? block.blockHash ?? "");
  if (
    !Number.isSafeInteger(number)
    || number < 0
    || !Number.isSafeInteger(timestamp)
    || timestamp <= 0
    || !HASH_PATTERN.test(hashValue)
  ) throw new AgentExecutionDriverError(
    "DIRECT_BLOCK_NOT_ACCEPTED",
    "The Starknet RPC did not return an accepted block pin.",
  );
  return { number, timestamp, hash: num.toHex(BigInt(hashValue)) as `0x${string}` };
}

async function pinIndexerBlock(runtime: DirectPrivacyDriverRuntime, discovery: PrivacyDiscovery): Promise<AcceptedBlock> {
  const health = await discovery.getHealth();
  const head = health.chain_head;
  if (
    health.status !== "OK"
    || !head
    || !Number.isSafeInteger(head.block_number)
    || !HASH_PATTERN.test(head.block_hash)
    || (health.lag_secs ?? Number.POSITIVE_INFINITY) > runtime.maxIndexerLagSeconds
  ) throw new AgentExecutionDriverError(
    "DIRECT_INDEXER_UNHEALTHY",
    "The private indexer is unhealthy, stale, or missing a canonical head.",
  );
  const rpcBlock = acceptedBlock(await runtime.provider.getBlock(head.block_number));
  if (BigInt(rpcBlock.hash) !== BigInt(head.block_hash)) {
    throw new AgentExecutionDriverError(
      "DIRECT_INDEXER_REORGED",
      "The private indexer head does not match the Starknet RPC.",
    );
  }
  return rpcBlock;
}

function privacyAddressMap<T>(value: unknown, label: string): PrivacyAddressMap<T> {
  const candidate = value as Partial<PrivacyAddressMap<T>> | null;
  if (!candidate || typeof candidate.entries !== "function" || typeof candidate.get !== "function") {
    throw new AgentExecutionDriverError(
      "DIRECT_DISCOVERY_RESPONSE_INVALID",
      `The private indexer returned invalid ${label}.`,
    );
  }
  return candidate as PrivacyAddressMap<T>;
}

function assertDiscoveryPin(value: unknown, pinned: AcceptedBlock, label: string): void {
  if (!isExactPinnedBlockReference(value, pinned.hash)) {
    throw new AgentExecutionDriverError(
      "DIRECT_DISCOVERY_BLOCK_MISMATCH",
      `The private indexer's ${label} response was not bound to the accepted block hash.`,
    );
  }
}

function channelRequirements(input: {
  request: LeasedAgentExecution["request"];
  config: Pick<
    ReturnType<typeof directPrivacyAccountConfigSchema.parse>,
    "policyAccountAddress" | "tokenAddresses"
  >;
}) {
  const treasuryAddress = BigInt(input.config.policyAccountAddress);
  const requirements = input.request.intents.map((intent) => ({
    recipient: BigInt(intent.recipientAddress),
    token: BigInt(input.config.tokenAddresses[intent.token]),
  }));
  for (const token of new Set(requirements.map(({ token }) => token))) {
    requirements.push({ recipient: treasuryAddress, token });
  }
  return { treasuryAddress, requirements };
}

async function fetchPrivateHistoryPage(input: {
  discovery: PrivacyDiscovery;
  treasuryAddress: bigint;
  notesCursor: unknown;
  channels: PrivacyAddressMap<DirectPrivacyDiscoveredChannel>;
  block: { number: number; hash: `0x${string}` };
  historyCursor?: unknown;
}) {
  const page = await input.discovery.fetchHistory(
    input.treasuryAddress,
    input.notesCursor,
    { channels: input.channels },
    {
      maxTransactions: PRIVATE_HISTORY_PAGE_SIZE,
      blockIdentifier: input.block.hash,
      ...(input.historyCursor === undefined ? {} : { historyCursor: input.historyCursor }),
    },
  );
  assertDiscoveryPin(page.blockRef, { ...input.block, timestamp: 1 }, "history");
  if (!Array.isArray(page.transactions) || page.transactions.length > PRIVATE_HISTORY_PAGE_SIZE) {
    throw new AgentExecutionDriverError(
      "DIRECT_PRIVATE_HISTORY_INVALID",
      "The private indexer returned an invalid history page.",
    );
  }
  return {
    transactions: page.transactions.map(serializePrivacyHistoryTransaction),
    cursor: serializePrivacyHistoryCursor(page.cursor),
  };
}

function isHistoryBranchReset(error: unknown): boolean {
  const name = error instanceof Error ? error.name : "";
  const message = error instanceof Error ? error.message : String(error);
  return name === "ReorgError"
    || /Block reorged during \/v1\/history/i.test(message)
    || /Indexer API \/v1\/history failed \((?:404|409|410)\)/i.test(message);
}

/**
 * One block-hash snapshot drives readiness, note selection and encrypted
 * history. Full refresh avoids cursor drift; a bounded cursor resumes only the
 * older history backfill and is reset safely if its old branch disappeared.
 */
export async function discoverDirectPrivacySnapshot(input: {
  discovery: PrivacyDiscovery;
  pinned: AcceptedBlock;
  context: Pick<DirectPrivacyExecutionContext, "viewingKey" | "state"> & {
    config: Pick<
      DirectPrivacyExecutionContext["config"],
      "policyAccountAddress" | "tokenAddresses"
    >;
  };
  job: Pick<LeasedAgentExecution, "request">;
}): Promise<PrivacyDiscoverySnapshot> {
  const treasuryAddress = BigInt(input.context.config.policyAccountAddress);
  const viewingKey = BigInt(input.context.viewingKey);
  const [notesResult, channelsResult] = await Promise.all([
    input.discovery.discoverNotes(treasuryAddress, viewingKey, {
      blockIdentifier: input.pinned.hash,
    }),
    input.discovery.discoverChannels(treasuryAddress, viewingKey, "all", {
      blockIdentifier: input.pinned.hash,
    }),
  ]);
  assertDiscoveryPin(notesResult.timestamp, input.pinned, "note discovery");
  assertDiscoveryPin(channelsResult.timestamp, input.pinned, "channel discovery");
  const notes = privacyAddressMap<unknown[]>(notesResult.notes, "private notes");
  const channels = privacyAddressMap<DirectPrivacyDiscoveredChannel>(
    channelsResult.channels,
    "private channels",
  );
  const needed = channelRequirements({ request: input.job.request, config: input.context.config });
  const readiness = findDirectPrivacyReadinessFailure({
    channels,
    treasuryAddress: needed.treasuryAddress,
    requirements: needed.requirements,
    allowSetup: true,
  });
  if (readiness) {
    throw new AgentExecutionDriverError(readiness.code, readiness.message);
  }
  if (
    channelsResult.total !== undefined
    && (!Number.isSafeInteger(channelsResult.total) || channelsResult.total < 0)
  ) {
    throw new AgentExecutionDriverError(
      "DIRECT_DISCOVERY_RESPONSE_INVALID",
      "The private indexer returned an invalid outgoing-channel total.",
    );
  }

  const fresh = await fetchPrivateHistoryPage({
    discovery: input.discovery,
    treasuryAddress,
    notesCursor: notesResult.cursor,
    channels,
    block: input.pinned,
  });
  let history = mergePrivacyHistory(input.context.state.history, fresh.transactions);
  let historyCursor = input.context.state.historyCursor;
  let historyPinnedBlock = input.context.state.historyPinnedBlock;
  let backfillCursor: unknown | undefined;
  let backfillBlock: { number: number; hash: `0x${string}` } | null = null;
  let remainingPages = 0;

  if (historyCursor && historyPinnedBlock && !historyCursor.historyComplete) {
    backfillCursor = deserializePrivacyHistoryCursor(historyCursor);
    backfillBlock = historyPinnedBlock;
    remainingPages = PRIVATE_HISTORY_BACKFILL_PAGES;
  } else if (!historyCursor || !historyPinnedBlock) {
    historyCursor = fresh.cursor;
    historyPinnedBlock = { number: input.pinned.number, hash: input.pinned.hash };
    backfillCursor = deserializePrivacyHistoryCursor(fresh.cursor);
    backfillBlock = historyPinnedBlock;
    remainingPages = fresh.cursor.historyComplete ? 0 : PRIVATE_HISTORY_BACKFILL_PAGES - 1;
  }

  try {
    while (backfillCursor && backfillBlock && remainingPages > 0) {
      const page = await fetchPrivateHistoryPage({
        discovery: input.discovery,
        treasuryAddress,
        notesCursor: notesResult.cursor,
        channels,
        block: backfillBlock,
        historyCursor: backfillCursor,
      });
      history = mergePrivacyHistory(history, page.transactions);
      historyCursor = page.cursor;
      backfillCursor = deserializePrivacyHistoryCursor(page.cursor);
      remainingPages -= 1;
      if (page.cursor.historyComplete) break;
    }
  } catch (error) {
    if (!isHistoryBranchReset(error)) throw error;
    // A persisted backfill cursor may point at a reorged/pruned branch. A new
    // hash-pinned scan is complete with respect to the current branch and is a
    // safe restart point; already encrypted history is retained and deduped.
    historyCursor = fresh.cursor;
    historyPinnedBlock = { number: input.pinned.number, hash: input.pinned.hash };
  }

  return {
    registry: { channels, notes, cursor: notesResult.cursor },
    channelTotal: channelsResult.total ?? null,
    history,
    historyCursor,
    historyPinnedBlock,
  };
}

function assertChain(actual: string, expected: string): void {
  if (BigInt(actual) !== BigInt(expected)) {
    throw new AgentExecutionDriverError(
      "DIRECT_CHAIN_MISMATCH",
      "The autonomous executor RPC is connected to the wrong Starknet chain.",
      true,
    );
  }
}

function proofWindow(input: DirectPrivacyPolicyAuthorization, blockTimestamp: number) {
  const validAfter = BigInt(input.proofValidAfterUnix);
  const validBefore = BigInt(input.proofValidBeforeUnix);
  const timestamp = BigInt(blockTimestamp);
  if (timestamp < validAfter || timestamp >= validBefore) {
    throw new AgentExecutionDriverError(
      "DIRECT_PAYO_PROOF_EXPIRED",
      "The PAYO payroll proof expired before autonomous submission.",
      true,
    );
  }
  const executeBefore = validBefore < timestamp + OUTSIDE_WINDOW_SECONDS
    ? validBefore
    : timestamp + OUTSIDE_WINDOW_SECONDS;
  if (executeBefore <= timestamp + 1n) {
    throw new AgentExecutionDriverError(
      "DIRECT_OUTSIDE_WINDOW_TOO_SHORT",
      "The remaining PAYO proof window is too short for safe submission.",
      true,
    );
  }
  return { execute_after: timestamp - 1n, execute_before: executeBefore };
}

function policyCall(input: DirectPrivacyPolicyAuthorization): Call {
  return {
    contractAddress: input.policyCall.contractAddress,
    entrypoint: input.policyCall.entrypoint,
    calldata: input.policyCall.calldata,
  };
}

function outerCalls(input: {
  provider: RpcProvider;
  policyAccountAddress: string;
  sessionPrivateKey: string;
  relayerAddress: string;
  preparation: DirectPrivacyPolicyAuthorization;
  blockTimestamp: number;
}): Promise<Call[]> {
  const sessionAccount = new Account({
    provider: input.provider,
    address: input.policyAccountAddress,
    signer: input.sessionPrivateKey,
    cairoVersion: "1",
  });
  return sessionAccount.getOutsideTransaction(
    {
      caller: input.relayerAddress,
      ...proofWindow(input.preparation, input.blockTimestamp),
    },
    policyCall(input.preparation),
    OutsideExecutionVersion.V2,
  ).then((transaction) => outsideExecution.buildExecuteFromOutsideCall(transaction));
}

function simulationFee(input: unknown): string {
  const response = record(input);
  const transactions = response.simulated_transactions ?? response.simulatedTransactions;
  if (!Array.isArray(transactions) || transactions.length !== 1) {
    throw new AgentExecutionDriverError("DIRECT_SIMULATION_INVALID", "Starknet returned an invalid simulation result.");
  }
  const fee = record(record(transactions[0]).fee_estimation ?? record(transactions[0]).feeEstimation);
  const overall = fee.overall_fee ?? fee.overallFee;
  try {
    const parsed = BigInt(String(overall));
    if (parsed < 0n) throw new Error();
    return parsed.toString();
  } catch {
    throw new AgentExecutionDriverError("DIRECT_SIMULATION_FEE_INVALID", "Starknet omitted the simulated fee.");
  }
}

type SignedInvokeTransaction =
  | DirectPrivacySignedTransaction
  | DirectPrivacyFinalizationSubmission["signedTransaction"];

function signedInvocation(transaction: SignedInvokeTransaction): AccountInvocations[0] {
  const resourceBounds = Object.fromEntries(
    Object.entries(transaction.resource_bounds).map(([resource, bounds]) => [resource, {
      max_amount: BigInt(bounds.max_amount),
      max_price_per_unit: BigInt(bounds.max_price_per_unit),
    }]),
  ) as ResourceBoundsBN;
  return {
    type: "INVOKE",
    contractAddress: transaction.sender_address,
    calldata: transaction.calldata,
    signature: transaction.signature,
    nonce: transaction.nonce,
    resourceBounds,
    tip: BigInt(transaction.tip),
    paymasterData: transaction.paymaster_data,
    accountDeploymentData: transaction.account_deployment_data,
    nonceDataAvailabilityMode: transaction.nonce_data_availability_mode === "L1" ? EDAMode.L1 : EDAMode.L2,
    feeDataAvailabilityMode: transaction.fee_data_availability_mode === "L1" ? EDAMode.L1 : EDAMode.L2,
    version: transaction.version,
    proofFacts: transaction.proof_facts ?? [],
    proof: transaction.proof,
  } as unknown as AccountInvocations[0];
}

function expectedTransactionHash(
  transaction: SignedInvokeTransaction,
  chainId: string,
): `0x${string}` {
  const invocation = signedInvocation(transaction);
  return hash.calculateInvokeTransactionHash({
    senderAddress: transaction.sender_address,
    version: transaction.version,
    compiledCalldata: transaction.calldata,
    chainId: chainId as constants.StarknetChainId,
    nonce: transaction.nonce,
    accountDeploymentData: transaction.account_deployment_data,
    nonceDataAvailabilityMode: transaction.nonce_data_availability_mode === "L1" ? EDAMode.L1 : EDAMode.L2,
    feeDataAvailabilityMode: transaction.fee_data_availability_mode === "L1" ? EDAMode.L1 : EDAMode.L2,
    resourceBounds: invocation.resourceBounds!,
    tip: transaction.tip,
    paymasterData: transaction.paymaster_data,
    proofFacts: transaction.proof_facts ?? [],
  }) as `0x${string}`;
}

async function simulateSigned(
  runtime: DirectPrivacyDriverRuntime,
  transaction: SignedInvokeTransaction,
  blockHash: string,
): Promise<void> {
  const result = await runtime.provider.getSimulateTransaction(
    [signedInvocation(transaction)],
    { blockIdentifier: blockHash, skipValidate: false, skipFeeCharge: false },
  );
  simulationFee(result);
}

function opaque(prepared: PreparedAgentExecution): DriverOpaque {
  const value = prepared.opaque as Partial<DriverOpaque> | null;
  if (
    !value
    || value.kind !== "payo-direct-privacy-preparation"
    || value.preparationCommitment !== prepared.submissionCommitment
    || value.job?.id !== prepared.executionId
    || value.simulated !== true
  ) throw new AgentExecutionDriverError(
    "DIRECT_PREPARED_OPAQUE_INVALID",
    "The direct private preparation was substituted.",
    true,
  );
  return value as DriverOpaque;
}

async function transactionExists(provider: RpcProvider, transactionHash: string): Promise<boolean> {
  try {
    await provider.getTransactionByHash(transactionHash);
    return true;
  } catch {
    return false;
  }
}

function payrollProofFromAuthorization(
  authorization: DirectPrivacyPayrollAuthorization,
): ProofWorkerSuccess {
  return {
    version: 1,
    type: "proof-complete",
    requestId: authorization.executionId,
    scheme: "ultra_keccak_zk_honk",
    circuitSha256: authorization.circuitSha256,
    provingTimeMs: 0,
    shards: authorization.shards.map((shard) => ({
      ...shard,
      proof: new Uint8Array(),
    })) as ProofWorkerSuccess["shards"],
  };
}

function payrollAuthorizationFromProof(input: {
  executionId: string;
  requestCommitment: string;
  sealAddress: string;
  payrollProof: ProofWorkerSuccess;
  plan: ReturnType<typeof buildDirectPrivacyPlan>;
}): DirectPrivacyPayrollAuthorization {
  const precommit = buildDirectPayrollPrecommitCall({
    sealAddress: input.sealAddress,
    sealedPayroll: input.plan.sealedPayroll,
  });
  if (!Array.isArray(precommit.calldata)) {
    throw new AgentExecutionDriverError(
      "DIRECT_PRECOMMIT_CALL_INVALID",
      "The Payroll Seal precommit call was not flattened.",
      true,
    );
  }
  return directPrivacyPayrollAuthorizationSchema.parse({
    version: "payo-direct-payroll-authorization-v1",
    executionId: input.executionId,
    requestCommitment: input.requestCommitment,
    circuitSha256: input.payrollProof.circuitSha256,
    precommitCall: {
      contractAddress: String(precommit.contractAddress),
      entrypoint: "precommit_direct",
      calldata: precommit.calldata,
    },
    shards: input.payrollProof.shards.map((shard) => ({
      shardIndex: shard.shardIndex,
      proofCalldata: shard.proofCalldata,
      calldataHash: shard.calldataHash,
      publicInputs: shard.publicInputs,
    })),
  });
}

async function submitPayrollAuthorizationCall(
  runtime: DirectPrivacyDriverRuntime,
  call: Call,
): Promise<string> {
  const response = await runtime.withRelayerLock(runtime.relayer.address, () =>
    runtime.relayer.execute(call, { tip: 0 }));
  const receipt = await runtime.provider.waitForTransaction(response.transaction_hash, {
    retries: 1_200,
    retryInterval: 250,
  });
  if (receipt.isReverted()) {
    throw new AgentExecutionDriverError(
      "DIRECT_PAYROLL_AUTHORIZATION_REVERTED",
      "A proof-first PayrollIntegrity transaction reverted.",
    );
  }
  return response.transaction_hash;
}

async function ensureDirectPayrollProven(input: {
  runtime: DirectPrivacyDriverRuntime;
  authorization: DirectPrivacyPayrollAuthorization;
}): Promise<void> {
  const { authorization, runtime } = input;
  const first = authorization.shards[0].publicInputs;
  const nullifier = {
    runNullifierHigh: first.runNullifierHigh,
    runNullifierLow: first.runNullifierLow,
  };
  for (let transition = 0; transition < 4; transition += 1) {
    const state = await readProofSealState(runtime.provider, {
      sealAddress: authorization.precommitCall.contractAddress,
      ...nullifier,
    });
    if (state.status === PAYO_RUN_STATUS_PROVEN) {
      if (!state.shardsVerified[0] || !state.shardsVerified[1]) {
        throw new AgentExecutionDriverError(
          "DIRECT_PAYROLL_PROVEN_STATE_INVALID",
          "The Payroll Seal reported PROVEN without both proof shards.",
          true,
        );
      }
      await recordDirectPrivacyPayrollAuthorizationProgress({
        executionId: authorization.executionId,
        state: "proven",
        now: runtime.now(),
      });
      return;
    }
    if (state.status === 0) {
      const transactionHash = await submitPayrollAuthorizationCall(runtime, {
        contractAddress: authorization.precommitCall.contractAddress,
        entrypoint: "precommit_direct",
        calldata: authorization.precommitCall.calldata,
      });
      await recordDirectPrivacyPayrollAuthorizationProgress({
        executionId: authorization.executionId,
        state: "sealed",
        transactionHash,
        now: runtime.now(),
      });
      continue;
    }
    if (state.status !== PAYO_RUN_STATUS_SEALED) {
      throw new AgentExecutionDriverError(
        "DIRECT_PAYROLL_SEAL_STATE_INVALID",
        `The Payroll Seal returned incompatible status ${state.status}.`,
        true,
      );
    }
    if (state.shardsVerified[1] && !state.shardsVerified[0]) {
      throw new AgentExecutionDriverError(
        "DIRECT_PAYROLL_SHARD_ORDER_INVALID",
        "The Payroll Seal contains an out-of-order proof shard.",
        true,
      );
    }
    const shardIndex: 0 | 1 = state.shardsVerified[0] ? 1 : 0;
    await recordDirectPrivacyPayrollAuthorizationProgress({
      executionId: authorization.executionId,
      state: shardIndex === 0 ? "sealed" : "shard0_verified",
      now: runtime.now(),
    });
    const shard = authorization.shards[shardIndex];
    const call = buildVerifySealedShardCalldataCall({
      sealAddress: authorization.precommitCall.contractAddress,
      runNullifierHigh: first.runNullifierHigh,
      runNullifierLow: first.runNullifierLow,
      shardIndex,
      proofCalldata: shard.proofCalldata,
      calldataHash: shard.calldataHash,
    });
    const transactionHash = await submitPayrollAuthorizationCall(runtime, call);
    await recordDirectPrivacyPayrollAuthorizationProgress({
      executionId: authorization.executionId,
      state: shardIndex === 0 ? "shard0_verified" : "shard1_verified",
      transactionHash,
      now: runtime.now(),
    });
  }
  throw new AgentExecutionDriverError(
    "DIRECT_PAYROLL_AUTHORIZATION_INCOMPLETE",
    "PayrollIntegrity did not reach PROVEN after its bounded transitions.",
  );
}

async function prepareSdkExecution(
  runtime: DirectPrivacyDriverRuntime,
  job: LeasedAgentExecution,
): Promise<{ preparation: DirectPrivacyPreparation; accountId: string }> {
  const context = await leaseDirectPrivacyExecutionContext(job, runtime.now());
  try {
    assertChain(await runtime.provider.getChainId(), context.config.chainId);
    const existingPreparation = await findDirectPrivacyPreparation(job);
    if (existingPreparation) {
      if (
        existingPreparation.accountId !== context.accountId
        || existingPreparation.preparation.expectedStateVersion !== context.stateVersion
      ) throw new AgentExecutionDriverError(
        "DIRECT_PREPARATION_REPLAY_CONFLICT",
        "The stored private preparation no longer matches the leased treasury state.",
        true,
      );
      return {
        preparation: existingPreparation.preparation,
        accountId: existingPreparation.accountId,
      };
    }
    const discovery = new runtime.sdk.sdk.IndexerDiscoveryProvider(
      runtime.indexerUrl,
      context.config.poolAddress,
    );
    const pinned = await pinIndexerBlock(runtime, discovery);
    if (context.state.pinnedBlock && context.state.pinnedBlock.number > pinned.number) {
      throw new AgentExecutionDriverError(
        "DIRECT_STATE_AHEAD_OF_INDEXER",
        "The encrypted private state is ahead of the canonical indexer.",
      );
    }
    if (job.request.intents.length > 3) {
      throw new AgentExecutionDriverError(
        "DIRECT_ATOMIC_BATCH_LIMIT",
        "Autonomous private payroll is limited to three lines per atomic run.",
        true,
      );
    }
    let reconciliation = await loadDirectPrivacyReconciliation(job.id);
    let draft: DirectPrivacyProofDraft;
    if (reconciliation?.draft) {
      draft = reconciliation.draft;
      if (
        reconciliation.account.id !== context.accountId
        || draft.executionId !== job.id
        || draft.requestCommitment.toLowerCase() !== job.requestCommitment.toLowerCase()
        || draft.expectedStateVersion !== context.stateVersion
      ) {
        throw new AgentExecutionDriverError(
          "DIRECT_PROOF_DRAFT_STALE",
          "The durable SDK proof draft no longer matches the authoritative account state.",
          true,
        );
      }
      const draftBlock = acceptedBlock(
        await runtime.provider.getBlock(draft.pinnedBlock.number),
      );
      if (
        BigInt(draftBlock.hash) !== BigInt(draft.pinnedBlock.hash)
        || draft.pinnedBlock.number > pinned.number
      ) {
        throw new AgentExecutionDriverError(
          "DIRECT_PROOF_DRAFT_REORGED",
          "The canonical chain no longer contains the block-pinned SDK draft.",
          true,
        );
      }
    } else {
      const snapshot = await discoverDirectPrivacySnapshot({
        discovery,
        pinned,
        context,
        job,
      });
      let storedAuthorization = await loadDirectPrivacyPayrollAuthorization(job.id);
      let payrollProof: ProofWorkerSuccess;
      if (storedAuthorization) {
        if (
          storedAuthorization.account.id !== context.accountId
          || storedAuthorization.authorization.requestCommitment.toLowerCase()
            !== job.requestCommitment.toLowerCase()
        ) throw new AgentExecutionDriverError(
          "DIRECT_PAYROLL_AUTHORIZATION_STALE",
          "The durable PayrollIntegrity authorization no longer matches this execution.",
          true,
        );
        payrollProof = payrollProofFromAuthorization(storedAuthorization.authorization);
      } else {
        const generated = await runtime.proofClient.payroll({
          requestId: job.id,
          encryptedWitness: context.material.encryptedWitness,
          principal: context.secrets.proofPrincipal,
        });
        if (!generated) {
          throw new AgentExecutionDriverError(
            "DIRECT_PAYROLL_PROOF_PENDING",
            "The authenticated payroll proof job is still running.",
          );
        }
        payrollProof = generated;
      }
      let plan = buildDirectPrivacyPlan({
        config: context.config,
        material: context.material,
        payrollProof,
        nowUnixSeconds: BigInt(pinned.timestamp),
      });
      if (!storedAuthorization) {
        const authorization = payrollAuthorizationFromProof({
          executionId: job.id,
          requestCommitment: job.requestCommitment,
          sealAddress: context.config.sealAddress,
          payrollProof,
          plan,
        });
        await storeDirectPrivacyPayrollAuthorization({
          accountId: context.accountId,
          organizationId: context.material.organizationId,
          executionId: job.id,
          requestCommitment: job.requestCommitment,
          authorization,
          now: runtime.now(),
        });
        storedAuthorization = await loadDirectPrivacyPayrollAuthorization(job.id);
        if (!storedAuthorization) throw new Error("DIRECT_PAYROLL_AUTHORIZATION_STORE_FAILED");
        payrollProof = payrollProofFromAuthorization(storedAuthorization.authorization);
        plan = buildDirectPrivacyPlan({
          config: context.config,
          material: context.material,
          payrollProof,
          nowUnixSeconds: BigInt(pinned.timestamp),
        });
      }
      await ensureDirectPayrollProven({
        runtime,
        authorization: storedAuthorization.authorization,
      });
      const provingProvider = new runtime.sdk.sdk.ProvingServiceProofProvider(
        runtime.provingUrl,
        context.config.chainId,
        {
          requestTimeoutMs: 30 * 60_000,
          blockIdentifier: pinned.hash,
          nodeUrl: runtime.rpcUrl,
          poolAddress: context.config.poolAddress,
          retry: { maxRetries: 2 },
        },
      );
      const transfers = runtime.sdk.sdk.createPrivateTransfers({
        account: {
          address: context.config.policyAccountAddress,
          signer: runtime.policyOwnerSigner,
        },
        viewingKeyProvider: { getViewingKey: async () => BigInt(context.viewingKey) },
        provingProvider,
        discoveryProvider: discovery,
        poolContractAddress: context.config.poolAddress,
      }) as PrivacyTransfers;
      const invocation = await transfers.createProofInvocation(plan.actions, {
        autoRegister: false,
        // Registration remains an explicit owner-reviewed prerequisite. Missing
        // outgoing channels/subchannels are safe to open atomically inside this
        // same bounded payroll proof; refresh at the exact proof pin so the SDK
        // also obtains the authoritative next-channel index when setup is needed.
        autoSetup: true,
        autoDiscover: { channels: "refresh" },
        autoSelectNotes: "all",
        registry: snapshot.registry,
        registryConst: true,
        provingBlockId: pinned.hash,
      });
      const sdkResult = await transfers.executeWithInvocation(
        invocation,
        { block_hash: pinned.hash },
      );
      assertDirectPrivacySdkResult({ result: sdkResult, poolAddress: context.config.poolAddress });
      const poolCalldata = sdkResult.callAndProof.call.calldata;
      if (!poolCalldata) throw new Error("DIRECT_POOL_CALLDATA_MISSING");
      const settlementEvidence = extractDirectPrivacySettlementEvidence({
        invocation,
        poolAddress: context.config.poolAddress,
        policyAccountAddress: context.config.policyAccountAddress,
        viewingKey: context.viewingKey,
        chainId: context.config.chainId,
        poolCalldata,
        payrollLineCount: job.request.intents.length,
      });
      const settlementWitness = settlementMatchWitnessSchema.parse({
        version: "payo-settlement-match-witness-v1",
        executionId: job.id,
        chainId: context.config.chainId,
        policyAccountAddress: context.config.policyAccountAddress,
        poolAddress: context.config.poolAddress,
        poolCalldata: settlementEvidence.poolCalldata,
        viewingKey: settlementEvidence.viewingKey,
        payrollNotes: settlementEvidence.payrollNotes,
        emittedNotes: settlementEvidence.emittedNotes,
      });
      const encryptedSettlementWitness = encryptVaultRecord(
        settlementWitness,
        {
          schemaVersion: 1,
          organizationId: context.material.organizationId,
          recordType: "settlement-match-proof-request",
          recordId: job.id,
          revision: context.material.runVersion,
        },
        [context.secrets.proofPrincipal],
      );
      const settlementRoot = buildSettlementRoot(settlementEvidence.emittedNotes);
      draft = directPrivacyProofDraftSchema.parse({
        version: "payo-direct-privacy-proof-draft-v1",
        executionId: job.id,
        requestCommitment: job.requestCommitment,
        poolCalldata,
        sdkProof: {
          data: sdkResult.callAndProof.proof.data,
          proofFacts: sdkResult.callAndProof.proof.proofFacts,
        },
        settlement: {
          transactionReference: settlementEvidence.transactionReference,
          settlementRoot,
          encryptedPayrollWitness: context.material.encryptedWitness,
          encryptedSettlementWitness,
        },
        proofValidAfterUnix: plan.sealedPayroll.validityStart.toString(),
        proofValidBeforeUnix: plan.sealedPayroll.validityExpiry.toString(),
        nextState: {
          ...context.state,
          registry: serializePrivacyRegistry(
            { ...record(sdkResult.registry), cursor: snapshot.registry.cursor },
            runtime.sdk.codecs,
            snapshot.channelTotal,
          ),
          history: snapshot.history,
          historyCursor: snapshot.historyCursor,
          historyPinnedBlock: snapshot.historyPinnedBlock,
          pinnedBlock: { number: pinned.number, hash: pinned.hash },
        },
        expectedStateVersion: context.stateVersion,
        pinnedBlock: { number: pinned.number, hash: pinned.hash },
      });
      await ensureDirectPrivacyReconciliation({
        executionId: job.id,
        accountId: context.accountId,
        organizationId: context.material.organizationId,
        settlementRoot,
        transactionReference: settlementEvidence.transactionReference,
        now: runtime.now(),
      });
      await storeDirectPrivacyProofDraft({
        executionId: job.id,
        requestCommitment: job.requestCommitment,
        draft,
        now: runtime.now(),
      });
      reconciliation = await loadDirectPrivacyReconciliation(job.id);
    }
    let settlementProof: SettlementMatchProofWorkerSuccess | null =
      reconciliation?.proof?.proof ?? null;
    if (!settlementProof) {
      settlementProof = await runtime.proofClient.settlement({
        requestId: job.id,
        encryptedPayrollWitness: draft.settlement.encryptedPayrollWitness,
        encryptedSettlementWitness: draft.settlement.encryptedSettlementWitness,
        principal: context.secrets.proofPrincipal,
      });
    }
    if (!settlementProof) {
      throw new AgentExecutionDriverError(
        "DIRECT_SETTLEMENT_PROOF_PENDING",
        "The authenticated SettlementMatch proof job is still running.",
      );
    }
    if (
      settlementProof.settlementRoot.toLowerCase()
        !== draft.settlement.settlementRoot.toLowerCase()
      || settlementProof.transactionReference.toLowerCase()
        !== draft.settlement.transactionReference.toLowerCase()
    ) {
      throw new AgentExecutionDriverError(
        "DIRECT_SETTLEMENT_BINDING_INVALID",
        "SettlementMatch does not bind the prepared SDK transaction.",
        true,
      );
    }
    if (settlementProof.chunks.length !== 1) {
      throw new AgentExecutionDriverError(
        "DIRECT_ATOMIC_BATCH_LIMIT",
        "Autonomous private payroll is limited to three lines per atomic run.",
        true,
      );
    }
    await storeDirectPrivacyReconciliationProof({
      executionId: job.id,
      requestCommitment: job.requestCommitment,
      proof: settlementProof,
      now: runtime.now(),
    });
    const call = buildDirectPrivacyPolicyCall({
      config: context.config,
      material: context.material,
      poolCalldata: draft.poolCalldata,
      settlementProofChunks: settlementProof.chunks,
    });
    const provisional: Omit<DirectPrivacyPreparation, "outsideCall"> = {
      version: "payo-direct-privacy-preparation-v1",
      executionId: job.id,
      requestCommitment: job.requestCommitment as `0x${string}`,
      policyCall: {
        contractAddress: String(call.contractAddress) as `0x${string}`,
        entrypoint: "execute_policy_intent",
        calldata: call.calldata as `0x${string}`[],
      },
      sdkProof: draft.sdkProof,
      settlement: draft.settlement,
      proofValidAfterUnix: draft.proofValidAfterUnix,
      proofValidBeforeUnix: draft.proofValidBeforeUnix,
      nextState: draft.nextState,
      expectedStateVersion: draft.expectedStateVersion,
      pinnedBlock: draft.pinnedBlock,
      feeEstimateAtomic: "0",
    };
    const sessionCalls = await outerCalls({
      provider: runtime.provider,
      policyAccountAddress: context.config.policyAccountAddress,
      sessionPrivateKey: context.secrets.sessionPrivateKey,
      relayerAddress: runtime.relayer.address,
      preparation: provisional,
      blockTimestamp: pinned.timestamp,
    });
    if (sessionCalls.length !== 1) {
      throw new AgentExecutionDriverError(
        "DIRECT_OUTSIDE_CALL_INVALID",
        "The session signer returned an invalid outside authorization.",
        true,
      );
    }
    assertDirectPrivacyOutsideCall({
      outsideCall: sessionCalls[0],
      policyCall: provisional.policyCall,
      relayerAddress: runtime.relayer.address,
      proofValidAfterUnix: provisional.proofValidAfterUnix,
      proofValidBeforeUnix: provisional.proofValidBeforeUnix,
      currentBlockTimestamp: pinned.timestamp,
    });
    const simulation = await runtime.relayer.simulateTransaction(
      [{ type: "INVOKE", payload: sessionCalls }],
      {
        blockIdentifier: pinned.hash,
        skipValidate: false,
        tip: 0,
        proofFacts: provisional.sdkProof.proofFacts,
        proof: provisional.sdkProof.data,
      },
    );
    return {
      accountId: context.accountId,
      preparation: directPrivacyPreparationSchema.parse({
        ...provisional,
        outsideCall: sessionCalls[0],
        feeEstimateAtomic: simulationFee(simulation),
      }),
    };
  } catch (error) {
    await releaseDirectPrivacyExecution(job, runtime.now());
    throw error;
  }
}

async function createSignedSubmission(input: {
  runtime: DirectPrivacyDriverRuntime;
  executionId: string;
  requestCommitment: string;
  preparationCommitment: string;
}): Promise<Awaited<ReturnType<typeof loadDirectPrivacySubmissionByExecution>>> {
  const existing = await loadDirectPrivacySubmissionByExecution(input.executionId);
  if (existing) return existing;
  const loaded = await loadDirectPrivacyPreparation(input);
  const config = directPrivacyAccountConfigSchema.parse(loaded.account.config);
  assertChain(await input.runtime.provider.getChainId(), config.chainId);
  const latest = acceptedBlock(await input.runtime.provider.getBlock("latest"));
  try {
    assertDirectPrivacyOutsideCall({
      outsideCall: loaded.preparation.outsideCall,
      policyCall: loaded.preparation.policyCall,
      relayerAddress: input.runtime.relayer.address,
      proofValidAfterUnix: loaded.preparation.proofValidAfterUnix,
      proofValidBeforeUnix: loaded.preparation.proofValidBeforeUnix,
      currentBlockTimestamp: latest.timestamp,
    });
  } catch (error) {
    throw new AgentExecutionDriverError(
      "DIRECT_OUTSIDE_CALL_SUBSTITUTED",
      error instanceof Error ? error.message : "The persisted outside authorization is invalid.",
      true,
    );
  }
  const calls = [loaded.preparation.outsideCall];
  const raw = await input.runtime.relayer.getSignedTransaction(calls, {
    blockIdentifier: latest.hash,
    tip: 0,
    proofFacts: loaded.preparation.sdkProof.proofFacts,
    proof: loaded.preparation.sdkProof.data,
  });
  const signedTransaction = directPrivacyPreparedSubmissionSchema.shape.signedTransaction.parse(raw);
  const expectedHash = expectedTransactionHash(signedTransaction, config.chainId);
  const prepared = directPrivacyPreparedSubmissionSchema.parse({
    version: "payo-direct-privacy-submission-v1",
    executionId: input.executionId,
    requestCommitment: input.requestCommitment,
    expectedTransactionHash: expectedHash,
    signedTransaction,
    settlement: loaded.preparation.settlement,
    proofValidAfterUnix: loaded.preparation.proofValidAfterUnix,
    proofValidBeforeUnix: loaded.preparation.proofValidBeforeUnix,
    nextState: loaded.preparation.nextState,
    expectedStateVersion: loaded.preparation.expectedStateVersion,
    pinnedBlock: loaded.preparation.pinnedBlock,
    feeEstimateAtomic: loaded.preparation.feeEstimateAtomic,
  });
  await storePreparedDirectPrivacySubmission({
    job: {
      id: input.executionId,
      capabilityId: loaded.account.capabilityId,
      organizationId: loaded.account.organizationId,
      requestCommitment: input.requestCommitment,
    },
    accountId: loaded.account.id,
    prepared,
    now: input.runtime.now(),
  });
  await markDirectPrivacyPreparationSigned(
    input.executionId,
    input.preparationCommitment,
    input.runtime.now(),
  );
  return loadDirectPrivacySubmissionByExecution(input.executionId);
}

async function broadcastSigned(
  runtime: DirectPrivacyDriverRuntime,
  stored: NonNullable<Awaited<ReturnType<typeof loadDirectPrivacySubmissionByExecution>>>,
): Promise<string> {
  const expectedHash = stored.prepared.expectedTransactionHash;
  if (stored.state === "confirmed" || stored.state === "submitted") return expectedHash;
  if (stored.state === "reverted") {
    throw new AgentExecutionDriverError("DIRECT_TRANSACTION_REVERTED", "The autonomous transaction reverted.", true);
  }
  if (await transactionExists(runtime.provider, expectedHash)) {
    if (stored.state === "prepared" || stored.state === "reorged") {
      await markDirectPrivacySubmissionBroadcasting(
        stored.prepared.executionId,
        stored.submissionCommitment,
        runtime.now(),
      );
    }
    await recordDirectPrivacyBroadcast({
      executionId: stored.prepared.executionId,
      submissionCommitment: stored.submissionCommitment,
      transactionHash: expectedHash,
      now: runtime.now(),
    });
    return expectedHash;
  }
  const currentBlock = acceptedBlock(await runtime.provider.getBlock("latest"));
  const currentTimestamp = BigInt(currentBlock.timestamp);
  if (
    currentTimestamp < BigInt(stored.prepared.proofValidAfterUnix)
    || currentTimestamp >= BigInt(stored.prepared.proofValidBeforeUnix)
  ) throw new AgentExecutionDriverError(
    "DIRECT_PAYO_PROOF_EXPIRED",
    "The PAYO payroll proof expired before broadcast.",
    true,
  );
  await simulateSigned(runtime, stored.prepared.signedTransaction, currentBlock.hash);
  await markDirectPrivacySubmissionBroadcasting(
    stored.prepared.executionId,
    stored.submissionCommitment,
    runtime.now(),
  );
  try {
    const response = await runtime.provider.invokeSignedTx(
      stored.prepared.signedTransaction as Parameters<typeof runtime.provider.invokeSignedTx>[0],
    );
    if (BigInt(response.transaction_hash) !== BigInt(expectedHash)) {
      throw new AgentExecutionDriverError(
        "DIRECT_TRANSACTION_HASH_MISMATCH",
        "The Starknet RPC returned a different transaction hash.",
        true,
      );
    }
  } catch (error) {
    if (!(await transactionExists(runtime.provider, expectedHash))) throw error;
  }
  await recordDirectPrivacyBroadcast({
    executionId: stored.prepared.executionId,
    submissionCommitment: stored.submissionCommitment,
    transactionHash: expectedHash,
    now: runtime.now(),
  });
  return expectedHash;
}

async function signAndBroadcast(input: {
  runtime: DirectPrivacyDriverRuntime;
  executionId: string;
  requestCommitment: string;
  preparationCommitment: string;
}): Promise<string> {
  return input.runtime.withRelayerLock(input.runtime.relayer.address, async () => {
    const stored = await createSignedSubmission(input);
    if (!stored) throw new Error("DIRECT_SUBMISSION_STORE_FAILED");
    return broadcastSigned(input.runtime, stored);
  });
}

function callResultFelts(value: unknown, label: string): string[] {
  const values = Array.isArray(value) ? value : record(value).result;
  if (!Array.isArray(values) || values.some((felt) => typeof felt !== "string")) {
    throw new AgentExecutionDriverError(
      "DIRECT_SEAL_RESPONSE_INVALID",
      "The Payroll Seal returned invalid " + label + " data.",
      true,
    );
  }
  return values as string[];
}

function settlementNullifier(
  proof: NonNullable<Awaited<ReturnType<typeof loadDirectPrivacyReconciliation>>>["proof"],
): { high: string; low: string } {
  const inputs = proof?.proof.chunks[0]?.publicInputs;
  if (!inputs) {
    throw new AgentExecutionDriverError(
      "DIRECT_SETTLEMENT_PROOF_MISSING",
      "The durable SettlementMatch proof is missing its public inputs.",
      true,
    );
  }
  return {
    high: num.toHex(BigInt(inputs.runNullifierHigh)),
    low: num.toHex(BigInt(inputs.runNullifierLow)),
  };
}

function settlementFinalizeCall(input: {
  sealAddress: string;
  runNullifierHigh: string;
  runNullifierLow: string;
  chunkIndex: number;
  chunkCount: number;
  proofCalldata: readonly string[];
}): Call {
  return {
    contractAddress: input.sealAddress,
    entrypoint: "finalize_settlement",
    calldata: [
      num.toHex(8n),
      num.toHex(BigInt(input.runNullifierHigh)),
      num.toHex(BigInt(input.runNullifierLow)),
      num.toHex(BigInt(input.chunkIndex)),
      num.toHex(BigInt(input.chunkCount)),
      num.toHex(BigInt(input.proofCalldata.length)),
      ...input.proofCalldata,
    ],
  };
}

async function broadcastActiveFinalization(
  runtime: DirectPrivacyDriverRuntime,
  executionId: string,
): Promise<string> {
  const loaded = await loadDirectPrivacyReconciliation(executionId);
  const active = loaded?.activeFinalization;
  if (!loaded || !active) {
    throw new AgentExecutionDriverError(
      "DIRECT_FINALIZATION_NOT_ACTIVE",
      "No durable FINALIZE transaction is available.",
      true,
    );
  }
  const expectedHash = active.expectedTransactionHash;
  if (await transactionExists(runtime.provider, expectedHash)) {
    await recordDirectPrivacyFinalizationBroadcast({
      executionId,
      expectedTransactionHash: expectedHash,
      transactionHash: expectedHash,
      now: runtime.now(),
    });
    return expectedHash;
  }
  const latest = acceptedBlock(await runtime.provider.getBlock("latest"));
  await simulateSigned(runtime, active.signedTransaction, latest.hash);
  try {
    const response = await runtime.provider.invokeSignedTx(
      active.signedTransaction as Parameters<typeof runtime.provider.invokeSignedTx>[0],
    );
    if (BigInt(response.transaction_hash) !== BigInt(expectedHash)) {
      throw new AgentExecutionDriverError(
        "DIRECT_FINALIZATION_HASH_MISMATCH",
        "The Starknet RPC returned a different FINALIZE transaction hash.",
        true,
      );
    }
  } catch (error) {
    if (!(await transactionExists(runtime.provider, expectedHash))) throw error;
  }
  await recordDirectPrivacyFinalizationBroadcast({
    executionId,
    expectedTransactionHash: expectedHash,
    transactionHash: expectedHash,
    now: runtime.now(),
  });
  return expectedHash;
}

async function signAndBroadcastFinalization(input: {
  runtime: DirectPrivacyDriverRuntime;
  stored: NonNullable<Awaited<ReturnType<typeof findDirectPrivacySubmission>>>;
  chunkIndex: number;
}): Promise<string> {
  return input.runtime.withRelayerLock(input.runtime.relayer.address, async () => {
    let reconciliation = await loadDirectPrivacyReconciliation(
      input.stored.prepared.executionId,
    );
    if (!reconciliation?.proof) {
      throw new AgentExecutionDriverError(
        "DIRECT_SETTLEMENT_PROOF_MISSING",
        "SettlementMatch must be proved before FINALIZE can be signed.",
        true,
      );
    }
    if (reconciliation.activeFinalization) {
      if (reconciliation.activeFinalization.chunkIndex !== input.chunkIndex) {
        throw new AgentExecutionDriverError(
          "DIRECT_FINALIZATION_ACTIVE_CONFLICT",
          "A different FINALIZE chunk is already pending.",
          true,
        );
      }
      return broadcastActiveFinalization(
        input.runtime,
        input.stored.prepared.executionId,
      );
    }
    const config = directPrivacyAccountConfigSchema.parse(input.stored.account.config);
    const proof = reconciliation.proof;
    const chunk = proof.proof.chunks[input.chunkIndex];
    if (!chunk) {
      throw new AgentExecutionDriverError(
        "DIRECT_SETTLEMENT_CHUNK_MISSING",
        "The requested SettlementMatch chunk does not exist.",
        true,
      );
    }
    const nullifier = settlementNullifier(proof);
    const latest = acceptedBlock(await input.runtime.provider.getBlock("latest"));
    const raw = await input.runtime.relayer.getSignedTransaction([
      settlementFinalizeCall({
        sealAddress: config.sealAddress,
        runNullifierHigh: nullifier.high,
        runNullifierLow: nullifier.low,
        chunkIndex: chunk.chunkIndex,
        chunkCount: chunk.chunkCount,
        proofCalldata: chunk.proofCalldata,
      }),
    ], { blockIdentifier: latest.hash, tip: 0 });
    const signedTransaction =
      directPrivacyFinalizationSubmissionSchema.shape.signedTransaction.parse(raw);
    const expectedHash = expectedTransactionHash(signedTransaction, config.chainId);
    await storeDirectPrivacyFinalization({
      submission: {
        version: "payo-direct-privacy-finalization-v1",
        executionId: input.stored.prepared.executionId,
        requestCommitment: input.stored.prepared.requestCommitment,
        chunkIndex: chunk.chunkIndex,
        chunkCount: chunk.chunkCount,
        calldataHash: chunk.calldataHash,
        expectedTransactionHash: expectedHash,
        signedTransaction,
      },
      now: input.runtime.now(),
    });
    reconciliation = await loadDirectPrivacyReconciliation(
      input.stored.prepared.executionId,
    );
    if (!reconciliation?.activeFinalization) {
      throw new AgentExecutionDriverError(
        "DIRECT_FINALIZATION_STORE_FAILED",
        "The signed FINALIZE transaction was not durably stored.",
      );
    }
    return broadcastActiveFinalization(
      input.runtime,
      input.stored.prepared.executionId,
    );
  });
}

async function observeActiveFinalization(
  runtime: DirectPrivacyDriverRuntime,
  executionId: string,
): Promise<void> {
  const transactionHash = await runtime.withRelayerLock(
    runtime.relayer.address,
    () => broadcastActiveFinalization(runtime, executionId),
  );
  let receipt: Record<string, unknown>;
  try {
    receipt = record(await runtime.provider.getTransactionReceipt(transactionHash));
  } catch {
    return;
  }
  const executionStatus = String(
    receipt.execution_status ?? receipt.executionStatus ?? "",
  ).toUpperCase();
  if (executionStatus === "REVERTED") {
    throw new AgentExecutionDriverError(
      "DIRECT_FINALIZATION_REVERTED",
      "The Payroll Seal rejected SettlementMatch FINALIZE.",
      true,
    );
  }
  const finality = String(
    receipt.finality_status ?? receipt.finalityStatus ?? "",
  ).toUpperCase();
  const blockNumber = Number(receipt.block_number ?? receipt.blockNumber);
  const blockHash = String(receipt.block_hash ?? receipt.blockHash ?? "");
  if (
    !finality.startsWith("ACCEPTED")
    || !Number.isSafeInteger(blockNumber)
    || !HASH_PATTERN.test(blockHash)
  ) return;
  const canonical = acceptedBlock(await runtime.provider.getBlock(blockNumber));
  if (BigInt(canonical.hash) !== BigInt(blockHash)) return;
  const latest = await runtime.provider.getBlockNumber();
  if (latest - blockNumber + 1 < runtime.finalityBlocks) return;
  await completeDirectPrivacyFinalizationChunk(transactionHash, runtime.now());
}

async function settlementChainState(input: {
  runtime: DirectPrivacyDriverRuntime;
  sealAddress: string;
  runNullifierHigh: string;
  runNullifierLow: string;
  chunkCount: number;
}): Promise<{
  status: number;
  verifiedCount: number;
  expectedChunkCount: number;
  verified: boolean[];
}> {
  const calldata = [input.runNullifierHigh, input.runNullifierLow];
  const [statusResult, progressResult, ...chunkResults] = await Promise.all([
    input.runtime.provider.callContract({
      contractAddress: input.sealAddress,
      entrypoint: "get_run_status",
      calldata,
    }),
    input.runtime.provider.callContract({
      contractAddress: input.sealAddress,
      entrypoint: "get_settlement_progress",
      calldata,
    }),
    ...Array.from({ length: input.chunkCount }, (_, chunkIndex) =>
      input.runtime.provider.callContract({
        contractAddress: input.sealAddress,
        entrypoint: "is_settlement_chunk_verified",
        calldata: [...calldata, num.toHex(BigInt(chunkIndex))],
      })),
  ]);
  const statusFelts = callResultFelts(statusResult, "run status");
  const progressFelts = callResultFelts(progressResult, "settlement progress");
  if (statusFelts.length !== 1 || progressFelts.length !== 2) {
    throw new AgentExecutionDriverError(
      "DIRECT_SEAL_RESPONSE_INVALID",
      "The Payroll Seal returned a malformed settlement status.",
      true,
    );
  }
  const verified = chunkResults.map((result, chunkIndex) => {
    const felts = callResultFelts(result, "chunk " + chunkIndex);
    if (felts.length !== 1 || (BigInt(felts[0]) !== 0n && BigInt(felts[0]) !== 1n)) {
      throw new AgentExecutionDriverError(
        "DIRECT_SEAL_RESPONSE_INVALID",
        "The Payroll Seal returned a malformed chunk status.",
        true,
      );
    }
    return BigInt(felts[0]) === 1n;
  });
  return {
    status: Number(BigInt(statusFelts[0])),
    verifiedCount: Number(BigInt(progressFelts[0])),
    expectedChunkCount: Number(BigInt(progressFelts[1])),
    verified,
  };
}

async function reconcileConfirmedDirectSubmission(
  runtime: DirectPrivacyDriverRuntime,
  stored: NonNullable<Awaited<ReturnType<typeof findDirectPrivacySubmission>>>,
): Promise<boolean> {
  const prepared = stored.prepared;
  await ensureDirectPrivacyReconciliation({
    executionId: prepared.executionId,
    accountId: stored.account.id,
    organizationId: stored.account.organizationId,
    settlementRoot: prepared.settlement.settlementRoot,
    transactionReference: prepared.settlement.transactionReference,
    now: runtime.now(),
  });
  let reconciliation = await loadDirectPrivacyReconciliation(prepared.executionId);
  if (!reconciliation) throw new Error("DIRECT_RECONCILIATION_STORE_FAILED");
  if (reconciliation.row.state === "reconciled") return true;
  if (!reconciliation.proof) {
    const secrets = decryptDirectPrivacyPayload(stored.account.encryptedSecrets, {
      accountId: stored.account.id,
      organizationId: stored.account.organizationId,
      capabilityId: stored.account.capabilityId,
      purpose: "secrets",
    });
    const proof = await runtime.proofClient.settlement({
      requestId: prepared.executionId,
      encryptedPayrollWitness: prepared.settlement.encryptedPayrollWitness,
      encryptedSettlementWitness: prepared.settlement.encryptedSettlementWitness,
      principal: secrets.proofPrincipal,
    });
    if (!proof) return false;
    if (
      proof.settlementRoot.toLowerCase()
        !== prepared.settlement.settlementRoot.toLowerCase()
      || proof.transactionReference.toLowerCase()
        !== prepared.settlement.transactionReference.toLowerCase()
    ) {
      throw new AgentExecutionDriverError(
        "DIRECT_SETTLEMENT_BINDING_INVALID",
        "SettlementMatch does not bind the confirmed SDK transaction.",
        true,
      );
    }
    await storeDirectPrivacyReconciliationProof({
      executionId: prepared.executionId,
      requestCommitment: prepared.requestCommitment,
      proof,
      now: runtime.now(),
    });
    reconciliation = await loadDirectPrivacyReconciliation(prepared.executionId);
  }
  if (!reconciliation?.proof) return false;
  if (reconciliation.activeFinalization) {
    await observeActiveFinalization(runtime, prepared.executionId);
    return false;
  }
  const config = directPrivacyAccountConfigSchema.parse(stored.account.config);
  const nullifier = settlementNullifier(reconciliation.proof);
  const chain = await settlementChainState({
    runtime,
    sealAddress: config.sealAddress,
    runNullifierHigh: nullifier.high,
    runNullifierLow: nullifier.low,
    chunkCount: reconciliation.proof.proof.chunks.length,
  });
  const actualVerified = chain.verified.filter(Boolean).length;
  if (
    actualVerified !== chain.verifiedCount
    || (
      chain.expectedChunkCount !== 0
      && chain.expectedChunkCount !== reconciliation.proof.proof.chunks.length
    )
  ) {
    throw new AgentExecutionDriverError(
      "DIRECT_SEAL_PROGRESS_INVALID",
      "Payroll Seal settlement progress is internally inconsistent.",
      true,
    );
  }
  if (chain.status === 3) {
    if (actualVerified !== reconciliation.proof.proof.chunks.length) {
      throw new AgentExecutionDriverError(
        "DIRECT_SEAL_FINALIZATION_INVALID",
        "Payroll Seal is finalized without every SettlementMatch chunk.",
        true,
      );
    }
    await markDirectPrivacyReconciled({
      executionId: prepared.executionId,
      verifiedCount: actualVerified,
      atomicTransactionHash: stored.row.transactionHash
        ?? prepared.expectedTransactionHash,
      now: runtime.now(),
    });
    return true;
  }
  if (chain.status !== 2) {
    throw new AgentExecutionDriverError(
      "DIRECT_SEAL_STATE_INVALID",
      "The confirmed direct-SDK run is not in the PROVEN seal state.",
      true,
    );
  }
  const nextChunk = chain.verified.findIndex((value) => !value);
  if (nextChunk < 0) {
    throw new AgentExecutionDriverError(
      "DIRECT_SEAL_FINALIZATION_INVALID",
      "All settlement chunks are verified but the run is not FINALIZED.",
      true,
    );
  }
  await signAndBroadcastFinalization({ runtime, stored, chunkIndex: nextChunk });
  return false;
}

function createDriver(runtime: DirectPrivacyDriverRuntime): StructuredAgentExecutionDriver {
  return {
    async prepareAndVerify(job) {
      const { preparation, accountId } = await prepareSdkExecution(runtime, job);
      let stored: Awaited<ReturnType<typeof storeDirectPrivacyPreparation>>;
      try {
        stored = await storeDirectPrivacyPreparation({
          job,
          accountId,
          preparation,
          now: runtime.now(),
        });
      } catch (error) {
        await releaseDirectPrivacyExecution(job, runtime.now());
        throw error;
      }
      return {
        version: "payo-prepared-agent-execution-v1",
        executionId: job.id,
        requestCommitment: job.requestCommitment,
        submissionCommitment: stored.preparationCommitment,
        opaque: {
          kind: "payo-direct-privacy-preparation",
          job,
          preparationCommitment: stored.preparationCommitment,
          simulated: true,
        } satisfies DriverOpaque,
      };
    },

    async simulate(prepared) {
      opaque(prepared);
      await loadDirectPrivacyPreparation({
        executionId: prepared.executionId,
        requestCommitment: prepared.requestCommitment,
        preparationCommitment: prepared.submissionCommitment,
      });
    },

    async submit(prepared) {
      const privatePrepared = opaque(prepared);
      return signAndBroadcast({
        runtime,
        executionId: prepared.executionId,
        requestCommitment: prepared.requestCommitment,
        preparationCommitment: privatePrepared.preparationCommitment,
      });
    },

    async recoverSubmission(input) {
      try {
        return await signAndBroadcast({
          runtime,
          executionId: input.executionId,
          requestCommitment: input.requestCommitment,
          preparationCommitment: input.submissionCommitment,
        });
      } catch (error) {
        if (error instanceof AgentExecutionDriverError && error.permanent) throw error;
        return null;
      }
    },

    async observe(transactionHash): Promise<AgentExecutionObservation> {
      const stored = await findDirectPrivacySubmission(transactionHash);
      if (!stored) {
        return { state: "reverted", errorCode: "DIRECT_SUBMISSION_NOT_FOUND" };
      }
      let receipt: Record<string, unknown>;
      try {
        receipt = record(await runtime.provider.getTransactionReceipt(transactionHash));
      } catch {
        let recoveryState = stored.row.state;
        if (
          recoveryState === "submitted"
          && runtime.now().getTime() - stored.row.updatedAt.getTime() >= 120_000
        ) {
          await failDirectPrivacySubmission(transactionHash, "reorged", runtime.now());
          recoveryState = "reorged";
        }
        if (recoveryState === "reorged" || recoveryState === "broadcasting") {
          try {
            await runtime.withRelayerLock(runtime.relayer.address, () => broadcastSigned(runtime, {
              prepared: stored.prepared,
              submissionCommitment: stored.row.submissionCommitment,
              state: recoveryState,
            }));
          } catch { /* observation remains pending and retries safely */ }
        }
        return { state: "pending" };
      }
      const executionStatus = String(receipt.execution_status ?? receipt.executionStatus ?? "").toUpperCase();
      if (executionStatus === "REVERTED") {
        await failDirectPrivacySubmission(transactionHash, "reverted", runtime.now());
        return { state: "reverted", errorCode: "DIRECT_TRANSACTION_REVERTED" };
      }
      const finality = String(receipt.finality_status ?? receipt.finalityStatus ?? "").toUpperCase();
      const blockNumber = Number(receipt.block_number ?? receipt.blockNumber);
      const blockHash = String(receipt.block_hash ?? receipt.blockHash ?? "");
      if (!finality.startsWith("ACCEPTED") || !Number.isSafeInteger(blockNumber) || !HASH_PATTERN.test(blockHash)) {
        return { state: "pending" };
      }
      const canonical = acceptedBlock(await runtime.provider.getBlock(blockNumber));
      if (BigInt(canonical.hash) !== BigInt(blockHash)) {
        await failDirectPrivacySubmission(transactionHash, "reorged", runtime.now());
        return { state: "reorged" };
      }
      const latest = await runtime.provider.getBlockNumber();
      if (latest - blockNumber + 1 < runtime.finalityBlocks) return { state: "pending" };
      await finalizeDirectPrivacySubmission(transactionHash, runtime.now());
      return await reconcileConfirmedDirectSubmission(runtime, stored)
        ? { state: "reconciled" }
        : { state: "pending" };
    },

    async abandon(prepared) {
      const privatePrepared = opaque(prepared);
      await abandonDirectPrivacyPreparation({
        executionId: prepared.executionId,
        preparationCommitment: privatePrepared.preparationCommitment,
        now: runtime.now(),
      });
    },
  };
}

export async function createDirectPrivacyAgentExecutionDriver(): Promise<StructuredAgentExecutionDriver> {
  const rpcUrl = requiredEnvironment("STARKNET_RPC_URL");
  const provingUrl = requiredEnvironment("PAYO_STRK20_PROVING_URL");
  const indexerUrl = requiredEnvironment("PAYO_STRK20_INDEXER_URL");
  const relayerAddress = process.env.PAYO_AGENT_RELAYER_ADDRESS?.trim()
    || requiredEnvironment("PAYO_PROOF_RELAYER_ADDRESS");
  const relayerPrivateKey = process.env.PAYO_AGENT_RELAYER_PRIVATE_KEY?.trim()
    || requiredEnvironment("PAYO_PROOF_RELAYER_PRIVATE_KEY");
  const agentProverUrl = requiredEnvironment("PAYO_AGENT_PROVER_URL");
  const workerSecret = requiredEnvironment("PAYO_WORKER_SECRET");
  const provider = new RpcProvider({ nodeUrl: rpcUrl });
  const relayer = new Account({
    provider,
    address: relayerAddress,
    signer: relayerPrivateKey,
    cairoVersion: "1",
  });
  return createDriver({
    rpcUrl,
    provingUrl,
    indexerUrl,
    provider,
    relayer,
    sdk: await loadPinnedPrivacySdk(),
    maxIndexerLagSeconds: boundedInteger(
      "PAYO_STRK20_INDEXER_MAX_LAG_SECONDS",
      DEFAULT_INDEXER_MAX_LAG_SECONDS,
      1,
      600,
    ),
    finalityBlocks: boundedInteger("PAYO_AGENT_FINALITY_BLOCKS", DEFAULT_FINALITY_BLOCKS, 1, 64),
    now: () => new Date(),
    proofClient: new AgentProofClient(agentProverUrl, workerSecret),
    policyOwnerSigner: PolicyOwnerSignerClient.fromEnvironment(),
    withRelayerLock: withStarknetRelayerSubmissionLock,
  });
}
