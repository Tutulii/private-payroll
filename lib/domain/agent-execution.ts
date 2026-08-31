import { z } from "zod";
import { hashCanonicalJson } from "@/lib/crypto/digest";
import {
  agentExecutionRequestSchema,
  type AgentExecutionRequest,
} from "./capability";

export const agentExecutionStates = [
  "reserved",
  "approval_pending",
  "submitting",
  "preparing",
  "submitted",
  "confirmed",
  "reconciled",
  "failed",
  "released",
] as const;
export const agentExecutionStateSchema = z.enum(agentExecutionStates);
export type AgentExecutionState = z.infer<typeof agentExecutionStateSchema>;

export const agentExecutionReceiptSchema = z.object({
  executionId: z.string().min(8).max(128),
  capabilityId: z.string().min(8).max(128),
  runId: z.string().min(8).max(128),
  settlementId: z.string().min(8).max(128).nullable(),
  state: agentExecutionStateSchema,
  requiresApproval: z.boolean(),
  requestCommitment: z.string().regex(/^0x[0-9a-f]{64}$/),
  transactionHash: z.string().regex(/^0x[0-9a-fA-F]{1,64}$/).nullable(),
  errorCode: z.string().min(1).max(80).nullable(),
  replayed: z.boolean(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
}).strict();
export type AgentExecutionReceipt = z.infer<typeof agentExecutionReceiptSchema>;

export function commitAgentExecutionRequest(requestInput: AgentExecutionRequest): `0x${string}` {
  const request = agentExecutionRequestSchema.parse(requestInput);
  return hashCanonicalJson({
    domain: "PAYO_AGENT_EXECUTION_REQUEST_V1",
    request,
  });
}

export const AGENT_EXECUTION_TRANSITIONS: Readonly<Record<AgentExecutionState, readonly AgentExecutionState[]>> = {
  reserved: ["approval_pending", "preparing", "failed", "released"],
  approval_pending: ["preparing", "submitted", "failed", "released"],
  preparing: ["submitting", "failed", "released"],
  submitted: ["confirmed", "reconciled", "failed"],
  submitting: ["submitted", "failed"],
  confirmed: [],
  reconciled: [],
  failed: [],
  released: [],
};

export function assertAgentExecutionTransition(from: AgentExecutionState, to: AgentExecutionState): void {
  if (!AGENT_EXECUTION_TRANSITIONS[from].includes(to)) {
    throw new Error(`Invalid agent execution transition: ${from} -> ${to}.`);
  }
}
