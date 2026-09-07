import { validateAndParseAddress } from "starknet";
import { z } from "zod";
import {
  parsePayoPublicIdentity,
  type PayoPublicIdentity,
} from "./proof-package-files";

const directoryRecordSchema = z.object({
  chainId: z.string().min(1).max(80),
  walletAddress: z.string().min(1).max(80),
  principalId: z.string().min(1).max(160),
  fingerprint: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  identity: z.unknown(),
  firstPublishedAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
}).strict();

export type PublicIdentityDirectoryRecord = z.infer<typeof directoryRecordSchema> & {
  identity: PayoPublicIdentity;
};

function sameFelt(left: string, right: string): boolean {
  try {
    return BigInt(left) === BigInt(right);
  } catch {
    return false;
  }
}

function canonicalWallet(value: string, label: string): string {
  try {
    return validateAndParseAddress(value);
  } catch {
    throw new Error(label + " is not a valid Starknet wallet address.");
  }
}

export function verifyWalletBoundPublicIdentity(input: {
  expectedChainId: string;
  expectedWalletAddress: string;
  record: unknown;
}): PublicIdentityDirectoryRecord {
  const recordResult = directoryRecordSchema.safeParse(input.record);
  if (!recordResult.success) {
    throw new Error("The public identity directory returned a malformed record.");
  }
  const record = recordResult.data;
  if (!sameFelt(record.chainId, input.expectedChainId)) {
    throw new Error("The public identity belongs to another Starknet deployment.");
  }

  const expectedWalletAddress = canonicalWallet(
    input.expectedWalletAddress,
    "The requested wallet",
  );
  const recordWalletAddress = canonicalWallet(
    record.walletAddress,
    "The published identity wallet",
  );
  if (recordWalletAddress !== expectedWalletAddress) {
    throw new Error("The public identity is bound to another Ready wallet.");
  }

  const identity = parsePayoPublicIdentity(record.identity);
  if (identity.format !== "payo-public-identity-v2") {
    throw new Error("The wallet must publish a version 2 PAYO identity.");
  }
  if (record.principalId !== identity.principalId) {
    throw new Error("The public identity principal does not match its wallet directory record.");
  }
  if (record.fingerprint.toLowerCase() !== identity.fingerprint.toLowerCase()) {
    throw new Error("The public identity fingerprint does not match its wallet directory record.");
  }

  return {
    ...record,
    walletAddress: recordWalletAddress,
    fingerprint: identity.fingerprint,
    identity,
  };
}
