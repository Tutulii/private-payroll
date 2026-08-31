import { describe, expect, it } from "vitest";
import { buildFxSnapshot } from "@/lib/domain/fx";
import { PAYROLL_TOKENS } from "@/lib/starknet/tokens";
import {
  buildPayrollIntegrityInputs,
  PAYO_NET_INVOICE_POLICY,
  type PayrollIntegrityLineInput,
} from "./input-builder";
import {
  PAYO_SETTLEMENT_TREE_DEPTH,
  buildSettlementMatchInputs,
  buildSettlementMembership,
  buildSettlementRoot,
  deriveStrk20EncryptedNote,
  deriveStrk20NoteId,
  deriveStrk20PackedValue,
  hashSettlementNode,
  hashSettlementNoteLeaf,
  settlementTransactionReference,
  type SettlementPayrollNote,
} from "./settlement-match";

type Hex = ReturnType<typeof deriveStrk20EncryptedNote>["noteId"];

function snapshot(token: "STRK" | "USDC", priceAtomic: string) {
  return buildFxSnapshot({
    baseToken: token,
    referenceCurrency: "USD",
    quoteDecimals: 6,
    haircutBps: 0,
    maximumAgeSeconds: 30,
    minimumSources: 3,
    feedId: "pragma:" + token + "/USD:median",
    quotes: ["a", "b", "c"].map((source, index) => ({
      source: "pragma-" + token.toLowerCase() + "-" + source,
      priceAtomic,
      observedAt: "1970-01-01T00:16:" + (40 + index) + ".000Z",
    })),
    now: new Date(1_010_000),
  });
}

function line(input: {
  agreementId: string;
  recipientAddress: string;
  token: "STRK" | "USDC";
  amount: string;
  saltByte: string;
}): PayrollIntegrityLineInput {
  return {
    agreementId: input.agreementId,
    recipientAddress: input.recipientAddress,
    recipientSalt: ("0x" + input.saltByte.repeat(32)) as Hex,
    agreementSalt: ("0x" + "22".repeat(32)) as Hex,
    lineSalt: ("0x" + "33".repeat(32)) as Hex,
    token: input.token,
    earningsAtomic: [input.amount],
    deductionsAtomic: [],
    policyId: PAYO_NET_INVOICE_POLICY.id,
    scheduleCommitment: ("0x" + "44".repeat(32)) as Hex,
    dueAt: 1_000n,
    validUntil: 2_000n,
    classification: { declared: 2, score: 2, employeeThreshold: 5 },
    fxFloorAtomic: "0",
    referenceCurrency: "USD",
  };
}

async function fixture() {
  const payroll = await buildPayrollIntegrityInputs({
    chainId: "0x1",
    sealAddress: "0x12345",
    organizationSecret: "0x" + "55".repeat(32),
    cycleId: "settlement-match-fixture",
    revision: 1,
    validityStart: 1_010n,
    validityExpiry: 2_000n,
    policies: [PAYO_NET_INVOICE_POLICY],
    fxSnapshots: [snapshot("STRK", "150000"), snapshot("USDC", "1000000")],
    lines: [
      line({
        agreementId: "invoice-b-strk",
        recipientAddress: "0x222",
        token: "STRK",
        amount: "1000000000000000000",
        saltByte: "66",
      }),
      line({
        agreementId: "invoice-a-usdc",
        recipientAddress: "0x111",
        token: "USDC",
        amount: "1000000",
        saltByte: "77",
      }),
    ],
  });
  const senderAddress = "0x123";
  const viewingKey = "0x456";
  const payrollNotes: SettlementPayrollNote[] = payroll.proofBindings.map(
    (binding, position) => {
      const tokenAddress = PAYROLL_TOKENS[binding.source.token].address as Hex;
      const recipientAddress = binding.source.recipientAddress as Hex;
      const recipientPublicKey = ("0x" + (0x800 + position).toString(16)) as Hex;
      const noteIndex = 5 + position;
      const salt = (0x5678n + BigInt(position)).toString();
      const encrypted = deriveStrk20EncryptedNote({
        senderAddress,
        viewingKey,
        recipientAddress,
        recipientPublicKey,
        tokenAddress,
        noteIndex,
        salt,
        amountAtomic: binding.calculated.netAtomic,
      });
      return {
        position,
        recipientAddress,
        recipientPublicKey,
        tokenAddress,
        amountAtomic: binding.calculated.netAtomic,
        noteIndex,
        salt,
        noteId: encrypted.noteId,
        packedValue: encrypted.packedValue,
      };
    },
  );
  const emittedNotes = [
    ...payrollNotes.map(({ noteId, packedValue }) => ({ noteId, packedValue })),
    {
      noteId: ("0x" + "ab".repeat(32)) as Hex,
      packedValue: ("0x" + "00".repeat(31) + "01") as Hex,
    },
  ];
  const transactionReference = settlementTransactionReference({
    chainId: "0x1",
    policyAccountAddress: senderAddress,
    poolAddress: "0x987",
    poolCalldata: ["0x1", "0x2", "0x3"],
  });
  return {
    payroll,
    senderAddress,
    viewingKey,
    payrollNotes,
    emittedNotes,
    transactionReference,
  };
}

describe("SettlementMatch v8 commitments and witness builder", () => {
  it("matches the official STRK20 Poseidon vectors used by Cairo and Noir", () => {
    const noteId = deriveStrk20NoteId({
      channelKey: 0xdefn,
      tokenAddress: 0x1234n,
      noteIndex: 5,
    });
    expect("0x" + noteId.toString(16).padStart(64, "0")).toBe(
      "0x06b098ad0b0b4b1881a77f962eb0650de748f24efcabd5a64ac941e9a05777e8",
    );
    const packed = deriveStrk20PackedValue({
      channelKey: 0xdefn,
      tokenAddress: 0x1234n,
      noteIndex: 5,
      salt: 0x5678n,
      amountAtomic: 1n,
    });
    expect("0x" + packed.toString(16).padStart(64, "0")).toBe(
      "0x00000000000000000000000000005678e860f260ec796ecdd862d35616ea6b41",
    );
  });

  it("binds note position, every Merkle path, and exact transaction calldata order", () => {
    const notes = [
      {
        noteId: ("0x" + "11".repeat(32)) as Hex,
        packedValue: ("0x" + "22".repeat(32)) as Hex,
      },
      {
        noteId: ("0x" + "33".repeat(32)) as Hex,
        packedValue: ("0x" + "44".repeat(32)) as Hex,
      },
    ];
    const root = buildSettlementRoot(notes);
    for (let position = 0; position < notes.length; position += 1) {
      const membership = buildSettlementMembership(notes, position);
      let current = hashSettlementNoteLeaf(position, notes[position]);
      for (let level = 0; level < PAYO_SETTLEMENT_TREE_DEPTH; level += 1) {
        current = membership.pathBits[level]
          ? hashSettlementNode(membership.siblings[level], current)
          : hashSettlementNode(current, membership.siblings[level]);
      }
      expect(current).toBe(root);
    }
    expect(buildSettlementRoot([...notes].reverse())).not.toBe(root);

    const reference = settlementTransactionReference({
      chainId: "0x1",
      policyAccountAddress: "0x2",
      poolAddress: "0x3",
      poolCalldata: ["0x4", "0x5"],
    });
    expect(settlementTransactionReference({
      chainId: "0x1",
      policyAccountAddress: "0x2",
      poolAddress: "0x3",
      poolCalldata: ["0x5", "0x4"],
    })).not.toBe(reference);
  });

  it("builds complete mixed-token chunks and rejects substitution or reordering", async () => {
    const input = await fixture();
    const built = buildSettlementMatchInputs(input);
    expect(built.circuitInputs).toHaveLength(1);
    expect(built.publicInputs[0]).toMatchObject({
      proofVersion: "8",
      chunkIndex: "0",
      chunkCount: "1",
    });
    expect(built.settlementRoot).toBe(buildSettlementRoot(input.emittedNotes));
    expect(built.transactionReference).toBe(input.transactionReference);

    expect(() => buildSettlementMatchInputs({
      ...input,
      payrollNotes: input.payrollNotes.map((note, index) =>
        index === 0 ? { ...note, amountAtomic: (BigInt(note.amountAtomic) + 1n).toString() } : note),
    })).toThrow("amount does not match");

    expect(() => buildSettlementMatchInputs({
      ...input,
      payrollNotes: [...input.payrollNotes].reverse(),
    })).toThrow("reordered");

    expect(() => buildSettlementMatchInputs({
      ...input,
      emittedNotes: [...input.emittedNotes.slice(0, 2).reverse(), input.emittedNotes[2]],
    })).toThrow("output order");

    expect(() => buildSettlementMatchInputs({
      ...input,
      payrollNotes: input.payrollNotes.map((note, index) =>
        index === 0
          ? { ...note, packedValue: ("0x" + "ff".repeat(32)) as Hex }
          : note),
    })).toThrow("ciphertext");
  });
});
