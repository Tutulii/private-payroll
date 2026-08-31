import { z } from "zod";

const feltSchema = z.string().regex(/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})$/);
const digestSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const uintStringSchema = z.string().regex(/^(?:0|[1-9]\d*)$/);

const emittedNoteSchema = z.object({
  noteId: digestSchema,
  packedValue: digestSchema,
}).strict();

export const settlementMatchWitnessSchema = z.object({
  version: z.literal("payo-settlement-match-witness-v1"),
  executionId: z.string().min(8).max(128),
  chainId: feltSchema,
  policyAccountAddress: feltSchema,
  poolAddress: feltSchema,
  poolCalldata: z.array(feltSchema).min(2).max(12_000),
  viewingKey: feltSchema,
  payrollNotes: z.array(z.object({
    position: z.number().int().nonnegative().max(49),
    recipientAddress: feltSchema,
    recipientPublicKey: feltSchema,
    tokenAddress: feltSchema,
    amountAtomic: uintStringSchema,
    noteIndex: z.number().int().nonnegative().max(4_294_967_295),
    salt: uintStringSchema,
    noteId: digestSchema,
    packedValue: digestSchema,
  }).strict()).min(1).max(50),
  emittedNotes: z.array(emittedNoteSchema).min(1).max(64),
}).strict().superRefine((value, context) => {
  if (value.emittedNotes.length < value.payrollNotes.length) {
    context.addIssue({
      code: "custom",
      path: ["emittedNotes"],
      message: "Settlement output must cover every payroll note.",
    });
  }
  value.payrollNotes.forEach((note, index) => {
    if (note.position !== index) {
      context.addIssue({
        code: "custom",
        path: ["payrollNotes", index, "position"],
        message: "Settlement payroll notes must be in manifest order.",
      });
    }
    if (
      note.noteId.toLowerCase() !== value.emittedNotes[index]?.noteId.toLowerCase()
      || note.packedValue.toLowerCase()
        !== value.emittedNotes[index]?.packedValue.toLowerCase()
    ) {
      context.addIssue({
        code: "custom",
        path: ["payrollNotes", index],
        message: "Settlement payroll note is not the corresponding emitted note.",
      });
    }
  });
});

export type SettlementMatchWitness = z.infer<typeof settlementMatchWitnessSchema>;
