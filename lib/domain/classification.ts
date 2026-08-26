import { z } from "zod";
import { hashCanonicalJson } from "@/lib/crypto/digest";

const commitmentSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);

export const CLASSIFICATION_RUBRIC_VERSION = "payo-classification-facts-v1" as const;
export const CLASSIFICATION_EMPLOYEE_THRESHOLD = 4 as const;

export const CLASSIFICATION_FACTS = [
  { key: "companyControlsSchedule", label: "The company controls when the work is performed" },
  { key: "companyControlsMethod", label: "The company controls how the work is performed" },
  { key: "companyProvidesPrimaryTools", label: "The company provides the primary tools or systems" },
  { key: "relationshipIsOngoing", label: "The relationship is expected to continue rather than end with one deliverable" },
  { key: "workerIsEconomicallyDependent", label: "The worker is economically dependent on this engagement" },
  { key: "workIsCoreToBusiness", label: "The work is central to the company’s ordinary business" },
] as const;

export const classificationFactsAnswersSchema = z.object({
  companyControlsSchedule: z.boolean(),
  companyControlsMethod: z.boolean(),
  companyProvidesPrimaryTools: z.boolean(),
  relationshipIsOngoing: z.boolean(),
  workerIsEconomicallyDependent: z.boolean(),
  workIsCoreToBusiness: z.boolean(),
}).strict();
export type ClassificationFactsAnswers = z.infer<typeof classificationFactsAnswersSchema>;

export const classificationAssessmentSchema = z.object({
  assessmentVersion: z.literal("payo-classification-assessment-v1"),
  rubricVersion: z.literal(CLASSIFICATION_RUBRIC_VERSION),
  answers: classificationFactsAnswersSchema,
  score: z.number().int().min(0).max(CLASSIFICATION_FACTS.length),
  employeeThreshold: z.literal(CLASSIFICATION_EMPLOYEE_THRESHOLD),
  treatment: z.enum(["employee", "contractor", "agent_service"]),
  reviewedAt: z.string().datetime(),
  assessorCommitment: commitmentSchema,
  salt: commitmentSchema,
}).strict().superRefine((assessment, context) => {
  const score = scoreClassificationFacts(assessment.answers);
  if (assessment.score !== score) {
    context.addIssue({ code: "custom", path: ["score"], message: "Classification score does not match the committed facts." });
  }
  const employeeLike = score >= CLASSIFICATION_EMPLOYEE_THRESHOLD;
  if (
    (assessment.treatment === "employee" && !employeeLike)
    || (assessment.treatment !== "employee" && employeeLike)
  ) {
    context.addIssue({ code: "custom", path: ["treatment"], message: "Classification treatment is inconsistent with the reference rubric." });
  }
});
export type ClassificationAssessment = z.infer<typeof classificationAssessmentSchema>;

export function scoreClassificationFacts(input: ClassificationFactsAnswers): number {
  const answers = classificationFactsAnswersSchema.parse(input);
  return CLASSIFICATION_FACTS.reduce((score, { key }) => score + (answers[key] ? 1 : 0), 0);
}

export function buildClassificationAssessment(input: {
  answers: ClassificationFactsAnswers;
  treatment: ClassificationAssessment["treatment"];
  principalKind: "human" | "agent";
  reviewedAt: string;
  assessorCommitment: `0x${string}`;
  salt: `0x${string}`;
}): ClassificationAssessment {
  if (
    (input.principalKind === "agent" && input.treatment !== "agent_service")
    || (input.principalKind === "human" && input.treatment === "agent_service")
  ) throw new Error("Classification treatment does not match the principal kind.");
  return classificationAssessmentSchema.parse({
    assessmentVersion: "payo-classification-assessment-v1",
    rubricVersion: CLASSIFICATION_RUBRIC_VERSION,
    answers: input.answers,
    score: scoreClassificationFacts(input.answers),
    employeeThreshold: CLASSIFICATION_EMPLOYEE_THRESHOLD,
    treatment: input.treatment,
    reviewedAt: input.reviewedAt,
    assessorCommitment: input.assessorCommitment,
    salt: input.salt,
  });
}

export function classificationFactsCommitment(input: {
  agreementId: string;
  assessment: ClassificationAssessment;
}): `0x${string}` {
  const assessment = classificationAssessmentSchema.parse(input.assessment);
  return hashCanonicalJson({
    domain: "PAYO_CLASSIFICATION_FACTS_V1",
    agreementId: input.agreementId,
    assessment,
  });
}

export function referenceClassificationAnswers(
  treatment: ClassificationAssessment["treatment"],
): ClassificationFactsAnswers {
  return treatment === "employee"
    ? {
        companyControlsSchedule: true,
        companyControlsMethod: true,
        companyProvidesPrimaryTools: true,
        relationshipIsOngoing: true,
        workerIsEconomicallyDependent: false,
        workIsCoreToBusiness: false,
      }
    : {
        companyControlsSchedule: false,
        companyControlsMethod: false,
        companyProvidesPrimaryTools: false,
        relationshipIsOngoing: false,
        workerIsEconomicallyDependent: false,
        workIsCoreToBusiness: false,
      };
}
