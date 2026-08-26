import { describe, expect, it } from "vitest";
import {
  buildClassificationAssessment,
  classificationAssessmentSchema,
  classificationFactsCommitment,
  referenceClassificationAnswers,
} from "./classification";

const commitment = (byte: string) => `0x${byte.repeat(64)}` as `0x${string}`;

describe("classification fact rubric", () => {
  it("derives and commits a versioned employee-consistent score", () => {
    const assessment = buildClassificationAssessment({
      answers: referenceClassificationAnswers("employee"),
      treatment: "employee",
      principalKind: "human",
      reviewedAt: "2026-08-26T00:00:00.000Z",
      assessorCommitment: commitment("a"),
      salt: commitment("b"),
    });
    expect(assessment.score).toBe(4);
    expect(classificationFactsCommitment({ agreementId: "agreement-1", assessment })).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("rejects treatment, score, and principal-kind inconsistencies", () => {
    expect(() => buildClassificationAssessment({
      answers: referenceClassificationAnswers("contractor"),
      treatment: "employee",
      principalKind: "human",
      reviewedAt: "2026-08-26T00:00:00.000Z",
      assessorCommitment: commitment("a"),
      salt: commitment("b"),
    })).toThrow(/inconsistent/i);
    expect(() => buildClassificationAssessment({
      answers: referenceClassificationAnswers("contractor"),
      treatment: "agent_service",
      principalKind: "human",
      reviewedAt: "2026-08-26T00:00:00.000Z",
      assessorCommitment: commitment("a"),
      salt: commitment("b"),
    })).toThrow(/principal kind/i);
    const valid = buildClassificationAssessment({
      answers: referenceClassificationAnswers("contractor"),
      treatment: "contractor",
      principalKind: "human",
      reviewedAt: "2026-08-26T00:00:00.000Z",
      assessorCommitment: commitment("a"),
      salt: commitment("b"),
    });
    expect(() => classificationAssessmentSchema.parse({ ...valid, score: 6 })).toThrow(/score/i);
  });
});
