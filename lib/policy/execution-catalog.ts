import type { EmploymentAgreement } from "@/lib/domain/obligations";
import { evaluatePolicyPack, type PolicyPack } from "./engine";
import {
  US_2026_SUPPLEMENTAL_FLAT,
} from "./reference-packs";
import { PAYO_NET_INVOICE_POLICY } from "@/lib/proof/input-builder";

export const PAYO_EXECUTION_POLICIES: readonly PolicyPack[] = Object.freeze([
  PAYO_NET_INVOICE_POLICY,
  // This is the only employee pack whose percentage calculation is invariant
  // under the USDC atomic scale. The UK pence-threshold pack remains a tested
  // reference example until the circuit consumes reference-currency gross.
  US_2026_SUPPLEMENTAL_FLAT.pack,
]);

export function resolveExecutionPolicy(input: {
  policyId: string;
  policyVersion: number;
  jurisdictionCode: string;
  classification: EmploymentAgreement["classification"];
  settlementToken: EmploymentAgreement["settlementToken"];
  at: Date;
}): PolicyPack {
  const policy = PAYO_EXECUTION_POLICIES.find(({ id, revision }) =>
    id === input.policyId && revision === input.policyVersion);
  if (!policy) throw new Error(`Policy ${input.policyId} v${input.policyVersion} is not installed.`);
  if (!policy.appliesTo.includes(input.classification)) {
    throw new Error(`Policy ${policy.id} does not apply to ${input.classification} agreements.`);
  }
  if (input.classification === "employee" && input.settlementToken !== "USDC") {
    throw new Error(`Policy ${policy.id} requires USDC settlement in this reference implementation.`);
  }
  if (policy.id !== PAYO_NET_INVOICE_POLICY.id) {
    const jurisdiction = input.jurisdictionCode.split("-")[0];
    if (jurisdiction !== policy.jurisdictionCode) {
      throw new Error(`Policy ${policy.id} does not apply in ${input.jurisdictionCode}.`);
    }
  }
  const effectiveDate = input.at.toISOString().slice(0, 10);
  if (effectiveDate < policy.effectiveFrom || effectiveDate > policy.effectiveUntil) {
    throw new Error(`Policy ${policy.id} is not effective on ${effectiveDate}.`);
  }
  return policy;
}

export function resolveExecutionPolicyForAgreement(
  agreement: EmploymentAgreement,
  at: Date,
): PolicyPack {
  return resolveExecutionPolicy({
    policyId: agreement.statutoryPolicy.policyId,
    policyVersion: agreement.statutoryPolicy.policyVersion,
    jurisdictionCode: agreement.jurisdictionCode,
    classification: agreement.classification,
    settlementToken: agreement.settlementToken,
    at,
  });
}

export function resolvePayrollPolicyCohort(
  agreements: readonly EmploymentAgreement[],
  at: Date,
): readonly [PolicyPack] {
  const policies = agreements.map((agreement) => resolveExecutionPolicyForAgreement(agreement, at));
  const unique = new Map(policies.map((policy) => [`${policy.id}:${policy.revision}`, policy]));
  if (unique.size !== 1) {
    throw new Error("Agreements with different statutory policy catalogs must run as separate private payroll cohorts.");
  }
  return [[...unique.values()][0]];
}

export function calculatePolicyDeductions(
  policy: PolicyPack,
  earningsAtomic: readonly string[],
): string[] {
  const gross = earningsAtomic.reduce((total, amount) => total + BigInt(amount), 0n);
  const inputs: Record<string, string> = { gross: gross.toString(), taxable_gross: gross.toString() };
  earningsAtomic.forEach((earning, index) => { inputs[`earning_${index}`] = earning; });
  const evaluated = evaluatePolicyPack(policy, inputs);
  const output = evaluated.statutoryWithholding
    ?? evaluated.statutoryDeduction
    ?? Object.values(evaluated)[0];
  if (output === undefined) throw new Error(`Policy ${policy.id} has no statutory output.`);
  return BigInt(output) === 0n ? [] : [output];
}

export const PAYO_EMPLOYEE_POLICY_OPTIONS = Object.freeze({
  US: US_2026_SUPPLEMENTAL_FLAT.pack,
});
