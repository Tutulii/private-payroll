import type { PolicyPack } from "./engine";

export type ReferencePolicyRelease = {
  pack: PolicyPack;
  authority: string;
  sourceTitle: string;
  sourceRetrievedAt: string;
  scope: string;
  assumptions: readonly string[];
  unsupportedCases: readonly string[];
};

/**
 * Narrow, source-pinned examples for proving a calculation was applied consistently.
 * They are deliberately not a substitute for tax, payroll, or employment-law advice.
 */
export const US_2026_SUPPLEMENTAL_FLAT: ReferencePolicyRelease = {
  authority: "United States Internal Revenue Service",
  sourceTitle: "Publication 15 (2026), section 7 — Supplemental Wages",
  sourceRetrievedAt: "2026-08-24",
  scope: "Optional 22% federal income-tax withholding on separately identified supplemental wages at or below the statutory annual limit.",
  assumptions: [
    "The employer withheld federal income tax from regular wages in the current or immediately preceding calendar year.",
    "The payment is separately identified supplemental wages and year-to-date supplemental wages do not exceed USD 1,000,000.",
    "The atomic input and output use the same USD scale.",
  ],
  unsupportedCases: [
    "Regular wage withholding or Form W-4 calculations",
    "The mandatory 37% rate above the annual supplemental-wage limit",
    "Social Security, Medicare, state, local, territory, or nonresident-alien adjustments",
  ],
  pack: {
    packVersion: "payo-policy-pack-v1",
    id: "us-irs-supplemental-flat-2026-v1",
    revision: 1,
    jurisdictionCode: "US",
    appliesTo: ["employee"],
    effectiveFrom: "2026-01-01",
    effectiveUntil: "2026-12-31",
    sourceUri: "https://www.irs.gov/pub/irs-prior/p15--2026.pdf",
    legalReviewRequired: true,
    instructions: [
      { op: "INPUT", out: "supplemental_gross", key: "gross" },
      {
        op: "MUL_DIV",
        out: "federal_withholding",
        value: "supplemental_gross",
        numerator: "22",
        denominator: "100",
      },
    ],
    outputs: { statutoryWithholding: "federal_withholding" },
  },
};

export const UK_2026_27_MONTHLY_NI_CATEGORY_A: ReferencePolicyRelease = {
  authority: "United Kingdom HM Revenue & Customs",
  sourceTitle: "Rates and thresholds for employers 2026 to 2027",
  sourceRetrievedAt: "2026-08-24",
  scope: "Monthly employee Class 1 National Insurance for category A using GBP pence inputs.",
  assumptions: [
    "The worker is an employee in National Insurance category A and the calculation period is monthly.",
    "GBP pence are used: primary threshold 104,800 and upper earnings limit 418,900.",
    "The atomic output is GBP pence and each bracket uses deterministic integer floor rounding.",
  ],
  unsupportedCases: [
    "PAYE income tax, tax-code adjustments, directors, non-monthly periods, or other NI categories",
    "Employer secondary contributions, benefits, statutory pay, loans, and jurisdiction-specific income-tax bands",
    "Any rule or correction published after this version was reviewed",
  ],
  pack: {
    packVersion: "payo-policy-pack-v1",
    id: "uk-hmrc-ni-a-monthly-2026-27-v1",
    revision: 1,
    jurisdictionCode: "GB",
    appliesTo: ["employee"],
    effectiveFrom: "2026-04-06",
    effectiveUntil: "2027-04-05",
    sourceUri: "https://www.gov.uk/guidance/rates-and-thresholds-for-employers-2026-to-2027",
    legalReviewRequired: true,
    instructions: [
      { op: "INPUT", out: "ni_earnings", key: "gross" },
      {
        op: "BRACKET",
        out: "employee_ni",
        input: "ni_earnings",
        brackets: [
          { upperAtomic: "104800", rateBps: 0 },
          { upperAtomic: "418900", rateBps: 800 },
          { rateBps: 200 },
        ],
      },
    ],
    outputs: { statutoryDeduction: "employee_ni" },
  },
};

export const CA_2026_SMALL_IRREGULAR_PAYMENT: ReferencePolicyRelease = {
  authority: "Canada Revenue Agency",
  sourceTitle: "Employers' Guide — Payroll Deductions and Remittances (2026), bonuses and retroactive pay increases",
  sourceRetrievedAt: "2026-09-05",
  scope: "Federal income-tax withholding at 15% for a non-Quebec bonus or retroactive payment when total annual remuneration including that payment is CAD 5,000 or less.",
  assumptions: [
    "The worker is an employee outside Quebec and the payment is a bonus or retroactive pay increase.",
    "The employer separately established that total remuneration for the year, including this payment, is CAD 5,000 or less.",
    "The atomic input and output use the same CAD scale.",
  ],
  unsupportedCases: [
    "Quebec's separate 10% rule, remuneration above CAD 5,000, regular periodic pay, or later CRA corrections",
    "CPP/QPP contributions, EI premiums, provincial deductions, benefits, pension, union-dues, or TD1 adjustments",
    "Any use without employer review of the eligibility assumptions and current source",
  ],
  pack: {
    packVersion: "payo-policy-pack-v1",
    id: "ca-cra-small-irregular-payment-2026-v1",
    revision: 1,
    jurisdictionCode: "CA",
    appliesTo: ["employee"],
    effectiveFrom: "2026-01-01",
    effectiveUntil: "2026-12-31",
    sourceUri: "https://www.canada.ca/en/revenue-agency/services/forms-publications/publications/t4001/employers-guide-payroll-deductions-remittances.html",
    legalReviewRequired: true,
    instructions: [
      { op: "INPUT", out: "irregular_gross", key: "gross" },
      {
        op: "MUL_DIV",
        out: "federal_withholding",
        value: "irregular_gross",
        numerator: "15",
        denominator: "100",
      },
    ],
    outputs: { statutoryWithholding: "federal_withholding" },
  },
};

export const REFERENCE_POLICY_RELEASES = [
  US_2026_SUPPLEMENTAL_FLAT,
  UK_2026_27_MONTHLY_NI_CATEGORY_A,
  CA_2026_SMALL_IRREGULAR_PAYMENT,
] as const;
