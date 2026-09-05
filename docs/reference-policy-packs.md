# PAYO v1 reference policy packs

These packs are narrowly scoped, versioned calculation examples. `legalReviewRequired` is always `true`: their inclusion proves which public rule program was used, not that the rule is legally sufficient for a worker or employer.

## United States: separately identified supplemental wages

- Pack: `us-irs-supplemental-flat-2026-v1`, revision 1
- Effective window: 2026-01-01 through 2026-12-31
- Program commitment: `0x325087e383de44739727f5614ebeb57356b9208d54ca87c7cc41ffdfd61c917e`
- Source: [IRS Publication 15 (2026), section 7](https://www.irs.gov/pub/irs-prior/p15--2026.pdf), retrieved 2026-08-24
- Implemented scope: the optional 22% federal withholding method for separately identified supplemental wages at or below the annual USD 1,000,000 boundary, when its IRS prerequisites are met
- Excluded: ordinary Form W-4 withholding, the mandatory 37% case, FICA, state/local rules, territories, and nonresident-alien adjustments

## United Kingdom: monthly employee Class 1 NI, category A

- Pack: `uk-hmrc-ni-a-monthly-2026-27-v1`, revision 1
- Effective window: 2026-04-06 through 2027-04-05
- Program commitment: `0x213b26fd90e85e4c6d75edf40b5c0cb641cdd4a4a03459d129b345c01328dc14`
- Source: [HMRC rates and thresholds for employers 2026 to 2027](https://www.gov.uk/guidance/rates-and-thresholds-for-employers-2026-to-2027), published 2026-01-30 and last updated 2026-06-05 when reviewed on 2026-08-24
- Implemented scope: monthly category-A employee National Insurance in GBP pence, with the £1,048 primary threshold, £4,189 upper earnings limit, 8% main rate, and 2% additional rate
- Excluded: PAYE income tax, other NI categories or periods, directors, employer contributions, benefits, statutory pay, loans, and later corrections

## Canada: small non-Quebec irregular payment

- Pack: `ca-cra-small-irregular-payment-2026-v1`, revision 1
- Effective window: 2026-01-01 through 2026-12-31
- Program commitment: `0xf8b8f3600c334d7cc22491ef61549096d83d81ef60a502dbe5a74bc67f71abd9`
- Source: [CRA Employers' Guide — Payroll Deductions and Remittances](https://www.canada.ca/en/revenue-agency/services/forms-publications/publications/t4001/employers-guide-payroll-deductions-remittances.html), reviewed 2026-09-05
- Implemented scope: 15% federal income-tax withholding for a bonus or retroactive pay increase outside Quebec when separately reviewed total annual remuneration, including the payment, is CAD 5,000 or less
- Excluded: Quebec, remuneration above CAD 5,000, regular pay, CPP/QPP, EI, provincial deductions, benefits, pension, union-dues and TD1 adjustments

`lib/policy/reference-packs.test.ts` checks all three results, source/review metadata, program bounds, and commitments. `compilePolicyPack` deterministically lowers `BRACKET` into the same 16-step primitive VM enforced by Noir.

## Familiar evidence views

`lib/disclosure/tax-evidence.ts` first creates one canonical verified-income record
from a report that has reproduced the independently observed annual payroll-book
accumulator. It then maps supported **employee** lines to W-2-, P60- or T4-style
readable evidence. The view carries the exact policy ID, revision, commitment and
catalog root; it does not replace or reinterpret the proved calculation.

These downloads are token-denominated cryptographic evidence, not official forms,
government filings, legal certification or tax advice. US and Canadian examples use
familiar numbered fields only where the narrow bound policy supplies the corresponding
income/withholding fact. The UK example labels its deduction as a bound deduction
because the implemented pack proves National Insurance, not PAYE income tax.
