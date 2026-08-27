type ActivityAgreementLabelInput = {
  classification: string;
  payeeName?: string;
};

type ActivityRunLabelInput = {
  state: string;
};

function titleCase(value: string): string {
  return value
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function activityAgreementOptionLabel(
  input: ActivityAgreementLabelInput,
  index: number,
): string {
  const payeeName = input.payeeName?.trim();
  return `Agreement ${index + 1} · ${payeeName || titleCase(input.classification)}`;
}

export function activityRunOptionLabel(input: ActivityRunLabelInput, index: number): string {
  return `Payday ${index + 1} · ${titleCase(input.state)}`;
}
