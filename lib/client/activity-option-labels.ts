type ActivityAgreementLabelInput = {
  classification: string;
  payeeName?: string;
};

type ActivityRunLabelInput = {
  state: string;
  updatedAt?: string;
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
  if (input.updatedAt) {
    const date = new Date(input.updatedAt);
    if (!Number.isNaN(date.getTime())) {
      const timestamp = new Intl.DateTimeFormat(undefined, {
        month: "short",
        day: "numeric",
        hour: "numeric",
        minute: "2-digit",
      }).format(date);
      return `Payday ${index + 1} · ${timestamp}`;
    }
  }
  return `Payday ${index + 1} · ${titleCase(input.state)}`;
}
