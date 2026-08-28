import type { VaultPrincipal } from "@/lib/crypto/vault";

export const DEFAULT_DISCLOSURE_LIFETIME_MS = 24 * 60 * 60 * 1_000;

function localDateTimeInputValue(value: Date): string {
  return new Date(value.getTime() - value.getTimezoneOffset() * 60_000)
    .toISOString()
    .slice(0, 16);
}

export function disclosureFormDefaults(
  principal: VaultPrincipal,
  now = new Date(),
): {
  principalId: string;
  publicKey: string;
  expiresAtInput: string;
} {
  return {
    principalId: principal.principalId,
    publicKey: principal.publicKey,
    expiresAtInput: localDateTimeInputValue(
      new Date(now.getTime() + DEFAULT_DISCLOSURE_LIFETIME_MS),
    ),
  };
}

export function resolveDisclosureSelection<T extends { id: string }>(
  settlements: readonly T[],
  selectedId: string,
): T | undefined {
  return settlements.find(({ id }) => id === selectedId) ?? settlements[0];
}
