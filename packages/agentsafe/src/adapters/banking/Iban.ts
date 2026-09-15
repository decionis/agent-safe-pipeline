const IBAN = /^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/;
const IBAN_REF = /^iban:([A-Z0-9]+)$/;

/**
 * ISO 13616 check-digit validation, for the one case where a reference is
 * transparent enough to check: a `iban:` prefixed reference. BEAP
 * recommends opaque references precisely so that a beneficiary is not
 * readable from an intent, and an executor that only ever sees a digest
 * cannot validate a beneficiary at all. Where an institution does put an
 * IBAN on the wire, a typo that would have sent money to a valid-looking
 * account is worth catching before the authority is asked.
 */
export function isValidIban(value: string): boolean {
  const iban = value.replace(/\s/g, "").toUpperCase();
  if (!IBAN.test(iban)) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const character of rearranged) {
    const digits =
      character >= "A" && character <= "Z" ? String(character.charCodeAt(0) - 55) : character;
    for (const digit of digits) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}

/** The IBAN a reference carries, or null when the reference is not one. */
export function ibanFromReference(reference: string): string | null {
  const match = IBAN_REF.exec(reference.trim());
  return match === null ? null : (match[1] as string);
}

/**
 * Whether a reference is acceptable: an opaque reference always is, and an
 * `iban:` reference only when its check digits hold.
 */
export function referenceIsValid(reference: string): boolean {
  const iban = ibanFromReference(reference);
  return iban === null || isValidIban(iban);
}
