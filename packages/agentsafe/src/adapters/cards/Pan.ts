/**
 * The value a doubled digit contributes to a Luhn sum, by digit: 2 × d, with
 * the two digits of a two-digit product added together.
 */
const DOUBLED = "0246813579";

/** A run of digits a card number could be: 13 to 19 of them, passing Luhn. */
function panShaped(digits: string): boolean {
  if (digits.length < 13 || digits.length > 19) return false;
  const sum = [...digits].reverse().reduce(
    (total, digit, index) =>
      // Stryker disable next-line ArithmeticOperator: divisibility by ten does not depend on the sum's sign.
      total + Number(index % 2 === 0 ? digit : DOUBLED[Number(digit)]),
    0,
  );
  return sum % 10 === 0;
}

/**
 * Whether a value carries something shaped like a primary account number:
 * 13 to 19 digits that pass the Luhn check, written together or grouped by
 * spaces, hyphens or other punctuation (`4111 1111 1111 1111`,
 * `4111-1111-1111-1111`). A letter ends a run, so `tok_4111111111111111`
 * is still caught by the digits after the prefix.
 *
 * A card reference crosses this boundary into a hashed intent, a Decision
 * Dossier and an evidence line, and none of those may ever hold a card
 * number; so a value that merely looks like one is refused, and a reference
 * that is refused by mistake costs a caller a different reference, which is
 * the right side to err on. Both the contiguous run and the run joined
 * across punctuation are checked, so a number cannot hide behind a trailing
 * group of other digits written after a separator.
 */
export function containsPan(value: string): boolean {
  let contiguous = "";
  let joined = "";
  // The trailing letter ends the last run, so it is checked like every other.
  for (const character of `${value}x`) {
    if (character >= "0" && character <= "9") {
      contiguous += character;
      joined += character;
      continue;
    }
    if (panShaped(contiguous)) return true;
    contiguous = "";
    // A letter is a character with case; punctuation and spaces have none.
    if (character.toLowerCase() !== character.toUpperCase()) {
      if (panShaped(joined)) return true;
      joined = "";
    }
  }
  return false;
}
