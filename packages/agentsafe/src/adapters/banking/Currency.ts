/**
 * The ISO 4217 minor-unit exponent per currency code: how many decimal
 * places the currency has. An amount is only a number once you know this,
 * so a code the table does not carry is refused rather than assumed to have
 * two places. The table holds the currencies with an exponent other than
 * two, and every two-place currency an institution is likely to name; an
 * institution adds its own by extending it, which is a code change and a
 * review, deliberately.
 */
const EXPONENTS: ReadonlyMap<string, number> = new Map([
  // No minor unit.
  ["BIF", 0],
  ["CLP", 0],
  ["DJF", 0],
  ["GNF", 0],
  ["ISK", 0],
  ["JPY", 0],
  ["KMF", 0],
  ["KRW", 0],
  ["PYG", 0],
  ["RWF", 0],
  ["UGX", 0],
  ["UYI", 0],
  ["VND", 0],
  ["VUV", 0],
  ["XAF", 0],
  ["XOF", 0],
  ["XPF", 0],
  // Three places.
  ["BHD", 3],
  ["IQD", 3],
  ["JOD", 3],
  ["KWD", 3],
  ["LYD", 3],
  ["OMR", 3],
  ["TND", 3],
  // Four places.
  ["CLF", 4],
  ["UYW", 4],
  // Two places.
  ["AED", 2],
  ["AUD", 2],
  ["BRL", 2],
  ["CAD", 2],
  ["CHF", 2],
  ["CNY", 2],
  ["CZK", 2],
  ["DKK", 2],
  ["EUR", 2],
  ["GBP", 2],
  ["HKD", 2],
  ["HUF", 2],
  ["ILS", 2],
  ["INR", 2],
  ["MXN", 2],
  ["NOK", 2],
  ["NZD", 2],
  ["PLN", 2],
  ["QAR", 2],
  ["RON", 2],
  ["SAR", 2],
  ["SEK", 2],
  ["SGD", 2],
  ["THB", 2],
  ["TRY", 2],
  ["USD", 2],
  ["ZAR", 2],
]);

export class CurrencyError extends Error {
  public constructor(public readonly code: "CURRENCY_UNSUPPORTED") {
    super(code);
    this.name = "CurrencyError";
  }
}

/** The currency's minor-unit exponent; a code the table does not carry is refused. */
export function minorUnitExponent(currency: string): number {
  const exponent = EXPONENTS.get(currency);
  if (exponent === undefined) throw new CurrencyError("CURRENCY_UNSUPPORTED");
  return exponent;
}

export function isSupportedCurrency(currency: string): boolean {
  return EXPONENTS.has(currency);
}

/** Every currency this build knows, for a status route and for the tests. */
export function supportedCurrencies(): readonly string[] {
  return [...EXPONENTS.keys()].sort();
}
