import { minorUnitExponent } from "./Currency.js";

export class MoneyError extends Error {
  public constructor(
    public readonly code:
      | "AMOUNT_NOT_A_DECIMAL_STRING"
      | "AMOUNT_SCALE_INVALID"
      | "AMOUNT_TOO_LARGE"
      | "CURRENCY_MISMATCH",
  ) {
    super(code);
    this.name = "MoneyError";
  }
}

const DECIMAL = /^(0|[1-9]\d{0,27})(?:\.(\d{1,18}))?$/;
const MAX_MINOR = 10n ** 30n;

/**
 * An amount of one currency, held as an integer of minor units. On the wire
 * BEAP writes a decimal string, because a JSON number cannot carry a bank's
 * amounts without a reader somewhere turning them into a float; in this
 * process the same amount is a `bigint`, because arithmetic on money must
 * not round. The two forms convert through the currency's own ISO 4217
 * exponent, and a decimal whose scale is not the currency's is refused
 * rather than padded: `"250000.0"` is not how CHF writes an amount, and an
 * implementation that quietly accepted it would hash a different string
 * than the one the authority signed.
 */
export class Money {
  private constructor(
    public readonly currency: string,
    public readonly minor: bigint,
  ) {}

  /** The wire form: a decimal string with exactly the currency's scale. */
  public static fromDecimal(amount: string, currency: string): Money {
    const exponent = minorUnitExponent(currency);
    const match = DECIMAL.exec(amount);
    if (match === null) throw new MoneyError("AMOUNT_NOT_A_DECIMAL_STRING");
    const whole = match[1] as string;
    const fraction = match[2] ?? "";
    if (fraction.length !== exponent) throw new MoneyError("AMOUNT_SCALE_INVALID");
    // `BigInt("")` is zero, which is exactly what a currency with no minor
    // unit has for a fraction, so the empty case needs no branch of its own.
    const minor = BigInt(whole) * 10n ** BigInt(exponent) + BigInt(fraction);
    if (minor >= MAX_MINOR) throw new MoneyError("AMOUNT_TOO_LARGE");
    return new Money(currency, minor);
  }

  public static fromMinor(minor: bigint, currency: string): Money {
    minorUnitExponent(currency);
    if (minor < 0n || minor >= MAX_MINOR) throw new MoneyError("AMOUNT_TOO_LARGE");
    return new Money(currency, minor);
  }

  /** The wire form again, with exactly the currency's scale, for a digest to match. */
  public toDecimal(): string {
    const exponent = minorUnitExponent(this.currency);
    if (exponent === 0) return this.minor.toString();
    const digits = this.minor.toString().padStart(exponent + 1, "0");
    return `${digits.slice(0, -exponent)}.${digits.slice(-exponent)}`;
  }

  public equals(other: Money): boolean {
    return this.currency === other.currency && this.minor === other.minor;
  }

  /** Addition within one currency only; mixing two is a refusal, never a conversion. */
  public add(other: Money): Money {
    if (other.currency !== this.currency) throw new MoneyError("CURRENCY_MISMATCH");
    return Money.fromMinor(this.minor + other.minor, this.currency);
  }

  /** The total of a non-empty list, all of one currency. */
  public static sum(amounts: readonly Money[]): Money {
    const first = amounts[0];
    if (first === undefined) throw new MoneyError("CURRENCY_MISMATCH");
    return amounts.slice(1).reduce((total, amount) => total.add(amount), first);
  }

  public toString(): string {
    return `${this.toDecimal()} ${this.currency}`;
  }
}
