import { createHmac, timingSafeEqual } from "node:crypto";

/** How old a signed event may be, as Stripe's own libraries default it. */
export const STRIPE_SIGNATURE_TOLERANCE_SECONDS = 300;

export class StripeSignatureError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "StripeSignatureError";
  }
}

/**
 * Verifies a `Stripe-Signature` header over the raw request body, as Stripe signs webhooks:
 * HMAC-SHA256 of `<t>.<body>` under the endpoint's signing secret, hex in one or more `v1`
 * entries. Any configured secret may match any `v1`, so a secret can be rolled without a gap.
 * The timestamp must be within the tolerance either way, so a captured event cannot be replayed
 * later. Comparison is constant-time. The body is never parsed before this passes.
 */
export function verifyStripeSignature(input: {
  readonly body: Buffer;
  readonly header: string | undefined;
  readonly secrets: readonly string[];
  readonly nowSeconds: number;
  readonly toleranceSeconds?: number;
}): void {
  if (input.secrets.length === 0) throw new StripeSignatureError("STRIPE_SECRET_NOT_CONFIGURED");
  if (input.header === undefined || input.header.length === 0 || input.header.length > 2_048) {
    throw new StripeSignatureError("STRIPE_SIGNATURE_MISSING");
  }
  let timestamp: number | null = null;
  const signatures: Buffer[] = [];
  for (const part of input.header.split(",")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (key === "t" && /^\d{1,12}$/.test(value)) timestamp = Number(value);
    if (key === "v1" && /^[0-9a-f]{64}$/.test(value)) signatures.push(Buffer.from(value, "hex"));
  }
  if (timestamp === null || signatures.length === 0) {
    throw new StripeSignatureError("STRIPE_SIGNATURE_MALFORMED");
  }
  const tolerance = input.toleranceSeconds ?? STRIPE_SIGNATURE_TOLERANCE_SECONDS;
  if (Math.abs(input.nowSeconds - timestamp) > tolerance) {
    throw new StripeSignatureError("STRIPE_SIGNATURE_STALE");
  }
  const signed = Buffer.concat([Buffer.from(`${String(timestamp)}.`, "utf8"), input.body]);
  for (const secret of input.secrets) {
    const expected = createHmac("sha256", secret).update(signed).digest();
    for (const candidate of signatures) {
      if (timingSafeEqual(expected, candidate)) return;
    }
  }
  throw new StripeSignatureError("STRIPE_SIGNATURE_INVALID");
}

/** A `Stripe-Signature` header for a body, as Stripe would send it. For tests and the simulator. */
export function stripeSignatureHeader(body: Buffer, secret: string, timestamp: number): string {
  const digest = createHmac("sha256", secret)
    .update(Buffer.concat([Buffer.from(`${String(timestamp)}.`, "utf8"), body]))
    .digest("hex");
  return `t=${String(timestamp)},v1=${digest}`;
}
