import { createHash, sign, verify, type KeyObject } from "node:crypto";

/**
 * Signed producer signals, as the hosted authority verifies them and as this
 * package's doubles and tests mint them.
 *
 * A producer (a card-presence provider such as `koard`) signs a standing
 * statement about a subject: the cardholder granted this agent permission to
 * buy on their behalf, within these limits, until then (Koard's "Tap to
 * Authenticate"). The agent's proposal carries that compact JWS as evidence;
 * the authority verifies it against the key the organisation registered for
 * the producer (purpose `signed_signal`) or an admitted provider's JWKS,
 * writes the verified FACTS under `agent_safe.signed_signals.<name>` for
 * policy to name with `required_signals`, and records those facts in the
 * binding, never the token. This module is that contract, letter for letter,
 * so a test against the local double proves what the hosted route proves.
 */
export const SIGNED_SIGNAL_TYPE = "decionis-signed-signal+jwt";

export const SIGNED_SIGNAL_REFUSAL_CODES = [
  "SIGNED_SIGNAL_MALFORMED",
  "SIGNED_SIGNAL_KEY_UNKNOWN",
  "SIGNED_SIGNAL_SIGNATURE_INVALID",
  "SIGNED_SIGNAL_EXPIRED",
  "SIGNED_SIGNAL_AUDIENCE_MISMATCH",
  "SIGNED_SIGNAL_ISSUER_MISMATCH",
  "SIGNED_SIGNAL_NOT_VERIFIED",
  "SIGNED_SIGNAL_DUPLICATE_NAME",
] as const;
export type SignedSignalRefusalCode = (typeof SIGNED_SIGNAL_REFUSAL_CODES)[number];

/** A standing signal may live thirty days; a tap for one intent lives five minutes. */
export const SIGNED_SIGNAL_MAX_LIFETIME_SECONDS = 30 * 24 * 60 * 60;
const CLOCK_TOLERANCE_SECONDS = 300;
const SIGNAL_NAME = /^[a-z][a-z0-9_]{0,63}$/;
const OPEN_NAME = /^[a-z][a-z0-9_.:-]*$/;
const ACTION_NAME = /^[a-z][a-z0-9._:-]*$/;
const CURRENCY = /^[a-z]{3}$/i;
const SIGNAL_KEYS = new Set([
  "name",
  "method",
  "result",
  "agent",
  "scope",
  "limits",
  "card_token_ref",
]);
/** Decionis Presence's own provider name; a producer can never speak as it. */
const RESERVED_PRODUCER = "presence";

/** The `signal` claim: what the producer states, and nothing else. */
export interface SignedSignalClaims {
  readonly name: string;
  readonly method: string;
  readonly result: "VERIFIED" | "FAILED";
  readonly agent?: string;
  readonly scope?: { readonly actions: readonly string[] };
  readonly limits?: { readonly currency: string; readonly amount_minor: number };
  readonly card_token_ref?: string;
}

/** What the intent says, as the facts are computed against it. */
export interface SignedSignalIntentView {
  readonly action: string;
  readonly actorId: string;
  readonly resource: string;
  readonly parameters: Readonly<Record<string, unknown>>;
}

/** Each entry is true, false, or null when the signal does not assert it. */
export interface SignedSignalCoverage {
  readonly action: boolean | null;
  readonly agent: boolean | null;
  readonly amount: boolean | null;
  readonly currency: boolean | null;
  readonly card: boolean | null;
}

/** The facts the authority writes under `agent_safe.signed_signals.<name>`. */
export interface SignedSignalFacts {
  readonly verified: true;
  readonly producer: string;
  readonly method: string;
  readonly subject: string;
  readonly signal_id: string;
  readonly key_id: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly evidence_digest: string;
  readonly agent?: string;
  readonly scope?: { readonly actions: readonly string[] };
  readonly limits?: { readonly currency: string; readonly amount_minor: number };
  readonly card_token_ref?: string;
  readonly covers: SignedSignalCoverage;
  readonly covers_intent: boolean;
}

export interface SignedSignalKey {
  readonly kid: string;
  readonly issuer: string;
  readonly publicKey: KeyObject;
}

/** A verified token, before the intent it is presented with is looked at. */
export interface VerifiedSignedSignal {
  readonly name: string;
  readonly producer: string;
  readonly method: string;
  readonly subject: string;
  readonly signal_id: string;
  readonly key_id: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly evidence_digest: string;
  readonly claims: SignedSignalClaims;
}

export type SignedSignalVerification =
  | { readonly ok: true; readonly signal: VerifiedSignedSignal }
  | { readonly ok: false; readonly code: SignedSignalRefusalCode };

function text(value: unknown, max: number): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= max ? value : null;
}

/** A primary account number must never reach a decision record. */
function looksLikePan(value: string): boolean {
  const digits = value.replace(/[\s-]/g, "");
  if (!/^\d{12,19}$/.test(digits)) return false;
  let sum = 0;
  for (let index = 0; index < digits.length; index += 1) {
    let digit = Number(digits[digits.length - 1 - index]);
    if (index % 2 === 1) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
  }
  return sum % 10 === 0;
}

function decodeSegment(segment: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** The `signal` claim read strictly: any key the contract does not name refuses the token. */
function signalClaims(value: unknown): SignedSignalClaims | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !SIGNAL_KEYS.has(key))) return null;
  const name = text(record.name, 64);
  const method = text(record.method, 64);
  if (name === null || !SIGNAL_NAME.test(name) || method === null || !OPEN_NAME.test(method)) {
    return null;
  }
  if (record.result !== "VERIFIED" && record.result !== "FAILED") return null;
  const claims: {
    name: string;
    method: string;
    result: "VERIFIED" | "FAILED";
    agent?: string;
    scope?: { actions: string[] };
    limits?: { currency: string; amount_minor: number };
    card_token_ref?: string;
  } = { name, method, result: record.result };
  if (record.agent !== undefined) {
    const agent = text(record.agent, 200);
    if (agent === null) return null;
    claims.agent = agent;
  }
  if (record.scope !== undefined) {
    const scope = record.scope as { actions?: unknown } | null;
    const actions = scope !== null && typeof scope === "object" ? scope.actions : undefined;
    if (
      !Array.isArray(actions) ||
      actions.length === 0 ||
      actions.length > 32 ||
      Object.keys(scope as object).length !== 1 ||
      !actions.every(
        (action) => typeof action === "string" && action.length <= 120 && ACTION_NAME.test(action),
      )
    ) {
      return null;
    }
    claims.scope = { actions: [...(actions as string[])] };
  }
  if (record.limits !== undefined) {
    const limits = record.limits as { currency?: unknown; amount_minor?: unknown } | null;
    if (
      limits === null ||
      typeof limits !== "object" ||
      Object.keys(limits).length !== 2 ||
      typeof limits.currency !== "string" ||
      !CURRENCY.test(limits.currency) ||
      typeof limits.amount_minor !== "number" ||
      !Number.isSafeInteger(limits.amount_minor) ||
      limits.amount_minor < 0
    ) {
      return null;
    }
    claims.limits = { currency: limits.currency.toUpperCase(), amount_minor: limits.amount_minor };
  }
  if (record.card_token_ref !== undefined) {
    const ref = text(record.card_token_ref, 200);
    if (ref === null || looksLikePan(ref)) return null;
    claims.card_token_ref = ref;
  }
  return claims;
}

/**
 * Verifies one token the way the hosted authority does: the protected header
 * names an Ed25519 key registered for the producer with purpose
 * `signed_signal`; the signature verifies under it; the issuer is the one
 * registered with the key and the audience is the organisation; the claims
 * are bounded, carry no card number, and the lifetime is within the cap.
 */
export function verifySignedSignal(
  token: string,
  options: {
    readonly orgId: string;
    readonly findKey: (kid: string) => SignedSignalKey | null;
    readonly nowMs?: number;
  },
): SignedSignalVerification {
  const refuse = (code: SignedSignalRefusalCode): SignedSignalVerification => ({ ok: false, code });
  const parts = token.split(".");
  if (parts.length !== 3) return refuse("SIGNED_SIGNAL_MALFORMED");
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
  const header = decodeSegment(encodedHeader);
  const payload = decodeSegment(encodedPayload);
  if (header === null || payload === null) return refuse("SIGNED_SIGNAL_MALFORMED");
  const kid = text(header.kid, 200);
  if (
    header.alg !== "EdDSA" ||
    header.typ !== SIGNED_SIGNAL_TYPE ||
    kid === null ||
    kid.trim() !== kid
  ) {
    return refuse("SIGNED_SIGNAL_MALFORMED");
  }
  const key = options.findKey(kid);
  if (key === null) return refuse("SIGNED_SIGNAL_KEY_UNKNOWN");
  const signed = Buffer.from(`${encodedHeader}.${encodedPayload}`, "ascii");
  if (!verify(null, signed, key.publicKey, Buffer.from(encodedSignature, "base64url"))) {
    return refuse("SIGNED_SIGNAL_SIGNATURE_INVALID");
  }
  const nowMs = options.nowMs ?? Date.now();
  const issuer = text(payload.iss, 100);
  const subject = text(payload.sub, 200);
  const signalId = text(payload.jti, 200);
  const iat = payload.iat;
  const exp = payload.exp;
  const claims = signalClaims(payload.signal);
  if (
    issuer === null ||
    payload.aud === undefined ||
    subject === null ||
    looksLikePan(subject) ||
    signalId === null ||
    typeof iat !== "number" ||
    typeof exp !== "number" ||
    !Number.isFinite(iat) ||
    !Number.isFinite(exp) ||
    exp <= iat ||
    exp - iat > SIGNED_SIGNAL_MAX_LIFETIME_SECONDS ||
    iat * 1_000 > nowMs + CLOCK_TOLERANCE_SECONDS * 1_000 ||
    claims === null
  ) {
    return refuse("SIGNED_SIGNAL_MALFORMED");
  }
  if (issuer === RESERVED_PRODUCER || issuer !== key.issuer)
    return refuse("SIGNED_SIGNAL_ISSUER_MISMATCH");
  if (payload.aud !== options.orgId) return refuse("SIGNED_SIGNAL_AUDIENCE_MISMATCH");
  if (exp * 1_000 + CLOCK_TOLERANCE_SECONDS * 1_000 <= nowMs)
    return refuse("SIGNED_SIGNAL_EXPIRED");
  if (claims.result !== "VERIFIED") return refuse("SIGNED_SIGNAL_NOT_VERIFIED");
  return {
    ok: true,
    signal: {
      name: claims.name,
      producer: key.issuer,
      method: claims.method,
      subject,
      signal_id: signalId,
      key_id: key.kid,
      issued_at: new Date(iat * 1_000).toISOString(),
      expires_at: new Date(exp * 1_000).toISOString(),
      evidence_digest: `sha256:${createHash("sha256").update(token, "utf8").digest("hex")}`,
      claims,
    },
  };
}

/**
 * The facts a verified signal contributes against one intent. `covers` says
 * what the signal asserts about the intent (null when it asserts nothing on
 * that axis); `covers_intent` is true when nothing it asserts is false. A
 * limit the intent gives nothing to check against is not covered.
 */
export function signedSignalFacts(
  verified: VerifiedSignedSignal,
  intent: SignedSignalIntentView,
): SignedSignalFacts {
  const { claims } = verified;
  const amountMinor = intent.parameters.amountMinor;
  const currency = intent.parameters.currency;
  const cardTokenRef = intent.parameters.cardTokenRef;
  const covers: SignedSignalCoverage = {
    action: claims.scope === undefined ? null : claims.scope.actions.includes(intent.action),
    agent: claims.agent === undefined ? null : claims.agent === intent.actorId,
    amount:
      claims.limits === undefined
        ? null
        : typeof amountMinor === "number" &&
          Number.isSafeInteger(amountMinor) &&
          amountMinor >= 0 &&
          amountMinor <= claims.limits.amount_minor,
    currency:
      claims.limits === undefined
        ? null
        : typeof currency === "string" && currency.toUpperCase() === claims.limits.currency,
    card:
      claims.card_token_ref === undefined
        ? null
        : cardTokenRef === claims.card_token_ref ||
          intent.resource === `card:${claims.card_token_ref}`,
  };
  return {
    verified: true,
    producer: verified.producer,
    method: verified.method,
    subject: verified.subject,
    signal_id: verified.signal_id,
    key_id: verified.key_id,
    issued_at: verified.issued_at,
    expires_at: verified.expires_at,
    evidence_digest: verified.evidence_digest,
    ...(claims.agent === undefined ? {} : { agent: claims.agent }),
    ...(claims.scope === undefined ? {} : { scope: { actions: [...claims.scope.actions] } }),
    ...(claims.limits === undefined ? {} : { limits: { ...claims.limits } }),
    ...(claims.card_token_ref === undefined ? {} : { card_token_ref: claims.card_token_ref }),
    covers,
    covers_intent: Object.values(covers).every((entry) => entry !== false),
  };
}

/** Every token verified and its facts keyed by name; two tokens with one name refuse the request. */
export function verifySignedSignals(
  tokens: readonly string[],
  options: {
    readonly orgId: string;
    readonly findKey: (kid: string) => SignedSignalKey | null;
    readonly intent: SignedSignalIntentView;
    readonly nowMs?: number;
  },
):
  | { readonly ok: true; readonly facts: Readonly<Record<string, SignedSignalFacts>> }
  | { readonly ok: false; readonly code: SignedSignalRefusalCode } {
  const facts: Record<string, SignedSignalFacts> = {};
  for (const token of tokens) {
    const verification = verifySignedSignal(token, options);
    if (!verification.ok) return verification;
    if (facts[verification.signal.name] !== undefined) {
      return { ok: false, code: "SIGNED_SIGNAL_DUPLICATE_NAME" };
    }
    facts[verification.signal.name] = signedSignalFacts(verification.signal, options.intent);
  }
  return { ok: true, facts };
}

/**
 * Mints a token as a producer does, for tests and demos: an Ed25519 private
 * key, the key id the organisation registered, and the claims. The lifetime
 * defaults to one day.
 */
export function mintSignedSignal(input: {
  readonly privateKey: KeyObject;
  readonly kid: string;
  readonly issuer: string;
  readonly audience: string;
  readonly subject: string;
  readonly signal: SignedSignalClaims;
  readonly issuedAtMs?: number;
  readonly lifetimeSeconds?: number;
  readonly jti?: string;
  /** Header overrides, for a test that wants a malformed token. */
  readonly header?: Readonly<Record<string, unknown>>;
}): string {
  const issuedAt = Math.floor((input.issuedAtMs ?? Date.now()) / 1_000);
  const header = { alg: "EdDSA", typ: SIGNED_SIGNAL_TYPE, kid: input.kid, ...input.header };
  const payload = {
    iss: input.issuer,
    aud: input.audience,
    sub: input.subject,
    iat: issuedAt,
    exp: issuedAt + (input.lifetimeSeconds ?? 24 * 60 * 60),
    jti: input.jti ?? `signal-${issuedAt}-${Math.random().toString(36).slice(2, 10)}`,
    signal: input.signal,
  };
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  const signingInput = `${encode(header)}.${encode(payload)}`;
  const signature = sign(null, Buffer.from(signingInput, "ascii"), input.privateKey);
  return `${signingInput}.${signature.toString("base64url")}`;
}
