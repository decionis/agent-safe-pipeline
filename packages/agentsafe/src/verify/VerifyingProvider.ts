import { createPublicKey, verify as verifySignature } from "node:crypto";
import type { JsonValue } from "@decionis/agent-safe-pipeline";
import { z } from "zod";
import { jcsDigest } from "../adapters/JcsDigest.js";
import {
  BASE_COMPONENTS,
  SIGNED_COMPONENTS,
  SignedRequestCredential,
} from "../credential/SignedRequestCredential.js";

/**
 * The Verifying Provider Profile (`docs/authority/verifying-provider.md`), as
 * a provider runs it: the reference for VP-1 and VP-2. Everything the profile
 * numbers is a step here, in the profile's order, and the first failing step
 * names the refusal. The signature half is `SignedRequestCredential.verify`,
 * unchanged; this adds what a provider does around it: the freshness window,
 * the key registry, the attestation, the canonical body digest, and the
 * single presentation of a grant. It is held to the same mutation gate,
 * because a mutant that accepts what it should refuse is a provider that
 * effects what the authority never claimed.
 */
export type ProviderRefusalCode =
  | "SIGNATURE_INVALID_OR_INCOMPLETE"
  | "ATTESTATION_INVALID"
  | "ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST"
  | "GRANT_REPLAYED";

export const ATTESTATION_TYPE = "decionis-claim-attestation+jwt";
export const JCS_PROFILE = "RFC8785/JCS";

/** A key the provider issued to, or registered for, the executor, by the `keyid` a signature names. */
export type ExecutorKey =
  | { readonly keyId: string; readonly algorithm: "ed25519"; readonly publicKeyPem: string }
  | { readonly keyId: string; readonly algorithm: "hmac-sha256"; readonly secret: Uint8Array };

/** The claims of an attestation, as far as the provider reads them; the authority's schema has more. */
export interface ClaimAttestationClaims {
  readonly iss: string;
  readonly sub: string;
  readonly decision_id: string;
  readonly binding: {
    readonly intent_hash: string;
    readonly execution_payload_digest: string;
    readonly execution_payload_canonicalization_profile: string;
  };
  readonly exp: number;
}

/**
 * Where a provider keeps the grants it accepted, until their attestation
 * expires. `record` answers true when the grant was not there and is now,
 * false when it was: the second presentation. Shared by every instance that
 * can effect; the profile's step 8.
 */
export interface ReplayStore {
  record(grantId: string, expiresAtMs: number): boolean;
}

export interface VerifyingProviderOptions {
  /** Whether this endpoint effects anything. An effecting provider requires all eight components. */
  readonly effects: boolean;
  /** Unique by `keyId`; the first match is the key. */
  readonly executorKeys: readonly ExecutorKey[];
  /** The authority's execution-grant JWKS, as its well-known path serves it. */
  readonly authorityJwks: { readonly keys: readonly Readonly<Record<string, unknown>>[] };
  /** The `iss` the provider trusts: `https://decionis.com` for Decionis. */
  readonly authorityIssuer: string;
  /** How far `created` may lie from `now`, each way. */
  readonly clockWindowSeconds: number;
  readonly replay: ReplayStore;
  readonly now?: () => number;
}

export interface ReceivedRequest {
  readonly method: string;
  /** The request path, without its query. */
  readonly path: string;
  readonly body: string | null;
  /** Header names in lower case. A covered header received more than once is a refusal; do not collapse it here. */
  readonly headers: Readonly<Record<string, string>>;
}

export type ProviderVerdict =
  | {
      readonly accepted: true;
      readonly reasonCode: null;
      readonly attestation: ClaimAttestationClaims | null;
    }
  | {
      readonly accepted: false;
      readonly reasonCode: ProviderRefusalCode;
      readonly attestation: null;
    };

// The executor writes its parameters in one order, `created`, `keyid`, `alg`
// last; the label and the components are the credential's to check.
const SIGNATURE_CREATED = /;created=(\d{1,12});/;
const SIGNATURE_KEY_ID = /;keyid="([^"]*)";/;

const ProtectedHeader = z.looseObject({
  alg: z.literal("EdDSA"),
  typ: z.literal(ATTESTATION_TYPE),
  kid: z.string(),
});
const Claims = z.looseObject({
  iss: z.string(),
  sub: z.string(),
  decision_id: z.string(),
  binding: z.looseObject({
    intent_hash: z.string(),
    execution_payload_digest: z.string(),
    execution_payload_canonicalization_profile: z.literal(JCS_PROFILE),
  }),
  exp: z.number(),
});

const REFUSE = (reasonCode: ProviderRefusalCode): ProviderVerdict => ({
  accepted: false,
  reasonCode,
  attestation: null,
});

/**
 * Steps 0 to 5: the signature the executor made, under a key the provider
 * knows, fresh, covering what this provider requires. Null on success.
 */
function signatureRefusal(
  received: ReceivedRequest,
  options: VerifyingProviderOptions,
  nowSeconds: number,
): ProviderRefusalCode | null {
  const input = String(received.headers["signature-input"]);
  const keyId = SIGNATURE_KEY_ID.exec(input)?.[1];
  const key = options.executorKeys.find((candidate) => candidate.keyId === keyId);
  if (key === undefined) return "SIGNATURE_INVALID_OR_INCOMPLETE";
  const created = Number(SIGNATURE_CREATED.exec(input)?.[1]);
  if (!(Math.abs(nowSeconds - created) <= options.clockWindowSeconds)) {
    return "SIGNATURE_INVALID_OR_INCOMPLETE";
  }
  const verified = SignedRequestCredential.verify(
    SignedRequestCredential.materialFrom(received),
    received.headers,
    key.algorithm === "ed25519" ? { publicKeyPem: key.publicKeyPem } : { secret: key.secret },
    { require: options.effects ? SIGNED_COMPONENTS : BASE_COMPONENTS },
  );
  return verified ? null : "SIGNATURE_INVALID_OR_INCOMPLETE";
}

/**
 * Step 6: the authority's attestation, by form, key, signature and issuer;
 * its claims, or null when it is not one. Whatever throws on the way, a part
 * that is not JSON, a kid that names no key, a key that is not one, is the
 * same refusal, and the caller makes it so.
 */
function attestationOf(compact: string, options: VerifyingProviderOptions): unknown {
  const parts = compact.split(".");
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts as [string, string, string];
  const decode = (part: string): unknown =>
    JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  const head = ProtectedHeader.parse(decode(header));
  const jwk = options.authorityJwks.keys.find((candidate) => candidate["kid"] === head.kid);
  const signed = verifySignature(
    null,
    Buffer.from(`${header}.${payload}`),
    createPublicKey({ key: jwk as never, format: "jwk" }),
    Buffer.from(signature, "base64url"),
  );
  if (!signed) return null;
  const claims = decode(payload);
  return (claims as Readonly<Record<string, unknown>>)["iss"] === options.authorityIssuer
    ? claims
    : null;
}

const DELIMITER = /[{}[\]:,"\s]/g;

/**
 * The tokens of a JSON text that `JSON.parse` accepted, in order: strings
 * with their escapes, punctuation, and a scalar as its first character,
 * since nothing reads a scalar's text; whitespace is nothing. One pass over
 * the text, no backtracking. The generator is pulled only as far as the
 * top-level value reaches, which for valid JSON is the end of the text, so
 * it needs no end of its own.
 */
function* tokensOf(json: string): Generator<string> {
  let index = 0;
  for (;;) {
    const char = json[index] as string;
    if (char === '"') {
      const start = index;
      index += 1;
      while (json[index] !== '"') index += json[index] === "\\" ? 2 : 1;
      index += 1;
      yield json.slice(start, index);
    } else if ("{}[]:,".includes(char)) {
      index += 1;
      yield char;
    } else if (" \n\r\t".includes(char)) {
      index += 1;
    } else {
      DELIMITER.lastIndex = index;
      const delimiter = DELIMITER.exec(json);
      index = delimiter === null ? json.length : delimiter.index;
      yield char;
    }
  }
}

/**
 * True when some object in a syntactically valid JSON text repeats a name.
 * `JSON.parse` keeps the last of a repeated name, which is exactly the
 * disagreement between parsers that makes such a body unsafe to digest, so
 * the tokens are walked once more, after the grammar is known to hold, and
 * each object's names are collected.
 */
function hasRepeatedName(json: string): boolean {
  const tokens = tokensOf(json);
  const next = (): string => tokens.next().value as string;
  const value = (first: string): boolean => {
    if (first === "{") {
      const names = new Set<string>();
      let token = next();
      while (token !== "}") {
        const name = JSON.parse(token) as string;
        if (names.has(name)) return true;
        names.add(name);
        next();
        if (value(next())) return true;
        token = next();
        if (token === ",") token = next();
      }
      return false;
    }
    if (first === "[") {
      // A comma between values is read as a value with nothing inside.
      let token = next();
      while (token !== "]") {
        if (value(token)) return true;
        token = next();
      }
    }
    return false;
  };
  return value(next());
}

/** The body as I-JSON, or null: not JSON, or a name repeated within one object. Lone surrogates are the canonicaliser's to refuse. */
export function parseIJson(body: string): JsonValue | null {
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch {
    return null;
  }
  return hasRepeatedName(body) ? null : (value as JsonValue);
}

/**
 * Step 7: whether the attestation describes this request; the claims when it
 * does. Claims of the wrong shape and a body that is not I-JSON throw, and
 * the caller refuses.
 */
function described(
  claims: unknown,
  received: ReceivedRequest,
  nowSeconds: number,
): ClaimAttestationClaims | null {
  const { iss, sub, decision_id, binding, exp } = Claims.parse(claims);
  // No body reads as the text `null`, which describes no parameters; nor
  // does anything that is not an object, since parameters are one.
  const value = parseIJson(String(received.body));
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const digest = jcsDigest(value);
  if (
    sub !== received.headers["x-agent-safe-grant-id"] ||
    decision_id !== received.headers["x-agent-safe-decision-id"] ||
    binding.intent_hash !== received.headers["x-agent-safe-intent-hash"] ||
    binding.execution_payload_digest !== digest ||
    exp <= nowSeconds
  ) {
    return null;
  }
  return {
    iss,
    sub,
    decision_id,
    binding: {
      intent_hash: binding.intent_hash,
      execution_payload_digest: binding.execution_payload_digest,
      execution_payload_canonicalization_profile:
        binding.execution_payload_canonicalization_profile,
    },
    exp,
  };
}

/**
 * The whole procedure for one received request. An accepted verdict carries
 * the attestation's claims for the provider's own record, or null for a read
 * a non-effecting provider verified at VP-1 alone; a refusal carries the code
 * the response body names.
 */
export function verifyProviderRequest(
  received: ReceivedRequest,
  options: VerifyingProviderOptions,
): ProviderVerdict {
  const nowSeconds = Math.floor((options.now ?? Date.now)() / 1_000);
  const refusal = signatureRefusal(received, options, nowSeconds);
  if (refusal !== null) return REFUSE(refusal);
  if (!options.effects) return { accepted: true, reasonCode: null, attestation: null };
  // An effecting provider required the attestation covered, and a covered
  // header is present: the signature step proved it.
  const compact = received.headers["x-agent-safe-claim-attestation"] as string;
  let claims: unknown;
  try {
    claims = attestationOf(compact, options);
  } catch {
    claims = null;
  }
  if (claims === null) return REFUSE("ATTESTATION_INVALID");
  let attestation: ClaimAttestationClaims | null;
  try {
    attestation = described(claims, received, nowSeconds);
  } catch {
    attestation = null;
  }
  if (attestation === null) return REFUSE("ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST");
  if (!options.replay.record(attestation.sub, attestation.exp * 1_000)) {
    return REFUSE("GRANT_REPLAYED");
  }
  return { accepted: true, reasonCode: null, attestation };
}

/** The refusal body the profile names; the status is the provider's, 409 in the references. */
export function refusalBody(reasonCode: ProviderRefusalCode): string {
  return JSON.stringify({ status: "REJECTED", reason_code: reasonCode });
}

/**
 * A replay store for one process: enough for a single instance, and for the
 * vectors. A provider with more than one instance that can effect shares one
 * instead, keyed the same way. Expired grants are forgotten on the next
 * record, which is why the store needs no life beyond the lease.
 */
export class MemoryReplayStore implements ReplayStore {
  private readonly seen = new Map<string, number>();

  public constructor(private readonly clock: () => number = () => Date.now()) {}

  public record(grantId: string, expiresAtMs: number): boolean {
    const now = this.clock();
    for (const [grant, expiry] of this.seen) if (expiry <= now) this.seen.delete(grant);
    if (this.seen.has(grantId)) return false;
    this.seen.set(grantId, expiresAtMs);
    return true;
  }

  public get size(): number {
    return this.seen.size;
  }
}
