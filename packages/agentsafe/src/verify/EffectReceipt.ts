import { createPrivateKey, sign, type KeyObject } from "node:crypto";
import type { JsonObject } from "@decionis/agent-safe-pipeline";
import { jcsCanonical } from "../adapters/JcsDigest.js";
import type { ClaimAttestationClaims } from "./VerifyingProvider.js";

/**
 * The effect receipt: the provider's half of the evidence (the Verifying
 * Provider Profile, VP-3).
 *
 * The attestation let this provider refuse what the authority never claimed.
 * The receipt closes the other direction: after effecting, or refusing, the
 * claimed request, the provider signs a compact JWS under its own key naming
 * the grant it acted under, the claim it answered and what it did, and
 * returns it in `x-agent-safe-effect-receipt`. The executor forwards it
 * unread at finalization; the authority verifies it against the public key
 * the organisation registered for this provider and records it with the
 * commit evidence, so the dossier carries the provider's signature over the
 * effect and not only the executor's report of it.
 *
 * Every field the receipt binds comes from the attestation the provider has
 * already verified, which is the point: `sub` is the grant, `decision_id`
 * and `dossier_id` are the decision's, and `claim_token_digest` is copied
 * from the attestation of this very claim, which is how the authority ties
 * the receipt to the claim being finalized without the claim token ever
 * reaching the provider. The header and the payload are serialised in RFC
 * 8785 canonical form, so every implementation of this profile signs the
 * same bytes for the same receipt and the conformance vectors can say so.
 */
export const EFFECT_RECEIPT_TYPE = "decionis-effect-receipt+jwt";
/** The response header the receipt travels in. */
export const EFFECT_RECEIPT_HEADER = "x-agent-safe-effect-receipt";

export type EffectStatus = "EFFECTED" | "REFUSED" | "INDETERMINATE";

export interface EffectReceiptEffect {
  /** What the provider did with the claimed request. A signed refusal is evidence too. */
  readonly status: EffectStatus;
  /** The provider's own reference for the effect: a ledger entry, an order id. */
  readonly reference?: string;
  /**
   * The digest of the effect as the provider observed it, in the terms the
   * grant committed to (`expected_effect_digest`). Equality is what confirms
   * the effect at the authority.
   */
  readonly digest?: string;
  /** When the effect took place, RFC 3339. */
  readonly effected_at: string;
}

/** The attestation claims a receipt is built from: what the provider verified before effecting. */
export type AttestedClaim = Pick<
  ClaimAttestationClaims,
  "sub" | "decision_id" | "dossier_id" | "claim_token_digest" | "jti"
> & { readonly binding: Pick<ClaimAttestationClaims["binding"], "intent_hash"> };

export interface EffectReceiptInput {
  /** The provider's Ed25519 private key, or its PKCS#8 PEM. Never leaves the provider. */
  readonly key: KeyObject | string;
  /** The `kid` the organisation registered this key under at the authority. */
  readonly kid: string;
  /** The `iss` registered with the key. */
  readonly issuer: string;
  /** The authority the receipt is for: its issuer, `https://decionis.com` for the hosted one. */
  readonly audience: string;
  /** The claims of the attestation this provider verified, as `verifyProviderRequest` returned them. */
  readonly attestation: AttestedClaim;
  /** The idempotency key of the request effected, when the provider records it. */
  readonly idempotencyKey?: string;
  readonly effect: EffectReceiptEffect;
  /** `iat`, as an epoch second. */
  readonly issuedAt: number;
  /** Unique per receipt. */
  readonly jti: string;
}

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const STATUSES: readonly EffectStatus[] = ["EFFECTED", "REFUSED", "INDETERMINATE"];

export class EffectReceiptError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = "EffectReceiptError";
  }
}

/** The payload of the receipt, before it is signed; what the authority reads. */
export function effectReceiptClaims(input: EffectReceiptInput): JsonObject {
  if (!STATUSES.includes(input.effect.status))
    throw new EffectReceiptError("EFFECT_STATUS_UNKNOWN");
  if (input.effect.digest !== undefined && !SHA256.test(input.effect.digest)) {
    throw new EffectReceiptError("EFFECT_DIGEST_MALFORMED");
  }
  if (Number.isNaN(Date.parse(input.effect.effected_at))) {
    throw new EffectReceiptError("EFFECTED_AT_MALFORMED");
  }
  if (!Number.isInteger(input.issuedAt) || input.issuedAt < 0) {
    throw new EffectReceiptError("ISSUED_AT_MALFORMED");
  }
  for (const [name, value] of [
    ["KID", input.kid],
    ["ISSUER", input.issuer],
    ["AUDIENCE", input.audience],
    ["JTI", input.jti],
  ] as const) {
    if (value.length === 0) throw new EffectReceiptError(`${name}_EMPTY`);
  }
  return {
    iss: input.issuer,
    aud: input.audience,
    sub: input.attestation.sub,
    decision_id: input.attestation.decision_id,
    dossier_id: input.attestation.dossier_id,
    claim_token_digest: input.attestation.claim_token_digest,
    attestation_jti: input.attestation.jti,
    intent_hash: input.attestation.binding.intent_hash,
    ...(input.idempotencyKey === undefined ? {} : { idempotency_key: input.idempotencyKey }),
    effect: {
      status: input.effect.status,
      ...(input.effect.reference === undefined ? {} : { reference: input.effect.reference }),
      ...(input.effect.digest === undefined ? {} : { digest: input.effect.digest }),
      effected_at: input.effect.effected_at,
    },
    iat: input.issuedAt,
    jti: input.jti,
  };
}

/** The `header.payload` the signature covers: both segments RFC 8785 canonical, base64url. */
export function effectReceiptSigningInput(input: EffectReceiptInput): string {
  const header = { alg: "EdDSA", kid: input.kid, typ: EFFECT_RECEIPT_TYPE };
  return `${base64url(jcsCanonical(header))}.${base64url(jcsCanonical(effectReceiptClaims(input)))}`;
}

/** The receipt: a compact EdDSA JWS the provider returns in `x-agent-safe-effect-receipt`. */
export function signEffectReceipt(input: EffectReceiptInput): string {
  const signingInput = effectReceiptSigningInput(input);
  const key = typeof input.key === "string" ? createPrivateKey(input.key) : input.key;
  if (key.asymmetricKeyType !== "ed25519") throw new EffectReceiptError("KEY_NOT_ED25519");
  const signature = sign(null, Buffer.from(signingInput), key);
  return `${signingInput}.${signature.toString("base64url")}`;
}

function base64url(text: string): string {
  return Buffer.from(text).toString("base64url");
}
