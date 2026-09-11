import { z } from "zod";
import { AuthorityBaseUrl } from "../http/AuthorityBaseUrl.js";
import { BoundedResponseBody } from "../http/BoundedResponseBody.js";
import { CanonicalIntentHasher } from "../intent/CanonicalIntentHasher.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import type { GateDecision } from "../decision/DecisionAuthority.js";

export interface VerifiedAuthorization {
  readonly decisionId: string;
  readonly dossierId: string;
  readonly grantId: string;
  readonly intentHash: string;
  readonly expiresAt: string;
}

/** Outcome of the downstream attempt reported to the authority after a claimed grant. */
export type ExecutionCommitOutcome = "COMMITTED" | "FAILED" | "INDETERMINATE";

/**
 * `RECORDED`: the authority accepted the commit evidence. `PENDING`: it could
 * not be delivered and the authority's lease recovery owns it. `UNSUPPORTED`:
 * the verifier has no finalization contract.
 */
export type ExecutionFinalization = "RECORDED" | "PENDING" | "UNSUPPORTED";

/**
 * Exact wire shape of the Decionis Protocol 1.1 `EffectEvidence` contract: an
 * observation of what happened downstream, supplied by the trusted runtime that
 * observed it. This package never constructs, interprets, upgrades, or
 * downgrades an observation; it forwards a bounded, validated copy of the one
 * it was handed, and drops anything outside the contract's own shape rather
 * than serialising a caller-controlled object onto an authenticated request.
 */
export interface AuthorityEffectEvidence {
  readonly version: "1.0";
  readonly status: "CONFIRMED" | "UNCONFIRMED";
  readonly observation_method:
    | "DOWNSTREAM_ACK"
    | "READ_AFTER_WRITE"
    | "EVENT_CONFIRMATION"
    | "STATE_RECONCILIATION"
    | "SIGNED_RECEIPT"
    | "EXTERNAL_ATTESTATION"
    | "HUMAN_VALIDATION";
  readonly observer: { readonly id: string; readonly version: string | null } | null;
  readonly expected_effect_digest: string;
  readonly observed_effect_digest: string | null;
  readonly observed_at: string | null;
  readonly evidence_digest: string | null;
  readonly evidence_reference: string | null;
  readonly execution_correlation_id: string;
}

/**
 * What the authority itself said about an observation it was sent, narrowed by
 * what this executor knows it sent. `effectEvidenceRecorded` and
 * `effectConfirmation` are the authority's statement, but they are only ever
 * reported for a finalization that actually carried the observation: an
 * authority claiming to have recorded evidence it was not sent is not evidence.
 */
export interface AuthorityEffectReport {
  /** The finalization that was recorded carried the observation. */
  readonly effectEvidenceSent: boolean;
  /**
   * An earlier finalization attempt carried the observation and the authority
   * refused it, so this commit record was recovered without it. Distinguishes a
   * refused observation from one that was dropped or never supplied.
   */
  readonly effectEvidenceRefused: boolean;
  readonly effectEvidenceRecorded: boolean;
  readonly effectConfirmation: "CONFIRMED" | "UNCONFIRMED";
}

export interface AuthorizationFinalizationInput {
  readonly captured: CapturedIntent;
  readonly decision: GateDecision;
  readonly authorization: VerifiedAuthorization;
  readonly outcome: ExecutionCommitOutcome;
  /**
   * Optional observation of the downstream effect, forwarded verbatim. It is
   * sent only when the signed grant committed to an expected-effect digest, the
   * evidence names that same digest, and its `execution_correlation_id` equals
   * the commit correlation id this grant was claimed with. Otherwise it is
   * dropped, because the authority refuses the entire finalization for evidence
   * it cannot bind and the commit outcome would be lost with it. It is also
   * dropped when it does not conform to the contract's own bounded shape.
   */
  readonly effectEvidence?: AuthorityEffectEvidence;
}

export interface AuthorizationVerifier {
  verifyAndConsume(
    captured: CapturedIntent,
    decision: GateDecision,
  ): Promise<VerifiedAuthorization | null>;
  /**
   * Reports the downstream attempt outcome for an authorization returned by
   * this verifier's `verifyAndConsume`. Finalization is evidence, never
   * authority: it must not retry a side effect, and it must not throw.
   */
  finalize?(input: AuthorizationFinalizationInput): Promise<"RECORDED" | "PENDING">;
}

const boundedIdentifier = z
  .string()
  .min(1)
  .max(200)
  .refine(hasNoControlCharacters, { message: "IDENTIFIER_INVALID" });
const sha256Digest = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const intentHash = sha256Digest;
const CLAIM_TOKEN_PATTERN = /^[\w-]{43,128}$/;
/** `boundedIdentifier` from the Decionis `EffectEvidence` contract, verbatim. */
const effectIdentifier = z.string().trim().min(1).max(500);

/**
 * The Decionis Protocol 1.1 `EffectEvidence` contract, mirrored so an
 * observation is bounded before it is serialised onto an authenticated
 * request. Parsing also takes the snapshot the drop rule then checks, so the
 * values that are verified are exactly the values that are sent. The
 * `CONFIRMED` refinements are deliberately not mirrored: whether an
 * observation qualifies as confirmed is the authority's judgement, not this
 * package's, and a refusal is recoverable by the evidence-free retry.
 */
const EffectEvidenceSchema = z.strictObject({
  version: z.literal("1.0"),
  status: z.enum(["CONFIRMED", "UNCONFIRMED"]),
  observation_method: z.enum([
    "DOWNSTREAM_ACK",
    "READ_AFTER_WRITE",
    "EVENT_CONFIRMATION",
    "STATE_RECONCILIATION",
    "SIGNED_RECEIPT",
    "EXTERNAL_ATTESTATION",
    "HUMAN_VALIDATION",
  ]),
  observer: z
    .strictObject({ id: effectIdentifier, version: effectIdentifier.nullable() })
    .nullable(),
  expected_effect_digest: sha256Digest,
  observed_effect_digest: sha256Digest.nullable(),
  observed_at: z.string().datetime().nullable(),
  evidence_digest: sha256Digest.nullable(),
  evidence_reference: effectIdentifier.nullable(),
  execution_correlation_id: effectIdentifier,
});

/**
 * Mirrors `ExecutionTokenResponse` and `ExecutionTokenClaims` in the Decionis
 * OpenAPI contract. Claims are declared `additionalProperties: true`, and the
 * live response carries revalidation fields beyond the documented envelope, so
 * unknown fields are tolerated; authority is established only by the positive
 * assertions checked below, never by an extra field.
 */
const ClaimResponseSchema = z.looseObject({
  valid: z.literal(true),
  reason_codes: z.array(boundedIdentifier).max(50).optional(),
  should_execute: z.boolean().optional(),
  claims: z.looseObject({
    iss: boundedIdentifier,
    sub: boundedIdentifier.optional(),
    aud: z.string().min(1).max(500).optional(),
    org_id: z.string().uuid(),
    dossier_id: boundedIdentifier,
    decision_id: boundedIdentifier,
    action: boundedIdentifier,
    decision: z.literal("allow"),
    scope: z.literal("execute"),
    binding: z.looseObject({
      intent_hash: intentHash,
      // An authority that stores no commitment may omit the property, serialise
      // its nullable column as `null`, or emit something this package does not
      // recognise. All three mean "no commitment this executor can read", and
      // all three must behave exactly as they did before this property existed,
      // when the loose envelope passed the value through untouched. Reading an
      // unrecognised value as absent keeps that promise and stays fail-closed:
      // an intent that committed a digest still finds no match and is refused.
      expected_effect_digest: sha256Digest.nullish().catch(undefined),
    }),
    jti: boundedIdentifier,
    iat: z.number().int(),
    nbf: z.number().int(),
    exp: z.number().int().positive(),
  }),
  claim_token: z.string().regex(CLAIM_TOKEN_PATTERN).nullable().optional(),
  claim_lease_expires_at: z.string().datetime().nullable().optional(),
});

/**
 * The response envelope is deliberately loose, and the two effect fields are
 * reporting-only: a value outside their contract must never turn a recorded
 * finalization into `PENDING` for a consumer using none of this. Anything
 * unrecognised reads as absent, which reports closed.
 */
const FinalizeResponseSchema = z.looseObject({
  finalized: z.boolean(),
  reason_codes: z.array(boundedIdentifier).max(50).optional(),
  effect_evidence_recorded: z.boolean().optional().catch(undefined),
  effect_confirmation: z.enum(["CONFIRMED", "UNCONFIRMED"]).optional().catch(undefined),
});

const MAX_RESPONSE_BYTES = 100 * 1024;

interface ClaimRecord {
  readonly executionToken: string;
  readonly claimToken: string;
  readonly commitCorrelationId: string;
  /** The expected-effect digest the authority committed into this grant's binding, if any. */
  readonly expectedEffectDigest: string | undefined;
}

export interface DecionisGrantVerifierOptions {
  readonly baseUrl: string;
  readonly apiKey: string;
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
  readonly allowInsecureLoopback?: boolean;
}

/**
 * Claims a Decionis execution grant through `/v1/execution/claim-token`
 * immediately before dispatch and finalizes the attempt through
 * `/v1/execution/finalize-token` afterwards, so commit evidence joins the
 * Decision Dossier chain.
 */
export class DecionisGrantVerifier implements AuthorizationVerifier {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  /** Claim material is keyed by the frozen authorization it belongs to and never exposed. */
  private readonly claims = new WeakMap<VerifiedAuthorization, ClaimRecord>();
  /** The authority's own answer about an observation, keyed by the frozen authorization. */
  private readonly reports = new WeakMap<VerifiedAuthorization, AuthorityEffectReport>();

  public constructor(options: DecionisGrantVerifierOptions) {
    this.baseUrl = AuthorityBaseUrl.normalize(
      options.baseUrl,
      options.allowInsecureLoopback === true,
    );
    this.apiKey = options.apiKey;
    this.timeoutMs = Math.min(Math.max(options.timeoutMs ?? 4_000, 1), 15_000);
    this.fetchImpl = options.fetch ?? fetch;
  }

  public async verifyAndConsume(
    captured: CapturedIntent,
    decision: GateDecision,
  ): Promise<VerifiedAuthorization | null> {
    if (
      decision.verdict !== "ALLOW" ||
      decision.failClosed ||
      decision.authorization === null ||
      decision.dossierId === null ||
      decision.intentHash !== captured.intentHash
    ) {
      return null;
    }
    const commitCorrelationId = captured.intent.intentId;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(`${this.baseUrl}/v1/execution/claim-token`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.apiKey}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          execution_token: decision.authorization.token,
          intent_hash: captured.intentHash,
          intent: CanonicalIntentHasher.bindingOf(captured.intent),
          // A Presence-bound decision is re-verified by the authority at claim
          // time, so the same evidence must accompany the claim.
          ...(decision.evidence === undefined ? {} : { evidence: decision.evidence }),
          consumed_by: captured.intent.actor.id,
          commit_correlation_id: commitCorrelationId,
        }),
        signal: controller.signal,
      });
      if (!response.ok) return null;
      const text = await BoundedResponseBody.read(response, MAX_RESPONSE_BYTES);
      if (text === null) return null;
      const parsed = ClaimResponseSchema.parse(JSON.parse(text));
      const claims = parsed.claims;
      /** A `null` commitment is no commitment, exactly as an absent one is. */
      const committedEffectDigest = claims.binding.expected_effect_digest ?? undefined;
      const claimExpiryMs = claims.exp * 1_000;
      const decisionExpirySeconds = Math.floor(
        Date.parse(decision.authorization.expiresAt) / 1_000,
      );
      const audience = `${captured.intent.downstreamTarget.system}:${captured.intent.downstreamTarget.operation}`;
      if (
        parsed.should_execute === false ||
        typeof parsed.claim_token !== "string" ||
        claims.binding.intent_hash !== captured.intentHash ||
        committedEffectDigest !== captured.intent.expectedEffectDigest ||
        claims.decision_id !== decision.decisionId ||
        claims.dossier_id !== decision.dossierId ||
        claims.org_id !== captured.intent.tenantId ||
        claims.sub !== captured.intent.actor.id ||
        claims.action !== captured.intent.action ||
        (claims.aud !== undefined && claims.aud !== audience) ||
        claims.exp !== decisionExpirySeconds ||
        claimExpiryMs <= Date.now() ||
        claimExpiryMs > Date.parse(captured.intent.expiresAt)
      ) {
        return null;
      }
      const authorization: VerifiedAuthorization = Object.freeze({
        decisionId: claims.decision_id,
        dossierId: claims.dossier_id,
        grantId: claims.jti,
        intentHash: claims.binding.intent_hash,
        expiresAt: new Date(claims.exp * 1_000).toISOString(),
      });
      this.claims.set(authorization, {
        executionToken: decision.authorization.token,
        claimToken: parsed.claim_token,
        commitCorrelationId,
        expectedEffectDigest: committedEffectDigest,
      });
      return authorization;
    } catch {
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }

  public async finalize(input: AuthorizationFinalizationInput): Promise<"RECORDED" | "PENDING"> {
    const claim = this.claims.get(input.authorization);
    if (claim === undefined) return "PENDING";
    const evidence = DecionisGrantVerifier.bindableEffectEvidence(input, claim);
    const first = await this.post(input, claim, evidence, false);
    if (first === "RECORDED") return "RECORDED";
    if (first === "PENDING" || evidence === undefined) return "PENDING";
    // The authority answered with the one status an effect refusal uses, and
    // every effect rejection precedes the commit transition, so the commit
    // record is still recoverable by reporting the same outcome without the
    // observation. This retries no side effect and sends nothing it has not
    // already sent: the second body is byte-identical to the body this package
    // sent before effect evidence existed.
    const second = await this.post(input, claim, undefined, true);
    return second === "RECORDED" ? "RECORDED" : "PENDING";
  }

  /**
   * What the authority reported about effect evidence for an authorization this
   * verifier finalized. `null` until a finalization was recorded. This is the
   * authority's statement, never this package's inference.
   */
  public effectReport(authorization: VerifiedAuthorization): AuthorityEffectReport | null {
    return this.reports.get(authorization) ?? null;
  }

  /**
   * `REFUSED` only for the one status a finalization refusal uses (409); every
   * other non-ok status, a throw, a timeout, or an oversize body is `PENDING`,
   * exactly as it was before effect evidence existed. A rate-limited or
   * unauthenticated authority must never be re-posted to.
   */
  private async post(
    input: AuthorizationFinalizationInput,
    claim: ClaimRecord,
    evidence: AuthorityEffectEvidence | undefined,
    evidenceRefused: boolean,
  ): Promise<"RECORDED" | "PENDING" | "REFUSED"> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(`${this.baseUrl}/v1/execution/finalize-token`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.apiKey}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          execution_token: claim.executionToken,
          claim_token: claim.claimToken,
          outcome: input.outcome,
          commit_correlation_id: claim.commitCorrelationId,
          ...(evidence === undefined ? {} : { effect_evidence: evidence }),
        }),
        signal: controller.signal,
      });
      if (!response.ok) return response.status === 409 ? "REFUSED" : "PENDING";
      const text = await BoundedResponseBody.read(response, MAX_RESPONSE_BYTES);
      if (text === null) return "PENDING";
      const parsed = FinalizeResponseSchema.parse(JSON.parse(text));
      if (!parsed.finalized) return "PENDING";
      // The authority's answer about an observation is only meaningful for a
      // finalization that carried one. What was not sent cannot have been
      // recorded, whatever the response says.
      const sent = evidence !== undefined;
      this.reports.set(input.authorization, {
        effectEvidenceSent: sent,
        effectEvidenceRefused: evidenceRefused,
        effectEvidenceRecorded: sent && parsed.effect_evidence_recorded === true,
        effectConfirmation:
          sent && parsed.effect_confirmation === "CONFIRMED" ? "CONFIRMED" : "UNCONFIRMED",
      });
      this.claims.delete(input.authorization);
      return "RECORDED";
    } catch {
      return "PENDING";
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Effect evidence reaches the authority only when this executor can prove the
   * authority will bind it: it must conform to the contract's bounded shape,
   * the grant the authority returned must have committed to an expected-effect
   * digest, the evidence must name that exact digest, and it must carry the
   * correlation id this claim was made with. Unbindable evidence is dropped
   * rather than sent, because the authority answers it with a 409 that aborts
   * the whole finalization rather than discarding the observation.
   *
   * The checks run against the parsed copy, which is also the copy that is
   * serialised, so a caller object with accessors cannot present one value to
   * the drop rule and another to the wire.
   */
  private static bindableEffectEvidence(
    input: AuthorizationFinalizationInput,
    claim: ClaimRecord,
  ): AuthorityEffectEvidence | undefined {
    if (input.effectEvidence === undefined || claim.expectedEffectDigest === undefined) {
      return undefined;
    }
    const parsed = EffectEvidenceSchema.safeParse(input.effectEvidence);
    if (!parsed.success) return undefined;
    const evidence: AuthorityEffectEvidence = parsed.data;
    if (evidence.expected_effect_digest !== claim.expectedEffectDigest) return undefined;
    if (evidence.execution_correlation_id !== claim.commitCorrelationId) return undefined;
    return Object.freeze(evidence);
  }
}

function hasNoControlCharacters(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || codeUnit === 0x7f) return false;
  }
  return true;
}
