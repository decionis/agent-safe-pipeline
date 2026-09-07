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

export interface AuthorizationFinalizationInput {
  readonly captured: CapturedIntent;
  readonly decision: GateDecision;
  readonly authorization: VerifiedAuthorization;
  readonly outcome: ExecutionCommitOutcome;
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
const intentHash = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const CLAIM_TOKEN_PATTERN = /^[\w-]{43,128}$/;

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
    binding: z.looseObject({ intent_hash: intentHash }),
    jti: boundedIdentifier,
    iat: z.number().int(),
    nbf: z.number().int(),
    exp: z.number().int().positive(),
  }),
  claim_token: z.string().regex(CLAIM_TOKEN_PATTERN).nullable().optional(),
  claim_lease_expires_at: z.string().datetime().nullable().optional(),
});

const FinalizeResponseSchema = z.looseObject({
  finalized: z.boolean(),
  reason_codes: z.array(boundedIdentifier).max(50).optional(),
});

const MAX_RESPONSE_BYTES = 100 * 1024;

interface ClaimRecord {
  readonly executionToken: string;
  readonly claimToken: string;
  readonly commitCorrelationId: string;
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
      const claimExpiryMs = claims.exp * 1_000;
      const decisionExpirySeconds = Math.floor(
        Date.parse(decision.authorization.expiresAt) / 1_000,
      );
      const audience = `${captured.intent.downstreamTarget.system}:${captured.intent.downstreamTarget.operation}`;
      if (
        parsed.should_execute === false ||
        typeof parsed.claim_token !== "string" ||
        claims.binding.intent_hash !== captured.intentHash ||
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
        }),
        signal: controller.signal,
      });
      if (!response.ok) return "PENDING";
      const text = await BoundedResponseBody.read(response, MAX_RESPONSE_BYTES);
      if (text === null) return "PENDING";
      const parsed = FinalizeResponseSchema.parse(JSON.parse(text));
      if (!parsed.finalized) return "PENDING";
      this.claims.delete(input.authorization);
      return "RECORDED";
    } catch {
      return "PENDING";
    } finally {
      clearTimeout(timeout);
    }
  }
}

function hasNoControlCharacters(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || codeUnit === 0x7f) return false;
  }
  return true;
}
