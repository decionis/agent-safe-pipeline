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

export interface AuthorizationVerifier {
  verifyAndConsume(
    captured: CapturedIntent,
    decision: GateDecision,
  ): Promise<VerifiedAuthorization | null>;
}

const ConsumeResponseSchema = z
  .object({
    valid: z.literal(true),
    claims: z
      .object({
        jti: z.string().min(1).max(200),
        decision_id: z.string().min(1).max(200),
        dossier_id: z.string().min(1).max(200),
        exp: z.number().int().positive(),
        binding: z.object({ intent_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/) }).strict(),
      })
      .strict(),
  })
  .strict();

const MAX_RESPONSE_BYTES = 100 * 1024;

export interface DecionisGrantVerifierOptions {
  readonly baseUrl: string;
  readonly apiKey: string;
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
  readonly allowInsecureLoopback?: boolean;
}

export class DecionisGrantVerifier implements AuthorizationVerifier {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

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
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(`${this.baseUrl}/v1/execution/consume-token`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.apiKey}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          execution_token: decision.authorization.token,
          intent_hash: captured.intentHash,
          intent: CanonicalIntentHasher.bindingOf(captured.intent),
          consumed_by: captured.intent.actor.id,
        }),
        signal: controller.signal,
      });
      if (!response.ok) return null;
      const text = await BoundedResponseBody.read(response, MAX_RESPONSE_BYTES);
      if (text === null) return null;
      const parsed = ConsumeResponseSchema.parse(JSON.parse(text));
      const claimExpiryMs = parsed.claims.exp * 1_000;
      const decisionExpirySeconds = Math.floor(
        Date.parse(decision.authorization.expiresAt) / 1_000,
      );
      if (
        parsed.claims.binding.intent_hash !== captured.intentHash ||
        parsed.claims.decision_id !== decision.decisionId ||
        parsed.claims.dossier_id !== decision.dossierId ||
        parsed.claims.exp !== decisionExpirySeconds ||
        claimExpiryMs <= Date.now() ||
        claimExpiryMs > Date.parse(captured.intent.expiresAt)
      ) {
        return null;
      }
      return Object.freeze({
        decisionId: parsed.claims.decision_id,
        dossierId: parsed.claims.dossier_id,
        grantId: parsed.claims.jti,
        intentHash: parsed.claims.binding.intent_hash,
        expiresAt: new Date(parsed.claims.exp * 1_000).toISOString(),
      });
    } catch {
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }
}
