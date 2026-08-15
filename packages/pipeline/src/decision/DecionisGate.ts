import { z } from "zod";
import { AuthorityBaseUrl } from "../http/AuthorityBaseUrl.js";
import { BoundedResponseBody } from "../http/BoundedResponseBody.js";
import { CanonicalIntentHasher } from "../intent/CanonicalIntentHasher.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import {
  FailClosedDecision,
  type DecisionAuthority,
  type DecisionEvidence,
  type GateDecision,
} from "./DecisionAuthority.js";

const reasonCode = z
  .string()
  .min(1)
  .max(120)
  .regex(/^[A-Z][A-Z0-9_:-]*$/);

const AuthorityResponseSchema = z
  .object({
    decision_id: z.string().min(1).max(200),
    status: z.enum(["ALLOW", "BLOCK", "ESCALATE", "REVIEW_REQUIRED", "ERROR"]),
    should_execute: z.boolean(),
    reason_codes: z.array(reasonCode).max(50),
    action_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    execution_token: z
      .string()
      .min(1)
      .max(100 * 1024)
      .nullable(),
    execution_token_expires_at: z.string().datetime().nullable(),
    dossier_id: z.string().min(1).max(200).nullable(),
  })
  .strict();

const MAX_RESPONSE_BYTES = 100 * 1024;

export interface DecionisGateOptions {
  readonly baseUrl: string;
  readonly apiKey: string;
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
  readonly allowInsecureLoopback?: boolean;
}

export class DecionisGate implements DecisionAuthority {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  public constructor(options: DecionisGateOptions) {
    this.baseUrl = AuthorityBaseUrl.normalize(
      options.baseUrl,
      options.allowInsecureLoopback === true,
    );
    this.apiKey = options.apiKey;
    this.timeoutMs = Math.min(Math.max(options.timeoutMs ?? 4_000, 1), 15_000);
    this.fetchImpl = options.fetch ?? fetch;
  }

  public async evaluate(
    captured: CapturedIntent,
    evidence?: DecisionEvidence,
  ): Promise<GateDecision> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(`${this.baseUrl}/v1/authority/enforce-and-bind`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.apiKey}`,
          "content-type": "application/json",
          "idempotency-key": captured.intent.idempotencyKey,
        },
        body: JSON.stringify({
          ...CanonicalIntentHasher.bindingOf(captured.intent),
          intent_hash: captured.intentHash,
          mode: "ENFORCEMENT",
          ...(evidence === undefined ? {} : { evidence }),
        }),
        signal: controller.signal,
      });
      if (!response.ok) {
        return FailClosedDecision.create(captured.intentHash, "AUTHORITY_REQUEST_FAILED");
      }
      const text = await BoundedResponseBody.read(response, MAX_RESPONSE_BYTES);
      if (text === null) {
        return FailClosedDecision.create(captured.intentHash, "AUTHORITY_RESPONSE_TOO_LARGE");
      }
      const parsed = AuthorityResponseSchema.parse(JSON.parse(text));
      if (parsed.action_hash !== captured.intentHash) {
        return FailClosedDecision.create(captured.intentHash, "AUTHORITY_BINDING_MISMATCH");
      }
      const verdict =
        parsed.status === "ALLOW"
          ? "ALLOW"
          : parsed.status === "ESCALATE" || parsed.status === "REVIEW_REQUIRED"
            ? "ESCALATE"
            : "BLOCK";
      const canExecute =
        verdict === "ALLOW" &&
        parsed.should_execute &&
        parsed.dossier_id !== null &&
        parsed.execution_token !== null &&
        parsed.execution_token_expires_at !== null &&
        Date.parse(parsed.execution_token_expires_at) > Date.now() &&
        Date.parse(parsed.execution_token_expires_at) <= Date.parse(captured.intent.expiresAt);
      if (verdict === "ALLOW" && !canExecute) {
        return FailClosedDecision.create(captured.intentHash, "AUTHORITY_GRANT_MISSING");
      }
      return Object.freeze({
        verdict,
        decisionId: parsed.decision_id,
        dossierId: parsed.dossier_id,
        intentHash: parsed.action_hash,
        reasonCodes: parsed.reason_codes,
        authorization: canExecute
          ? {
              token: parsed.execution_token as string,
              expiresAt: parsed.execution_token_expires_at as string,
            }
          : null,
        failClosed: parsed.status === "ERROR",
      });
    } catch {
      return FailClosedDecision.create(captured.intentHash, "AUTHORITY_UNAVAILABLE");
    } finally {
      clearTimeout(timeout);
    }
  }
}
