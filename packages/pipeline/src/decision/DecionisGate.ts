import { z } from "zod";
import { AuthorityBaseUrl } from "../http/AuthorityBaseUrl.js";
import { BoundedResponseBody } from "../http/BoundedResponseBody.js";
import { CanonicalIntentHasher } from "../intent/CanonicalIntentHasher.js";
import type { CapturedIntent } from "../intent/ExecutionIntent.js";
import {
  FailClosedDecision,
  type DecisionAuthority,
  type DecisionEvaluationMode,
  type DecisionEvidence,
  type GateDecision,
} from "./DecisionAuthority.js";
import { immutableGateDecision } from "./ImmutableGateDecision.js";

const boundedIdentifier = z
  .string()
  .min(1)
  .max(200)
  .refine(hasNoControlCharacters, { message: "IDENTIFIER_INVALID" });

/**
 * Mirrors `ExecutionAuthorityDecision` in the Decionis OpenAPI contract, which
 * declares `additionalProperties: false`; an undocumented field therefore fails
 * closed instead of being interpreted as execution semantics.
 */
const AuthorityResponseSchema = z
  .object({
    decision_id: boundedIdentifier,
    chain_id: boundedIdentifier.nullable(),
    status: z.enum(["ALLOW", "BLOCK", "ESCALATE", "REVIEW_REQUIRED", "ERROR"]),
    should_execute: z.boolean(),
    reason_codes: z.array(boundedIdentifier).max(50),
    action_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    policy_version: boundedIdentifier.nullable().optional(),
    mode: z.enum(["SHADOW", "PARALLEL", "ENFORCEMENT"]).nullable().optional(),
    execution_token: z.string().min(1).max(20_000).nullable(),
    execution_token_expires_at: z.string().datetime().nullable(),
    dossier_id: boundedIdentifier.nullable(),
    dossier_sha256: boundedIdentifier.nullable().optional(),
    dossier_url: z.string().min(1).max(2_000).nullable(),
    approval_request_id: boundedIdentifier.nullable().optional(),
    ledger_entry_id: boundedIdentifier.nullable().optional(),
  })
  .strict();

const MAX_RESPONSE_BYTES = 100 * 1024;

export interface DecionisGateOptions {
  readonly baseUrl: string;
  readonly apiKey: string;
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
  readonly allowInsecureLoopback?: boolean;
  /**
   * `ENFORCEMENT` (default) asks Decionis for an executable decision.
   * `SHADOW` asks Decionis to evaluate and record the exact intent without
   * issuing a grant; the gate then never returns an authorization, even if a
   * response carries one.
   */
  readonly mode?: DecisionEvaluationMode;
}

export class DecionisGate implements DecisionAuthority {
  public readonly evaluationMode: DecisionEvaluationMode;
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
    const mode = options.mode ?? "ENFORCEMENT";
    if (mode !== "ENFORCEMENT" && mode !== "SHADOW") {
      throw new Error("DECIONIS_GATE_MODE_INVALID");
    }
    this.evaluationMode = mode;
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
          // The contract requires the header to equal the signed intent_id;
          // intent_id is the authority's grant-issuance boundary.
          "idempotency-key": captured.intent.intentId,
        },
        body: JSON.stringify({
          ...CanonicalIntentHasher.bindingOf(captured.intent),
          intent_hash: captured.intentHash,
          mode: this.evaluationMode,
          ...(evidence === undefined ? {} : { evidence }),
        }),
        signal: controller.signal,
      });
      const text = await BoundedResponseBody.read(response, MAX_RESPONSE_BYTES);
      if (text === null) {
        return FailClosedDecision.create(captured.intentHash, "AUTHORITY_RESPONSE_TOO_LARGE");
      }
      if (!response.ok) {
        return DecionisGate.failedResponse(captured, text);
      }
      const parsed = AuthorityResponseSchema.parse(JSON.parse(text));
      if (parsed.action_hash !== captured.intentHash) {
        return FailClosedDecision.create(captured.intentHash, "AUTHORITY_BINDING_MISMATCH");
      }
      const mode = parsed.mode ?? null;
      if (mode !== null && mode !== this.evaluationMode) {
        return FailClosedDecision.create(captured.intentHash, "AUTHORITY_MODE_MISMATCH");
      }
      const verdict =
        parsed.status === "ALLOW"
          ? "ALLOW"
          : parsed.status === "ESCALATE" || parsed.status === "REVIEW_REQUIRED"
            ? "ESCALATE"
            : "BLOCK";
      if (this.evaluationMode === "SHADOW") {
        // Observational traffic never yields execution authority. A token in a
        // shadow response is discarded here so it cannot reach a verifier.
        return immutableGateDecision({
          verdict,
          decisionId: parsed.decision_id,
          dossierId: parsed.dossier_id,
          intentHash: parsed.action_hash,
          reasonCodes: parsed.reason_codes,
          authorization: null,
          failClosed: parsed.status === "ERROR",
          ...(evidence === undefined ? {} : { evidence }),
        });
      }
      const canExecute =
        verdict === "ALLOW" &&
        parsed.should_execute &&
        mode === "ENFORCEMENT" &&
        parsed.dossier_id !== null &&
        parsed.execution_token !== null &&
        parsed.execution_token_expires_at !== null &&
        Date.parse(parsed.execution_token_expires_at) > Date.now() &&
        Date.parse(parsed.execution_token_expires_at) <= Date.parse(captured.intent.expiresAt);
      if (verdict === "ALLOW" && !canExecute) {
        return FailClosedDecision.create(captured.intentHash, "AUTHORITY_GRANT_MISSING");
      }
      return immutableGateDecision({
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
        ...(evidence === undefined ? {} : { evidence }),
      });
    } catch {
      return FailClosedDecision.create(captured.intentHash, "AUTHORITY_UNAVAILABLE");
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * The contract returns an `ERROR` decision body on 409 and 503 so the
   * refusal is evidence-bearing. Anything else fails closed generically.
   */
  private static failedResponse(captured: CapturedIntent, text: string): GateDecision {
    try {
      const parsed = AuthorityResponseSchema.parse(JSON.parse(text));
      if (parsed.status !== "ERROR" || parsed.action_hash !== captured.intentHash) {
        return FailClosedDecision.create(captured.intentHash, "AUTHORITY_REQUEST_FAILED");
      }
      return immutableGateDecision({
        verdict: "BLOCK",
        decisionId: parsed.decision_id,
        dossierId: parsed.dossier_id,
        intentHash: captured.intentHash,
        reasonCodes:
          parsed.reason_codes.length === 0 ? ["AUTHORITY_REQUEST_FAILED"] : parsed.reason_codes,
        authorization: null,
        failClosed: true,
      });
    } catch {
      return FailClosedDecision.create(captured.intentHash, "AUTHORITY_REQUEST_FAILED");
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
