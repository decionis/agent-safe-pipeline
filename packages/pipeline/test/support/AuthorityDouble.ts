import { IntentCapture, type IntentCaptureOptions } from "../../src/intent/IntentCapture.js";
import type { CapturedIntent } from "../../src/intent/ExecutionIntent.js";
import type {
  DecisionAuthority,
  DecisionEvaluationMode,
  DecisionVerdict,
  GateDecision,
} from "../../src/decision/DecisionAuthority.js";
import { immutableGateDecision } from "../../src/decision/ImmutableGateDecision.js";

export const TENANT_ID = "00000000-0000-4000-8000-000000000002";

export function captured(options: IntentCaptureOptions = {}): CapturedIntent {
  return new IntentCapture(options).capture(
    { action: "deploy", target: "github:repo:main", parameters: { environment: "production" } },
    {
      tenantId: TENANT_ID,
      actor: { id: "synthetic-deploy-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "github", operation: "deploy" },
      idempotencyKey: "deploy-1",
      context: {},
    },
  );
}

/** A complete `ExecutionAuthorityDecision` body as the Decionis contract documents it. */
export function decisionBody(intent: CapturedIntent, overrides: Record<string, unknown> = {}) {
  return {
    decision_id: "decision-1",
    chain_id: "chain-1",
    status: "ALLOW",
    should_execute: true,
    reason_codes: ["POLICY_ALLOW"],
    action_hash: intent.intentHash,
    policy_version: "policy-2026.09",
    mode: "ENFORCEMENT",
    execution_token: "token",
    execution_token_expires_at: intent.intent.expiresAt,
    dossier_id: "dossier-1",
    dossier_sha256: `sha256:${"a".repeat(64)}`,
    dossier_url: "/v1/protocol/dossiers/dossier-1",
    approval_request_id: null,
    ledger_entry_id: "ledger-1",
    ...overrides,
  };
}

/** The same body for a verdict that carries no grant, in the mode Decionis was asked for. */
export function verdictBody(
  intent: CapturedIntent,
  status: "ALLOW" | "ESCALATE" | "BLOCK",
  mode: DecisionEvaluationMode = "ENFORCEMENT",
) {
  if (status === "ALLOW" && mode === "ENFORCEMENT") return decisionBody(intent);
  return decisionBody(intent, {
    status,
    should_execute: false,
    reason_codes: [`POLICY_${status}`],
    mode,
    execution_token: null,
    execution_token_expires_at: null,
  });
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

/** An authority that answers with a fixed verdict about whatever it is asked. */
export function stubAuthority(
  verdict: DecisionVerdict,
  overrides: Partial<GateDecision> = {},
): DecisionAuthority {
  return {
    evaluate: async (intent) =>
      immutableGateDecision({
        verdict,
        decisionId: `stub-${verdict.toLowerCase()}`,
        dossierId: `stub-dossier-${verdict.toLowerCase()}`,
        intentHash: intent.intentHash,
        reasonCodes: [`STUB_${verdict}`],
        authorization:
          verdict === "ALLOW" ? { token: "stub-token", expiresAt: intent.intent.expiresAt } : null,
        failClosed: false,
        ...overrides,
      }),
  };
}
