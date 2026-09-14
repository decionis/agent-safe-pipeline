import { AuditRecorder, IntentCapture } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { LineAuditSink } from "../../src/audit/LineAuditSink.js";
import { TENANT_ID } from "../support/Environment.js";

describe("LineAuditSink", () => {
  it("writes one line per event with identifiers and digests only", async () => {
    const lines: string[] = [];
    const recorder = new AuditRecorder({ sink: new LineAuditSink((line) => lines.push(line)) });
    const captured = new IntentCapture({ ttlSeconds: 300 }).capture(
      { action: "forward_request", target: "payout:synthetic-beneficiary-1", parameters: {} },
      {
        tenantId: TENANT_ID,
        actor: { id: "synthetic-payout-agent", type: "AI_AGENT" },
        downstreamTarget: {
          system: "payout-rail",
          operation: "create_payout",
          environment: "local",
        },
        context: {},
        idempotencyKey: "payout-1-v1",
        correlationId: "synthetic-run-1",
      },
    );
    expect(await recorder.record({ eventType: "INTENT_CAPTURED", captured })).toBe(true);
    expect(lines).toHaveLength(1);
    const line = JSON.parse(lines[0] ?? "{}") as Record<string, unknown>;
    expect(Object.keys(line)).toEqual([
      "at",
      "event",
      "authority",
      "verdict",
      "reason_codes",
      "intent_id",
      "intent_hash",
      "correlation_id",
      "decision_id",
      "dossier_id",
      "grant_id",
      "duration_ms",
    ]);
    expect(line).toMatchObject({
      event: "INTENT_CAPTURED",
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      correlation_id: "synthetic-run-1",
      decision_id: null,
      dossier_id: null,
      grant_id: null,
    });
    expect(lines[0]).not.toContain("payout:synthetic-beneficiary-1");
  });
});
