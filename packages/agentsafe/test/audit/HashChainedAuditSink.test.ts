import { AuditRecorder, IntentCapture } from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { CHAIN_GENESIS, HashChain } from "../../src/audit/HashChain.js";
import { EVIDENCE_STREAM, HashChainedAuditSink } from "../../src/audit/HashChainedAuditSink.js";
import { RequestContext } from "../../src/http/RequestContext.js";
import { verifyAuditChain } from "../../src/verify/VerifyAuditChain.js";
import { TENANT_ID } from "../support/Environment.js";

const captured = new IntentCapture({ ttlSeconds: 300 }).capture(
  { action: "forward_request", target: "payout:synthetic-beneficiary-1", parameters: {} },
  {
    tenantId: TENANT_ID,
    actor: { id: "synthetic-payout-agent", type: "AI_AGENT" },
    downstreamTarget: { system: "payout-rail", operation: "create_payout", environment: "local" },
    context: {},
    idempotencyKey: "payout-1-v1",
    correlationId: "synthetic-run-1",
  },
);

describe("HashChainedAuditSink", () => {
  it("links the audit fields and the caller on the evidence chain, in order", async () => {
    const lines: string[] = [];
    const chain = new HashChain(EVIDENCE_STREAM);
    const recorder = new AuditRecorder({
      sink: new HashChainedAuditSink((line) => lines.push(line), chain),
    });
    expect(await recorder.record({ eventType: "INTENT_CAPTURED", captured })).toBe(true);
    await RequestContext.run({ principal: "legacy-caller" }, async () => {
      expect(await recorder.record({ eventType: "INTENT_CAPTURED", captured })).toBe(true);
    });
    expect(lines).toHaveLength(2);
    const first = JSON.parse(lines[0] ?? "{}") as Record<string, unknown>;
    const second = JSON.parse(lines[1] ?? "{}") as Record<string, unknown>;
    expect(Object.keys(first)).toEqual([
      "stream",
      "seq",
      "prev_hash",
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
      "caller_principal",
      "hash",
    ]);
    expect(first).toMatchObject({
      stream: EVIDENCE_STREAM,
      seq: 1,
      prev_hash: CHAIN_GENESIS,
      event: "INTENT_CAPTURED",
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      correlation_id: "synthetic-run-1",
      caller_principal: null,
    });
    expect(second).toMatchObject({
      seq: 2,
      prev_hash: first["hash"],
      caller_principal: "legacy-caller",
    });
    expect(lines[0]).not.toContain("payout:synthetic-beneficiary-1");
    expect(verifyAuditChain(lines).ok).toBe(true);
    expect(chain.head).toEqual({ seq: 2, hash: second["hash"] });
  });

  it("takes the scope from whatever the executor injects", async () => {
    const lines: string[] = [];
    const sink = new HashChainedAuditSink(
      (line) => lines.push(line),
      new HashChain(EVIDENCE_STREAM),
      () => ({ principal: "injected" }),
    );
    await new AuditRecorder({ sink }).record({ eventType: "INTENT_CAPTURED", captured });
    expect(JSON.parse(lines[0] ?? "{}")).toMatchObject({ caller_principal: "injected" });
  });
});
