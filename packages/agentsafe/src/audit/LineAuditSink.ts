import type { AuditEventV1, AuditSink } from "@decionis/agent-safe-pipeline";

export type LineWriter = (line: string) => void;

/**
 * The executor's evidence stream: one JSON line per lifecycle event with
 * identifiers, digests, the verdict, and reason codes. The recorder has
 * already bounded and redacted the event; this sink adds nothing from the
 * request, the response, or the process environment. Under the executor's
 * failure policy, nothing executes unless its events were written.
 */
export class LineAuditSink implements AuditSink {
  public constructor(private readonly emit: LineWriter) {}

  public write(event: AuditEventV1): void {
    this.emit(
      JSON.stringify({
        at: event.occurredAt,
        event: event.eventType,
        authority: event.authority,
        verdict: event.verdict,
        reason_codes: event.reasonCodes,
        intent_id: event.correlation.intentId,
        intent_hash: event.correlation.intentHash,
        correlation_id: event.correlation.correlationId ?? null,
        decision_id: event.correlation.decisionId ?? null,
        dossier_id: event.correlation.dossierId ?? null,
        grant_id: event.correlation.grantId ?? null,
        duration_ms: event.durationMs,
      }),
    );
  }
}
