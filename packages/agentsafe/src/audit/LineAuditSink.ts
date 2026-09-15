import type { AuditEventV1, AuditSink } from "@decionis/agent-safe-pipeline";
import type { ChainFields } from "./HashChain.js";

export type LineWriter = (line: string) => void;

/**
 * The executor's evidence line: identifiers, digests, the verdict, and
 * reason codes from one lifecycle event. The recorder has already bounded
 * and redacted the event; this adds nothing from the request, the response,
 * or the process environment. Under the executor's failure policy, nothing
 * executes unless its events were written. The chained sink wraps these
 * same fields; this unchained form is for a sink that chains elsewhere.
 */
export class LineAuditSink implements AuditSink {
  public constructor(private readonly emit: LineWriter) {}

  /** The fields, in the order the line carries them. */
  public static fields(event: AuditEventV1): ChainFields {
    return {
      at: event.occurredAt,
      event: event.eventType,
      authority: event.authority,
      verdict: event.verdict,
      reason_codes: [...event.reasonCodes],
      intent_id: event.correlation.intentId,
      intent_hash: event.correlation.intentHash,
      correlation_id: event.correlation.correlationId ?? null,
      decision_id: event.correlation.decisionId ?? null,
      dossier_id: event.correlation.dossierId ?? null,
      grant_id: event.correlation.grantId ?? null,
      duration_ms: event.durationMs,
    };
  }

  public write(event: AuditEventV1): void {
    this.emit(JSON.stringify(LineAuditSink.fields(event)));
  }
}
