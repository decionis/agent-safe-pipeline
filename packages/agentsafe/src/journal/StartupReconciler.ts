import {
  CanonicalIntentHasher,
  ExecutionIntentSchema,
  type ActionRegistry,
  type CapturedIntent,
} from "@decionis/agent-safe-pipeline";
import type { SecurityEvents } from "../incident/SecurityEvents.js";
import type { ExecutionJournal, OpenAttempt } from "./ExecutionJournal.js";

export type AttemptResolution =
  | "RECONCILED_COMPLETED"
  | "RECONCILED_NOT_EXECUTED"
  | "STILL_UNKNOWN"
  | "UNCLAIMED"
  | "BINDING_MISMATCH";

export interface ResolvedAttempt {
  readonly intentId: string;
  readonly intentHash: string;
  readonly idempotencyKey: string;
  readonly openedAt: string;
  readonly state: OpenAttempt["state"];
  readonly resolution: AttemptResolution;
}

export interface RecoveryReport {
  readonly attempts: readonly ResolvedAttempt[];
  /** Attempts whose outcome is still not known; `/ready` can be made to wait on these. */
  readonly unknown: number;
}

export interface StartupReconcilerOptions {
  readonly journal: ExecutionJournal;
  readonly registry: ActionRegistry;
  readonly events: SecurityEvents;
  readonly clock?: () => Date;
}

/**
 * What the last process left behind, resolved before this one accepts a
 * request. Every attempt the journal has open is read back, its stored
 * intent re-hashed rather than trusted, and the provider asked what it did
 * with that idempotency key, read-only. Nothing is ever re-executed here:
 * the reconciler calls the registry's read path, never the execute path.
 *
 * An attempt that was opened but never claimed had no grant consumed, so
 * the provider was never reached; the authority's own lease recovery owns
 * it and this process says so rather than guessing. An attempt whose stored
 * intent no longer hashes to its recorded hash is a tampered journal and is
 * reported as such.
 */
export class StartupReconciler {
  private readonly hasher = new CanonicalIntentHasher();
  private readonly clock: () => Date;

  public constructor(private readonly options: StartupReconcilerOptions) {
    this.clock = options.clock ?? (() => new Date());
  }

  public async recover(): Promise<RecoveryReport> {
    const open = await this.options.journal.openAttempts();
    const attempts: ResolvedAttempt[] = [];
    for (const attempt of open) {
      this.options.events.emit({
        event: "OPEN_ATTEMPT_FOUND_AT_STARTUP",
        intent_id: attempt.intentId,
        state: attempt.state,
      });
      const resolution = await this.resolve(attempt);
      attempts.push({
        intentId: attempt.intentId,
        intentHash: attempt.intentHash,
        idempotencyKey: attempt.idempotencyKey,
        openedAt: attempt.openedAt,
        state: attempt.state,
        resolution,
      });
      this.options.events.emit({
        event: "OPEN_ATTEMPT_RESOLVED",
        intent_id: attempt.intentId,
        resolution,
      });
    }
    return {
      attempts,
      unknown: attempts.filter((attempt) => attempt.resolution === "STILL_UNKNOWN").length,
    };
  }

  private async resolve(attempt: OpenAttempt): Promise<AttemptResolution> {
    if (attempt.state === "OPENED") {
      await this.close(attempt, "BLOCKED");
      return "UNCLAIMED";
    }
    let captured: CapturedIntent;
    try {
      captured = this.hasher.capture(ExecutionIntentSchema.parse(attempt.intent));
    } catch {
      return "BINDING_MISMATCH";
    }
    if (captured.intentHash !== attempt.intentHash) return "BINDING_MISMATCH";
    const reconciliation = await this.options.registry.reconcile(captured, attempt.idempotencyKey);
    if (reconciliation.status === "COMPLETED") {
      await this.close(attempt, "COMPLETED");
      return "RECONCILED_COMPLETED";
    }
    if (reconciliation.status === "NOT_EXECUTED") {
      await this.close(attempt, "DEFINITELY_NOT_EXECUTED");
      return "RECONCILED_NOT_EXECUTED";
    }
    return "STILL_UNKNOWN";
  }

  /** Records how the attempt ended, so the next start does not ask again. */
  private async close(
    attempt: OpenAttempt,
    status: "COMPLETED" | "DEFINITELY_NOT_EXECUTED" | "BLOCKED",
  ): Promise<void> {
    await this.options.journal.append({
      record: "RECONCILED",
      at: this.clock().toISOString(),
      intent_id: attempt.intentId,
      intent_hash: attempt.intentHash,
      status,
      source: "STARTUP",
    });
  }
}
