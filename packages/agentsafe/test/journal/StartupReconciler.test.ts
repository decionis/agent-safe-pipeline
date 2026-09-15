import {
  ActionRegistry,
  IntentCapture,
  JsonObjectSchema,
  type ActionHandler,
  type JsonObject,
  type ProviderReconciliation,
} from "@decionis/agent-safe-pipeline";
import { describe, expect, it, vi } from "vitest";
import { InMemoryExecutionJournal } from "../../src/journal/InMemoryExecutionJournal.js";
import { StartupReconciler } from "../../src/journal/StartupReconciler.js";
import { collectedEvents, TENANT_ID } from "../support/Environment.js";
import type { JournalRecord } from "../../src/journal/ExecutionJournal.js";

const captured = (key: string) =>
  new IntentCapture({ ttlSeconds: 300 }).capture(
    {
      action: "forward_request",
      target: `payout:synthetic-beneficiary-${key}`,
      parameters: { amountMinor: 2_500, currency: "CHF" },
    },
    {
      tenantId: TENANT_ID,
      actor: { id: "synthetic-payout-agent", type: "AI_AGENT" },
      downstreamTarget: {
        system: "payout-rail",
        operation: "create_payout",
        environment: "local",
      },
      context: { caller_principal: "synthetic-treasury-workflow" },
      idempotencyKey: key,
    },
  );

function records(
  key: string,
  options: { readonly claimed?: boolean; readonly intent?: Record<string, unknown> } = {},
): { readonly records: JournalRecord[]; readonly intentId: string; readonly intentHash: string } {
  const intent = captured(key);
  const opened: JournalRecord = {
    record: "ATTEMPT_OPENED",
    at: "2026-09-15T10:00:00.000Z",
    intent_id: intent.intent.intentId,
    intent_hash: intent.intentHash,
    idempotency_key: key,
    decision_id: "decision-1",
    dossier_id: "dossier-1",
    caller_principal: "synthetic-treasury-workflow",
    intent: options.intent ?? (intent.intent as unknown as Record<string, unknown>),
  };
  const claimed: JournalRecord = {
    record: "GRANT_CLAIMED",
    at: "2026-09-15T10:00:00.500Z",
    intent_id: intent.intent.intentId,
    intent_hash: intent.intentHash,
    idempotency_key: key,
    grant_id: "grant-1",
    expires_at: intent.intent.expiresAt,
    request_digest: `sha256:${"d".repeat(64)}`,
  };
  return {
    records: options.claimed === false ? [opened] : [opened, claimed],
    intentId: intent.intent.intentId,
    intentHash: intent.intentHash,
  };
}

type Reconciler = () => Promise<ProviderReconciliation<unknown>>;

function registry(reconcile?: Reconciler): ActionRegistry {
  const handler: ActionHandler<JsonObject, unknown> = {
    parametersSchema: JsonObjectSchema,
    execute: () => {
      throw new Error("the reconciler must never execute");
    },
    ...(reconcile === undefined ? {} : { reconcile: async () => await reconcile() }),
  };
  return new ActionRegistry().register("forward_request", handler).seal();
}

async function recover(
  journalRecords: JournalRecord[],
  reconcile?: Reconciler,
): Promise<{
  readonly report: Awaited<ReturnType<StartupReconciler["recover"]>>;
  readonly journal: InMemoryExecutionJournal;
  readonly lines: string[];
}> {
  const journal = new InMemoryExecutionJournal();
  for (const record of journalRecords) await journal.append(record);
  const lines: string[] = [];
  const report = await new StartupReconciler({
    journal,
    registry: registry(reconcile),
    events: collectedEvents(lines),
    clock: () => new Date("2026-09-15T10:05:00.000Z"),
  }).recover();
  return { report, journal, lines };
}

const events = (lines: string[]): Record<string, unknown>[] =>
  lines.map((line) => JSON.parse(line) as Record<string, unknown>);

describe("StartupReconciler", () => {
  it("has nothing to do when the journal is empty", async () => {
    const { report, lines } = await recover([]);
    expect(report).toEqual({ attempts: [], unknown: 0 });
    expect(lines).toEqual([]);
  });

  it("asks the provider what it did with a claimed attempt, and records the answer", async () => {
    const attempt = records("payout-1-v1");
    const reconcile = vi.fn<Reconciler>(async () => ({
      status: "COMPLETED",
      result: { status: 200 },
    }));
    const { report, journal, lines } = await recover(attempt.records, reconcile);
    expect(report.unknown).toBe(0);
    expect(report.attempts).toEqual([
      expect.objectContaining({
        intentId: attempt.intentId,
        intentHash: attempt.intentHash,
        idempotencyKey: "payout-1-v1",
        state: "CLAIMED",
        resolution: "RECONCILED_COMPLETED",
      }),
    ]);
    expect(reconcile).toHaveBeenCalledTimes(1);
    expect(journal.all.at(-1)).toEqual({
      record: "RECONCILED",
      at: "2026-09-15T10:05:00.000Z",
      intent_id: attempt.intentId,
      intent_hash: attempt.intentHash,
      status: "COMPLETED",
      source: "STARTUP",
    });
    expect(await journal.openAttempts()).toEqual([]);
    expect(
      events(lines).map(
        (event) => `${String(event["event"])}:${String(event["state"] ?? event["resolution"])}`,
      ),
    ).toEqual([
      "OPEN_ATTEMPT_FOUND_AT_STARTUP:CLAIMED",
      "OPEN_ATTEMPT_RESOLVED:RECONCILED_COMPLETED",
    ]);
  });

  it("records a provider that confirms it never acted, and leaves one that cannot say", async () => {
    const notExecuted = await recover(
      records("payout-2-v1").records,
      vi.fn<Reconciler>(async () => ({ status: "NOT_EXECUTED" })),
    );
    expect(notExecuted.report.attempts[0]?.resolution).toBe("RECONCILED_NOT_EXECUTED");
    expect(notExecuted.report.unknown).toBe(0);
    expect(notExecuted.journal.all.at(-1)).toMatchObject({ status: "DEFINITELY_NOT_EXECUTED" });
    const unknown = await recover(
      records("payout-3-v1").records,
      vi.fn<Reconciler>(async () => ({ status: "UNKNOWN" })),
    );
    expect(unknown.report.attempts[0]?.resolution).toBe("STILL_UNKNOWN");
    expect(unknown.report.unknown).toBe(1);
    // Nothing is written for an attempt still unresolved: the next start asks again.
    expect(unknown.journal.all.map((record) => record.record)).toEqual([
      "ATTEMPT_OPENED",
      "GRANT_CLAIMED",
    ]);
    const noLookup = await recover(records("payout-4-v1").records);
    expect(noLookup.report.attempts[0]?.resolution).toBe("STILL_UNKNOWN");
  });

  it("never asks the provider about an attempt that claimed no grant, and closes it", async () => {
    const attempt = records("payout-5-v1", { claimed: false });
    const reconcile = vi.fn<Reconciler>(async () => ({ status: "COMPLETED", result: 1 }));
    const { report, journal } = await recover(attempt.records, reconcile);
    expect(report.attempts[0]).toMatchObject({ state: "OPENED", resolution: "UNCLAIMED" });
    expect(report.unknown).toBe(0);
    expect(reconcile).not.toHaveBeenCalled();
    expect(journal.all.at(-1)).toMatchObject({ status: "BLOCKED", source: "STARTUP" });
  });

  it("refuses a stored intent that no longer hashes to its record, and asks nothing", async () => {
    const attempt = records("payout-6-v1");
    const tampered = attempt.records.map((record) =>
      record.record === "ATTEMPT_OPENED"
        ? {
            ...record,
            intent: {
              ...(record.intent as Record<string, unknown>),
              parameters: { amountMinor: 9_999_999, currency: "CHF" },
            },
          }
        : record,
    );
    const reconcile = vi.fn<Reconciler>(async () => ({ status: "COMPLETED", result: 1 }));
    const { report, journal } = await recover(tampered, reconcile);
    expect(report.attempts[0]?.resolution).toBe("BINDING_MISMATCH");
    expect(reconcile).not.toHaveBeenCalled();
    expect(journal.all.map((record) => record.record)).toEqual(["ATTEMPT_OPENED", "GRANT_CLAIMED"]);
    const notAnIntent = await recover(
      records("payout-7-v1", { intent: { not: "an intent" } }).records,
      reconcile,
    );
    expect(notAnIntent.report.attempts[0]?.resolution).toBe("BINDING_MISMATCH");
  });

  it("resolves every attempt it finds, oldest first", async () => {
    const first = records("payout-8-v1");
    const second = records("payout-9-v1", { claimed: false });
    const reconcile = vi.fn<Reconciler>(async () => ({ status: "UNKNOWN" }));
    const { report } = await recover([...first.records, ...second.records], reconcile);
    expect(report.attempts.map((attempt) => [attempt.idempotencyKey, attempt.resolution])).toEqual([
      ["payout-8-v1", "STILL_UNKNOWN"],
      ["payout-9-v1", "UNCLAIMED"],
    ]);
    expect(report.unknown).toBe(1);
  });
});
