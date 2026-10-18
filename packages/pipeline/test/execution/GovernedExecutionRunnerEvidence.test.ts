import { describe, expect, it, vi } from "vitest";
import { AuditRecorder, type AuditEventV1 } from "../../src/audit/AuditRecorder.js";
import type { DecisionAuthority, DecisionGate } from "../../src/decision/DecisionAuthority.js";
import { immutableDecisionGate } from "../../src/decision/ImmutableDecisionGate.js";
import type {
  AuthorityEffectEvidence,
  AuthorizationFinalizationInput,
  AuthorizationReconciliationInput,
  AuthorizationVerifier,
  VerifiedAuthorization,
} from "../../src/execution/AuthorizationVerifier.js";
import {
  authorizationsFrom,
  openAttemptsFrom,
  type ExecutionJournal,
  type JournalRecord,
} from "../../src/execution/ExecutionJournal.js";
import type { ExecutorEvidenceLine } from "../../src/execution/ExecutorEvidence.js";
import {
  GovernedExecutionRunner,
  type GovernedExecutionRunnerOptions,
} from "../../src/execution/GovernedExecutionRunner.js";
import type {
  ClaimedExecution,
  EffectObservation,
  ExecutionCapability,
  ExecutionEffect,
  ExecutorScope,
  NativeExecutor,
  PreparedAction,
  ReconcileContext,
  ReconcileResult,
} from "../../src/execution/NativeExecutor.js";
import type { CapturedIntent } from "../../src/intent/ExecutionIntent.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import type { JsonObject } from "../../src/intent/JsonValue.js";

/**
 * The runner's records, held field by field: the evidence lines it writes,
 * the journal records it appends, the finalizations and reconciliation
 * reports it makes, and the settlements it returns. These are wire objects
 * and audit material, so every field is pinned, not sampled.
 */

const TENANT = "00000000-0000-4000-8000-000000000006";
const ACTOR = { id: "synthetic-evidence-agent", type: "agent" };
const ACTION: JsonObject = { line: "PAY-7", amount_minor: 900 };
const EFFECT = `sha256:${"e".repeat(64)}` as const;
const SCOPE: ExecutorScope = {
  orgId: TENANT,
  workspaceId: "workspace-7",
  connectionId: "connection-7",
  connectionRevision: "9",
  store: "fixture_store",
  environment: "sandbox",
};
const EVIDENCE_SCOPE = {
  org_id: TENANT,
  workspace_id: "workspace-7",
  connection_id: "connection-7",
  connection_revision: "9",
  environment: "sandbox",
};
const OBSERVATION_EVIDENCE: AuthorityEffectEvidence = {
  version: "1.0",
  status: "UNCONFIRMED",
  observation_method: "STATE_RECONCILIATION",
  observer: { id: "evidence-executor", version: "2" },
  expected_effect_digest: EFFECT,
  observed_effect_digest: null,
  observed_at: null,
  evidence_digest: null,
  evidence_reference: null,
  execution_correlation_id: "intent",
};

function prepared(action: JsonObject, overrides: Partial<PreparedAction> = {}): PreparedAction {
  return {
    actionType: "evidence.write",
    proposal: { action: "evidence.write", target: "ledger:7", parameters: action },
    downstreamTarget: { system: "evidence", operation: "write" },
    idempotencyKey: "evidence-key-7",
    expectedEffectDigest: null,
    requestDigest: `sha256:${"7".repeat(64)}`,
    facts: {},
    ...overrides,
  };
}

function capture(overrides: Partial<PreparedAction> = {}): CapturedIntent {
  const p = prepared(ACTION, overrides);
  return new IntentCapture().capture(p.proposal, {
    tenantId: TENANT,
    actor: ACTOR,
    downstreamTarget: p.downstreamTarget,
    context: p.facts,
    idempotencyKey: p.idempotencyKey,
    ...(p.expectedEffectDigest === null ? {} : { expectedEffectDigest: p.expectedEffectDigest }),
  });
}

function allow(captured: CapturedIntent, overrides: Partial<DecisionGate> = {}): DecisionGate {
  return immutableDecisionGate({
    verdict: "ALLOW",
    decisionId: "decision-7",
    dossierId: "dossier-7",
    intentHash: captured.intentHash,
    reasonCodes: [],
    authorization: { token: "token-7", expiresAt: captured.intent.expiresAt },
    failClosed: false,
    ...overrides,
  });
}

/** A verifier that grants what it is asked for and records every call, exactly. */
class RecordingVerifier implements AuthorizationVerifier {
  public readonly finalized: AuthorizationFinalizationInput[] = [];
  public readonly reconciled: AuthorizationReconciliationInput[] = [];
  public refuse = false;
  public extra: Partial<VerifiedAuthorization> = {};

  public async verifyAndConsume(
    captured: CapturedIntent,
    decision: DecisionGate,
  ): Promise<VerifiedAuthorization | null> {
    if (this.refuse || decision.authorization === null || decision.dossierId === null) return null;
    return Object.freeze({
      decisionId: decision.decisionId,
      dossierId: decision.dossierId,
      grantId: "grant-7",
      intentHash: captured.intentHash,
      expiresAt: decision.authorization.expiresAt,
      ...this.extra,
    });
  }

  public async finalize(input: AuthorizationFinalizationInput): Promise<"RECORDED"> {
    this.finalized.push(input);
    return "RECORDED";
  }

  public async reconcile(input: AuthorizationReconciliationInput): Promise<"RECORDED"> {
    this.reconciled.push(input);
    return "RECORDED";
  }
}

type Script = Partial<{
  capabilities: () => Promise<readonly ExecutionCapability[]>;
  prepare: (action: JsonObject) => Promise<PreparedAction>;
  execute: (run: ClaimedExecution<JsonObject>) => Promise<ExecutionEffect<JsonObject>>;
  observe: (effect: ExecutionEffect<JsonObject>) => Promise<EffectObservation<JsonObject>>;
  reconcile: (context: ReconcileContext) => Promise<ReconcileResult<JsonObject>>;
}>;

class Executor implements NativeExecutor<JsonObject, JsonObject, JsonObject> {
  public readonly platform = "evidence-platform";
  public readonly version = "2.0.0";
  public readonly actionTypes = ["evidence.write"];
  public readonly reconcileContexts: ReconcileContext[] = [];

  public constructor(
    public readonly style: "dispatch" | "permit",
    private readonly script: Script = {},
  ) {}

  public async capabilities(): Promise<readonly ExecutionCapability[]> {
    if (this.script.capabilities !== undefined) return await this.script.capabilities();
    return [
      {
        platform: "evidence-platform",
        actionType: "evidence.write",
        enabled: true,
        scopeGranted: true,
        connected: true,
        requirement: "",
      },
    ];
  }

  public async prepare(action: JsonObject): Promise<PreparedAction> {
    return this.script.prepare === undefined ? prepared(action) : await this.script.prepare(action);
  }

  public async execute(run: ClaimedExecution<JsonObject>): Promise<ExecutionEffect<JsonObject>> {
    if (this.script.execute !== undefined) return await this.script.execute(run);
    if (this.style === "permit") {
      return {
        kind: "PERMIT",
        permit: { permitId: null, intentHash: run.intent.intentHash, expiresAt: "ignored" },
      };
    }
    return await run.dispatch.run(async () => ({ kind: "DISPATCHED", receipt: { ok: true } }));
  }

  public async observe(
    effect: ExecutionEffect<JsonObject>,
  ): Promise<EffectObservation<JsonObject>> {
    if (this.script.observe !== undefined) return await this.script.observe(effect);
    const receipt =
      effect.kind === "DISPATCHED" || effect.kind === "RECEIPT" ? effect.receipt : null;
    if (receipt?.["ok"] === true) return { status: "COMMITTED", reason: null, result: receipt };
    if (receipt?.["ok"] === false) {
      return { status: "FAILED", reason: "EVIDENCE_REJECTED", result: { ignored: true } };
    }
    return { status: "INDETERMINATE", reason: null, result: null };
  }

  public async reconcile(context: ReconcileContext): Promise<ReconcileResult<JsonObject>> {
    this.reconcileContexts.push(context);
    if (this.script.reconcile !== undefined) return await this.script.reconcile(context);
    return { status: "UNKNOWN" };
  }
}

class Journal implements ExecutionJournal {
  public readonly records: JournalRecord[] = [];
  public readonly failing = new Set<string>();

  public async append(record: JournalRecord): Promise<void> {
    if (this.failing.has(record.record)) throw new Error("disk full");
    this.records.push(record);
  }

  public async openAttempts() {
    return openAttemptsFrom(this.records);
  }

  public async authorizationsOf(intentId: string) {
    return authorizationsFrom(this.records, intentId);
  }

  public close(): void {
    this.records.length = 0;
  }
}

/** A clock that reads T at its first call and T + 7 ms ever after, so a step's duration is exactly 7. */
function steppingClock(): () => number {
  let first = true;
  const start = Date.parse("2026-10-18T09:00:00.000Z");
  return () => {
    if (!first) return start + 7;
    first = false;
    return start;
  };
}

function runner(options: Partial<GovernedExecutionRunnerOptions> = {}) {
  const verifier = new RecordingVerifier();
  const lines: ExecutorEvidenceLine[] = [];
  const journal = new Journal();
  const instance = new GovernedExecutionRunner({
    verifier,
    journal,
    evidence: { emit: (line) => void lines.push(line) },
    ...options,
  });
  return { runner: instance, verifier, lines, journal };
}

/** The line a step writes, with its time read off so the rest can be compared whole. */
function line(lines: readonly ExecutorEvidenceLine[]): Omit<ExecutorEvidenceLine, "at"> {
  const last = lines.at(-1);
  if (last === undefined) throw new Error("no evidence line");
  const { at, ...rest } = last;
  expect(Date.parse(at)).not.toBeNaN();
  return rest;
}

const EXECUTOR = { platform: "evidence-platform", version: "2.0.0", style: "dispatch" } as const;

describe("what submit captures and decides", () => {
  it("binds the executor's expected effect and correlation, and nothing it did not name", async () => {
    const decisions: CapturedIntent[] = [];
    const authority: DecisionAuthority = {
      evaluate: async (captured) => {
        decisions.push(captured);
        return allow(captured);
      },
    };
    const { runner: instance } = runner({ authority });
    await instance.submit(new Executor("dispatch"), { action: ACTION, scope: SCOPE, actor: ACTOR });
    expect(Object.keys(decisions[0]?.intent ?? {})).not.toContain("expectedEffectDigest");
    expect(Object.keys(decisions[0]?.intent ?? {})).not.toContain("correlationId");
    await instance.submit(
      new Executor("dispatch", {
        prepare: async (action) =>
          prepared(action, { expectedEffectDigest: EFFECT, idempotencyKey: "evidence-key-8" }),
      }),
      { action: ACTION, scope: SCOPE, actor: ACTOR, correlationId: "case-7" },
    );
    expect(decisions[1]?.intent.expectedEffectDigest).toBe(EFFECT);
    expect(decisions[1]?.intent.correlationId).toBe("case-7");
  });

  it("records an authority that throws as unavailable, and fails closed", async () => {
    const { runner: instance } = runner({
      authority: {
        evaluate: async () => {
          throw new Error("ECONNRESET");
        },
      },
    });
    const { decision, result } = await instance.submit(new Executor("dispatch"), {
      action: ACTION,
      scope: SCOPE,
      actor: ACTOR,
    });
    expect(decision).toMatchObject({ failClosed: true, reasonCodes: ["AUTHORITY_UNAVAILABLE"] });
    expect(result).toEqual({
      outcome: "BLOCKED",
      executed: false,
      reason: "DECISION_NOT_ALLOW",
      result: null,
      authorization: null,
    });
  });
});

describe("the evidence line of a dispatched run", () => {
  it("names the executor, the decision, the grant, the scope and the duration, exactly", async () => {
    const { runner: instance, lines, journal, verifier } = runner({ clock: steppingClock() });
    const captured = capture();
    const result = await instance.run(new Executor("dispatch"), {
      captured,
      decision: allow(captured),
      action: ACTION,
      scope: SCOPE,
    });
    expect(result.outcome).toBe("COMPLETED");
    expect(line(lines)).toEqual({
      version: "agent-safe.executor-evidence/1",
      contract: "agent-safe.executors.native/1",
      stage: "RUN",
      executor: EXECUTOR,
      action_type: "evidence.write",
      intent_id: captured.intent.intentId,
      intent_hash: captured.intentHash,
      decision_id: "decision-7",
      dossier_id: "dossier-7",
      verdict: "ALLOW",
      grant_id: "grant-7",
      outcome: "COMPLETED",
      executed: true,
      reason: null,
      code: null,
      governed: true,
      authority_state: "DECIDED",
      posture: "STRICT",
      disposition: null,
      finalization: "RECORDED",
      duration_ms: 7,
      scope: EVIDENCE_SCOPE,
    });
    expect(journal.records).toEqual([
      {
        record: "ATTEMPT_OPENED",
        at: "2026-10-18T09:00:00.007Z",
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
        idempotency_key: "evidence-key-7",
        decision_id: "decision-7",
        dossier_id: "dossier-7",
        caller_principal: null,
        intent: { ...captured.intent },
      },
      {
        record: "GRANT_CLAIMED",
        at: "2026-10-18T09:00:00.007Z",
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
        idempotency_key: "evidence-key-7",
        grant_id: "grant-7",
        expires_at: captured.intent.expiresAt,
        request_digest: `sha256:${"7".repeat(64)}`,
      },
      {
        record: "ATTEMPT_CLOSED",
        at: "2026-10-18T09:00:00.007Z",
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
        outcome: "COMPLETED",
        executed: true,
        finalization: "RECORDED",
      },
    ]);
    // No observation, no receipt: the finalization carries neither key.
    expect(Object.keys(verifier.finalized[0] ?? {}).sort()).toEqual([
      "authorization",
      "captured",
      "decision",
      "outcome",
    ]);
  });

  it("closes an attempt whose claim was refused, and says so in the line", async () => {
    const { runner: instance, lines, journal, verifier } = runner();
    verifier.refuse = true;
    const captured = capture();
    const result = await instance.run(new Executor("dispatch"), {
      captured,
      decision: allow(captured),
      action: ACTION,
      scope: SCOPE,
    });
    expect(result).toEqual({
      outcome: "BLOCKED",
      executed: false,
      reason: "AUTHORIZATION_INVALID",
      result: null,
      authorization: null,
    });
    expect(journal.records.map((record) => record.record)).toEqual([
      "ATTEMPT_OPENED",
      "ATTEMPT_CLOSED",
    ]);
    expect(journal.records[1]).toMatchObject({
      outcome: "BLOCKED",
      executed: false,
      finalization: null,
    });
    expect(line(lines)).toMatchObject({
      stage: "RUN",
      outcome: "BLOCKED",
      executed: false,
      reason: "AUTHORIZATION_INVALID",
      code: null,
      grant_id: null,
      governed: false,
      finalization: null,
    });
  });

  it("fails a dispatch whose window closed, before the executor, and says which window", async () => {
    const { runner: instance, lines, journal, verifier } = runner();
    verifier.extra = { leaseExpiresAt: "2000-01-01T00:00:00.000Z" };
    const captured = capture();
    const result = await instance.run(new Executor("dispatch"), {
      captured,
      decision: allow(captured),
      action: ACTION,
    });
    expect(result).toMatchObject({
      outcome: "FAILED_BEFORE_DISPATCH",
      reason: "HANDLER_FAILED_BEFORE_DISPATCH",
      code: "DISPATCH_WINDOW_CLOSED",
    });
    expect(journal.records.at(-1)).toMatchObject({
      record: "ATTEMPT_CLOSED",
      outcome: "FAILED_BEFORE_DISPATCH",
      executed: false,
      finalization: "RECORDED",
    });
    expect(line(lines)).toMatchObject({
      stage: "RUN",
      outcome: "FAILED_BEFORE_DISPATCH",
      reason: "HANDLER_FAILED_BEFORE_DISPATCH",
      code: "DISPATCH_WINDOW_CLOSED",
      grant_id: "grant-7",
      governed: true,
      finalization: "RECORDED",
      scope: null,
    });
  });

  it("reports a refusal with no reason as PROVIDER_REFUSED, and an unknown with its reason", async () => {
    const { runner: instance, lines } = runner();
    const refused = capture();
    const result = await instance.run(
      new Executor("dispatch", {
        observe: async () => ({ status: "FAILED", reason: null, result: null }),
      }),
      { captured: refused, decision: allow(refused), action: ACTION },
    );
    expect(result).toMatchObject({
      outcome: "DEFINITELY_NOT_EXECUTED",
      reason: "PROVIDER_REFUSED",
    });
    expect(line(lines)).toMatchObject({
      outcome: "DEFINITELY_NOT_EXECUTED",
      executed: false,
      reason: "PROVIDER_REFUSED",
    });
    const lost = capture({ idempotencyKey: "evidence-key-9" });
    await instance.run(
      new Executor("dispatch", {
        prepare: async (action) => prepared(action, { idempotencyKey: "evidence-key-9" }),
        observe: async () => ({ status: "INDETERMINATE", reason: null, result: null }),
      }),
      { captured: lost, decision: allow(lost), action: ACTION },
    );
    expect(line(lines)).toMatchObject({
      outcome: "UNKNOWN_AFTER_DISPATCH",
      executed: null,
      reason: "PROVIDER_OUTCOME_UNKNOWN",
      code: null,
    });
  });

  it("forwards the receipt the observation, the effect or the dispatch carried, in that order", async () => {
    const cases: readonly [Script, string][] = [
      [
        {
          execute: async (run) =>
            await run.dispatch.run(async () => ({
              kind: "DISPATCHED" as const,
              receipt: { ok: true },
              signedReceipt: "effect.receipt.jws",
            })),
        },
        "effect.receipt.jws",
      ],
      [
        {
          execute: async (run) =>
            await run.dispatch.run(async () => {
              run.dispatch.receipt("dispatch.receipt.jws");
              return { kind: "DISPATCHED" as const, receipt: { ok: true } };
            }),
        },
        "dispatch.receipt.jws",
      ],
      [
        {
          execute: async (run) =>
            await run.dispatch.run(async () => ({
              kind: "DISPATCHED" as const,
              receipt: { ok: true },
              signedReceipt: "effect.receipt.jws",
            })),
          observe: async () => ({
            status: "COMMITTED",
            reason: null,
            result: {},
            signedReceipt: "observed.receipt.jws",
            evidence: OBSERVATION_EVIDENCE,
          }),
        },
        "observed.receipt.jws",
      ],
    ];
    for (const [script, receipt] of cases) {
      const { runner: instance, verifier } = runner();
      const captured = capture();
      await instance.run(new Executor("dispatch", script), {
        captured,
        decision: allow(captured),
        action: ACTION,
      });
      expect(verifier.finalized[0]?.effectReceipt).toBe(receipt);
    }
  });
});

describe("the evidence line of a refused admission", () => {
  it("names no scope when the run had none, and nothing the authority did not decide", async () => {
    const { runner: instance, lines } = runner();
    const captured = capture();
    const result = await instance.run(new Executor("dispatch"), {
      captured,
      decision: allow(captured, { dossierId: null }),
      action: ACTION,
    });
    expect(Object.keys(result)).not.toContain("code");
    expect(line(lines)).toMatchObject({
      stage: "RUN",
      outcome: "BLOCKED",
      executed: false,
      reason: "DOSSIER_MISSING",
      code: null,
      dossier_id: null,
      governed: false,
      authority_state: "DECIDED",
      disposition: null,
      finalization: null,
      scope: null,
    });
  });

  it("says the authority was unavailable under a strict posture, and adds nothing to the result", async () => {
    const { runner: instance, lines } = runner();
    const captured = capture();
    const result = await instance.run(new Executor("dispatch"), {
      captured,
      decision: immutableDecisionGate({
        verdict: "BLOCK",
        decisionId: "unavailable",
        dossierId: null,
        intentHash: captured.intentHash,
        reasonCodes: ["AUTHORITY_UNAVAILABLE"],
        authorization: null,
        failClosed: true,
      }),
      action: ACTION,
      scope: SCOPE,
    });
    expect(result).toEqual({
      outcome: "BLOCKED",
      executed: false,
      reason: "DECISION_NOT_ALLOW",
      result: null,
      authorization: null,
    });
    expect(line(lines)).toMatchObject({
      authority_state: "AUTHORITY_UNAVAILABLE",
      disposition: "NOT_FORWARDED",
      scope: EVIDENCE_SCOPE,
    });
  });

  it("never applies a posture to a BLOCK the authority answered", async () => {
    const { runner: instance, lines } = runner({ posture: { posture: "BOUNDED_CONTINUITY" } });
    const captured = capture();
    const result = await instance.run(new Executor("dispatch"), {
      captured,
      decision: allow(captured, { verdict: "BLOCK", authorization: null }),
      action: ACTION,
    });
    expect(Object.keys(result)).not.toContain("unavailable");
    expect(line(lines)).toMatchObject({ disposition: null, posture: "BOUNDED_CONTINUITY" });
  });

  it("hands an institution's rule the intent and the decision it is choosing for", async () => {
    const decide = vi.fn(() => "HELD" as const);
    const { runner: instance } = runner({ posture: { posture: "CUSTOM", decide } });
    const captured = capture();
    const decision = immutableDecisionGate({
      verdict: "BLOCK",
      decisionId: "unavailable",
      dossierId: null,
      intentHash: captured.intentHash,
      reasonCodes: ["AUTHORITY_UNAVAILABLE"],
      authorization: null,
      failClosed: true,
    });
    const result = await instance.run(new Executor("dispatch"), {
      captured,
      decision,
      action: ACTION,
    });
    expect(decide).toHaveBeenCalledWith({ captured, decision });
    expect(result).toMatchObject({ unavailable: { posture: "CUSTOM", disposition: "HELD" } });
  });

  it("holds the executor to the decided action type, its own action, system and parameters", async () => {
    for (const drift of [
      { actionType: "evidence.other" },
      {
        proposal: { action: "evidence.other", target: "ledger:7", parameters: ACTION },
      },
      { downstreamTarget: { system: "other", operation: "write" } },
      {
        proposal: {
          action: "evidence.write",
          target: "ledger:7",
          parameters: { amount: 10n } as unknown as JsonObject,
        },
      },
    ]) {
      const { runner: instance } = runner();
      const captured = capture();
      const result = await instance.run(
        new Executor("dispatch", {
          prepare: async (action) => prepared(action, drift as Partial<PreparedAction>),
        }),
        { captured, decision: allow(captured), action: ACTION },
      );
      expect(result).toMatchObject({ outcome: "BLOCKED", reason: "INTENT_BINDING_MISMATCH" });
    }
  });

  it("does not take another platform's capability for this executor's", async () => {
    const { runner: instance } = runner();
    const captured = capture();
    const result = await instance.run(
      new Executor("dispatch", {
        capabilities: async () => [
          {
            platform: "someone-else",
            actionType: "evidence.write",
            enabled: true,
            scopeGranted: true,
            connected: true,
            requirement: "",
          },
        ],
      }),
      { captured, decision: allow(captured), action: ACTION, scope: SCOPE },
    );
    expect(result).toMatchObject({ reason: "CAPABILITY_UNAVAILABLE", code: "UNSUPPORTED_ACTION" });
  });

  it("opens attempts with a journal that cannot say which keys were dispatched", async () => {
    const journal = new Journal();
    const lean: ExecutionJournal = {
      append: async (record) => await journal.append(record),
      openAttempts: async () => await journal.openAttempts(),
      authorizationsOf: async (id) => await journal.authorizationsOf(id),
      close: () => undefined,
    };
    const { runner: instance } = runner({ journal: lean });
    const captured = capture();
    const result = await instance.run(new Executor("dispatch"), {
      captured,
      decision: allow(captured),
      action: ACTION,
    });
    expect(result.outcome).toBe("COMPLETED");
  });

  it("refuses an attempt it cannot open, as a run step, before anything is held", async () => {
    const { runner: instance, lines, journal } = runner();
    journal.failing.add("ATTEMPT_OPENED");
    const captured = capture();
    const held = await instance.hold(new Executor("permit"), {
      captured,
      decision: allow(captured),
      action: ACTION,
    });
    expect(held).toMatchObject({ outcome: "BLOCKED", reason: "JOURNAL_UNAVAILABLE" });
    expect(line(lines)).toMatchObject({ stage: "RUN", reason: "JOURNAL_UNAVAILABLE" });
  });

  it("refuses a hold whose record cannot be delivered, as a run step", async () => {
    const sink = {
      write: (event: AuditEventV1) => {
        if (event.eventType === "GRANT_HELD") throw new Error("sink down");
      },
    };
    const { runner: instance, lines } = runner({
      audit: new AuditRecorder({ sink, failurePolicy: "REQUIRE_BEFORE_EXECUTION" }),
    });
    const captured = capture();
    const held = await instance.hold(new Executor("permit"), {
      captured,
      decision: allow(captured),
      action: ACTION,
    });
    expect(held).toMatchObject({ outcome: "BLOCKED", reason: "AUDIT_UNAVAILABLE" });
    expect(line(lines)).toMatchObject({ stage: "RUN", reason: "AUDIT_UNAVAILABLE" });
  });
});

describe("the evidence of a permit", () => {
  const permitExecutor = (script: Script = {}): Executor => new Executor("permit", script);

  it("writes a line per step, with the scope the hold was made under", async () => {
    const { runner: instance, lines, journal, verifier } = runner();
    const captured = capture();
    const held = await instance.hold(permitExecutor(), {
      captured,
      decision: allow(captured),
      action: ACTION,
      scope: SCOPE,
    });
    if (held.outcome !== "HELD" || !("permit" in held)) throw new Error("not held");
    expect(held.permit).toEqual({
      permitId: null,
      intentHash: captured.intentHash,
      expiresAt: captured.intent.expiresAt,
    });
    expect(line(lines)).toMatchObject({
      stage: "RUN",
      outcome: "HELD",
      executed: false,
      grant_id: null,
      governed: true,
      scope: EVIDENCE_SCOPE,
      executor: { ...EXECUTOR, style: "permit" },
    });
    expect(journal.records.map((record) => record.record)).toEqual(["ATTEMPT_OPENED"]);

    const presented = await instance.present(held.held);
    expect(presented).toEqual({
      outcome: "CLAIMED",
      authorization: expect.objectContaining({ grantId: "grant-7" }),
      permit: {
        permitId: "grant-7",
        intentHash: captured.intentHash,
        expiresAt: captured.intent.expiresAt,
      },
    });
    expect(line(lines)).toMatchObject({
      stage: "PRESENTATION",
      outcome: "CLAIMED",
      executed: null,
      grant_id: "grant-7",
      governed: true,
      scope: EVIDENCE_SCOPE,
    });

    const settled = await instance.settle(held.held, {
      receipt: { ok: true },
      signedReceipt: "posting.receipt.jws",
    });
    expect(Object.keys(settled)).not.toContain("recovery");
    expect(settled).toMatchObject({
      status: "SETTLED",
      outcome: "COMPLETED",
      executed: true,
      result: { ok: true },
      reason: null,
      finalization: "RECORDED",
    });
    expect(verifier.finalized.at(-1)?.effectReceipt).toBe("posting.receipt.jws");
    expect(line(lines)).toMatchObject({
      stage: "SETTLEMENT",
      outcome: "COMPLETED",
      executed: true,
      reason: null,
      code: null,
      grant_id: "grant-7",
      governed: true,
      finalization: "RECORDED",
      scope: EVIDENCE_SCOPE,
    });
  });

  it("carries the authority's claim attestation on the permit, and only the authority's", async () => {
    const { runner: instance, verifier } = runner();
    verifier.extra = { claimAttestation: "authority.claim.jws" };
    const captured = capture();
    const held = await instance.hold(permitExecutor(), {
      captured,
      decision: allow(captured),
      action: ACTION,
    });
    if (held.outcome !== "HELD") throw new Error("not held");
    expect(await instance.present(held.held)).toMatchObject({
      permit: { permitId: "grant-7", claimAttestation: "authority.claim.jws" },
    });
  });

  it("refuses a permit executor that tries to write, by either half of the dispatch", async () => {
    for (const execute of [
      async (run: ClaimedExecution<JsonObject>) => {
        await run.dispatch.run(() => "written");
        return {
          kind: "PERMIT" as const,
          permit: { permitId: null, intentHash: run.intent.intentHash, expiresAt: "x" },
        };
      },
      async (run: ClaimedExecution<JsonObject>) => {
        run.dispatch.receipt("receipt.jws");
        return {
          kind: "PERMIT" as const,
          permit: { permitId: null, intentHash: run.intent.intentHash, expiresAt: "x" },
        };
      },
    ]) {
      const { runner: instance, lines, journal } = runner();
      const captured = capture();
      const held = await instance.hold(permitExecutor({ execute }), {
        captured,
        decision: allow(captured),
        action: ACTION,
      });
      if (held.outcome !== "HELD") throw new Error("not held");
      expect(await instance.present(held.held)).toMatchObject({
        outcome: "FAILED_BEFORE_DISPATCH",
        reason: "HANDLER_FAILED_BEFORE_DISPATCH",
        code: "PERMIT_NOT_ISSUED",
      });
      expect(line(lines)).toMatchObject({ stage: "PRESENTATION", code: "PERMIT_NOT_ISSUED" });
      expect(journal.records.at(-1)).toMatchObject({
        record: "ATTEMPT_CLOSED",
        outcome: "FAILED_BEFORE_DISPATCH",
      });
    }
  });

  it("writes a presentation line and closes the attempt when the claim is refused", async () => {
    const { runner: instance, lines, journal, verifier } = runner();
    const captured = capture();
    const held = await instance.hold(permitExecutor(), {
      captured,
      decision: allow(captured),
      action: ACTION,
    });
    if (held.outcome !== "HELD") throw new Error("not held");
    verifier.refuse = true;
    expect(await instance.present(held.held)).toMatchObject({ outcome: "BLOCKED" });
    expect(line(lines)).toMatchObject({ stage: "PRESENTATION", outcome: "BLOCKED" });
    expect(journal.records.at(-1)).toMatchObject({ record: "ATTEMPT_CLOSED", outcome: "BLOCKED" });
  });

  it("settles a refusal without its result, and an unknown with a recovery reference", async () => {
    for (const [receipt, expected] of [
      [
        { ok: false },
        {
          outcome: "DEFINITELY_NOT_EXECUTED",
          executed: false,
          result: null,
          reason: "EVIDENCE_REJECTED",
        },
      ],
      [
        { unreadable: true },
        {
          outcome: "UNKNOWN_AFTER_DISPATCH",
          executed: null,
          result: null,
          reason: "PROVIDER_OUTCOME_UNKNOWN",
        },
      ],
    ] as const) {
      const { runner: instance, journal } = runner();
      const captured = capture();
      const held = await instance.hold(permitExecutor(), {
        captured,
        decision: allow(captured),
        action: ACTION,
      });
      if (held.outcome !== "HELD") throw new Error("not held");
      await instance.present(held.held);
      const settled = await instance.settle(held.held, { receipt });
      expect(settled).toMatchObject({ status: "SETTLED", ...expected });
      expect("recovery" in settled).toBe(expected.outcome === "UNKNOWN_AFTER_DISPATCH");
      expect(journal.records.at(-1)).toMatchObject({
        record: "ATTEMPT_CLOSED",
        outcome: expected.outcome,
        executed: expected.executed,
      });
    }
  });

  it("settles an adopted claim with the scope it was adopted under", async () => {
    const { runner: instance, lines } = runner();
    const captured = capture();
    const decision = allow(captured);
    const held = instance.adoptClaim(
      permitExecutor(),
      { captured, decision, action: ACTION, scope: SCOPE },
      Object.freeze({
        decisionId: "decision-7",
        dossierId: "dossier-7",
        grantId: "grant-7",
        intentHash: captured.intentHash,
        expiresAt: captured.intent.expiresAt,
      }),
    );
    await instance.settle(held, { outcome: "COMMITTED" });
    expect(line(lines)).toMatchObject({ stage: "SETTLEMENT", scope: EVIDENCE_SCOPE });
  });
});

describe("the evidence of a reconciliation", () => {
  async function unknownAttempt(script: Script) {
    const parts = runner();
    const captured = capture();
    const executor = new Executor("dispatch", {
      observe: async () => ({ status: "INDETERMINATE", reason: null, result: null }),
      ...script,
    });
    const result = await parts.runner.run(executor, {
      captured,
      decision: allow(captured),
      action: ACTION,
      scope: SCOPE,
    });
    if (result.outcome !== "UNKNOWN_AFTER_DISPATCH") throw new Error("not unknown");
    return { ...parts, executor, captured, recovery: result.recovery };
  }

  it("journals and reports a proven answer, with the observation when there is one", async () => {
    for (const [answer, outcome, report] of [
      [
        { status: "COMPLETED" as const, result: { ok: true }, evidence: OBSERVATION_EVIDENCE },
        "COMPLETED",
        "COMMITTED",
      ],
      [{ status: "NOT_EXECUTED" as const }, "DEFINITELY_NOT_EXECUTED", "FAILED"],
    ] as const) {
      const {
        runner: instance,
        executor,
        captured,
        recovery,
        journal,
        verifier,
        lines,
      } = await unknownAttempt({ reconcile: async () => answer });
      const reconciled = await instance.reconcile(executor, {
        captured,
        recovery,
        action: ACTION,
        scope: SCOPE,
      });
      expect(reconciled.outcome).toBe(outcome);
      expect(executor.reconcileContexts.at(-1)?.scope).toBe(SCOPE);
      expect(journal.records.at(-1)).toEqual({
        record: "RECONCILED",
        at: expect.any(String),
        intent_id: captured.intent.intentId,
        intent_hash: captured.intentHash,
        status: outcome,
        source: "CALLER",
      });
      const reported = verifier.reconciled.at(-1);
      expect(reported?.outcome).toBe(report);
      expect(Object.keys(reported ?? {}).sort()).toEqual(
        "evidence" in answer
          ? ["authorization", "captured", "effectEvidence", "outcome"]
          : ["authorization", "captured", "outcome"],
      );
      expect(line(lines)).toMatchObject({
        stage: "RECONCILIATION",
        outcome,
        executed: outcome === "COMPLETED",
        reason: outcome === "COMPLETED" ? null : "PROVIDER_CONFIRMED_NOT_EXECUTED",
        grant_id: "grant-7",
        governed: true,
        finalization: "RECORDED",
        decision_id: null,
        scope: EVIDENCE_SCOPE,
      });
    }
  });

  it("reports nothing it could not prove, and journals it as still unknown", async () => {
    const {
      runner: instance,
      executor,
      captured,
      recovery,
      journal,
      verifier,
      lines,
    } = await unknownAttempt({});
    await instance.reconcile(executor, { captured, recovery, action: ACTION, scope: SCOPE });
    expect(verifier.reconciled).toEqual([]);
    expect(journal.records.at(-1)).toMatchObject({
      record: "RECONCILED",
      status: "UNKNOWN_AFTER_DISPATCH",
    });
    expect(line(lines)).toMatchObject({
      outcome: "UNKNOWN_AFTER_DISPATCH",
      executed: null,
      reason: "PROVIDER_OUTCOME_UNKNOWN",
      finalization: null,
    });
  });
});
