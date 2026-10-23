import { describe, expect, it, vi } from "vitest";
import type { DecisionGate } from "../../src/decision/DecisionAuthority.js";
import { createFixtureAuthorityPair } from "../../src/decision/FixtureDecisionAuthority.js";
import { immutableDecisionGate } from "../../src/decision/ImmutableDecisionGate.js";
import { ActionRegistry, PreDispatchRefusal } from "../../src/execution/ActionRegistry.js";
import type {
  AuthorityEffectEvidence,
  AuthorizationVerifier,
} from "../../src/execution/AuthorizationVerifier.js";
import { IndeterminateOutcome } from "../../src/execution/EffectAdapter.js";
import {
  JournalError,
  dispatchedUnderFrom,
  authorizationsFrom,
  openAttemptsFrom,
  type ExecutionJournal,
  type JournalRecord,
} from "../../src/execution/ExecutionJournal.js";
import { unavailableDisposition } from "../../src/execution/ExecutionPosture.js";
import { evidenceScope, type ExecutorEvidenceLine } from "../../src/execution/ExecutorEvidence.js";
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
  ReconcileResult,
} from "../../src/execution/NativeExecutor.js";
import { RegistryExecutor } from "../../src/execution/RegistryExecutor.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import type {
  AgentProposal,
  CapturedIntent,
  ExecutionIntent,
  PolicyProjection,
  TrustedIntentContext,
} from "../../src/intent/ExecutionIntent.js";
import type { JsonObject } from "../../src/intent/JsonValue.js";

const TENANT = "00000000-0000-4000-8000-000000000004";
const SCOPE: ExecutorScope = {
  orgId: TENANT,
  workspaceId: "workspace-1",
  connectionId: "connection-1",
  connectionRevision: "3",
  company: "CRONUS",
  environment: "production",
};
const ACTION: JsonObject = { line: "PAY-1", amount_minor: 4_200 };
const ACTOR = { id: "synthetic-agent-1", type: "agent" };
const PROJECTION: PolicyProjection = {
  decisionType: "PAYMENT_RELEASE",
  transactionType: "payment_release",
  workflowKey: null,
  channel: "connector",
};
const EVIDENCE: AuthorityEffectEvidence = {
  version: "1.0",
  status: "UNCONFIRMED",
  observation_method: "DOWNSTREAM_ACK",
  observer: { id: "scripted", version: "1" },
  expected_effect_digest: `sha256:${"e".repeat(64)}`,
  observed_effect_digest: null,
  observed_at: null,
  evidence_digest: null,
  evidence_reference: null,
  execution_correlation_id: "intent",
};

type Script = Partial<{
  capabilities: (scope: ExecutorScope) => Promise<readonly ExecutionCapability[]>;
  prepare: (action: JsonObject) => Promise<PreparedAction>;
  execute: (run: ClaimedExecution<JsonObject>) => Promise<ExecutionEffect<JsonObject>>;
  observe: (effect: ExecutionEffect<JsonObject>) => Promise<EffectObservation<JsonObject>>;
  reconcile: () => Promise<ReconcileResult<JsonObject>>;
}>;

/** An executor whose every method the test scripts; the defaults commit. */
class ScriptedExecutor implements NativeExecutor<JsonObject, JsonObject, JsonObject> {
  public readonly platform = "scripted";
  public readonly version = "1.0.0";
  public readonly actionTypes = ["scripted.write"];
  public readonly calls: string[] = [];

  public constructor(
    public readonly style: "dispatch" | "permit",
    private readonly script: Script = {},
  ) {}

  public async capabilities(scope: ExecutorScope): Promise<readonly ExecutionCapability[]> {
    this.calls.push("capabilities");
    if (this.script.capabilities !== undefined) return await this.script.capabilities(scope);
    return [capability()];
  }

  public async prepare(action: JsonObject): Promise<PreparedAction> {
    this.calls.push("prepare");
    if (this.script.prepare !== undefined) return await this.script.prepare(action);
    return prepared(action);
  }

  public async execute(run: ClaimedExecution<JsonObject>): Promise<ExecutionEffect<JsonObject>> {
    this.calls.push("execute");
    if (this.script.execute !== undefined) return await this.script.execute(run);
    if (this.style === "permit") {
      return {
        kind: "PERMIT",
        permit: {
          permitId: run.authorization.grantId,
          intentHash: run.intent.intentHash,
          expiresAt: run.authorization.expiresAt,
          claimAttestation: "a.b.c",
        },
      };
    }
    return await run.dispatch.run(async () => ({ kind: "DISPATCHED", receipt: { ok: true } }));
  }

  public async observe(
    effect: ExecutionEffect<JsonObject>,
  ): Promise<EffectObservation<JsonObject>> {
    this.calls.push("observe");
    if (this.script.observe !== undefined) return await this.script.observe(effect);
    const receipt =
      effect.kind === "DISPATCHED" || effect.kind === "RECEIPT" ? effect.receipt : null;
    if (receipt?.["ok"] === true) return { status: "COMMITTED", reason: null, result: receipt };
    if (receipt?.["ok"] === false) return { status: "FAILED", reason: null, result: null };
    return { status: "INDETERMINATE", reason: null, result: null };
  }

  public async reconcile(): Promise<ReconcileResult<JsonObject>> {
    this.calls.push("reconcile");
    if (this.script.reconcile !== undefined) return await this.script.reconcile();
    return { status: "COMPLETED", result: { ok: true }, evidence: EVIDENCE };
  }
}

function capability(overrides: Partial<ExecutionCapability> = {}): ExecutionCapability {
  return {
    platform: "scripted",
    actionType: "scripted.write",
    enabled: true,
    scopeGranted: true,
    connected: true,
    requirement: "",
    ...overrides,
  };
}

function prepared(action: JsonObject, overrides: Partial<PreparedAction> = {}): PreparedAction {
  return {
    actionType: "scripted.write",
    proposal: { action: "scripted.write", target: "ledger:1", parameters: action },
    downstreamTarget: { system: "scripted", operation: "write" },
    idempotencyKey: "scripted-key-1",
    expectedEffectDigest: null,
    requestDigest: `sha256:${"1".repeat(64)}`,
    facts: { company_bank_account_changed: true },
    ...overrides,
  };
}

/** A journal in memory, with failures a test can inject by record kind. */
class MemoryJournal implements ExecutionJournal {
  public readonly records: JournalRecord[] = [];
  public readonly failing = new Map<string, Error>();

  public async append(record: JournalRecord): Promise<void> {
    const failure = this.failing.get(record.record);
    if (failure !== undefined) throw failure;
    this.records.push(record);
  }

  public async openAttempts() {
    return openAttemptsFrom(this.records);
  }

  public async authorizationsOf(intentId: string) {
    return authorizationsFrom(this.records, intentId);
  }

  public async dispatchedUnder(key: string) {
    return dispatchedUnderFrom(this.records, key);
  }

  public close(): void {
    this.records.length = 0;
  }
}

function setup(
  options: Partial<GovernedExecutionRunnerOptions> = {},
  verdict: "ALLOW" | "ESCALATE" | "BLOCK" = "ALLOW",
) {
  const pair = createFixtureAuthorityPair(() => verdict, { unsafeAllowDevelopmentFixture: true });
  const lines: ExecutorEvidenceLine[] = [];
  const runner = new GovernedExecutionRunner({
    verifier: pair.verifier,
    authority: pair.authority,
    evidence: { emit: (line) => void lines.push(line) },
    ...options,
  });
  return { ...pair, runner, lines };
}

async function decided(
  verdict: "ALLOW" | "ESCALATE" | "BLOCK" = "ALLOW",
  policyProjection?: PolicyProjection,
): Promise<{ captured: CapturedIntent; decision: DecisionGate; verifier: AuthorizationVerifier }> {
  const pair = createFixtureAuthorityPair(() => verdict, { unsafeAllowDevelopmentFixture: true });
  const p = prepared(ACTION);
  const captured = new IntentCapture().capture(p.proposal, {
    tenantId: TENANT,
    actor: ACTOR,
    downstreamTarget: p.downstreamTarget,
    context: p.facts,
    idempotencyKey: p.idempotencyKey,
    ...(policyProjection === undefined ? {} : { policyProjection }),
  });
  return { captured, decision: await pair.authority.evaluate(captured), verifier: pair.verifier };
}

describe("GovernedExecutionRunner admission", () => {
  it("submits through prepare, capture and decision, and writes once on an ALLOW", async () => {
    const { runner, verifier, lines } = setup();
    const executor = new ScriptedExecutor("dispatch");
    const { captured, decision, result } = await runner.submit(executor, {
      action: ACTION,
      scope: SCOPE,
      actor: ACTOR,
      correlationId: "case-1",
    });
    expect(result).toMatchObject({ outcome: "COMPLETED", executed: true, result: { ok: true } });
    expect(captured.intent.context).toEqual({ company_bank_account_changed: true });
    expect(captured.intent.correlationId).toBe("case-1");
    expect(decision.verdict).toBe("ALLOW");
    expect(executor.calls).toEqual(["prepare", "prepare", "capabilities", "execute", "observe"]);
    expect(verifier.ledger()[0]?.outcome).toBe("COMMITTED");
    expect(lines.at(-1)).toMatchObject({
      stage: "RUN",
      outcome: "COMPLETED",
      governed: true,
      authority_state: "DECIDED",
      scope: evidenceScope(SCOPE),
    });
  });

  it("refuses to submit without an authority to ask", async () => {
    const runner = new GovernedExecutionRunner({ verifier: (await decided()).verifier });
    await expect(
      runner.submit(new ScriptedExecutor("dispatch"), {
        action: ACTION,
        scope: SCOPE,
        actor: ACTOR,
      }),
    ).rejects.toThrow("RUNNER_AUTHORITY_MISSING");
  });

  it.each([
    ["UNSUPPORTED_ACTION", async () => [capability({ actionType: "scripted.other" })]],
    ["NOT_CONNECTED", async () => [capability({ connected: false, enabled: false })]],
    ["SCOPE_NOT_GRANTED", async () => [capability({ scopeGranted: false, enabled: false })]],
    ["CAPABILITY_DISABLED", async () => [capability({ enabled: false })]],
    [
      "CAPABILITY_UNREADABLE",
      async (): Promise<readonly ExecutionCapability[]> => {
        throw new Error("platform down");
      },
    ],
  ])(
    "refuses before any grant is spent when the connection cannot take it: %s",
    async (code, read) => {
      const { runner, verifier, lines } = setup();
      const executor = new ScriptedExecutor("dispatch", { capabilities: read });
      const { result } = await runner.submit(executor, {
        action: ACTION,
        scope: SCOPE,
        actor: ACTOR,
      });
      expect(result).toMatchObject({ outcome: "BLOCKED", reason: "CAPABILITY_UNAVAILABLE", code });
      expect(verifier.ledger()).toEqual([]);
      expect(executor.calls).not.toContain("execute");
      expect(lines.at(-1)).toMatchObject({ outcome: "BLOCKED", code, governed: false });
    },
  );

  it("refuses an executor whose description of the action is not what was decided", async () => {
    const { captured, decision, verifier } = await decided();
    const runner = new GovernedExecutionRunner({ verifier });
    for (const drift of [
      { proposal: { action: "scripted.write", target: "ledger:2", parameters: ACTION } },
      { idempotencyKey: "scripted-key-2" },
      { expectedEffectDigest: `sha256:${"9".repeat(64)}` as const },
      { downstreamTarget: { system: "scripted", operation: "delete" } },
      { proposal: { action: "scripted.write", target: "ledger:1", parameters: { line: "PAY-2" } } },
      {
        proposal: {
          action: "scripted.write",
          target: "ledger:1",
          parameters: { cyclic: undefined } as unknown as JsonObject,
        },
      },
    ]) {
      const executor = new ScriptedExecutor("dispatch", {
        prepare: async (action) => prepared(action, drift as Partial<PreparedAction>),
      });
      const result = await runner.run(executor, { captured, decision, action: ACTION });
      expect(result).toMatchObject({ outcome: "BLOCKED", reason: "INTENT_BINDING_MISMATCH" });
    }
  });

  it("captures the projection an executor states, and admits the intent its own re-hash reproduces", async () => {
    const { runner, verifier } = setup();
    const executor = new ScriptedExecutor("dispatch", {
      prepare: async (action) => prepared(action, { policyProjection: PROJECTION }),
    });
    const { captured, result } = await runner.submit(executor, {
      action: ACTION,
      scope: SCOPE,
      actor: ACTOR,
    });
    // 0.4.0 could not state a projection, and an intent hashed with one failed
    // the runner's private re-hash; the binding now carries it on both sides.
    expect(result).toMatchObject({ outcome: "COMPLETED", executed: true });
    expect(captured.intent.policyProjection).toEqual(PROJECTION);
    expect(JSON.parse(captured.canonicalIntent)).toHaveProperty(
      "policy_projection.decision_type",
      "PAYMENT_RELEASE",
    );
    expect(executor.calls.filter((call) => call === "execute")).toHaveLength(1);
    expect(verifier.ledger()[0]?.outcome).toBe("COMMITTED");
  });

  it("reads the target once before asking and binds the version into the intent", async () => {
    const { runner } = setup();
    const reads: unknown[][] = [];
    const precondition = {
      version: '"17"',
      state: "staged",
      source: "scripted#items.get",
      read_at: "2026-10-23T12:00:00.000Z",
    };
    const executor = new (class extends ScriptedExecutor {
      public async readState(...args: unknown[]): Promise<typeof precondition> {
        reads.push(args);
        this.calls.push("readState");
        return precondition;
      }
    })("dispatch");
    const { captured, result } = await runner.submit(executor, {
      action: ACTION,
      scope: SCOPE,
      actor: ACTOR,
    });
    expect(result).toMatchObject({ outcome: "COMPLETED", executed: true });
    expect(captured.intent.context).toEqual({
      company_bank_account_changed: true,
      agent_safe: { precondition },
    });
    expect(reads).toEqual([[ACTION, prepared(ACTION), SCOPE]]);
    expect(executor.calls.slice(0, 2)).toEqual(["prepare", "readState"]);
  });

  it("binds no precondition when the executor reads none, or its read names no target", async () => {
    const { runner } = setup();
    const none = new (class extends ScriptedExecutor {
      public async readState(): Promise<null> {
        return null;
      }
    })("dispatch");
    const { captured, result } = await runner.submit(none, {
      action: ACTION,
      scope: SCOPE,
      actor: ACTOR,
    });
    expect(result).toMatchObject({ outcome: "COMPLETED" });
    expect(captured.intent.context).toEqual({ company_bank_account_changed: true });
  });

  it("refuses to decide anything when the read fails or states no precondition", async () => {
    for (const read of [
      async () => {
        throw new Error("upstream said: secret detail");
      },
      async () => ({ version: "has a space", source: "scripted", read_at: "2026-10-23T12:00:00Z" }),
      async () => undefined,
    ]) {
      const { runner, verifier } = setup();
      // An executor that breaks the contract at run time, as a read can.
      const executor = new (class extends ScriptedExecutor {
        public readState = read as NonNullable<NativeExecutor<JsonObject>["readState"]>;
      })("dispatch");
      await expect(
        runner.submit(executor, { action: ACTION, scope: SCOPE, actor: ACTOR }),
      ).rejects.toThrow(/^TARGET_STATE_UNREADABLE$/);
      expect(executor.calls).toEqual(["prepare"]);
      expect(verifier.ledger()).toEqual([]);
    }
  });

  it("hands the capture a projection only when the executor states one, never an undefined key", async () => {
    // The capture is replaceable (`options.capture`), and it is handed the
    // trusted context as it is: one that reads key presence (`in`,
    // `Object.hasOwn`) must see no projection where the executor stated none.
    // The default capture drops an undefined key itself, so the captured
    // intent alone cannot tell the two apart; what was handed over can.
    const handed: TrustedIntentContext[] = [];
    class RecordingCapture extends IntentCapture {
      public override capture(
        proposal: AgentProposal,
        trusted: TrustedIntentContext,
      ): CapturedIntent {
        handed.push(trusted);
        return super.capture(proposal, trusted);
      }
    }
    const { runner } = setup({ capture: new RecordingCapture() });
    const plain = await runner.submit(new ScriptedExecutor("dispatch"), {
      action: ACTION,
      scope: SCOPE,
      actor: ACTOR,
    });
    await runner.submit(
      new ScriptedExecutor("dispatch", {
        prepare: async (action) => prepared(action, { policyProjection: PROJECTION }),
      }),
      { action: ACTION, scope: SCOPE, actor: ACTOR },
    );

    expect(handed.map((trusted) => Object.hasOwn(trusted, "policyProjection"))).toEqual([
      false,
      true,
    ]);
    expect(handed[1]?.policyProjection).toStrictEqual(PROJECTION);
    expect(Object.hasOwn(plain.captured.intent, "policyProjection")).toBe(false);
    expect("policy_projection" in JSON.parse(plain.captured.canonicalIntent)).toBe(false);
  });

  it("refuses an executor that describes another policy path than the one decided", async () => {
    const plain = await decided();
    const projected = await decided("ALLOW", PROJECTION);
    for (const [{ captured, decision, verifier }, drift] of [
      [plain, { policyProjection: PROJECTION }],
      [projected, {}],
      [projected, { policyProjection: { ...PROJECTION, decisionType: "PRICE_CHANGE" } }],
      [projected, { policyProjection: { ...PROJECTION, transactionType: null } }],
      [projected, { policyProjection: { ...PROJECTION, workflowKey: "payments" } }],
      [projected, { policyProjection: { ...PROJECTION, channel: "api" } }],
    ] as const) {
      const executor = new ScriptedExecutor("dispatch", {
        prepare: async (action) => prepared(action, drift),
      });
      const result = await new GovernedExecutionRunner({ verifier }).run(executor, {
        captured,
        decision,
        action: ACTION,
      });
      expect(result).toMatchObject({ outcome: "BLOCKED", reason: "INTENT_BINDING_MISMATCH" });
      expect(executor.calls).not.toContain("execute");
    }
  });

  it("refuses an intent whose projection changed after it was captured, before a grant is spent", async () => {
    const { captured, decision, verifier } = await decided("ALLOW", PROJECTION);
    const claims = vi.spyOn(verifier, "verifyAndConsume");
    for (const policyProjection of [undefined, { ...PROJECTION, decisionType: "PRICE_CHANGE" }]) {
      const intent: Partial<ExecutionIntent> = { ...captured.intent };
      delete intent.policyProjection;
      const forged = {
        ...captured,
        intent: policyProjection === undefined ? intent : { ...intent, policyProjection },
      } as CapturedIntent;
      const executor = new ScriptedExecutor("dispatch", {
        prepare: async (action) =>
          prepared(action, policyProjection === undefined ? {} : { policyProjection }),
      });
      const result = await new GovernedExecutionRunner({ verifier }).run(executor, {
        captured: forged,
        decision,
        action: ACTION,
      });
      expect(result).toMatchObject({ outcome: "BLOCKED", reason: "INTENT_CONFORMANCE_FAILED" });
      expect(executor.calls).not.toContain("execute");
    }
    expect(claims).not.toHaveBeenCalled();
  });

  it("requires a dossier, and admits Commerce's PROCEED as it admits ALLOW", async () => {
    const { captured, decision, verifier } = await decided();
    const runner = new GovernedExecutionRunner({ verifier });
    const executor = new ScriptedExecutor("dispatch");
    const noDossier = immutableDecisionGate({ ...decision, dossierId: null });
    expect(
      await runner.run(executor, { captured, decision: noDossier, action: ACTION }),
    ).toMatchObject({
      outcome: "BLOCKED",
      reason: "DOSSIER_MISSING",
    });
    const proceed = { ...decision, verdict: "PROCEED" } as unknown as DecisionGate;
    expect(
      await runner.run(executor, { captured, decision: proceed, action: ACTION }),
    ).toMatchObject({
      outcome: "COMPLETED",
    });
  });
});

describe("GovernedExecutionRunner dispatch", () => {
  it("never moves an unknown to a definite answer, whatever the executor reports", async () => {
    for (const [script, outcome, code] of [
      [
        {
          execute: async (run: ClaimedExecution<JsonObject>) => {
            await run.dispatch.run(() => "sent");
            return { kind: "NOT_DISPATCHED" as const, code: "NOT_REALLY" };
          },
        },
        "UNKNOWN_AFTER_DISPATCH",
        undefined,
      ],
      [
        { execute: async () => ({ kind: "NOT_DISPATCHED" as const, code: "lower case" }) },
        "FAILED_BEFORE_DISPATCH",
        "HANDLER_FAILED_BEFORE_DISPATCH",
      ],
      [
        { execute: async () => ({ kind: "NOT_DISPATCHED" as const }) },
        "FAILED_BEFORE_DISPATCH",
        undefined,
      ],
      [
        {
          execute: async () => {
            throw new PreDispatchRefusal("PAYLOAD_BINDING_MISMATCH");
          },
        },
        "FAILED_BEFORE_DISPATCH",
        "PAYLOAD_BINDING_MISMATCH",
      ],
      [
        {
          execute: async () => ({
            kind: "PERMIT" as const,
            permit: {
              permitId: null,
              intentHash: `sha256:${"0".repeat(64)}` as const,
              expiresAt: "x",
            },
          }),
        },
        "FAILED_BEFORE_DISPATCH",
        "EXECUTOR_CONTRACT_VIOLATION",
      ],
      [
        {
          execute: async (run: ClaimedExecution<JsonObject>) => {
            await run.dispatch.run(() => "sent");
            return {
              kind: "PERMIT" as const,
              permit: {
                permitId: null,
                intentHash: `sha256:${"0".repeat(64)}` as const,
                expiresAt: "x",
              },
            };
          },
        },
        "UNKNOWN_AFTER_DISPATCH",
        undefined,
      ],
      [
        {
          observe: async () => {
            throw new Error("unreadable");
          },
        },
        "UNKNOWN_AFTER_DISPATCH",
        undefined,
      ],
      [
        {
          execute: async (run: ClaimedExecution<JsonObject>) =>
            await run.dispatch.run(() => {
              throw new IndeterminateOutcome("TIMEOUT");
            }),
        },
        "UNKNOWN_AFTER_DISPATCH",
        undefined,
      ],
    ] as const) {
      const { captured, decision, verifier } = await decided();
      const runner = new GovernedExecutionRunner({ verifier });
      const result = await runner.run(new ScriptedExecutor("dispatch", script as Script), {
        captured,
        decision,
        action: ACTION,
      });
      expect(result.outcome).toBe(outcome);
      expect("code" in result ? result.code : undefined).toBe(code);
    }
  });

  it("refuses a second dispatch inside one write", async () => {
    const { captured, decision, verifier } = await decided();
    const runner = new GovernedExecutionRunner({ verifier });
    const result = await runner.run(
      new ScriptedExecutor("dispatch", {
        execute: async (run) => {
          await run.dispatch.run(() => "first");
          await run.dispatch.run(() => "second");
          return { kind: "DISPATCHED", receipt: { ok: true } };
        },
      }),
      { captured, decision, action: ACTION },
    );
    expect(result.outcome).toBe("UNKNOWN_AFTER_DISPATCH");
  });

  it("refuses a receipt before the dispatch began", async () => {
    const { captured, decision, verifier } = await decided();
    const runner = new GovernedExecutionRunner({ verifier });
    const result = await runner.run(
      new ScriptedExecutor("dispatch", {
        execute: async (run) => {
          run.dispatch.receipt("a.b.c");
          return { kind: "DISPATCHED", receipt: { ok: true } };
        },
      }),
      { captured, decision, action: ACTION },
    );
    expect(result).toMatchObject({ outcome: "FAILED_BEFORE_DISPATCH" });
  });

  it("forwards the signed receipt and the executor's evidence to the finalization", async () => {
    const { captured, decision } = await decided();
    const finalize = vi.fn(async () => "RECORDED" as const);
    const verifier: AuthorizationVerifier = {
      verifyAndConsume: async () =>
        Object.freeze({
          decisionId: decision.decisionId,
          dossierId: decision.dossierId ?? "",
          grantId: "grant-1",
          intentHash: captured.intentHash,
          expiresAt: decision.authorization?.expiresAt ?? "",
        }),
      finalize,
    };
    const runner = new GovernedExecutionRunner({ verifier });
    const result = await runner.run(
      new ScriptedExecutor("dispatch", {
        execute: async (run) =>
          await run.dispatch.run(async () => {
            run.dispatch.receipt("h.p.s");
            return { kind: "DISPATCHED", receipt: { ok: true } };
          }),
        observe: async () => ({
          status: "COMMITTED",
          reason: null,
          result: {},
          evidence: EVIDENCE,
        }),
      }),
      { captured, decision, action: ACTION },
    );
    expect(result).toMatchObject({ outcome: "COMPLETED", finalization: "RECORDED" });
    expect(finalize).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: "COMMITTED",
        effectReceipt: "h.p.s",
        effectEvidence: EVIDENCE,
      }),
    );
  });

  it("refuses to start a dispatch whose window has already closed", async () => {
    const { captured, decision, verifier: fixture } = await decided();
    const verifier: AuthorizationVerifier = {
      verifyAndConsume: async (c, d) => {
        const authorization = await fixture.verifyAndConsume(c, d);
        return authorization === null
          ? null
          : Object.freeze({ ...authorization, leaseExpiresAt: "2000-01-01T00:00:00.000Z" });
      },
      finalize: async (input) => await (fixture.finalize?.(input) ?? "PENDING"),
    };
    const executor = new ScriptedExecutor("dispatch");
    const result = await new GovernedExecutionRunner({ verifier }).run(executor, {
      captured,
      decision,
      action: ACTION,
    });
    expect(result).toMatchObject({
      outcome: "FAILED_BEFORE_DISPATCH",
      code: "DISPATCH_WINDOW_CLOSED",
    });
    expect(executor.calls).not.toContain("execute");
  });

  it("keeps the outcome when the evidence sink fails", async () => {
    const { runner } = setup({
      evidence: {
        emit: () => {
          throw new Error("sink down");
        },
      },
    });
    const { result } = await runner.submit(new ScriptedExecutor("dispatch"), {
      action: ACTION,
      scope: SCOPE,
      actor: ACTOR,
    });
    expect(result.outcome).toBe("COMPLETED");
  });
});

describe("GovernedExecutionRunner journal", () => {
  it("opens, claims durably and closes every attempt, and reconciles against its own record", async () => {
    const journal = new MemoryJournal();
    const { runner } = setup({ journal });
    const executor = new ScriptedExecutor("dispatch", {
      observe: async () => ({ status: "INDETERMINATE", reason: null, result: null }),
    });
    const { captured, result } = await runner.submit(executor, {
      action: ACTION,
      scope: SCOPE,
      actor: ACTOR,
    });
    expect(result.outcome).toBe("UNKNOWN_AFTER_DISPATCH");
    expect(journal.records.map((record) => record.record)).toEqual([
      "ATTEMPT_OPENED",
      "GRANT_CLAIMED",
      "ATTEMPT_CLOSED",
    ]);
    if (result.outcome !== "UNKNOWN_AFTER_DISPATCH") throw new Error("unreachable");
    const reconciled = await runner.reconcile(executor, {
      captured,
      recovery: result.recovery,
      action: ACTION,
    });
    expect(reconciled.outcome).toBe("COMPLETED");
    expect(journal.records.at(-1)).toMatchObject({ record: "RECONCILED", status: "COMPLETED" });
    // A recovery reference that names a grant this runner never journaled is refused.
    const forged = { ...result.recovery, grantId: "grant-forged" };
    expect(
      await runner.reconcile(executor, { captured, recovery: forged, action: ACTION }),
    ).toMatchObject({ outcome: "BLOCKED", reason: "RECOVERY_BINDING_MISMATCH" });
  });

  it("refuses a second dispatch under a key already claimed, before a grant is spent", async () => {
    const journal = new MemoryJournal();
    const { runner, verifier } = setup({ journal });
    const executor = new ScriptedExecutor("dispatch");
    await runner.submit(executor, { action: ACTION, scope: SCOPE, actor: ACTOR });
    const { result } = await runner.submit(executor, {
      action: ACTION,
      scope: SCOPE,
      actor: ACTOR,
    });
    expect(result).toMatchObject({ outcome: "BLOCKED", reason: "IDEMPOTENCY_KEY_DISPATCHED" });
    expect(verifier.ledger()).toHaveLength(1);
  });

  it("refuses an attempt it cannot open, and fails one it cannot claim durably", async () => {
    const opening = new MemoryJournal();
    opening.failing.set("ATTEMPT_OPENED", new Error("disk full"));
    const first = setup({ journal: opening });
    expect(
      (
        await first.runner.submit(new ScriptedExecutor("dispatch"), {
          action: ACTION,
          scope: SCOPE,
          actor: ACTOR,
        })
      ).result,
    ).toMatchObject({
      outcome: "BLOCKED",
      reason: "JOURNAL_UNAVAILABLE",
      code: "JOURNAL_WRITE_FAILED",
    });
    expect(first.verifier.ledger()).toEqual([]);

    const claiming = new MemoryJournal();
    claiming.failing.set("GRANT_CLAIMED", new JournalError("IDEMPOTENCY_KEY_DISPATCHED"));
    claiming.failing.set("ATTEMPT_CLOSED", new Error("disk full"));
    const second = setup({ journal: claiming });
    const executor = new ScriptedExecutor("dispatch");
    const { result } = await second.runner.submit(executor, {
      action: ACTION,
      scope: SCOPE,
      actor: ACTOR,
    });
    expect(result).toMatchObject({
      outcome: "FAILED_BEFORE_DISPATCH",
      reason: "JOURNAL_UNAVAILABLE",
      code: "IDEMPOTENCY_KEY_DISPATCHED",
      finalization: "RECORDED",
    });
    expect(second.verifier.ledger()[0]?.outcome).toBe("FAILED");
    expect(executor.calls).not.toContain("execute");
  });
});

describe("GovernedExecutionRunner permits", () => {
  it("holds with a permit, claims it once on presentation, and settles from the receipt", async () => {
    const journal = new MemoryJournal();
    const { runner, verifier, lines } = setup({ journal });
    const executor = new ScriptedExecutor("permit");
    const { result } = await runner.submit(executor, {
      action: ACTION,
      scope: SCOPE,
      actor: ACTOR,
    });
    if (result.outcome !== "HELD" || !("permit" in result)) throw new Error("not held");
    expect(result.permit.permitId).toMatch(/^[0-9a-f-]{36}$/);
    const presented = await runner.present(result.held);
    // The executor's own attestation is not the authority's, so it is not carried.
    expect(presented).toMatchObject({
      outcome: "CLAIMED",
      permit: { permitId: result.permit.permitId },
    });
    if (presented.outcome !== "CLAIMED" || !("permit" in presented)) throw new Error("not claimed");
    expect(Object.keys(presented.permit)).not.toContain("claimAttestation");
    const settlement = await runner.settle(result.held, { receipt: { ok: true } });
    expect(settlement).toMatchObject({ status: "SETTLED", outcome: "COMPLETED", executed: true });
    expect(verifier.ledger()[0]?.outcome).toBe("COMMITTED");
    expect(lines.map((line) => line.stage)).toEqual(["RUN", "PRESENTATION", "SETTLEMENT"]);
    expect(journal.records.map((record) => record.record)).toEqual([
      "ATTEMPT_OPENED",
      "GRANT_CLAIMED",
      "ATTEMPT_CLOSED",
    ]);
  });

  it("fails a presentation whose executor issues no permit, after the claim, before any write", async () => {
    for (const execute of [
      async () => ({ kind: "NOT_DISPATCHED" as const }),
      async () => {
        throw new Error("issuer config missing");
      },
      async (run: ClaimedExecution<JsonObject>) =>
        await run.dispatch.run(async () => ({ kind: "DISPATCHED" as const, receipt: null })),
    ]) {
      const { runner, verifier } = setup();
      const { result } = await runner.submit(new ScriptedExecutor("permit", { execute }), {
        action: ACTION,
        scope: SCOPE,
        actor: ACTOR,
      });
      if (result.outcome !== "HELD") throw new Error("not held");
      expect(await runner.present(result.held)).toMatchObject({
        outcome: "FAILED_BEFORE_DISPATCH",
        code: "PERMIT_NOT_ISSUED",
      });
      expect(verifier.ledger()[0]?.outcome).toBe("FAILED");
    }
  });

  it("settles a claim adopted from another replica, preparing it only when a receipt needs it", async () => {
    const { captured, decision, verifier } = await decided();
    const first = new GovernedExecutionRunner({ verifier });
    const executor = new ScriptedExecutor("permit");
    const held = await first.hold(executor, { captured, decision, action: ACTION });
    if (held.outcome !== "HELD") throw new Error("not held");
    const claim = await first.present(held.held);
    if (claim.outcome !== "CLAIMED") throw new Error("not claimed");

    const second = new GovernedExecutionRunner({ verifier });
    const material = second.claimMaterial(claim.authorization);
    expect(material).not.toBeNull();
    expect(() =>
      second.adoptClaim(executor, { captured, decision, action: ACTION }, claim.authorization, {
        kind: "someone-else",
      }),
    ).toThrow("CLAIM_MATERIAL_REFUSED");
    expect(() =>
      second.adoptClaim(
        executor,
        {
          captured,
          decision: { ...decision, intentHash: `sha256:${"f".repeat(64)}` },
          action: ACTION,
        },
        claim.authorization,
      ),
    ).toThrow("CLAIM_ADOPTION_MISMATCH");
    const adopted = second.adoptClaim(
      executor,
      { captured, decision, action: ACTION },
      claim.authorization,
      material,
    );
    expect(executor.calls.filter((call) => call === "prepare")).toHaveLength(1);
    const settlement = await second.settle(adopted, { receipt: { ok: false } });
    expect(settlement).toMatchObject({
      status: "SETTLED",
      outcome: "DEFINITELY_NOT_EXECUTED",
      reason: "PROVIDER_REFUSED",
    });
    expect(executor.calls.filter((call) => call === "prepare")).toHaveLength(2);
    expect(await second.settle(adopted, { receipt: { ok: true } })).toEqual({
      status: "REFUSED",
      reason: "RECEIPT_DUPLICATE",
    });
  });

  it("reads a receipt the executor cannot read as unknown, with a recovery reference", async () => {
    const { runner } = setup();
    const executor = new ScriptedExecutor("permit", {
      observe: async () => {
        throw new Error("unreadable posting entry");
      },
    });
    const { result } = await runner.submit(executor, {
      action: ACTION,
      scope: SCOPE,
      actor: ACTOR,
    });
    if (result.outcome !== "HELD") throw new Error("not held");
    await runner.present(result.held);
    const settlement = await runner.settle(result.held, {
      receipt: { ok: true },
      signedReceipt: "a.b.c",
    });
    expect(settlement).toMatchObject({
      status: "SETTLED",
      outcome: "UNKNOWN_AFTER_DISPATCH",
      reason: "PROVIDER_OUTCOME_UNKNOWN",
      recovery: { version: "agent-safe.recovery/1" },
    });
  });

  it("holds a dispatch-style executor for a caller that performs the effect, with no permit", async () => {
    const { runner } = setup();
    const { result } = await runner.submit(new ScriptedExecutor("dispatch"), {
      action: ACTION,
      scope: SCOPE,
      actor: ACTOR,
    });
    expect(result.outcome).toBe("COMPLETED");
    const { captured, decision, verifier } = await decided();
    const holder = new GovernedExecutionRunner({ verifier });
    const held = await holder.hold(new ScriptedExecutor("dispatch"), {
      captured,
      decision,
      action: ACTION,
    });
    if (held.outcome !== "HELD") throw new Error("not held");
    expect("permit" in held).toBe(false);
    expect(await holder.present(held.held)).toEqual({
      outcome: "CLAIMED",
      authorization: expect.objectContaining({ intentHash: captured.intentHash }),
    });
    expect(await holder.settle(held.held, { outcome: "COMMITTED" })).toMatchObject({
      outcome: "COMPLETED",
    });
  });
});

describe("GovernedExecutionRunner reconciliation reports", () => {
  async function unknown(
    verifier: AuthorizationVerifier,
    options: Partial<GovernedExecutionRunnerOptions> = {},
  ) {
    const { captured, decision } = await decided();
    const runner = new GovernedExecutionRunner({ ...options, verifier });
    const lines: ExecutorEvidenceLine[] = [];
    const reporting = new GovernedExecutionRunner({
      ...options,
      verifier,
      evidence: { emit: (line) => void lines.push(line) },
    });
    const recovery = {
      version: "agent-safe.recovery/1" as const,
      decisionId: decision.decisionId,
      dossierId: decision.dossierId ?? "",
      grantId: "grant-1",
      intentHash: captured.intentHash,
      expiresAt: decision.authorization?.expiresAt ?? "",
      idempotencyKey: captured.intent.idempotencyKey,
    };
    void runner;
    return { reporting, captured, recovery, lines };
  }

  it("reports a proven answer to the authority, and records what the authority said", async () => {
    for (const [answer, report, finalization] of [
      ["COMPLETED", async () => "RECORDED" as const, "RECORDED"],
      ["NOT_EXECUTED", async () => "PENDING" as const, "PENDING"],
      [
        "COMPLETED",
        async (): Promise<"RECORDED"> => {
          throw new Error("authority down");
        },
        "PENDING",
      ],
    ] as const) {
      const reconcile = vi.fn(report);
      const { reporting, captured, recovery, lines } = await unknown({
        verifyAndConsume: async () => null,
        reconcile,
      });
      const executor = new ScriptedExecutor("dispatch", {
        reconcile: async () =>
          answer === "COMPLETED"
            ? { status: "COMPLETED", result: { ok: true }, evidence: EVIDENCE }
            : { status: "NOT_EXECUTED" },
      });
      await reporting.reconcile(executor, { captured, recovery, action: ACTION });
      expect(reconcile).toHaveBeenCalledWith(
        expect.objectContaining({ outcome: answer === "COMPLETED" ? "COMMITTED" : "FAILED" }),
      );
      expect(lines.at(-1)).toMatchObject({ stage: "RECONCILIATION", finalization });
    }
  });

  it("says when the verifier has no reconciliation contract, and stays quiet when told to", async () => {
    const quiet = await unknown({ verifyAndConsume: async () => null });
    await quiet.reporting.reconcile(new ScriptedExecutor("dispatch"), {
      captured: quiet.captured,
      recovery: quiet.recovery,
      action: ACTION,
    });
    expect(quiet.lines.at(-1)?.finalization).toBe("UNSUPPORTED");

    const reconcile = vi.fn(async () => "RECORDED" as const);
    const off = await unknown(
      { verifyAndConsume: async () => null, reconcile },
      { reportReconciliations: false },
    );
    await off.reporting.reconcile(new ScriptedExecutor("dispatch"), {
      captured: off.captured,
      recovery: off.recovery,
      action: ACTION,
    });
    expect(reconcile).not.toHaveBeenCalled();
    expect(off.lines.at(-1)?.finalization).toBeNull();
  });
});

describe("the runner's supporting pieces", () => {
  it("reads an unreadable custom posture as strict", () => {
    const context = { captured: {} as CapturedIntent, decision: {} as DecisionGate };
    expect(unavailableDisposition({ posture: "STRICT" }, context)).toBe("NOT_FORWARDED");
    expect(unavailableDisposition({ posture: "BOUNDED_CONTINUITY" }, context)).toBe(
      "FORWARDED_UNGOVERNED",
    );
    expect(
      unavailableDisposition(
        {
          posture: "CUSTOM",
          decide: () => {
            throw new Error("rule broke");
          },
        },
        context,
      ),
    ).toBe("NOT_FORWARDED");
    expect(
      unavailableDisposition({ posture: "CUSTOM", decide: () => "ALLOW" as never }, context),
    ).toBe("NOT_FORWARDED");
    expect(unavailableDisposition({ posture: "CUSTOM", decide: () => "HELD" }, context)).toBe(
      "HELD",
    );
    expect(evidenceScope(null)).toBeNull();
  });

  it("states no capability for a registry, and reads anything but a dispatch as unknown", async () => {
    const executor = new RegistryExecutor(new ActionRegistry().seal(), "runtime");
    expect(executor.platform).toBe("runtime");
    expect(await executor.capabilities()).toEqual([]);
    expect(await executor.observe({ kind: "NOT_DISPATCHED" })).toMatchObject({
      status: "INDETERMINATE",
    });
    expect(new IndeterminateOutcome("TIMEOUT")).toMatchObject({
      name: "IndeterminateOutcome",
      reason: "TIMEOUT",
      providerStatus: null,
      receipt: null,
    });
  });
});
