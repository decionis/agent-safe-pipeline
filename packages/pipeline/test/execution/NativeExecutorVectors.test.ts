import { readFile, readdir } from "node:fs/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DecisionAuthority } from "../../src/decision/DecisionAuthority.js";
import { createFixtureAuthorityPair } from "../../src/decision/FixtureDecisionAuthority.js";
import { PreDispatchRefusal, ProviderRefusal } from "../../src/execution/ActionRegistry.js";
import type { FixtureAuthorizationVerifier } from "../../src/decision/FixtureDecisionAuthority.js";
import type {
  ExecutionRecoveryReference,
  HeldExecution,
} from "../../src/execution/ExecutionOutcome.js";
import type { ExecutorEvidenceLine } from "../../src/execution/ExecutorEvidence.js";
import { GovernedExecutionRunner } from "../../src/execution/GovernedExecutionRunner.js";
import type {
  ClaimedExecution,
  EffectObservation,
  ExecutionEffect,
  ExecutorScope,
  NativeExecutor,
  PreparedAction,
  ReconcileResult,
} from "../../src/execution/NativeExecutor.js";
import {
  ExecutorEvidenceLineSchema,
  ExecutorVectorSchema,
  NATIVE_EXECUTOR_SCHEMA_ID,
  nativeExecutorJsonSchema,
  type ExecutorVector,
} from "../../src/execution/NativeExecutorSchema.js";
import type { CapturedIntent } from "../../src/intent/ExecutionIntent.js";
import type { JsonObject } from "../../src/intent/JsonValue.js";

const VECTORS = new URL("../../../../spec/executors/native/v1/vectors/", import.meta.url);
const PUBLISHED = new URL("../../../../spec/executors/native/v1/schema.json", import.meta.url);

const SCOPE: ExecutorScope = {
  orgId: "00000000-0000-4000-8000-000000000005",
  workspaceId: "workspace-vector",
  connectionId: "connection-vector",
  connectionRevision: "1",
  environment: "sandbox",
};

type Write = Extract<ExecutorVector["steps"][number], { op: "run" }>["write"];
type Receipt = { readonly status: "POSTED" | "REJECTED" | "UNREADABLE" };

/**
 * The vector platform: one action type, a write the vector scripts, a
 * posting receipt in its own vocabulary, and a read-only lookup the vector
 * answers. It does only what the contract lets an executor do.
 */
class VectorExecutor implements NativeExecutor<JsonObject, Receipt, JsonObject> {
  public readonly platform = "vector-platform";
  public readonly version = "1.0.0";
  public readonly actionTypes = ["vector.write"];
  public writes = 0;
  public write: Write = "COMMIT";
  public answer: ReconcileResult<JsonObject>["status"] = "UNKNOWN";

  public constructor(public readonly style: "dispatch" | "permit") {}

  public async capabilities(scope: ExecutorScope) {
    return [
      {
        platform: this.platform,
        actionType: "vector.write",
        enabled: scope.connectionId === SCOPE.connectionId,
        scopeGranted: true,
        connected: true,
        requirement: "",
      },
    ];
  }

  public async prepare(action: JsonObject): Promise<PreparedAction> {
    return {
      actionType: "vector.write",
      proposal: { action: "vector.write", target: "vector:ledger-1", parameters: action },
      downstreamTarget: { system: "vector", operation: "write" },
      idempotencyKey: "vector-key-1",
      expectedEffectDigest: null,
      requestDigest: `sha256:${"0".repeat(64)}`,
      facts: {},
    };
  }

  public async execute(run: ClaimedExecution<JsonObject>): Promise<ExecutionEffect<Receipt>> {
    if (this.style === "permit") {
      return {
        kind: "PERMIT",
        permit: {
          permitId: run.authorization.grantId,
          intentHash: run.intent.intentHash,
          expiresAt: run.authorization.expiresAt,
        },
      };
    }
    if (this.write === "FAIL_BEFORE_DISPATCH")
      throw new PreDispatchRefusal("VECTOR_PAYLOAD_INVALID");
    return await run.dispatch.run(async () => {
      this.writes += 1;
      if (this.write === "THROW_AFTER_DISPATCH") throw new Error("connection reset");
      if (this.write === "REFUSE") throw new ProviderRefusal("VECTOR_PLATFORM_REFUSED");
      if (this.write === "INDETERMINATE") return { kind: "DISPATCHED", receipt: null };
      return { kind: "DISPATCHED", receipt: { status: "POSTED" } };
    });
  }

  public async observe(effect: ExecutionEffect<Receipt>): Promise<EffectObservation<JsonObject>> {
    const receipt =
      effect.kind === "DISPATCHED" || effect.kind === "RECEIPT" ? effect.receipt : null;
    if (receipt?.status === "POSTED") {
      return { status: "COMMITTED", reason: null, result: { posted: true } };
    }
    if (receipt?.status === "REJECTED") {
      return { status: "FAILED", reason: "VECTOR_POSTING_REJECTED", result: null };
    }
    return { status: "INDETERMINATE", reason: null, result: null };
  }

  public async reconcile(): Promise<ReconcileResult<JsonObject>> {
    if (this.answer === "COMPLETED") return { status: "COMPLETED", result: { posted: true } };
    return { status: this.answer };
  }
}

/** An authority that cannot be reached: the runner records it as a decision that failed closed. */
const unreachable: DecisionAuthority = {
  evaluate: async () => {
    throw new Error("connect ECONNREFUSED");
  },
};

interface RunState {
  captured: CapturedIntent | null;
  held: HeldExecution | null;
  recovery: ExecutionRecoveryReference | null;
  grantId: string | null;
}

async function vectors(): Promise<readonly { name: string; vector: ExecutorVector }[]> {
  const files = (await readdir(VECTORS)).filter((file) => file.endsWith(".json")).sort();
  return await Promise.all(
    files.map(async (name) => ({
      name,
      vector: ExecutorVectorSchema.parse(
        JSON.parse(await readFile(new URL(name, VECTORS), "utf8")),
      ),
    })),
  );
}

async function play(vector: ExecutorVector): Promise<void> {
  const { authority, verifier } = createFixtureAuthorityPair(() => vector.decision.verdict, {
    unsafeAllowDevelopmentFixture: true,
  });
  const lines: ExecutorEvidenceLine[] = [];
  const runner = new GovernedExecutionRunner({
    verifier,
    authority: vector.decision.fail_closed ? unreachable : authority,
    evidence: { emit: (line) => void lines.push(line) },
    posture:
      vector.posture === "CUSTOM"
        ? { posture: "CUSTOM", decide: () => vector.custom_disposition ?? "NOT_FORWARDED" }
        : { posture: vector.posture },
  });
  const executor = new VectorExecutor(vector.style);
  const action: JsonObject = { line: "BC-1", amount_minor: 125_000, currency: "EUR" };
  const state: RunState = { captured: null, held: null, recovery: null, grantId: null };
  const actor = { id: "synthetic-vector-agent", type: "agent" };

  for (const [index, step] of vector.steps.entries()) {
    const at = `step ${index + 1} (${step.op})`;
    if (step.op === "advance") {
      vi.setSystemTime(Date.now() + step.ms);
      continue;
    }
    const linesBefore = lines.length;
    let observed: Record<string, unknown>;
    if (step.op === "run" || step.op === "hold") {
      if (step.op === "run") executor.write = step.write;
      const submitted = await runner.submit(executor, { action, scope: SCOPE, actor });
      state.captured = submitted.captured;
      const result = submitted.result;
      if (result.outcome === "HELD") state.held = result.held;
      if (result.outcome === "UNKNOWN_AFTER_DISPATCH") state.recovery = result.recovery;
      if (result.authorization !== null) state.grantId = result.authorization.grantId;
      observed = { ...result, permit: "permit" in result };
    } else if (step.op === "present") {
      const presented = await runner.present(requireHeld(state, at));
      if (presented.authorization !== null) state.grantId = presented.authorization.grantId;
      observed = { ...presented, permit: "permit" in presented };
    } else if (step.op === "receipt") {
      const settlement = await runner.settle<Receipt, JsonObject>(requireHeld(state, at), {
        receipt: { status: step.status },
      });
      if (settlement.status === "SETTLED" && settlement.recovery !== undefined) {
        state.recovery = settlement.recovery;
      }
      observed =
        settlement.status === "REFUSED"
          ? { outcome: "REFUSED", reason: settlement.reason }
          : settlement;
    } else {
      executor.answer = step.answer;
      const captured = state.captured;
      const recovery = state.recovery;
      if (captured === null || recovery === null) throw new Error(`${at}: nothing to reconcile`);
      observed = {
        ...(await runner.reconcile(executor, { captured, recovery, action, scope: SCOPE })),
      };
    }

    const expected = step.expect;
    expect(observed["outcome"], at).toBe(expected.outcome);
    if (expected.executed !== undefined) expect(observed["executed"], at).toBe(expected.executed);
    if (expected.reason !== undefined) expect(observed["reason"], at).toBe(expected.reason);
    if (expected.code !== undefined) expect(observed["code"], at).toBe(expected.code);
    if (expected.permit !== undefined) expect(observed["permit"], at).toBe(expected.permit);
    if (expected.writes !== undefined) expect(executor.writes, at).toBe(expected.writes);
    if (expected.finalized !== undefined) {
      expect(finalizedOf(verifier, state.grantId), at).toBe(expected.finalized);
    }
    const emitted = lines.slice(linesBefore);
    if (expected.disposition !== undefined) {
      expect(emitted.at(-1)?.disposition, at).toBe(expected.disposition);
      if (vector.posture !== "STRICT") {
        expect(
          (observed["unavailable"] as { disposition?: string } | undefined)?.disposition,
          at,
        ).toBe(expected.disposition);
      }
    }
    // Every line the runner wrote is the published evidence shape.
    for (const line of emitted) {
      const parsed = ExecutorEvidenceLineSchema.safeParse(line);
      expect(parsed.success, `${at}: ${JSON.stringify(parsed.error?.issues ?? [])}`).toBe(true);
    }
  }
}

function requireHeld(state: RunState, at: string): HeldExecution {
  if (state.held === null) throw new Error(`${at}: nothing held`);
  return state.held;
}

function finalizedOf(
  verifier: FixtureAuthorizationVerifier,
  grantId: string | null,
): string | null {
  return grantId === null ? null : (verifier.commitOf(grantId)?.outcome ?? null);
}

describe("agent-safe.executors.native/1 conformance vectors", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("publishes a schema that is exactly the reference implementation's", async () => {
    const published = JSON.parse(await readFile(PUBLISHED, "utf8")) as Record<string, unknown>;
    expect(published["$id"]).toBe(NATIVE_EXECUTOR_SCHEMA_ID);
    expect(published).toEqual(nativeExecutorJsonSchema());
  });

  it("covers both styles, the receipt rules, an indeterminate dispatch and every posture", async () => {
    const all = await vectors();
    const names = all.map(({ name }) => name);
    for (const required of [
      "dispatch-commit.json",
      "permit-settled.json",
      "duplicate-receipt.json",
      "expired-permit.json",
      "replayed-permit.json",
      "dispatch-indeterminate.json",
      "posture-strict.json",
      "posture-bounded-continuity.json",
      "posture-custom-held.json",
    ]) {
      expect(names).toContain(required);
    }
    expect(new Set(all.map(({ vector }) => vector.style))).toEqual(new Set(["dispatch", "permit"]));
  });

  it("holds the runner to every vector", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    for (const { name, vector } of await vectors()) {
      vi.setSystemTime(new Date("2026-10-18T09:00:00.000Z"));
      await expect(play(vector), name).resolves.toBeUndefined();
    }
  });
});
