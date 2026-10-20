/**
 * Loopback proof for the policy projection. Every assertion runs over a real
 * HTTP stack against `LocalAuthority`, whose independent canonicalizer
 * re-derives the intent hash from the binding it receives, so a projection
 * that reaches a grant, a managed escalation and a claim is bound the way
 * Decionis binds it. The double's policy routes by the projection, as Core
 * does: no projection, no rule.
 *
 * All tenants, actors, orders and grants are synthetic.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DecionisGate } from "../../src/decision/DecionisGate.js";
import { DecionisGrantVerifier } from "../../src/execution/AuthorizationVerifier.js";
import { GovernedExecutionRunner } from "../../src/execution/GovernedExecutionRunner.js";
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
import type {
  CapturedIntent,
  ExecutionIntent,
  PolicyProjection,
} from "../../src/intent/ExecutionIntent.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import type { JsonObject } from "../../src/intent/JsonValue.js";
import {
  LOCAL_AUTHORITY_API_KEY,
  LocalAuthority,
  LocalPresence,
  type LocalAuthorityRequestRecord,
} from "../../src/testing/Index.js";

const CRO = "synthetic-cro";
const TENANT = "00000000-0000-4000-8000-000000000006";
const ACTOR = { id: "synthetic-commerce-walmart", type: "SERVICE" };
const SCOPE: ExecutorScope = {
  orgId: TENANT,
  workspaceId: "synthetic-workspace",
  connectionId: "synthetic-connection",
  connectionRevision: "1",
  environment: "sandbox",
};
const ACCEPTANCE: PolicyProjection = {
  decisionType: "ORDER_ACCEPTANCE",
  transactionType: "order_acceptance",
  workflowKey: "commerce_order_acceptance",
  channel: "connector",
};
const RELEASE: PolicyProjection = {
  decisionType: "ORDER_RELEASE",
  transactionType: "order_release",
  workflowKey: "commerce_order_release",
  channel: null,
};

const presence = new LocalPresence({ autoComplete: "MANUAL", roles: { [CRO]: "CRO" } });
const authority = new LocalAuthority({
  presence,
  // Core routes a grant by the projection; without one it evaluates the
  // action type, which no order rule names.
  policy: (request) => {
    switch (request.policy_projection?.decision_type) {
      case "ORDER_ACCEPTANCE":
        return "ALLOW";
      case "ORDER_RELEASE":
        return "ESCALATE";
      default:
        return "BLOCK";
    }
  },
});
let sequence = 0;

beforeAll(async () => {
  await presence.start();
  await authority.start();
});

afterAll(async () => {
  await authority.stop();
  await presence.stop();
});

interface OrderAck {
  readonly orderId: string;
}

/** A dispatch-style order acknowledgement that states the policy path it is decided under. */
class OrderAckExecutor implements NativeExecutor<OrderAck, JsonObject, JsonObject> {
  public readonly platform = "walmart-marketplace";
  public readonly version = "1.0.0";
  public readonly style = "dispatch";
  public readonly actionTypes = ["order.acknowledge"];
  public readonly writes: string[] = [];

  public constructor(private readonly projection: PolicyProjection | null) {}

  public async capabilities(): Promise<readonly ExecutionCapability[]> {
    return [
      {
        platform: this.platform,
        actionType: "order.acknowledge",
        enabled: true,
        scopeGranted: true,
        connected: true,
        requirement: "",
      },
    ];
  }

  public async prepare(action: OrderAck): Promise<PreparedAction> {
    return {
      actionType: "order.acknowledge",
      proposal: {
        action: "order.acknowledge",
        target: `walmart-marketplace/orders/${action.orderId}`,
        parameters: { purchase_order_id: action.orderId },
      },
      downstreamTarget: { system: "walmart-marketplace", operation: "order.acknowledge" },
      idempotencyKey: `synthetic-ack-${action.orderId}`,
      expectedEffectDigest: null,
      requestDigest: `sha256:${"1".repeat(64)}`,
      facts: { lane: "sandbox" },
      ...(this.projection === null ? {} : { policyProjection: this.projection }),
    };
  }

  public async execute(run: ClaimedExecution<OrderAck>): Promise<ExecutionEffect<JsonObject>> {
    return await run.dispatch.run(async () => {
      this.writes.push(run.idempotencyKey);
      return { kind: "DISPATCHED", receipt: { ok: true } };
    });
  }

  public async observe(
    effect: ExecutionEffect<JsonObject>,
  ): Promise<EffectObservation<JsonObject>> {
    return effect.kind === "DISPATCHED" && effect.receipt?.["ok"] === true
      ? { status: "COMMITTED", reason: null, result: effect.receipt }
      : { status: "INDETERMINATE", reason: null, result: null };
  }

  public async reconcile(): Promise<ReconcileResult<JsonObject>> {
    return { status: "UNKNOWN" };
  }
}

function gate() {
  return new DecionisGate({
    baseUrl: authority.baseUrl,
    apiKey: LOCAL_AUTHORITY_API_KEY,
    allowInsecureLoopback: true,
  });
}

function verifier() {
  return new DecionisGrantVerifier({
    baseUrl: authority.baseUrl,
    apiKey: LOCAL_AUTHORITY_API_KEY,
    allowInsecureLoopback: true,
  });
}

function runner() {
  return new GovernedExecutionRunner({
    verifier: verifier(),
    authority: gate(),
    capture: new IntentCapture({ ttlSeconds: 120 }),
  });
}

function nextOrder(): OrderAck {
  sequence += 1;
  return { orderId: `synthetic-${sequence}` };
}

/** The requests the authority saw for one intent: the grant request first, then its claim. */
function requestsFor(captured: CapturedIntent): readonly LocalAuthorityRequestRecord[] {
  return authority.requests.filter((record) => {
    const body = record.body as { intent_id?: unknown; intent?: { intent_id?: unknown } } | null;
    return (
      body?.intent_id === captured.intent.intentId ||
      body?.intent?.intent_id === captured.intent.intentId
    );
  });
}

/** The claim the authority saw for one intent, on the grant's resource or the deprecated alias. */
function claimFor(captured: CapturedIntent): LocalAuthorityRequestRecord | undefined {
  return requestsFor(captured).find(
    (record) => record.path.endsWith("/claims") || record.path.endsWith("/claim-token"),
  );
}

const WIRE_ACCEPTANCE = {
  decision_type: "ORDER_ACCEPTANCE",
  transaction_type: "order_acceptance",
  workflow_key: "commerce_order_acceptance",
  channel: "connector",
};

describe("the policy projection over the wire", () => {
  it("is granted, claimed and written once under the projection the executor states", async () => {
    const executor = new OrderAckExecutor(ACCEPTANCE);
    const order = nextOrder();
    const { captured, decision, result } = await runner().submit(executor, {
      action: order,
      scope: SCOPE,
      actor: ACTOR,
    });

    expect(decision.verdict).toBe("ALLOW");
    expect(result).toMatchObject({ outcome: "COMPLETED", executed: true });
    expect(executor.writes).toEqual([`synthetic-ack-${order.orderId}`]);
    expect(captured.intent.policyProjection).toEqual(ACCEPTANCE);

    const [grant] = requestsFor(captured);
    const claim = claimFor(captured);
    const grantBody = grant?.body as Record<string, unknown>;
    // The projection travels at the binding's top level, never as a context fact,
    // and the authority's own re-hash of what it received is the captured hash.
    expect(grantBody["policy_projection"]).toEqual(WIRE_ACCEPTANCE);
    expect(grantBody["context"]).not.toHaveProperty("policy_projection");
    expect(grant?.recomputedHash).toBe(captured.intentHash);
    const claimed = (claim?.body as { intent: Record<string, unknown> }).intent;
    expect(claimed["policy_projection"]).toEqual(WIRE_ACCEPTANCE);
    expect(claim?.recomputedHash).toBe(captured.intentHash);
  });

  it("is decided under the action type when no projection is stated, and sends none", async () => {
    const executor = new OrderAckExecutor(null);
    const { captured, decision, result } = await runner().submit(executor, {
      action: nextOrder(),
      scope: SCOPE,
      actor: ACTOR,
    });

    expect(decision.verdict).toBe("BLOCK");
    expect(result).toMatchObject({ outcome: "BLOCKED" });
    expect(executor.writes).toEqual([]);
    const [grant] = requestsFor(captured);
    expect(grant?.body).not.toHaveProperty("policy_projection");
    expect(grant?.recomputedHash).toBe(captured.intentHash);
  });

  it("refuses at the claim a projection stripped or changed after the grant was decided", async () => {
    const executor = new OrderAckExecutor(ACCEPTANCE);
    const order = nextOrder();
    const prepared = await executor.prepare(order);
    const captured = new IntentCapture({ ttlSeconds: 120 }).capture(prepared.proposal, {
      tenantId: TENANT,
      actor: ACTOR,
      downstreamTarget: prepared.downstreamTarget,
      context: prepared.facts,
      idempotencyKey: prepared.idempotencyKey,
      policyProjection: ACCEPTANCE,
    });
    const decision = await gate().evaluate(captured);
    expect(decision.verdict).toBe("ALLOW");

    const withoutProjection: Partial<ExecutionIntent> = { ...captured.intent };
    delete withoutProjection.policyProjection;
    for (const intent of [
      withoutProjection,
      { ...captured.intent, policyProjection: { ...ACCEPTANCE, decisionType: "PRICE_CHANGE" } },
    ]) {
      // The decided hash with another binding: what a process that dropped or
      // rewrote the projection between decision and claim would present.
      const forged = { ...captured, intent: intent as CapturedIntent["intent"] };
      expect(await verifier().verifyAndConsume(forged, decision)).toBeNull();
      const claim = authority.requests.at(-1);
      expect(claim?.response?.body).toMatchObject({ reason_codes: ["INTENT_HASH_MISMATCH"] });
    }

    // The grant was never spent by the forgeries; the decided intent still claims it.
    expect(await verifier().verifyAndConsume(captured, decision)).not.toBeNull();
  });

  it("carries the projection through a managed escalation to the grant the approval earns", async () => {
    const executor = new OrderAckExecutor(RELEASE);
    const order = nextOrder();
    const prepared = await executor.prepare(order);
    const captured = new IntentCapture({ ttlSeconds: 120 }).capture(prepared.proposal, {
      tenantId: TENANT,
      actor: ACTOR,
      downstreamTarget: prepared.downstreamTarget,
      context: prepared.facts,
      idempotencyKey: prepared.idempotencyKey,
      policyProjection: RELEASE,
    });
    const authorityGate = gate();
    const pending = await authorityGate.evaluate(captured, undefined, {
      escalation: {
        mode: "MANAGED",
        approver: { principal_id: CRO, role_id: "CRO" },
      },
    });
    expect(pending.verdict).toBe("ESCALATE");
    expect(pending.managedEscalation?.status).toBe("PENDING_PRESENCE");

    const [grant] = requestsFor(captured);
    const body = grant?.body as Record<string, unknown>;
    expect(body["policy_projection"]).toEqual({
      decision_type: "ORDER_RELEASE",
      transaction_type: "order_release",
      workflow_key: "commerce_order_release",
      channel: null,
    });
    expect(body["escalation"]).toMatchObject({ mode: "MANAGED" });
    expect(grant?.recomputedHash).toBe(captured.intentHash);

    const record = authority.escalations.get(pending.managedEscalation?.escalationId ?? "");
    if (record === undefined || record.presenceRequestId === null) {
      throw new Error("TEST_EXPECTED_ORCHESTRATED_ESCALATION");
    }
    const waiting = authorityGate.waitForAuthorization(captured, pending, {
      initialDelayMs: 5,
      maxDelayMs: 10,
    });
    await new Promise((resolve) => setTimeout(resolve, 25));
    presence.approve(record.presenceRequestId);
    const authorized = await waiting;
    expect(authorized.verdict).toBe("ALLOW");

    const result = await runner().run(executor, {
      captured,
      decision: authorized,
      action: order,
      scope: SCOPE,
    });
    expect(result).toMatchObject({ outcome: "COMPLETED" });
    expect(executor.writes).toEqual([`synthetic-ack-${order.orderId}`]);
    const claim = claimFor(captured);
    expect((claim?.body as { intent: Record<string, unknown> }).intent).toHaveProperty(
      "policy_projection.decision_type",
      "ORDER_RELEASE",
    );
    expect(claim?.recomputedHash).toBe(captured.intentHash);
  });
});
