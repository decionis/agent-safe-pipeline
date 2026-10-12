import { z } from "zod";
import { describe, expect, it } from "vitest";
import type { AuditRecorder } from "../../src/audit/AuditRecorder.js";
import type { DecisionGate } from "../../src/decision/DecisionAuthority.js";
import { immutableDecisionGate } from "../../src/decision/ImmutableDecisionGate.js";
import {
  FixtureAuthorizationVerifier,
  createFixtureAuthorityPair,
} from "../../src/decision/FixtureDecisionAuthority.js";
import { ActionRegistry } from "../../src/execution/ActionRegistry.js";
import { InMemoryReplayStore } from "../../src/execution/ReplayStore.js";
import { SafeExecutor } from "../../src/execution/SafeExecutor.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

function captured(amount = 350) {
  return new IntentCapture({ ttlSeconds: 120 }).capture(
    {
      action: "refund_order",
      target: "shopify:order:58291",
      parameters: { amount, currency: "USD" },
    },
    {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: { id: "synthetic-refund-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "shopify", operation: "refund" },
      idempotencyKey: `refund-${amount}`,
      context: {},
    },
  );
}

const registry = new ActionRegistry()
  .register("refund_order", {
    parametersSchema: z.object({ amount: z.number().positive(), currency: z.string().length(3) }),
    execute: async () => ({}),
  })
  .seal();

/** An audit recorder that keeps what it was asked to record. */
function audit() {
  const events: { eventType: string; reasonCodes?: readonly string[] }[] = [];
  const recorder = {
    requiresDeliveryBeforeExecution: false,
    record: async (input: { eventType: string; reasonCodes?: readonly string[] }) => {
      events.push({
        eventType: input.eventType,
        ...(input.reasonCodes ? { reasonCodes: input.reasonCodes } : {}),
      });
      return true;
    },
  } as unknown as AuditRecorder;
  return { recorder, events };
}

/** One "replica": an authority pair of its own, over a shared replay store. */
function replica(replayStore = new InMemoryReplayStore()) {
  const pair = createFixtureAuthorityPair(() => "ALLOW", {
    unsafeAllowDevelopmentFixture: true,
    replayStore,
  });
  const { recorder, events } = audit();
  return { pair, events, executor: new SafeExecutor(registry, pair.verifier, recorder) };
}

describe("hold adoption", () => {
  it("admits a hold another executor made, records it as adopted, and the grant is still claimed once", async () => {
    const replay = new InMemoryReplayStore();
    const a = replica(replay);
    // B verifies A's authority's grants: the same issuer key, the same replay store, a different process.
    const b = {
      ...replica(replay),
      executor: new SafeExecutor(
        registry,
        new FixtureAuthorizationVerifier(a.pair.authority.publicKey(), replay, true),
        audit().recorder,
      ),
    };
    const intent = captured();
    const decision = await a.pair.authority.evaluate(intent);
    const held = await a.executor.hold(intent, decision);
    expect(held.outcome).toBe("HELD");
    const adopted = await b.executor.adoptHold(intent, decision);
    expect(adopted.outcome).toBe("HELD");
    if (adopted.outcome !== "HELD" || held.outcome !== "HELD") throw new Error("not held");
    expect(adopted.held).not.toBe(held.held);
    expect(adopted.held.expiresAt).toBe(held.held.expiresAt);
    // B claims the adopted hold; A's own handle then finds the grant spent at the replay store.
    const claimed = await b.executor.claimHeld(adopted.held);
    expect(claimed.outcome).toBe("CLAIMED");
    const late = await a.executor.claimHeld(held.held);
    expect(late.outcome).toBe("BLOCKED");
    expect(late).toMatchObject({ reason: "AUTHORIZATION_INVALID" });
    // A second adoption of the same hold is a fresh handle, refused at the claim the same way.
    const again = await b.executor.adoptHold(intent, decision);
    if (again.outcome !== "HELD") throw new Error("not held");
    expect((await b.executor.claimHeld(again.held)).outcome).toBe("BLOCKED");
  });

  it("records an adopted hold with its reason, and refuses what it would not hold", async () => {
    const a = replica();
    const intent = captured();
    const decision = await a.pair.authority.evaluate(intent);
    const adopted = await a.executor.adoptHold(intent, decision);
    expect(adopted.outcome).toBe("HELD");
    expect(a.events.map((event) => event.eventType)).toEqual([
      "INTENT_CAPTURED",
      "AUTHORITY_DECISION",
      "GRANT_HELD",
    ]);
    expect(a.events[2]).toEqual({ eventType: "GRANT_HELD", reasonCodes: ["HOLD_ADOPTED"] });
    // A plain hold carries no reason.
    const other = captured(351);
    await a.executor.hold(other, await a.pair.authority.evaluate(other));
    expect(a.events[5]).toEqual({ eventType: "GRANT_HELD" });
    // A decision for another intent, or without a grant, is refused as `hold` refuses it.
    const mismatch = await a.executor.adoptHold(captured(352), decision);
    expect(mismatch).toMatchObject({
      outcome: "BLOCKED",
      reason: "INTENT_BINDING_MISMATCH",
    });
    const blocking = createFixtureAuthorityPair(() => "BLOCK", {
      unsafeAllowDevelopmentFixture: true,
    });
    const blocked = await a.executor.adoptHold(intent, await blocking.authority.evaluate(intent));
    expect(blocked).toMatchObject({ outcome: "BLOCKED", reason: "DECISION_NOT_ALLOW" });
  });

  it("adopts a claim with the verifier's material so another executor can settle it, and refuses the rest", async () => {
    const replay = new InMemoryReplayStore();
    const a = replica(replay);
    const intent = captured();
    const decision = await a.pair.authority.evaluate(intent);
    const held = await a.executor.hold(intent, decision);
    if (held.outcome !== "HELD") throw new Error("not held");
    const claimed = await a.executor.claimHeld(held.held);
    if (claimed.outcome !== "CLAIMED") throw new Error("not claimed");
    const { authorization } = claimed;
    const material = a.executor.claimMaterial(authorization);
    expect(material).toEqual({ kind: "fixture", grant_id: authorization.grantId });
    expect(a.executor.claimMaterial({ ...authorization, grantId: "other" })).toBeNull();
    // B: its own verifier, which never saw the claim, learns of it from the material.
    const verifier = new FixtureAuthorizationVerifier(a.pair.authority.publicKey(), replay, true);
    const b = new SafeExecutor(registry, verifier, audit().recorder);
    const handle = b.adoptClaim(intent, decision, authorization, material);
    // The handle is the hold's, exactly: what settlement finalizes and records.
    expect(handle).toEqual({ captured: intent, decision, expiresAt: authorization.expiresAt });
    expect(Object.isFrozen(handle)).toBe(true);
    expect(await b.settleHeld(handle, "COMMITTED")).toBe("RECORDED");
    expect(verifier.commitOf(authorization.grantId)).toMatchObject({ outcome: "COMMITTED" });
    // Without material, the settlement has nowhere to go; with wrong material, it is refused.
    const c = new SafeExecutor(
      registry,
      new FixtureAuthorizationVerifier(a.pair.authority.publicKey(), replay, true),
      audit().recorder,
    );
    expect(await c.settleHeld(c.adoptClaim(intent, decision, authorization), "COMMITTED")).toBe(
      "PENDING",
    );
    expect(() =>
      c.adoptClaim(intent, decision, authorization, { kind: "fixture", grant_id: "other" }),
    ).toThrow("CLAIM_MATERIAL_REFUSED");
    expect(() => c.adoptClaim(captured(353), decision, authorization, material)).toThrow(
      "CLAIM_ADOPTION_MISMATCH",
    );
    // Each binding is checked on its own: a decision about another intent
    // with an authorization that matches, and an observation that is no
    // decision at all, are refused the same way.
    const elsewhere = immutableDecisionGate({
      ...decision,
      intentHash: `sha256:${"c".repeat(64)}`,
    });
    expect(() => c.adoptClaim(intent, elsewhere, authorization, material)).toThrow(
      "CLAIM_ADOPTION_MISMATCH",
    );
    for (const observation of [
      { ...decision, authority: "OBSERVATIONAL" },
      { ...decision, mode: "SHADOW" },
    ]) {
      expect(() =>
        c.adoptClaim(intent, observation as unknown as DecisionGate, authorization, material),
      ).toThrow("CLAIM_ADOPTION_MISMATCH");
    }
    expect(() =>
      c.adoptClaim(
        intent,
        decision,
        { ...authorization, intentHash: `sha256:${"b".repeat(64)}` },
        material,
      ),
    ).toThrow("CLAIM_ADOPTION_MISMATCH");
    // A verifier without the seam refuses material too.
    const bare = new SafeExecutor(
      registry,
      { verifyAndConsume: async () => null },
      audit().recorder,
    );
    expect(() => bare.adoptClaim(intent, decision, authorization, material)).toThrow(
      "CLAIM_MATERIAL_REFUSED",
    );
    expect(bare.claimMaterial(authorization)).toBeNull();
  });
});
