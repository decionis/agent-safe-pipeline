import { describe, expect, it, vi } from "vitest";
import type { GateDecision } from "../../src/decision/DecisionAuthority.js";
import type {
  AuthorizationFinalizationInput,
  AuthorizationVerifier,
  VerifiedAuthorization,
} from "../../src/execution/AuthorizationVerifier.js";
import {
  LocalAuthorizationVerifier,
  LocalGrants,
  type LocalGrant,
  type LocalFinalizationRecord,
} from "../../src/execution/LocalAuthorizationVerifier.js";
import { InMemoryReplayStore, type ReplayStore } from "../../src/execution/ReplayStore.js";
import { captured } from "../support/AuthorityDouble.js";

const NOW = Date.parse("2026-10-02T12:00:00.000Z");

function grantFor(intent = captured(), overrides: Partial<LocalGrant> = {}): LocalGrant {
  return {
    intentId: intent.intent.intentId,
    intentHash: intent.intentHash,
    decisionId: "edge:decision-1",
    dossierId: "edge:record-1",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    ...overrides,
  };
}

function decisionFor(
  grant: LocalGrant,
  token: string,
  overrides: Partial<GateDecision> = {},
): GateDecision {
  return {
    verdict: "ALLOW",
    decisionId: grant.decisionId,
    dossierId: grant.dossierId,
    intentHash: grant.intentHash,
    reasonCodes: ["POLICY_ALLOW"],
    authorization: { token, expiresAt: grant.expiresAt },
    failClosed: false,
    ...overrides,
  };
}

function setup(options: { delegate?: AuthorizationVerifier; replay?: ReplayStore } = {}) {
  const grants = new LocalGrants();
  const records: LocalFinalizationRecord[] = [];
  const verifier = new LocalAuthorizationVerifier({
    grants,
    replay: options.replay ?? new InMemoryReplayStore(),
    ...(options.delegate === undefined ? {} : { delegate: options.delegate }),
    record: (record) => records.push(record),
  });
  return { grants, verifier, records };
}

describe("LocalGrants", () => {
  it("issues an unguessable token per grant and gives each grant up once", () => {
    const grants = new LocalGrants();
    const grant = grantFor();
    const first = grants.issue(grant);
    const second = grants.issue(grant);
    expect(first).toMatch(/^[\w-]{43}$/);
    expect(second).not.toBe(first);
    expect(grants.take(first)).toEqual(grant);
    expect(grants.take(first)).toBeUndefined();
    expect(grants.take("unknown")).toBeUndefined();
  });

  it("holds a frozen copy, so the issuer's object cannot be edited afterwards", () => {
    const grants = new LocalGrants();
    const grant = { ...grantFor() };
    const token = grants.issue(grant);
    (grant as { decisionId: string }).decisionId = "edited";
    const taken = grants.take(token);
    expect(taken?.decisionId).toBe("edge:decision-1");
    expect(Object.isFrozen(taken)).toBe(true);
  });

  it("is bounded, and drops lapsed grants (expiry at or before now) before counting", () => {
    let now = NOW;
    const grants = new LocalGrants(() => now, 1);
    grants.issue(grantFor(undefined, { expiresAt: new Date(NOW).toISOString() }));
    // The first grant expires exactly now, so it is dropped and there is room.
    const token = grants.issue(grantFor(undefined, { expiresAt: new Date(NOW + 1).toISOString() }));
    expect(() =>
      grants.issue(grantFor(undefined, { expiresAt: new Date(NOW + 5).toISOString() })),
    ).toThrow("LOCAL_GRANTS_CAPACITY_EXCEEDED");
    now = NOW + 1;
    expect(() => grants.issue(grantFor())).not.toThrow();
    expect(grants.take(token)).toBeUndefined();
  });

  it("keeps a grant that has not lapsed", () => {
    const grants = new LocalGrants(() => NOW, 2);
    const token = grants.issue(grantFor(undefined, { expiresAt: new Date(NOW + 1).toISOString() }));
    grants.issue(grantFor());
    expect(grants.take(token)).toBeDefined();
  });

  it("defaults to the wall clock", () => {
    const grants = new LocalGrants();
    const token = grants.issue(
      grantFor(undefined, { expiresAt: new Date(Date.now() - 1).toISOString() }),
    );
    grants.issue(grantFor());
    expect(grants.take(token)).toBeUndefined();
  });
});

describe("LocalAuthorizationVerifier", () => {
  it("consumes a local authorization once, and only for its own intent", async () => {
    const intent = captured();
    const { grants, verifier } = setup();
    const grant = grantFor(intent);
    const token = grants.issue(grant);
    const authorization = await verifier.verifyAndConsume(intent, decisionFor(grant, token));
    expect(authorization).toEqual({
      decisionId: grant.decisionId,
      dossierId: grant.dossierId,
      grantId: `edge:${intent.intent.intentId}`,
      intentHash: intent.intentHash,
      expiresAt: grant.expiresAt,
    });
    expect(Object.isFrozen(authorization)).toBe(true);
    expect(await verifier.verifyAndConsume(intent, decisionFor(grant, token))).toBeNull();
  });

  it("refuses a second local grant for an intent that already ran", async () => {
    const intent = captured();
    const { grants, verifier } = setup();
    const grant = grantFor(intent);
    const first = grants.issue(grant);
    const second = grants.issue(grant);
    expect(await verifier.verifyAndConsume(intent, decisionFor(grant, first))).not.toBeNull();
    expect(await verifier.verifyAndConsume(intent, decisionFor(grant, second))).toBeNull();
  });

  it("refuses a decision without an authorization", async () => {
    const intent = captured();
    const { verifier } = setup({
      delegate: { verifyAndConsume: vi.fn(async () => null) },
    });
    const grant = grantFor(intent);
    expect(
      await verifier.verifyAndConsume(intent, decisionFor(grant, "x", { authorization: null })),
    ).toBeNull();
  });

  const mismatches: [string, (grant: LocalGrant) => Partial<GateDecision>][] = [
    ["a verdict other than ALLOW", () => ({ verdict: "ESCALATE" })],
    ["a fail-closed decision", () => ({ failClosed: true })],
    ["another decision id", () => ({ decisionId: "edge:other" })],
    ["another dossier id", () => ({ dossierId: "edge:other" })],
    ["another decision intent hash", () => ({ intentHash: `sha256:${"0".repeat(64)}` })],
  ];
  for (const [name, change] of mismatches) {
    it(`refuses ${name}, and the token is spent`, async () => {
      const intent = captured();
      const { grants, verifier } = setup();
      const grant = grantFor(intent);
      const token = grants.issue(grant);
      const decision = decisionFor(grant, token, change(grant));
      expect(await verifier.verifyAndConsume(intent, decision)).toBeNull();
      expect(await verifier.verifyAndConsume(intent, decisionFor(grant, token))).toBeNull();
    });
  }

  it("refuses an authorization whose expiry differs from the grant's", async () => {
    const intent = captured();
    const { grants, verifier } = setup();
    const grant = grantFor(intent);
    const token = grants.issue(grant);
    const decision = decisionFor(grant, token, {
      authorization: { token, expiresAt: new Date(Date.now() + 120_000).toISOString() },
    });
    expect(await verifier.verifyAndConsume(intent, decision)).toBeNull();
  });

  it("refuses a grant presented with another intent", async () => {
    const intent = captured();
    const other = captured();
    const { grants, verifier } = setup();
    const grant = grantFor(intent);
    const token = grants.issue(grant);
    expect(await verifier.verifyAndConsume(other, decisionFor(grant, token))).toBeNull();
  });

  it("refuses an intent edited after the decision, though it keeps its intent id", async () => {
    const intent = captured();
    const { grants, verifier } = setup();
    const grant = grantFor(intent);
    const token = grants.issue(grant);
    const edited = { ...intent, intentHash: `sha256:${"f".repeat(64)}` as const };
    expect(await verifier.verifyAndConsume(edited, decisionFor(grant, token))).toBeNull();
  });

  it("refuses a grant whose intent id is not the presented intent's", async () => {
    const intent = captured();
    const { grants, verifier } = setup();
    const grant = grantFor(intent, { intentId: "another-intent" });
    const token = grants.issue(grant);
    expect(await verifier.verifyAndConsume(intent, decisionFor(grant, token))).toBeNull();
  });

  it("refuses a grant at or after its expiry", async () => {
    const intent = captured();
    const grants = new LocalGrants(() => NOW - 10);
    // A replay store that would accept, so the expiry check alone refuses (an
    // InMemoryReplayStore also refuses a claim already past by the wall clock,
    // which would hide a broken expiry check once NOW is in the past).
    const unchecked: ReplayStore = { claim: vi.fn(async () => true) };
    const verifier = new LocalAuthorizationVerifier({
      grants,
      replay: unchecked,
      clock: () => NOW,
      record: () => undefined,
    });
    const atExpiry = grantFor(intent, { expiresAt: new Date(NOW).toISOString() });
    expect(
      await verifier.verifyAndConsume(intent, decisionFor(atExpiry, grants.issue(atExpiry))),
    ).toBeNull();
    const after = grantFor(intent, { expiresAt: new Date(NOW - 1).toISOString() });
    expect(
      await verifier.verifyAndConsume(intent, decisionFor(after, grants.issue(after))),
    ).toBeNull();
    expect(unchecked.claim).not.toHaveBeenCalled();
    const before = grantFor(intent, { expiresAt: new Date(NOW + 1).toISOString() });
    const replay: ReplayStore = { claim: vi.fn(async () => true) };
    const accepting = new LocalAuthorizationVerifier({
      grants,
      replay,
      clock: () => NOW,
      record: () => undefined,
    });
    expect(
      await accepting.verifyAndConsume(intent, decisionFor(before, grants.issue(before))),
    ).not.toBeNull();
    expect(replay.claim).toHaveBeenCalledWith(intent.intent.intentId, new Date(NOW + 1));
  });

  it("refuses when the replay store says the intent was claimed", async () => {
    const intent = captured();
    const { grants, verifier } = setup({ replay: { claim: async () => false } });
    const grant = grantFor(intent);
    expect(
      await verifier.verifyAndConsume(intent, decisionFor(grant, grants.issue(grant))),
    ).toBeNull();
  });

  it("hands an authorization it did not issue to the delegate, and claims the intent too", async () => {
    const intent = captured();
    const hosted: VerifiedAuthorization = Object.freeze({
      decisionId: "decision-1",
      dossierId: "dossier-1",
      grantId: "jti-1",
      intentHash: intent.intentHash,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const delegate: AuthorizationVerifier = { verifyAndConsume: vi.fn(async () => hosted) };
    const replay = new InMemoryReplayStore();
    const { verifier } = setup({ delegate, replay });
    const decision = decisionFor(grantFor(intent), "hosted-token");
    expect(await verifier.verifyAndConsume(intent, decision)).toBe(hosted);
    expect(delegate.verifyAndConsume).toHaveBeenCalledWith(intent, decision);
    // The intent is now spent for every path.
    expect(await verifier.verifyAndConsume(intent, decision)).toBeNull();
    expect(await replay.claim(intent.intent.intentId, new Date(Date.now() + 1_000))).toBe(false);
  });

  it("refuses a delegated authorization the delegate refused, or when there is no delegate", async () => {
    const intent = captured();
    const refusing = setup({ delegate: { verifyAndConsume: async () => null } });
    expect(
      await refusing.verifier.verifyAndConsume(intent, decisionFor(grantFor(intent), "t")),
    ).toBeNull();
    const none = setup();
    expect(
      await none.verifier.verifyAndConsume(intent, decisionFor(grantFor(intent), "t")),
    ).toBeNull();
  });

  it("refuses a delegated authorization for an intent that already ran locally", async () => {
    const intent = captured();
    const hosted: VerifiedAuthorization = {
      decisionId: "decision-1",
      dossierId: "dossier-1",
      grantId: "jti-1",
      intentHash: intent.intentHash,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };
    const { grants, verifier } = setup({ delegate: { verifyAndConsume: async () => hosted } });
    const grant = grantFor(intent);
    expect(
      await verifier.verifyAndConsume(intent, decisionFor(grant, grants.issue(grant))),
    ).not.toBeNull();
    expect(await verifier.verifyAndConsume(intent, decisionFor(grant, "hosted"))).toBeNull();
  });

  it("records a local attempt's outcome as its finalization", async () => {
    const intent = captured();
    const { grants, verifier, records } = setup();
    const grant = grantFor(intent);
    const decision = decisionFor(grant, grants.issue(grant));
    const authorization = (await verifier.verifyAndConsume(
      intent,
      decision,
    )) as VerifiedAuthorization;
    const input: AuthorizationFinalizationInput = {
      captured: intent,
      decision,
      authorization,
      outcome: "COMMITTED",
    };
    expect(await verifier.finalize(input)).toBe("RECORDED");
    expect(records).toEqual([
      {
        event: "EDGE_EXECUTION_FINALIZED",
        intent_id: intent.intent.intentId,
        intent_hash: intent.intentHash,
        decision_id: grant.decisionId,
        outcome: "COMMITTED",
      },
    ]);
  });

  it("reports a local finalization pending when it cannot be recorded", async () => {
    const intent = captured();
    const grants = new LocalGrants();
    const throwing = new LocalAuthorizationVerifier({
      grants,
      replay: new InMemoryReplayStore(),
      record: () => {
        throw new Error("disk full");
      },
    });
    for (const verifier of [throwing]) {
      const grant = grantFor(intent);
      const decision = decisionFor(grant, grants.issue(grant));
      const authorization = (await verifier.verifyAndConsume(
        intent,
        decision,
      )) as VerifiedAuthorization;
      expect(authorization).not.toBeNull();
      expect(
        await verifier.finalize({ captured: intent, decision, authorization, outcome: "FAILED" }),
      ).toBe("PENDING");
    }
  });

  it("hands a delegated finalization to the delegate, bound to it", async () => {
    const intent = captured();
    const delegate = {
      marker: "delegate",
      verifyAndConsume: async () => null,
      finalize: vi.fn(async function (this: { marker: string }) {
        return this.marker === "delegate" ? ("RECORDED" as const) : ("PENDING" as const);
      }),
    };
    const { verifier, records } = setup({ delegate });
    const authorization: VerifiedAuthorization = {
      decisionId: "decision-1",
      dossierId: "dossier-1",
      grantId: "jti-1",
      intentHash: intent.intentHash,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };
    const input: AuthorizationFinalizationInput = {
      captured: intent,
      decision: decisionFor(grantFor(intent), "t"),
      authorization,
      outcome: "INDETERMINATE",
    };
    expect(await verifier.finalize(input)).toBe("RECORDED");
    expect(delegate.finalize).toHaveBeenCalledWith(input);
    expect(records).toEqual([]);
    const without = setup({ delegate: { verifyAndConsume: async () => null } });
    expect(await without.verifier.finalize(input)).toBe("PENDING");
    expect(await setup().verifier.finalize(input)).toBe("PENDING");
  });
});
