import {
  CanonicalIntentHasher,
  type AuthorizationFinalizationInput,
  type AuthorizationVerifier,
  type CapturedIntent,
  type GateDecision,
  type VerifiedAuthorization,
} from "@decionis/agent-safe-pipeline";
import { describe, expect, it } from "vitest";
import { EffectAwareGrantVerifier } from "../../src/adapters/EffectAwareGrantVerifier.js";
import { EffectEvidenceRegister } from "../../src/adapters/EffectEvidenceRegister.js";
import { buildEffectRecord } from "../../src/adapters/EffectEvidenceBuilder.js";
import { jcsDigest } from "../../src/adapters/JcsDigest.js";
import type { PreparedAction } from "../../src/adapters/EffectAdapter.js";

const observer = { id: "synthetic-adapter", version: "0.1.0" };
const expectedEffect = { effect_type: "TESTED", amount: "10.00" };

const prepared: PreparedAction = {
  expectedEffect,
  expectedEffectDigest: jcsDigest(expectedEffect),
  intentDigest: jcsDigest({ a: 1 }),
  requestDigest: jcsDigest({ a: 1 }),
  resourceRef: "fixture_resource_1",
  effectType: "TESTED",
  domain: "TEST_DOMAIN",
  actionType: "TEST_ACTION",
};

const authorization: VerifiedAuthorization = Object.freeze({
  decisionId: "synthetic-decision-1",
  dossierId: "synthetic-dossier-1",
  grantId: "synthetic-grant-1",
  intentHash: `sha256:${"a".repeat(64)}`,
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
});

const decision: GateDecision = {
  verdict: "ALLOW",
  decisionId: "synthetic-decision-1",
  dossierId: "synthetic-dossier-1",
  intentHash: `sha256:${"a".repeat(64)}`,
  reasonCodes: [],
  authorization: null,
  failClosed: false,
};

function captured(): CapturedIntent {
  return new CanonicalIntentHasher().capture({
    version: "agent-safe.intent/1",
    intentId: "11111111-1111-4111-8111-111111111111",
    tenantId: "00000000-0000-4000-8000-000000000007",
    capturedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    actor: { id: "synthetic-treasury-agent", type: "AI_AGENT" },
    action: "fake.test.action",
    target: "fixture_resource_1",
    parameters: {},
    downstreamTarget: { system: "fake", operation: "test", environment: "local" },
    context: {},
    idempotencyKey: "synthetic-key-7",
    expectedEffectDigest: prepared.expectedEffectDigest,
  });
}

/** A delegate that records what it was handed, and can have no finalization at all. */
function delegate(options: { readonly finalizes: boolean }): AuthorityVerifierDouble {
  const seen: AuthorizationFinalizationInput[] = [];
  const claims: CapturedIntent[] = [];
  const base = {
    seen,
    claims,
    verifyAndConsume: async (intent: CapturedIntent) => {
      claims.push(intent);
      return await Promise.resolve(authorization);
    },
  };
  if (!options.finalizes) return base as AuthorityVerifierDouble;
  return {
    ...base,
    finalize: async (input: AuthorizationFinalizationInput) => {
      seen.push(input);
      return await Promise.resolve("RECORDED" as const);
    },
  } as AuthorityVerifierDouble;
}

type AuthorityVerifierDouble = AuthorizationVerifier & {
  readonly seen: AuthorizationFinalizationInput[];
  readonly claims: CapturedIntent[];
};

const record = (observed: Record<string, unknown> | null) =>
  buildEffectRecord({
    prepared,
    result: {
      status: "COMMITTED",
      providerStatus: "POSTED",
      providerReference: "fixture_provider_ref_9",
      responseDigest: jcsDigest({ status: "POSTED" }),
      failureReason: null,
      observed: observed as never,
      observationMethod: "READ_AFTER_WRITE",
      providerGenerated: true,
      source: "FAKE",
    },
    observer,
    correlationId: "11111111-1111-4111-8111-111111111111",
    idempotencyKey: "synthetic-key-7",
    observedAt: new Date().toISOString(),
  });

describe("EffectAwareGrantVerifier", () => {
  it("adds nothing to the claim: the grant is consumed by the delegate alone", async () => {
    const inner = delegate({ finalizes: true });
    const register = new EffectEvidenceRegister();
    const verifier = new EffectAwareGrantVerifier({ verifier: inner, register, observer });
    const intent = captured();
    expect(await verifier.verifyAndConsume(intent, decision)).toBe(authorization);
    expect(inner.claims).toEqual([intent]);
  });

  it("finalizes with the observation registered for this exact authorization", async () => {
    const inner = delegate({ finalizes: true });
    const register = new EffectEvidenceRegister();
    const verifier = new EffectAwareGrantVerifier({ verifier: inner, register, observer });
    const intent = captured();
    register.attach(authorization, record({ ...expectedEffect }));
    expect(
      await verifier.finalize({ captured: intent, decision, authorization, outcome: "COMMITTED" }),
    ).toBe("RECORDED");
    const evidence = inner.seen[0]?.effectEvidence;
    expect(evidence?.status).toBe("CONFIRMED");
    expect(evidence?.expected_effect_digest).toBe(prepared.expectedEffectDigest);
    expect(evidence?.execution_correlation_id).toBe(intent.intent.intentId);
    expect(evidence?.observer).toEqual(observer);
  });

  it("reports a mismatch as unconfirmed, with the digest that was observed", async () => {
    const inner = delegate({ finalizes: true });
    const register = new EffectEvidenceRegister();
    const verifier = new EffectAwareGrantVerifier({ verifier: inner, register, observer });
    register.attach(authorization, record({ ...expectedEffect, amount: "99.00" }));
    await verifier.finalize({
      captured: captured(),
      decision,
      authorization,
      outcome: "COMMITTED",
    });
    const evidence = inner.seen[0]?.effectEvidence;
    expect(evidence?.status).toBe("UNCONFIRMED");
    expect(evidence?.observed_effect_digest).not.toBe(prepared.expectedEffectDigest);
  });

  it("finalizes exactly as the delegate would when nothing observed an effect", async () => {
    const inner = delegate({ finalizes: true });
    const verifier = new EffectAwareGrantVerifier({
      verifier: inner,
      register: new EffectEvidenceRegister(),
      observer,
    });
    await verifier.finalize({
      captured: captured(),
      decision,
      authorization,
      outcome: "COMMITTED",
    });
    expect(inner.seen[0]?.effectEvidence).toBeUndefined();
  });

  it("is PENDING when the delegate has no finalization contract at all", async () => {
    const inner = delegate({ finalizes: false });
    const register = new EffectEvidenceRegister();
    register.attach(authorization, record({ ...expectedEffect }));
    const verifier = new EffectAwareGrantVerifier({ verifier: inner, register, observer });
    expect(
      await verifier.finalize({
        captured: captured(),
        decision,
        authorization,
        outcome: "COMMITTED",
      }),
    ).toBe("PENDING");
  });
});
