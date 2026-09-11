/**
 * Loopback proof for the expected-effect commitment and the Protocol 1.1 effect
 * evidence path. Every assertion here runs over a real HTTP stack against
 * `LocalAuthority`, whose independent canonicalizer re-derives the intent hash,
 * so a commitment that reaches the grant is byte-identical evidence that the
 * package binds the digest the way Decionis does.
 *
 * All tenants, actors, grants, digests, and observations are synthetic.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DecionisGate } from "../../src/decision/DecionisGate.js";
import { DecionisGrantVerifier } from "../../src/execution/AuthorizationVerifier.js";
import type { AuthorityEffectEvidence } from "../../src/execution/AuthorizationVerifier.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import type { CapturedIntent } from "../../src/intent/ExecutionIntent.js";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "../../src/testing/Index.js";

const EFFECT_DIGEST = `sha256:${"1".repeat(64)}`;
const OTHER_DIGEST = `sha256:${"2".repeat(64)}`;
const authority = new LocalAuthority();
let sequence = 0;

beforeAll(async () => {
  await authority.start();
});

afterAll(async () => {
  await authority.stop();
});

function capture(expectedEffectDigest?: string) {
  sequence += 1;
  return new IntentCapture({ ttlSeconds: 120 }).capture(
    {
      action: "refund_order",
      target: `shopify:order:synthetic-${sequence}`,
      parameters: { amountMinor: 5_000, currency: "USD" },
    },
    {
      tenantId: "00000000-0000-4000-8000-000000000005",
      actor: { id: "synthetic-effect-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "shopify", operation: "refund" },
      idempotencyKey: `effect-${sequence}`,
      context: {},
      ...(expectedEffectDigest === undefined ? {} : { expectedEffectDigest }),
    },
  );
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

/** Drives enforce-and-bind and the claim, returning everything a finalize needs. */
async function claim(captured: CapturedIntent) {
  const decision = await gate().evaluate(captured);
  expect(decision.verdict).toBe("ALLOW");
  const token = decision.authorization?.token;
  if (token === undefined) throw new Error("TEST_EXPECTED_GRANT");
  const grantVerifier = verifier();
  const authorization = await grantVerifier.verifyAndConsume(captured, decision);
  if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
  const grant = authority.grants.get(token);
  if (grant === undefined) throw new Error("TEST_EXPECTED_GRANT_RECORD");
  return { captured, decision, authorization, grant, token, verifier: grantVerifier };
}

function evidence(
  captured: CapturedIntent,
  overrides: Partial<AuthorityEffectEvidence> = {},
): AuthorityEffectEvidence {
  return {
    version: "1.0",
    status: "UNCONFIRMED",
    observation_method: "DOWNSTREAM_ACK",
    observer: null,
    expected_effect_digest: EFFECT_DIGEST,
    observed_effect_digest: null,
    observed_at: null,
    evidence_digest: null,
    evidence_reference: null,
    execution_correlation_id: captured.intent.intentId,
    ...overrides,
  };
}

/** Posts a finalize body the package itself would not send, to read the double's refusal. */
async function postFinalize(body: Record<string, unknown>) {
  const response = await fetch(`${authority.baseUrl}/v1/execution/finalize-token`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${LOCAL_AUTHORITY_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

describe("LocalAuthority effect commitment and evidence", () => {
  it("re-hashes a binding that carries an expected-effect digest and issues a grant", async () => {
    const captured = capture(EFFECT_DIGEST);

    const decision = await gate().evaluate(captured);

    expect(decision.verdict).toBe("ALLOW");
    const enforce = authority.requests.filter(
      (request) => request.path === "/v1/authority/enforce-and-bind",
    );
    const last = enforce[enforce.length - 1];
    // The double's independent canonicalizer reproduced the same hash from a
    // binding that carries the commitment.
    expect(last?.recomputedHash).toBe(captured.intentHash);
    expect((last?.body as Record<string, unknown>).expected_effect_digest).toBe(EFFECT_DIGEST);
    const grant = authority.grants.get(decision.authorization?.token ?? "");
    expect(grant?.expectedEffectDigest).toBe(EFFECT_DIGEST);
  });

  it("echoes the committed expected-effect digest in the claim's grant claims", async () => {
    const { authorization } = await claim(capture(EFFECT_DIGEST));

    // The claim-time echo check refused nothing, so the authority committed to
    // exactly the digest the intent bound.
    expect(authorization.intentHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    const claims = authority.requests
      .filter((request) => request.path === "/v1/execution/claim-token")
      .at(-1)?.response?.body as { claims: { binding: Record<string, unknown> } };
    expect(claims.claims.binding.expected_effect_digest).toBe(EFFECT_DIGEST);

    // A grant that committed nothing echoes nothing, and is still accepted.
    const plain = await claim(capture());
    const plainClaims = authority.requests
      .filter((request) => request.path === "/v1/execution/claim-token")
      .at(-1)?.response?.body as { claims: { binding: Record<string, unknown> } };
    expect("expected_effect_digest" in plainClaims.claims.binding).toBe(false);
    expect(plain.grant.expectedEffectDigest).toBeNull();
  });

  it("records unconfirmed effect evidence bound to the committed digest", async () => {
    const captured = capture(EFFECT_DIGEST);
    const claimed = await claim(captured);

    const status = await claimed.verifier.finalize({
      captured,
      decision: claimed.decision,
      authorization: claimed.authorization,
      outcome: "COMMITTED",
      effectEvidence: evidence(captured),
    });

    expect(status).toBe("RECORDED");
    expect(claimed.grant.finalized).toBe("COMMITTED");
    expect(claimed.verifier.effectReport(claimed.authorization)).toEqual({
      effectEvidenceSent: true,
      effectEvidenceRefused: false,
      effectEvidenceRecorded: true,
      effectConfirmation: "UNCONFIRMED",
    });
  });

  it("refuses effect evidence against a grant that committed no expected effect", async () => {
    const captured = capture();
    const claimed = await claim(captured);

    const refused = await postFinalize({
      execution_token: claimed.token,
      claim_token: claimed.grant.claimToken,
      outcome: "COMMITTED",
      commit_correlation_id: captured.intent.intentId,
      effect_evidence: evidence(captured),
    });

    expect(refused.status).toBe(409);
    expect(refused.body).toEqual({
      finalized: false,
      reason_codes: ["EFFECT_EXPECTED_BINDING_UNAVAILABLE"],
    });
    // The refusal precedes the commit transition, so the grant is still open.
    expect(claimed.grant.finalized).toBeNull();

    const mismatched = await postFinalize({
      execution_token: claimed.token,
      claim_token: claimed.grant.claimToken,
      outcome: "COMMITTED",
      commit_correlation_id: captured.intent.intentId,
      effect_evidence: evidence(captured, { execution_correlation_id: "synthetic-other" }),
    });
    expect(mismatched.body.reason_codes).toEqual(["EXECUTION_CORRELATION_MISMATCH"]);
  });

  it("refuses confirmed evidence from an observer the deployment does not trust", async () => {
    const captured = capture(EFFECT_DIGEST);
    const claimed = await claim(captured);
    const confirmed = evidence(captured, {
      status: "CONFIRMED" as const,
      observation_method: "READ_AFTER_WRITE" as const,
      observer: { id: "synthetic-observer", version: "1" },
      observed_effect_digest: EFFECT_DIGEST,
      observed_at: new Date().toISOString(),
      evidence_digest: `sha256:${"3".repeat(64)}`,
    });

    // The hosted default is an unset allowlist, and an unset allowlist refuses
    // the whole finalization rather than downgrading to UNCONFIRMED.
    const refused = await postFinalize({
      execution_token: claimed.token,
      claim_token: claimed.grant.claimToken,
      outcome: "COMMITTED",
      commit_correlation_id: captured.intent.intentId,
      effect_evidence: confirmed,
    });
    expect(refused.status).toBe(409);
    expect(refused.body.reason_codes).toEqual(["EFFECT_OBSERVER_PROVENANCE_UNAVAILABLE"]);

    const wrongDigest = await postFinalize({
      execution_token: claimed.token,
      claim_token: claimed.grant.claimToken,
      outcome: "COMMITTED",
      commit_correlation_id: captured.intent.intentId,
      effect_evidence: evidence(captured, { expected_effect_digest: OTHER_DIGEST }),
    });
    expect(wrongDigest.body.reason_codes).toEqual(["EFFECT_EXPECTED_DIGEST_MISMATCH"]);

    const wrongOutcome = await postFinalize({
      execution_token: claimed.token,
      claim_token: claimed.grant.claimToken,
      outcome: "FAILED",
      commit_correlation_id: captured.intent.intentId,
      effect_evidence: confirmed,
    });
    expect(wrongOutcome.body.reason_codes).toEqual(["EFFECT_EVIDENCE_OUTCOME_MISMATCH"]);
    expect(claimed.grant.finalized).toBeNull();
  });

  it("finalizes on the executor's evidence-free retry after refusing the evidence", async () => {
    const captured = capture(EFFECT_DIGEST);
    const claimed = await claim(captured);
    const from = authority.requests.length;

    // CONFIRMED evidence the drop rule cannot predict a refusal for: the digest
    // and the correlation id both match, so the verifier forwards it, and the
    // authority refuses it over its own observer allowlist.
    const status = await claimed.verifier.finalize({
      captured,
      decision: claimed.decision,
      authorization: claimed.authorization,
      outcome: "COMMITTED",
      effectEvidence: evidence(captured, {
        status: "CONFIRMED",
        observation_method: "SIGNED_RECEIPT",
        observer: { id: "synthetic-untrusted-observer", version: "1" },
        observed_effect_digest: EFFECT_DIGEST,
        observed_at: new Date().toISOString(),
        evidence_reference: "synthetic-receipt-1",
      }),
    });

    // The observation is lost; the commit record is not.
    expect(status).toBe("RECORDED");
    expect(claimed.grant.finalized).toBe("COMMITTED");
    const finalizes = authority.requests
      .slice(from)
      .filter((request) => request.path === "/v1/execution/finalize-token");
    expect(finalizes).toHaveLength(2);
    expect((finalizes[0]?.response as { status: number }).status).toBe(409);
    expect((finalizes[0]?.body as Record<string, unknown>).effect_evidence).toBeDefined();
    expect((finalizes[1]?.body as Record<string, unknown>).effect_evidence).toBeUndefined();
    expect((finalizes[1]?.response as { status: number }).status).toBe(200);
    // The refusal is on the record: an observation that was refused is not the
    // same fact as an observation that never existed.
    expect(claimed.verifier.effectReport(claimed.authorization)).toEqual({
      effectEvidenceSent: false,
      effectEvidenceRefused: true,
      effectEvidenceRecorded: false,
      effectConfirmation: "UNCONFIRMED",
    });
  });

  it("accepts confirmed evidence from an observer the deployment does trust", async () => {
    // The hosted route intersects the allowlist with the caller's own
    // authenticated API-key identity, so the trusted observer is the caller.
    const trusting = new LocalAuthority({
      trustedEffectObserverIds: [LOCAL_AUTHORITY_API_KEY],
    });
    await trusting.start();
    try {
      const captured = capture(EFFECT_DIGEST);
      const decision = await new DecionisGate({
        baseUrl: trusting.baseUrl,
        apiKey: LOCAL_AUTHORITY_API_KEY,
        allowInsecureLoopback: true,
      }).evaluate(captured);
      const grantVerifier = new DecionisGrantVerifier({
        baseUrl: trusting.baseUrl,
        apiKey: LOCAL_AUTHORITY_API_KEY,
        allowInsecureLoopback: true,
      });
      const authorization = await grantVerifier.verifyAndConsume(captured, decision);
      if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

      const status = await grantVerifier.finalize({
        captured,
        decision,
        authorization,
        outcome: "COMMITTED",
        effectEvidence: evidence(captured, {
          status: "CONFIRMED",
          observation_method: "READ_AFTER_WRITE",
          observer: { id: LOCAL_AUTHORITY_API_KEY, version: "1" },
          observed_effect_digest: EFFECT_DIGEST,
          observed_at: new Date().toISOString(),
          evidence_digest: `sha256:${"4".repeat(64)}`,
        }),
      });

      expect(status).toBe("RECORDED");
      expect(grantVerifier.effectReport(authorization)).toEqual({
        effectEvidenceSent: true,
        effectEvidenceRefused: false,
        effectEvidenceRecorded: true,
        effectConfirmation: "CONFIRMED",
      });
    } finally {
      await trusting.stop();
    }
  });
  it("answers a successful finalization with the hosted route's own body", async () => {
    const captured = capture(EFFECT_DIGEST);
    const claimed = await claim(captured);

    const recorded = await postFinalize({
      execution_token: claimed.token,
      claim_token: claimed.grant.claimToken,
      outcome: "COMMITTED",
      commit_correlation_id: captured.intent.intentId,
      effect_evidence: evidence(captured),
    });

    // Key for key the hosted success body: the commit's decision-chain evidence
    // is queued and not yet recorded, so a 200 still carries a reason code.
    expect(recorded.status).toBe(200);
    expect(recorded.body).toEqual({
      finalized: true,
      outcome: "COMMITTED",
      evidence_durably_queued: true,
      decision_chain_evidence_recorded: false,
      evidence_recorded: false,
      effect_evidence_recorded: true,
      effect_confirmation: "UNCONFIRMED",
      reason_codes: ["COMMIT_EVIDENCE_PENDING"],
    });
  });

  it("refuses malformed effect evidence the way the hosted route does", async () => {
    const captured = capture(EFFECT_DIGEST);
    const claimed = await claim(captured);
    const finalizeWith = async (effect_evidence: unknown) =>
      postFinalize({
        execution_token: claimed.token,
        claim_token: claimed.grant.claimToken,
        outcome: "COMMITTED",
        commit_correlation_id: captured.intent.intentId,
        effect_evidence,
      });

    // A malformed observation is a 409 with a reason code, not a 400: the
    // executor's evidence-free retry depends on that distinction.
    const invalid = await finalizeWith({ ...evidence(captured), version: "0.9" });
    expect(invalid.status).toBe(409);
    expect(invalid.body).toEqual({
      finalized: false,
      reason_codes: ["EFFECT_EVIDENCE_INVALID"],
    });

    const unversionedObserver = await finalizeWith({
      ...evidence(captured),
      status: "CONFIRMED",
      observation_method: "READ_AFTER_WRITE",
      observer: { id: LOCAL_AUTHORITY_API_KEY, version: null },
      observed_effect_digest: EFFECT_DIGEST,
      observed_at: new Date().toISOString(),
      evidence_digest: `sha256:${"5".repeat(64)}`,
    });
    expect(unversionedObserver.status).toBe(409);
    expect(unversionedObserver.body.reason_codes).toEqual([
      "EFFECT_OBSERVER_PROVENANCE_UNAVAILABLE",
    ]);
    expect(claimed.grant.finalized).toBeNull();
  });

  it("refuses confirmed evidence naming an observer other than the caller", async () => {
    const trusting = new LocalAuthority({ trustedEffectObserverIds: [LOCAL_AUTHORITY_API_KEY] });
    await trusting.start();
    try {
      const captured = capture(EFFECT_DIGEST);
      const decision = await new DecionisGate({
        baseUrl: trusting.baseUrl,
        apiKey: LOCAL_AUTHORITY_API_KEY,
        allowInsecureLoopback: true,
      }).evaluate(captured);
      const token = decision.authorization?.token ?? "";
      const grantVerifier = new DecionisGrantVerifier({
        baseUrl: trusting.baseUrl,
        apiKey: LOCAL_AUTHORITY_API_KEY,
        allowInsecureLoopback: true,
      });
      expect(await grantVerifier.verifyAndConsume(captured, decision)).not.toBeNull();
      const grant = trusting.grants.get(token);

      const response = await fetch(`${trusting.baseUrl}/v1/execution/finalize-token`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${LOCAL_AUTHORITY_API_KEY}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          execution_token: token,
          claim_token: grant?.claimToken,
          outcome: "COMMITTED",
          commit_correlation_id: captured.intent.intentId,
          effect_evidence: evidence(captured, {
            status: "CONFIRMED",
            observation_method: "READ_AFTER_WRITE",
            // On the allowlist of no deployment: the allowlist is intersected
            // with the identity that presented the credential.
            observer: { id: "synthetic-other-observer", version: "1" },
            observed_effect_digest: EFFECT_DIGEST,
            observed_at: new Date().toISOString(),
            evidence_digest: `sha256:${"6".repeat(64)}`,
          }),
        }),
      });

      expect(response.status).toBe(409);
      expect(await response.json()).toEqual({
        finalized: false,
        reason_codes: ["EFFECT_OBSERVER_PROVENANCE_MISMATCH"],
      });
      expect(grant?.finalized).toBeNull();
    } finally {
      await trusting.stop();
    }
  });
});
