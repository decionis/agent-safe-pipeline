import { describe, expect, it, vi } from "vitest";
import type { GateDecision } from "../../src/decision/DecisionAuthority.js";
import { DecionisGrantVerifier } from "../../src/execution/AuthorizationVerifier.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

const CLAIM_TOKEN = "c".repeat(43);

function setup() {
  const captured = new IntentCapture().capture(
    { action: "deploy", target: "github:repo", parameters: { environment: "production" } },
    {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: { id: "synthetic-deploy-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "github", operation: "deploy" },
      idempotencyKey: "deploy-1",
      context: {},
    },
  );
  const expiresAtSeconds = Math.floor(Date.parse(captured.intent.expiresAt) / 1_000);
  const decision: GateDecision = {
    verdict: "ALLOW",
    decisionId: "decision-1",
    dossierId: "dossier-1",
    intentHash: captured.intentHash,
    reasonCodes: [],
    authorization: {
      token: "token-1",
      expiresAt: new Date(expiresAtSeconds * 1_000).toISOString(),
    },
    failClosed: false,
  };
  /** Full `ExecutionTokenClaims` as the Decionis contract documents them. */
  const claims = {
    iss: "decionis",
    sub: "synthetic-deploy-agent",
    aud: "github:deploy",
    org_id: "00000000-0000-4000-8000-000000000002",
    dossier_id: "dossier-1",
    decision_id: "decision-1",
    chain_id: "chain-1",
    action: "deploy",
    decision: "allow",
    scope: "execute",
    binding: {
      intent_hash: captured.intentHash,
      execution_binding_digest: `sha256:${"b".repeat(64)}`,
      execution_nonce: "n".repeat(43),
      execution_correlation_id: captured.intent.intentId,
    },
    jti: "grant-1",
    iat: expiresAtSeconds - 60,
    nbf: expiresAtSeconds - 60,
    exp: expiresAtSeconds,
  };
  /** The live claim response carries revalidation fields beyond the documented envelope. */
  const claimResponse = {
    valid: true,
    should_execute: true,
    would_block: false,
    verdict: "ALLOW",
    reason_codes: [],
    claims,
    claim_token: CLAIM_TOKEN,
    claim_lease_expires_at: captured.intent.expiresAt,
    evidence: { nonce_claim_state: "CLAIMED" },
  };
  return { captured, decision, expiresAtSeconds, claims, claimResponse };
}

function verifierWith(fetchMock: typeof fetch) {
  return new DecionisGrantVerifier({
    baseUrl: "http://127.0.0.1:3001",
    apiKey: "key",
    allowInsecureLoopback: true,
    fetch: fetchMock,
  });
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

describe("DecionisGrantVerifier", () => {
  it("claims a grant through the contract route with the exact binding and evidence", async () => {
    const { captured, decision, claimResponse } = setup();
    const evidence = {
      humanApproval: {
        provider: "presence" as const,
        requestId: "synthetic-presence-request",
        receiptDossierId: "synthetic-presence-receipt",
      },
    };
    const fetchMock = vi.fn<typeof fetch>(async () => json(claimResponse));
    const verifier = verifierWith(fetchMock);

    const authorization = await verifier.verifyAndConsume(captured, { ...decision, evidence });

    expect(authorization).toEqual({
      decisionId: "decision-1",
      dossierId: "dossier-1",
      grantId: "grant-1",
      intentHash: captured.intentHash,
      expiresAt: decision.authorization?.expiresAt,
    });
    expect(Object.isFrozen(authorization)).toBe(true);
    expect(JSON.stringify(authorization)).not.toContain(CLAIM_TOKEN);

    const [url, request] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://127.0.0.1:3001/v1/execution/claim-token");
    const body = JSON.parse(request.body as string) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual([
      "commit_correlation_id",
      "consumed_by",
      "evidence",
      "execution_token",
      "intent",
      "intent_hash",
    ]);
    expect(body).toMatchObject({
      execution_token: "token-1",
      intent_hash: captured.intentHash,
      consumed_by: "synthetic-deploy-agent",
      commit_correlation_id: captured.intent.intentId,
      evidence,
    });
    const intent = body.intent as Record<string, unknown>;
    expect(Object.keys(intent).sort()).toEqual([
      "action",
      "actor",
      "captured_at",
      "context",
      "downstream_target",
      "expires_at",
      "intent_id",
      "protocol_version",
      "tenant_id",
    ]);
    expect(intent.context).toEqual({ idempotency_key: "deploy-1" });

    const withoutEvidence = vi.fn<typeof fetch>(async () => json(claimResponse));
    await verifierWith(withoutEvidence).verifyAndConsume(captured, decision);
    const plainBody = JSON.parse(
      (withoutEvidence.mock.calls[0]?.[1] as RequestInit).body as string,
    ) as Record<string, unknown>;
    expect("evidence" in plainBody).toBe(false);
  });

  it("rejects missing tokens, failed claims, and every grant-binding mismatch", async () => {
    const { captured, decision, expiresAtSeconds, claims, claimResponse } = setup();
    const noToken = { ...decision, authorization: null };
    const rejected = verifierWith(async () =>
      json({ valid: false, reason_codes: ["NONCE_REPLAY_DETECTED"], claims: null }, 409),
    );
    expect(await rejected.verifyAndConsume(captured, noToken)).toBeNull();
    expect(await rejected.verifyAndConsume(captured, decision)).toBeNull();

    const mismatches: Array<Record<string, unknown>> = [
      { ...claims, decision_id: "other" },
      { ...claims, dossier_id: "other" },
      { ...claims, binding: { ...claims.binding, intent_hash: `sha256:${"0".repeat(64)}` } },
      { ...claims, exp: expiresAtSeconds - 1 },
      { ...claims, jti: "" },
      { ...claims, org_id: "00000000-0000-4000-8000-000000000009" },
      { ...claims, sub: "another-agent" },
      { ...claims, sub: undefined },
      { ...claims, action: "delete_repo" },
      { ...claims, aud: "github:delete" },
      { ...claims, decision: "deny" },
      { ...claims, scope: "verify" },
      { ...claims, iss: undefined },
    ];
    for (const mismatchedClaims of mismatches) {
      const mismatch = verifierWith(async () =>
        json({ ...claimResponse, claims: mismatchedClaims }),
      );
      expect(
        await mismatch.verifyAndConsume(captured, decision),
        JSON.stringify(mismatchedClaims),
      ).toBeNull();
    }

    const envelopes: Array<Record<string, unknown>> = [
      { ...claimResponse, valid: false },
      { ...claimResponse, should_execute: false },
      { ...claimResponse, claim_token: null },
      { ...claimResponse, claim_token: "too-short" },
      { ...claimResponse, claims: null },
    ];
    for (const envelope of envelopes) {
      const verifier = verifierWith(async () => json(envelope));
      expect(
        await verifier.verifyAndConsume(captured, decision),
        JSON.stringify(envelope),
      ).toBeNull();
    }

    const malformed = verifierWith(async () => new Response("{not-json", { status: 200 }));
    expect(await malformed.verifyAndConsume(captured, decision)).toBeNull();
  });

  it("finalizes a claimed grant with the downstream outcome and never throws", async () => {
    const { captured, decision, claimResponse } = setup();
    const fetchMock = vi.fn<typeof fetch>(async (input) =>
      String(input).endsWith("/v1/execution/claim-token")
        ? json(claimResponse)
        : json({
            finalized: true,
            outcome: "COMMITTED",
            evidence_recorded: true,
            reason_codes: [],
          }),
    );
    const verifier = verifierWith(fetchMock);
    const authorization = await verifier.verifyAndConsume(captured, decision);
    if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");

    const status = await verifier.finalize({
      captured,
      decision,
      authorization,
      outcome: "COMMITTED",
    });

    expect(status).toBe("RECORDED");
    const [url, request] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(url).toBe("http://127.0.0.1:3001/v1/execution/finalize-token");
    expect(JSON.parse(request.body as string)).toEqual({
      execution_token: "token-1",
      claim_token: CLAIM_TOKEN,
      outcome: "COMMITTED",
      commit_correlation_id: captured.intent.intentId,
    });

    // A finalized claim is consumed; a second report has nothing to finalize.
    expect(
      await verifier.finalize({ captured, decision, authorization, outcome: "COMMITTED" }),
    ).toBe("PENDING");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("reports PENDING for an unknown authorization or a rejected, malformed, or failed finalization", async () => {
    const { captured, decision, claimResponse } = setup();
    const foreign = Object.freeze({
      decisionId: "decision-1",
      dossierId: "dossier-1",
      grantId: "grant-1",
      intentHash: captured.intentHash,
      expiresAt: decision.authorization?.expiresAt ?? "",
    });
    const idle = vi.fn<typeof fetch>();
    expect(
      await verifierWith(idle).finalize({
        captured,
        decision,
        authorization: foreign,
        outcome: "FAILED",
      }),
    ).toBe("PENDING");
    expect(idle).not.toHaveBeenCalled();

    const finalizeResponses: Array<() => Response | never> = [
      () => json({ finalized: false, reason_codes: ["NONCE_REPLAY_DETECTED"] }, 409),
      () => json({ finalized: false, reason_codes: ["NONCE_REPLAY_DETECTED"] }),
      () => new Response("{not-json", { status: 200 }),
      () => {
        throw new Error("offline");
      },
    ];
    for (const finalizeResponse of finalizeResponses) {
      const verifier = verifierWith(async (input) =>
        String(input).endsWith("/v1/execution/claim-token")
          ? json(claimResponse)
          : finalizeResponse(),
      );
      const authorization = await verifier.verifyAndConsume(captured, decision);
      if (authorization === null) throw new Error("TEST_EXPECTED_AUTHORIZATION");
      expect(
        await verifier.finalize({ captured, decision, authorization, outcome: "INDETERMINATE" }),
      ).toBe("PENDING");
    }
  });

  it("stops reading an oversized claim response", async () => {
    const { captured, decision } = setup();
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(60 * 1024));
      },
      cancel() {
        cancelled = true;
      },
    });
    const verifier = verifierWith(async () => new Response(body, { status: 200 }));

    expect(await verifier.verifyAndConsume(captured, decision)).toBeNull();
    expect(cancelled).toBe(true);
  });

  it("rejects unsafe authority URLs", () => {
    expect(
      () => new DecionisGrantVerifier({ baseUrl: "http://example.com", apiKey: "key" }),
    ).toThrow("DECIONIS_URL_MUST_USE_HTTPS");
    expect(
      () =>
        new DecionisGrantVerifier({
          baseUrl: "https://user:secret@example.com",
          apiKey: "key",
        }),
    ).toThrow("DECIONIS_URL_MUST_NOT_CONTAIN_CREDENTIALS");
    expect(
      () =>
        new DecionisGrantVerifier({
          baseUrl: "https://example.com#credential",
          apiKey: "key",
        }),
    ).toThrow("DECIONIS_URL_MUST_NOT_CONTAIN_QUERY_OR_FRAGMENT");
  });
});
