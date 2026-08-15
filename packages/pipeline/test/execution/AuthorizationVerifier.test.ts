import { describe, expect, it } from "vitest";
import type { GateDecision } from "../../src/decision/DecisionAuthority.js";
import { DecionisGrantVerifier } from "../../src/execution/AuthorizationVerifier.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

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
  return { captured, decision, expiresAtSeconds };
}

describe("DecionisGrantVerifier", () => {
  it("accepts only an atomically consumed grant bound to the decision and intent", async () => {
    const { captured, decision, expiresAtSeconds } = setup();
    const verifier = new DecionisGrantVerifier({
      baseUrl: "http://127.0.0.1:3001",
      apiKey: "key",
      allowInsecureLoopback: true,
      fetch: (async () =>
        new Response(
          JSON.stringify({
            valid: true,
            claims: {
              jti: "grant-1",
              decision_id: "decision-1",
              dossier_id: "dossier-1",
              exp: expiresAtSeconds,
              binding: { intent_hash: captured.intentHash },
            },
          }),
          { status: 200 },
        )) as typeof fetch,
    });

    expect(await verifier.verifyAndConsume(captured, decision)).toMatchObject({
      grantId: "grant-1",
      intentHash: captured.intentHash,
    });
  });

  it("rejects missing tokens, failed consumption, and every grant-binding mismatch", async () => {
    const { captured, decision, expiresAtSeconds } = setup();
    const noToken = { ...decision, authorization: null };
    const unavailable = new DecionisGrantVerifier({
      baseUrl: "http://localhost:3001",
      apiKey: "key",
      allowInsecureLoopback: true,
      fetch: (async () => new Response("{}", { status: 409 })) as typeof fetch,
    });
    expect(await unavailable.verifyAndConsume(captured, noToken)).toBeNull();
    expect(await unavailable.verifyAndConsume(captured, decision)).toBeNull();

    const claims = {
      jti: "grant-1",
      decision_id: decision.decisionId,
      dossier_id: decision.dossierId,
      exp: expiresAtSeconds,
      binding: { intent_hash: captured.intentHash },
    };
    const mismatches = [
      { ...claims, decision_id: "other" },
      { ...claims, dossier_id: "other" },
      { ...claims, binding: { intent_hash: `sha256:${"0".repeat(64)}` } },
      { ...claims, exp: expiresAtSeconds - 1 },
      { ...claims, jti: "" },
      { ...claims, unexpected_execution_mode: "bypass" },
    ];
    for (const mismatchedClaims of mismatches) {
      const mismatch = new DecionisGrantVerifier({
        baseUrl: "http://localhost:3001",
        apiKey: "key",
        allowInsecureLoopback: true,
        fetch: (async () =>
          new Response(JSON.stringify({ valid: true, claims: mismatchedClaims }), {
            status: 200,
          })) as typeof fetch,
      });
      expect(await mismatch.verifyAndConsume(captured, decision)).toBeNull();
    }
  });

  it("stops reading an oversized consume response", async () => {
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
    const verifier = new DecionisGrantVerifier({
      baseUrl: "http://localhost:3001",
      apiKey: "key",
      allowInsecureLoopback: true,
      fetch: (async () => new Response(body, { status: 200 })) as typeof fetch,
    });

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
