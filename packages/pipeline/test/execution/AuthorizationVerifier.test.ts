import { describe, expect, it } from "vitest";
import type { GateDecision } from "../../src/decision/DecisionAuthority.js";
import { DecionisGrantVerifier } from "../../src/execution/AuthorizationVerifier.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

function setup() {
  const captured = new IntentCapture().capture(
    { action: "deploy", target: "github:repo", parameters: { environment: "production" } },
    {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: { id: "deploy-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "github", operation: "deploy" },
      idempotencyKey: "deploy-1",
      context: {},
    },
  );
  const decision: GateDecision = {
    verdict: "ALLOW",
    decisionId: "decision-1",
    dossierId: "dossier-1",
    intentHash: captured.intentHash,
    reasonCodes: [],
    authorization: { token: "token-1", expiresAt: "2026-08-14T10:00:30.000Z" },
    failClosed: false,
  };
  return { captured, decision };
}

describe("DecionisGrantVerifier", () => {
  it("accepts only an atomically consumed grant bound to the decision and intent", async () => {
    const { captured, decision } = setup();
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
              exp: 1_900_000_000,
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

  it("rejects missing tokens, failed consumption, malformed responses, and binding mismatch", async () => {
    const { captured, decision } = setup();
    const noToken = { ...decision, authorization: null };
    const unavailable = new DecionisGrantVerifier({
      baseUrl: "http://localhost:3001",
      apiKey: "key",
      allowInsecureLoopback: true,
      fetch: (async () => new Response("{}", { status: 409 })) as typeof fetch,
    });
    expect(await unavailable.verifyAndConsume(captured, noToken)).toBeNull();
    expect(await unavailable.verifyAndConsume(captured, decision)).toBeNull();

    const mismatch = new DecionisGrantVerifier({
      baseUrl: "http://localhost:3001",
      apiKey: "key",
      allowInsecureLoopback: true,
      fetch: (async () =>
        new Response(
          JSON.stringify({
            valid: true,
            claims: {
              jti: "grant-1",
              decision_id: "other",
              dossier_id: "dossier-1",
              exp: 1_900_000_000,
              binding: { intent_hash: captured.intentHash },
            },
          }),
          { status: 200 },
        )) as typeof fetch,
    });
    expect(await mismatch.verifyAndConsume(captured, decision)).toBeNull();
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
  });
});
