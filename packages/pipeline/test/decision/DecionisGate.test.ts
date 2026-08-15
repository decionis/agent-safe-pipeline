import { describe, expect, it, vi } from "vitest";
import { DecionisGate } from "../../src/decision/DecionisGate.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

function captured() {
  return new IntentCapture().capture(
    { action: "deploy", target: "github:repo:main", parameters: { environment: "production" } },
    {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: { id: "synthetic-deploy-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "github", operation: "deploy" },
      idempotencyKey: "deploy-1",
      context: {},
    },
  );
}

describe("DecionisGate", () => {
  it("maps a bound strict authority response to ALLOW", async () => {
    const intent = captured();
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            decision_id: "decision-1",
            status: "ALLOW",
            should_execute: true,
            reason_codes: [],
            action_hash: intent.intentHash,
            execution_token: "token",
            execution_token_expires_at: intent.intent.expiresAt,
            dossier_id: "dossier-1",
          }),
          { status: 200 },
        ),
    );
    const gate = new DecionisGate({
      baseUrl: "http://127.0.0.1:3001",
      apiKey: "test-key",
      fetch: fetchMock as typeof fetch,
      allowInsecureLoopback: true,
    });

    const decision = await gate.evaluate(intent);

    expect(decision).toMatchObject({ verdict: "ALLOW", intentHash: intent.intentHash });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("fails closed on a hash mismatch, transport error, or missing ALLOW grant", async () => {
    const intent = captured();
    const bodies = [
      {
        decision_id: "decision-1",
        status: "ALLOW",
        should_execute: true,
        reason_codes: [],
        action_hash: `sha256:${"0".repeat(64)}`,
        execution_token: "token",
        execution_token_expires_at: "2026-08-14T10:00:30.000Z",
        dossier_id: "dossier-1",
      },
      {
        decision_id: "decision-1",
        status: "ALLOW",
        should_execute: true,
        reason_codes: [],
        action_hash: intent.intentHash,
        execution_token: null,
        execution_token_expires_at: null,
        dossier_id: "dossier-1",
      },
    ];

    for (const body of bodies) {
      const gate = new DecionisGate({
        baseUrl: "http://localhost:3001",
        apiKey: "test-key",
        allowInsecureLoopback: true,
        fetch: (async () => new Response(JSON.stringify(body), { status: 200 })) as typeof fetch,
      });
      expect(await gate.evaluate(intent)).toMatchObject({ verdict: "BLOCK", failClosed: true });
    }

    const unavailable = new DecionisGate({
      baseUrl: "http://localhost:3001",
      apiKey: "test-key",
      allowInsecureLoopback: true,
      fetch: (async () => {
        throw new Error("offline");
      }) as typeof fetch,
    });
    expect(await unavailable.evaluate(intent)).toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
    });
  });

  it("bounds response streaming and rejects malformed or schema-invalid responses", async () => {
    const intent = captured();
    let cancelled = false;
    const oversizedBody = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(60 * 1024));
      },
      cancel() {
        cancelled = true;
      },
    });
    const responses = [
      new Response("upstream failure", { status: 503 }),
      new Response("{not-json", { status: 200 }),
      new Response(
        JSON.stringify({
          decision_id: "decision-1",
          status: "ALLOW",
          should_execute: true,
          reason_codes: [],
          action_hash: intent.intentHash,
          execution_token: "token",
          execution_token_expires_at: intent.intent.expiresAt,
          dossier_id: "dossier-1",
          unexpected_execution_mode: "bypass",
        }),
        { status: 200 },
      ),
      new Response(oversizedBody, { status: 200 }),
    ];

    for (const response of responses) {
      const gate = new DecionisGate({
        baseUrl: "http://localhost:3001",
        apiKey: "test-key",
        allowInsecureLoopback: true,
        fetch: (async () => response) as typeof fetch,
      });
      expect(await gate.evaluate(intent)).toMatchObject({ verdict: "BLOCK", failClosed: true });
    }
    expect(cancelled).toBe(true);
  });

  it("rejects insecure non-loopback and credential-bearing authority URLs", () => {
    expect(() => new DecionisGate({ baseUrl: "http://example.com", apiKey: "key" })).toThrow(
      "DECIONIS_URL_MUST_USE_HTTPS",
    );
    expect(
      () => new DecionisGate({ baseUrl: "https://user:secret@example.com", apiKey: "key" }),
    ).toThrow("DECIONIS_URL_MUST_NOT_CONTAIN_CREDENTIALS");
    expect(
      () => new DecionisGate({ baseUrl: "https://example.com?api_key=secret", apiKey: "key" }),
    ).toThrow("DECIONIS_URL_MUST_NOT_CONTAIN_QUERY_OR_FRAGMENT");
  });
});
