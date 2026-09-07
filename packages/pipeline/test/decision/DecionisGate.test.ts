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
    expect(Object.isFrozen(decision)).toBe(true);
    expect(Object.isFrozen(decision.reasonCodes)).toBe(true);
    expect(Object.isFrozen(decision.authorization)).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("sends SHADOW mode and never returns authorization from a shadow evaluation", async () => {
    const intent = captured();
    const bodies = [
      {
        decision_id: "decision-1",
        status: "ALLOW",
        should_execute: true,
        reason_codes: ["POLICY_ALLOW"],
        action_hash: intent.intentHash,
        execution_token: "token-that-must-be-discarded",
        execution_token_expires_at: intent.intent.expiresAt,
        dossier_id: "dossier-1",
      },
      {
        decision_id: "decision-2",
        status: "ALLOW",
        should_execute: false,
        reason_codes: [],
        action_hash: intent.intentHash,
        execution_token: null,
        execution_token_expires_at: null,
        dossier_id: "dossier-2",
      },
      {
        decision_id: "decision-3",
        status: "ESCALATE",
        should_execute: false,
        reason_codes: ["HUMAN_REQUIRED"],
        action_hash: intent.intentHash,
        execution_token: null,
        execution_token_expires_at: null,
        dossier_id: "dossier-3",
      },
      {
        decision_id: "decision-4",
        status: "ERROR",
        should_execute: false,
        reason_codes: ["DEPENDENCY_FAILED"],
        action_hash: intent.intentHash,
        execution_token: null,
        execution_token_expires_at: null,
        dossier_id: null,
      },
    ];
    const expected = [
      { verdict: "ALLOW", failClosed: false, dossierId: "dossier-1" },
      { verdict: "ALLOW", failClosed: false, dossierId: "dossier-2" },
      { verdict: "ESCALATE", failClosed: false, dossierId: "dossier-3" },
      { verdict: "BLOCK", failClosed: true, dossierId: null },
    ];

    for (const [index, body] of bodies.entries()) {
      const fetchMock = vi.fn<typeof fetch>(
        async () => new Response(JSON.stringify(body), { status: 200 }),
      );
      const gate = new DecionisGate({
        baseUrl: "http://127.0.0.1:3001",
        apiKey: "test-key",
        allowInsecureLoopback: true,
        mode: "SHADOW",
        fetch: fetchMock as typeof fetch,
      });
      expect(gate.evaluationMode).toBe("SHADOW");

      const decision = await gate.evaluate(intent);

      expect(decision).toMatchObject({ ...expected[index], authorization: null });
      expect(Object.isFrozen(decision)).toBe(true);
      const request = fetchMock.mock.calls[0]?.[1] as RequestInit;
      expect(JSON.parse(request.body as string)).toMatchObject({ mode: "SHADOW" });
      expect(JSON.stringify(decision)).not.toContain("token-that-must-be-discarded");
    }

    const enforcementFetch = vi.fn<typeof fetch>(async () => new Response("", { status: 503 }));
    const enforcement = new DecionisGate({
      baseUrl: "http://127.0.0.1:3001",
      apiKey: "test-key",
      allowInsecureLoopback: true,
      fetch: enforcementFetch as typeof fetch,
    });
    expect(enforcement.evaluationMode).toBe("ENFORCEMENT");
    await enforcement.evaluate(intent);
    const enforcementRequest = enforcementFetch.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(enforcementRequest.body as string)).toMatchObject({ mode: "ENFORCEMENT" });
    expect(
      () =>
        new DecionisGate({
          baseUrl: "http://127.0.0.1:3001",
          apiKey: "test-key",
          allowInsecureLoopback: true,
          mode: "PARALLEL" as unknown as "SHADOW",
        }),
    ).toThrow("DECIONIS_GATE_MODE_INVALID");
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
      const decision = await gate.evaluate(intent);
      expect(decision).toMatchObject({ verdict: "BLOCK", failClosed: true });
      expect(Object.isFrozen(decision)).toBe(true);
      expect(Object.isFrozen(decision.reasonCodes)).toBe(true);
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
