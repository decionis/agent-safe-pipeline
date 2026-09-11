import { describe, expect, it, vi } from "vitest";
import { DecionisGate } from "../../src/decision/DecionisGate.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";
import type { CapturedIntent } from "../../src/intent/ExecutionIntent.js";

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

/** A complete `ExecutionAuthorityDecision` body as the Decionis contract documents it. */
function decisionBody(intent: CapturedIntent, overrides: Record<string, unknown> = {}) {
  return {
    decision_id: "decision-1",
    chain_id: "chain-1",
    status: "ALLOW",
    should_execute: true,
    reason_codes: ["POLICY_ALLOW"],
    action_hash: intent.intentHash,
    policy_version: "policy-2026.09",
    mode: "ENFORCEMENT",
    execution_token: "token",
    execution_token_expires_at: intent.intent.expiresAt,
    dossier_id: "dossier-1",
    dossier_sha256: `sha256:${"a".repeat(64)}`,
    dossier_url: "/v1/protocol/dossiers/dossier-1",
    approval_request_id: null,
    ledger_entry_id: "ledger-1",
    ...overrides,
  };
}

function gateWith(fetchMock: typeof fetch, mode?: "ENFORCEMENT" | "SHADOW") {
  return new DecionisGate({
    baseUrl: "http://127.0.0.1:3001",
    apiKey: "test-key",
    allowInsecureLoopback: true,
    fetch: fetchMock,
    ...(mode === undefined ? {} : { mode }),
  });
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

describe("DecionisGate", () => {
  it("sends the contract binding and maps a bound authority response to ALLOW", async () => {
    const intent = captured();
    const fetchMock = vi.fn<typeof fetch>(async () => json(decisionBody(intent)));
    const gate = gateWith(fetchMock);

    const decision = await gate.evaluate(intent);

    expect(decision).toMatchObject({
      verdict: "ALLOW",
      intentHash: intent.intentHash,
      decisionId: "decision-1",
      dossierId: "dossier-1",
      reasonCodes: ["POLICY_ALLOW"],
    });
    expect(decision.evidence).toBeUndefined();
    expect(Object.isFrozen(decision)).toBe(true);
    expect(Object.isFrozen(decision.reasonCodes)).toBe(true);
    expect(Object.isFrozen(decision.authorization)).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [url, request] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://127.0.0.1:3001/v1/authority/enforce-and-bind");
    const headers = request.headers as Record<string, string>;
    // The contract requires Idempotency-Key to equal the signed intent_id.
    expect(headers["idempotency-key"]).toBe(intent.intent.intentId);
    expect(headers.authorization).toBe("Bearer test-key");
    const body = JSON.parse(request.body as string) as Record<string, unknown>;
    // Exactly the ExecutionAuthorityRequest properties; the contract forbids extras.
    expect(Object.keys(body).sort()).toEqual([
      "action",
      "actor",
      "captured_at",
      "context",
      "downstream_target",
      "expires_at",
      "intent_hash",
      "intent_id",
      "mode",
      "protocol_version",
      "tenant_id",
    ]);
    expect(body).toMatchObject({
      protocol_version: "agent-safe.intent/1",
      intent_id: intent.intent.intentId,
      intent_hash: intent.intentHash,
      mode: "ENFORCEMENT",
      context: { idempotency_key: "deploy-1" },
      action: { type: "deploy", resource: "github:repo:main" },
    });
  });

  it("sends the expected-effect digest as a top-level binding property on enforce-and-bind", async () => {
    const expectedEffectDigest = `sha256:${"c".repeat(64)}`;
    const intent = new IntentCapture().capture(
      { action: "deploy", target: "github:repo:main", parameters: { environment: "production" } },
      {
        tenantId: "00000000-0000-4000-8000-000000000002",
        actor: { id: "synthetic-deploy-agent", type: "AI_AGENT" },
        downstreamTarget: { system: "github", operation: "deploy" },
        idempotencyKey: "deploy-1",
        context: {},
        expectedEffectDigest,
      },
    );
    const fetchMock = vi.fn<typeof fetch>(async () => json(decisionBody(intent)));

    const decision = await gateWith(fetchMock).evaluate(intent);

    expect(decision.verdict).toBe("ALLOW");
    const request = fetchMock.mock.calls[0]?.[1] as RequestInit;
    const body = JSON.parse(request.body as string) as Record<string, unknown>;
    // The commitment travels as a top-level binding property, so it is inside intent_hash.
    expect(Object.keys(body).sort()).toEqual([
      "action",
      "actor",
      "captured_at",
      "context",
      "downstream_target",
      "expected_effect_digest",
      "expires_at",
      "intent_hash",
      "intent_id",
      "mode",
      "protocol_version",
      "tenant_id",
    ]);
    expect(body.expected_effect_digest).toBe(expectedEffectDigest);
    expect(body.intent_hash).toBe(intent.intentHash);
  });

  it("attaches the evidence it evaluated with to the decision", async () => {
    const intent = captured();
    const fetchMock = vi.fn<typeof fetch>(async () => json(decisionBody(intent)));
    const evidence = {
      humanApproval: {
        provider: "presence" as const,
        requestId: "synthetic-presence-request",
        receiptDossierId: "synthetic-presence-receipt",
      },
    };

    const decision = await gateWith(fetchMock).evaluate(intent, evidence);

    expect(decision.evidence).toEqual(evidence);
    expect(Object.isFrozen(decision.evidence)).toBe(true);
    expect(Object.isFrozen(decision.evidence?.humanApproval)).toBe(true);
    const request = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(request.body as string)).toMatchObject({ evidence });
  });

  it("sends SHADOW mode and never returns authorization from a shadow evaluation", async () => {
    const intent = captured();
    const bodies = [
      decisionBody(intent, { mode: "SHADOW", execution_token: "token-that-must-be-discarded" }),
      decisionBody(intent, {
        decision_id: "decision-2",
        mode: "SHADOW",
        should_execute: false,
        execution_token: null,
        execution_token_expires_at: null,
        dossier_id: "dossier-2",
      }),
      decisionBody(intent, {
        decision_id: "decision-3",
        status: "ESCALATE",
        mode: "SHADOW",
        should_execute: false,
        reason_codes: ["HUMAN_REQUIRED"],
        execution_token: null,
        execution_token_expires_at: null,
        dossier_id: "dossier-3",
        approval_request_id: "approval-3",
      }),
      decisionBody(intent, {
        decision_id: "decision-4",
        status: "ERROR",
        mode: null,
        should_execute: false,
        reason_codes: ["DEPENDENCY_FAILED"],
        execution_token: null,
        execution_token_expires_at: null,
        dossier_id: null,
        dossier_url: null,
        ledger_entry_id: null,
      }),
    ];
    const expected = [
      { verdict: "ALLOW", failClosed: false, dossierId: "dossier-1" },
      { verdict: "ALLOW", failClosed: false, dossierId: "dossier-2" },
      { verdict: "ESCALATE", failClosed: false, dossierId: "dossier-3" },
      { verdict: "BLOCK", failClosed: true, dossierId: null },
    ];

    for (const [index, body] of bodies.entries()) {
      const fetchMock = vi.fn<typeof fetch>(async () => json(body));
      const gate = gateWith(fetchMock, "SHADOW");
      expect(gate.evaluationMode).toBe("SHADOW");

      const decision = await gate.evaluate(intent);

      expect(decision).toMatchObject({ ...expected[index], authorization: null });
      expect(Object.isFrozen(decision)).toBe(true);
      const request = fetchMock.mock.calls[0]?.[1] as RequestInit;
      expect(JSON.parse(request.body as string)).toMatchObject({ mode: "SHADOW" });
      expect(JSON.stringify(decision)).not.toContain("token-that-must-be-discarded");
    }

    const enforcementFetch = vi.fn<typeof fetch>(async () => new Response("", { status: 503 }));
    const enforcement = gateWith(enforcementFetch);
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

  it("fails closed on a hash, mode, or grant condition that the contract does not satisfy", async () => {
    const intent = captured();
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ action_hash: `sha256:${"0".repeat(64)}` }, "AUTHORITY_BINDING_MISMATCH"],
      [{ mode: "SHADOW" }, "AUTHORITY_MODE_MISMATCH"],
      [{ mode: "PARALLEL" }, "AUTHORITY_MODE_MISMATCH"],
      [{ mode: null }, "AUTHORITY_GRANT_MISSING"],
      [{ execution_token: null, execution_token_expires_at: null }, "AUTHORITY_GRANT_MISSING"],
      [{ should_execute: false }, "AUTHORITY_GRANT_MISSING"],
      [{ dossier_id: null }, "AUTHORITY_GRANT_MISSING"],
      [{ execution_token_expires_at: "2020-01-01T00:00:00.000Z" }, "AUTHORITY_GRANT_MISSING"],
    ];

    for (const [overrides, reasonCode] of cases) {
      const gate = gateWith(async () => json(decisionBody(intent, overrides)));
      const decision = await gate.evaluate(intent);
      expect(decision, reasonCode).toMatchObject({
        verdict: "BLOCK",
        failClosed: true,
        authorization: null,
        reasonCodes: [reasonCode],
      });
      expect(Object.isFrozen(decision)).toBe(true);
      expect(Object.isFrozen(decision.reasonCodes)).toBe(true);
    }

    const unavailable = gateWith(async () => {
      throw new Error("offline");
    });
    expect(await unavailable.evaluate(intent)).toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      reasonCodes: ["AUTHORITY_UNAVAILABLE"],
    });
  });

  it("surfaces an ERROR decision body from a 409 or 503 as evidence-bearing fail-closed", async () => {
    const intent = captured();
    const conflict = decisionBody(intent, {
      status: "ERROR",
      should_execute: false,
      reason_codes: ["AUTHORITY_IDEMPOTENCY_CONFLICT"],
      execution_token: null,
      execution_token_expires_at: null,
      mode: null,
    });

    const conflicted = await gateWith(async () => json(conflict, 409)).evaluate(intent);
    expect(conflicted).toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      decisionId: "decision-1",
      dossierId: "dossier-1",
      reasonCodes: ["AUTHORITY_IDEMPOTENCY_CONFLICT"],
      authorization: null,
    });

    const emptyReasons = await gateWith(async () =>
      json({ ...conflict, reason_codes: [] }, 503),
    ).evaluate(intent);
    expect(emptyReasons.reasonCodes).toEqual(["AUTHORITY_REQUEST_FAILED"]);

    // A non-ERROR body on an error status must never become executable.
    const allowOn409 = await gateWith(async () => json(decisionBody(intent), 409)).evaluate(intent);
    expect(allowOn409).toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      authorization: null,
      reasonCodes: ["AUTHORITY_REQUEST_FAILED"],
    });

    const plainText = await gateWith(
      async () => new Response("upstream failure", { status: 503 }),
    ).evaluate(intent);
    expect(plainText.reasonCodes).toEqual(["AUTHORITY_REQUEST_FAILED"]);
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
      new Response("{not-json", { status: 200 }),
      json(decisionBody(intent, { unexpected_execution_mode: "bypass" })),
      json(decisionBody(intent, { reason_codes: ["bad code"] })),
      json({ decision_id: "decision-1", status: "ALLOW" }),
      new Response(oversizedBody, { status: 200 }),
    ];

    for (const response of responses) {
      const gate = gateWith(async () => response);
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
