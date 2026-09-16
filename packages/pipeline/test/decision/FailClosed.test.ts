/**
 * One test per way the hosted gate can fail, and the same proof for each: the
 * decision is BLOCK, carries no grant, says it failed closed, and SafeExecutor
 * refuses it. Several cases are also covered in DecionisGate.test.ts; this
 * file exists so the fail-closed claim can be read top to bottom in one place.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { DecionisGate, type DecionisGateOptions } from "../../src/decision/DecionisGate.js";
import type { GateDecision } from "../../src/decision/DecisionAuthority.js";
import { ActionRegistry } from "../../src/execution/ActionRegistry.js";
import { DecionisGrantVerifier } from "../../src/execution/AuthorizationVerifier.js";
import { SafeExecutor } from "../../src/execution/SafeExecutor.js";
import type { CapturedIntent } from "../../src/intent/ExecutionIntent.js";
import { captured, decisionBody, json, verdictBody } from "../support/AuthorityDouble.js";

const API_KEY = "synthetic-authority-key";
const BASE_URL = "http://127.0.0.1:3001";

function gate(fetchImpl: typeof fetch, options: Partial<DecionisGateOptions> = {}) {
  return new DecionisGate({
    baseUrl: BASE_URL,
    apiKey: API_KEY,
    allowInsecureLoopback: true,
    fetch: fetchImpl,
    ...options,
  });
}

function registry() {
  return new ActionRegistry()
    .register("deploy", {
      parametersSchema: z.object({ environment: z.string() }).strict(),
      execute: async ({ parameters, dispatch }) =>
        await dispatch.run(async () => ({ deployed: parameters.environment })),
    })
    .seal();
}

/** A fetch that never answers on its own and rejects only when the gate aborts it. */
function hanging() {
  const signals: AbortSignal[] = [];
  const fetchImpl = vi.fn<typeof fetch>(
    (_url, init) =>
      new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal;
        if (signal === undefined || signal === null) return;
        signals.push(signal);
        signal.addEventListener("abort", () => reject(new Error("AbortError")), { once: true });
      }),
  );
  return { fetchImpl, signals };
}

async function expectFailClosed(
  intent: CapturedIntent,
  decision: GateDecision,
  reasonCode?: string,
): Promise<void> {
  expect(decision).toMatchObject({
    verdict: "BLOCK",
    failClosed: true,
    authorization: null,
    intentHash: intent.intentHash,
  });
  if (reasonCode !== undefined) expect(decision.reasonCodes).toEqual([reasonCode]);
  expect(Object.isFrozen(decision)).toBe(true);

  // The executor never consults a verifier for a BLOCK: the fetch here must stay idle.
  const verifierFetch = vi.fn<typeof fetch>();
  const executor = new SafeExecutor(
    registry(),
    new DecionisGrantVerifier({
      baseUrl: BASE_URL,
      apiKey: API_KEY,
      allowInsecureLoopback: true,
      fetch: verifierFetch,
    }),
  );
  const result = await executor.run(intent, decision);
  expect(result).toMatchObject({
    outcome: "BLOCKED",
    executed: false,
    reason: "DECISION_NOT_ALLOW",
  });
  expect(verifierFetch).not.toHaveBeenCalled();
}

describe("the hosted gate fails closed", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("on a timeout: the request is aborted and no verdict is inferred from silence", async () => {
    const intent = captured();
    const { fetchImpl, signals } = hanging();

    const decision = await gate(fetchImpl, { timeoutMs: 1 }).evaluate(intent);

    await expectFailClosed(intent, decision, "AUTHORITY_UNAVAILABLE");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(signals[0]?.aborted).toBe(true);
  });

  it("on a network error", async () => {
    const intent = captured();
    const failures = [
      new TypeError("fetch failed"),
      Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }),
      "not even an Error",
    ];
    for (const failure of failures) {
      const decision = await gate(async () => {
        throw failure;
      }).evaluate(intent);
      await expectFailClosed(intent, decision, "AUTHORITY_UNAVAILABLE");
    }
  });

  it("on a non-2xx response, whatever the body says", async () => {
    const intent = captured();
    const responses: Array<[Response, string]> = [
      [new Response("unauthorized", { status: 401 }), "AUTHORITY_REQUEST_FAILED"],
      [json({ error: "AUTHORITY_TENANT_MISMATCH" }, 403), "AUTHORITY_REQUEST_FAILED"],
      [json({ error: "RATE_LIMITED" }, 429), "AUTHORITY_REQUEST_FAILED"],
      [new Response("<html>bad gateway</html>", { status: 502 }), "AUTHORITY_REQUEST_FAILED"],
      // An ALLOW body on an error status is still not executable.
      [json(decisionBody(intent), 500), "AUTHORITY_REQUEST_FAILED"],
      // A 3xx is not ok either; nothing is followed.
      [
        new Response(null, { status: 302, headers: { location: "/elsewhere" } }),
        "AUTHORITY_REQUEST_FAILED",
      ],
    ];
    for (const [response, reasonCode] of responses) {
      const decision = await gate(async () => response).evaluate(intent);
      await expectFailClosed(intent, decision, reasonCode);
    }

    // The contract's own ERROR body on 409 or 503 is refused with its evidence kept.
    const evidenceBearing = json(
      decisionBody(intent, {
        status: "ERROR",
        should_execute: false,
        reason_codes: ["AUTHORITY_STORE_UNAVAILABLE"],
        mode: null,
        execution_token: null,
        execution_token_expires_at: null,
      }),
      503,
    );
    const decision = await gate(async () => evidenceBearing).evaluate(intent);
    await expectFailClosed(intent, decision, "AUTHORITY_STORE_UNAVAILABLE");
    expect(decision.dossierId).toBe("dossier-1");
  });

  it("on a body that is not the contract's decision", async () => {
    const intent = captured();
    const bodies = [
      new Response("{not-json", { status: 200 }),
      new Response("", { status: 200 }),
      new Response("null", { status: 200 }),
      new Response("[]", { status: 200 }),
      new Response("<html>ok</html>", { status: 200 }),
      json({ decision_id: "decision-1", status: "ALLOW" }),
      json(decisionBody(intent, { execution_bypass: true })),
    ];
    for (const body of bodies) {
      const decision = await gate(async () => body).evaluate(intent);
      await expectFailClosed(intent, decision, "AUTHORITY_UNAVAILABLE");
    }
  });

  it("on a verdict the contract does not define", async () => {
    const intent = captured();
    for (const status of ["RESTRAIN", "allow", "APPROVE", "", null, 1]) {
      const decision = await gate(async () =>
        json(decisionBody(intent, { status, should_execute: false })),
      ).evaluate(intent);
      await expectFailClosed(intent, decision, "AUTHORITY_UNAVAILABLE");
    }
  });

  it("on a decision about a different intent", async () => {
    const intent = captured();
    const other = captured();
    expect(other.intentHash).not.toBe(intent.intentHash);

    for (const mode of ["ENFORCEMENT", "SHADOW"] as const) {
      const decision = await gate(async () => json(verdictBody(other, "ALLOW", mode)), {
        mode,
      }).evaluate(intent);
      await expectFailClosed(intent, decision, "AUTHORITY_BINDING_MISMATCH");
    }
  });

  it("on an intent that expired before evaluation, without asking the authority", async () => {
    const expired = captured({ clock: () => new Date(Date.now() - 120_000) });
    expect(Date.parse(expired.intent.expiresAt)).toBeLessThan(Date.now());
    const fetchImpl = vi.fn<typeof fetch>(async () => json(decisionBody(expired)));

    for (const mode of ["ENFORCEMENT", "SHADOW"] as const) {
      const decision = await gate(fetchImpl, { mode }).evaluate(expired);
      await expectFailClosed(expired, decision, "INTENT_EXPIRED");
    }
    expect(fetchImpl).not.toHaveBeenCalled();

    // An intent expiring during the call is refused by the grant check instead.
    const closing = captured({ clock: () => new Date(Date.now() - 59_950) });
    const decision = await gate(async () => {
      await new Promise((resolve) => setTimeout(resolve, 100));
      return json(decisionBody(closing));
    }).evaluate(closing);
    await expectFailClosed(closing, decision, "AUTHORITY_GRANT_MISSING");
  });

  it("on an ALLOW that lacks the grant or the dossier it must carry", async () => {
    const intent = captured();
    const cases: Array<Record<string, unknown>> = [
      { execution_token: null, execution_token_expires_at: null },
      { execution_token_expires_at: null },
      { dossier_id: null },
      { should_execute: false },
      { execution_eligible: false },
      { authority_classification: "OBSERVATIONAL" },
      { mode: "SHADOW" },
    ];
    for (const overrides of cases) {
      const decision = await gate(async () => json(decisionBody(intent, overrides))).evaluate(
        intent,
      );
      expect(decision, JSON.stringify(overrides)).toMatchObject({
        verdict: "BLOCK",
        failClosed: true,
        authorization: null,
      });
    }
  });
});

describe("the wire payload", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("carries the intent binding and nothing from the process around it", async () => {
    vi.stubEnv("DOWNSTREAM_CREDENTIAL", "synthetic-downstream-secret");
    const intent = captured();
    const requests: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = vi.fn<typeof fetch>(async (url, init) => {
      requests.push({ url: String(url), init: init ?? {} });
      return json(verdictBody(intent, "ALLOW", requests.length === 1 ? "ENFORCEMENT" : "SHADOW"));
    });
    // A verifier holding the same process's credentials is not consulted by the gate.
    new DecionisGrantVerifier({
      baseUrl: BASE_URL,
      apiKey: "synthetic-verifier-key",
      allowInsecureLoopback: true,
      fetch: fetchImpl,
    });

    await gate(fetchImpl, { mode: "ENFORCEMENT" }).evaluate(intent);
    await gate(fetchImpl, { mode: "SHADOW" }).evaluate(intent);
    expect(requests).toHaveLength(2);

    for (const { url, init } of requests) {
      expect(url).toBe(`${BASE_URL}/v1/authority/enforce-and-bind`);
      expect(init.method).toBe("POST");
      const headers = init.headers as Record<string, string>;
      expect(headers.authorization).toBe(`Bearer ${API_KEY}`);
      expect(headers["idempotency-key"]).toBe(intent.intent.intentId);
      expect(headers["user-agent"]).toMatch(/^agent-safe-pipeline\/\d+\.\d+\.\d+/);

      const raw = init.body as string;
      const body = JSON.parse(raw) as Record<string, unknown>;
      // The ExecutionAuthorityRequest properties, exactly; the contract forbids extras.
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
        tenant_id: intent.intent.tenantId,
        intent_id: intent.intent.intentId,
        intent_hash: intent.intentHash,
        actor: { id: "synthetic-deploy-agent", type: "AI_AGENT" },
        action: {
          type: "deploy",
          resource: "github:repo:main",
          parameters: { environment: "production" },
        },
        context: { idempotency_key: "deploy-1" },
        downstream_target: { system: "github", operation: "deploy" },
      });
      // The credential travels in the header only; nothing else in the process is in the body.
      expect(raw).not.toContain(API_KEY);
      expect(raw).not.toContain("synthetic-verifier-key");
      expect(raw).not.toContain("synthetic-downstream-secret");
      expect(raw).not.toContain("DOWNSTREAM_CREDENTIAL");
    }

    const [enforcement, shadow] = requests.map(({ init }) => JSON.parse(init.body as string));
    expect(enforcement).toMatchObject({ mode: "ENFORCEMENT" });
    expect(shadow).toMatchObject({ mode: "SHADOW" });
    expect({ ...enforcement, mode: null }).toEqual({ ...shadow, mode: null });
  });
});
