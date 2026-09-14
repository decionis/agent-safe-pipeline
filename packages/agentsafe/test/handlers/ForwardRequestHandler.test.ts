import { ActionRegistry, IntentCapture, type CapturedIntent } from "@decionis/agent-safe-pipeline";
import { describe, expect, it, vi } from "vitest";
import type { DownstreamConfig } from "../../src/config/ExecutorConfig.js";
import { StaticHeaderCredential } from "../../src/credential/StaticHeaderCredential.js";
import {
  FORWARD_REQUEST_ACTION,
  REGISTERED_ACTIONS,
  forwardRequestHandlers,
  registerHandlers,
} from "../../src/handlers/ForwardRequestHandler.js";
import { SecretHandle } from "../../src/secrets/SecretHandle.js";
import { DOWNSTREAM_CREDENTIAL, TENANT_ID } from "../support/Environment.js";

const downstream: DownstreamConfig = {
  url: "https://payouts.provider.example/v1/payouts",
  lookupUrl: "https://payouts.provider.example/v1/payouts/{idempotency_key}",
  system: "payout-rail",
  operation: "create_payout",
  environment: "production",
  credentialHeader: "authorization",
  timeoutMs: 2_000,
};

const credential = new StaticHeaderCredential("authorization", () =>
  SecretHandle.fromString("DOWNSTREAM_CREDENTIAL", DOWNSTREAM_CREDENTIAL),
);

function captured(idempotencyKey = "payout 1/v1"): CapturedIntent {
  return new IntentCapture({ ttlSeconds: 300 }).capture(
    {
      action: FORWARD_REQUEST_ACTION,
      target: "payout:synthetic-beneficiary-1",
      parameters: { amountMinor: 5_000, currency: "USD" },
    },
    {
      tenantId: TENANT_ID,
      actor: { id: "synthetic-payout-agent", type: "AI_AGENT" },
      downstreamTarget: {
        system: "payout-rail",
        operation: "create_payout",
        environment: "production",
      },
      context: {},
      idempotencyKey,
    },
  );
}

const authorization = (intent: CapturedIntent) => ({
  decisionId: "fixture_decision_1",
  dossierId: "fixture_dossier_1",
  grantId: "fixture_grant_1",
  intentHash: intent.intentHash,
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
});

const response = (status: number): Response => new Response(null, { status });

describe("forward_request handler", () => {
  it("posts the verified parameters with the credential and the intent-bound key", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(response(202));
    const registry = registerHandlers(
      new ActionRegistry(),
      downstream,
      credential,
      fetchImpl,
    ).seal();
    const intent = captured();
    const attempt = await registry.executeTracked(intent, authorization(intent));
    expect(attempt).toEqual({ status: "COMPLETED", result: { status: 202, accepted: true } });
    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(downstream.url);
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({
      authorization: DOWNSTREAM_CREDENTIAL,
      "content-type": "application/json",
      "idempotency-key": "payout 1/v1",
      "x-agent-safe-intent-hash": intent.intentHash,
      "x-agent-safe-decision-id": "fixture_decision_1",
      "x-agent-safe-dossier-id": "fixture_dossier_1",
    });
    expect(init.body).toBe(JSON.stringify({ amountMinor: 5_000, currency: "USD" }));
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it("reports a provider refusal as a result, never a body", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response('{"secret":1}', { status: 500 }));
    const registry = registerHandlers(
      new ActionRegistry(),
      downstream,
      credential,
      fetchImpl,
    ).seal();
    const intent = captured();
    expect(await registry.executeTracked(intent, authorization(intent))).toEqual({
      status: "COMPLETED",
      result: { status: 500, accepted: false },
    });
  });

  it("reports a transport failure after dispatch as unknown", async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error("socket hang up"));
    const registry = registerHandlers(
      new ActionRegistry(),
      downstream,
      credential,
      fetchImpl,
    ).seal();
    const intent = captured();
    expect(await registry.executeTracked(intent, authorization(intent))).toEqual({
      status: "UNKNOWN_AFTER_DISPATCH",
    });
  });

  it("reconciles by reading the provider with the encoded key and never re-sends", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(response(404))
      .mockResolvedValueOnce(response(200))
      .mockResolvedValueOnce(response(503));
    const registry = registerHandlers(
      new ActionRegistry(),
      downstream,
      credential,
      fetchImpl,
    ).seal();
    const intent = captured();
    expect(await registry.reconcile(intent, "payout 1/v1")).toEqual({ status: "NOT_EXECUTED" });
    expect(await registry.reconcile(intent, "payout 1/v1")).toEqual({
      status: "COMPLETED",
      result: { status: 200, accepted: true },
    });
    expect(await registry.reconcile(intent, "payout 1/v1")).toEqual({ status: "UNKNOWN" });
    for (const [url, init] of fetchImpl.mock.calls as [string, RequestInit][]) {
      expect(url).toBe("https://payouts.provider.example/v1/payouts/payout%201%2Fv1");
      expect(init.method).toBe("GET");
      expect(init.headers).toEqual({ authorization: DOWNSTREAM_CREDENTIAL });
    }
  });

  it("registers no reconciliation when no lookup URL is configured", async () => {
    const fetchImpl = vi.fn();
    const registry = registerHandlers(
      new ActionRegistry(),
      { ...downstream, lookupUrl: null },
      credential,
      fetchImpl,
    ).seal();
    const intent = captured();
    expect(await registry.reconcile(intent, "payout 1/v1")).toEqual({ status: "UNKNOWN" });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("is the reference registration the executor accepts", () => {
    const registry = new ActionRegistry();
    const registered = forwardRequestHandlers()({
      registry,
      downstream,
      credential,
      fetch: vi.fn(),
    });
    expect(registered).toBe(REGISTERED_ACTIONS);
    expect(registry.has(FORWARD_REQUEST_ACTION)).toBe(true);
  });
});
