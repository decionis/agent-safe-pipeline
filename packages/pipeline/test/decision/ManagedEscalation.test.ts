import { describe, expect, it, vi } from "vitest";
import {
  DecionisGate,
  type ManagedEscalationStatusResult,
} from "../../src/decision/DecionisGate.js";
import type {
  DecisionEvidence,
  GateDecision,
  ManagedEscalationState,
} from "../../src/decision/DecisionAuthority.js";
import type { CapturedIntent } from "../../src/intent/ExecutionIntent.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

const FIXED_TIME = Date.parse("2030-01-01T00:00:00.000Z");

function captured(
  target = "shopify:order:synthetic-3001",
  amountMinor = 50_000,
  action = "refund_order",
): CapturedIntent {
  return new IntentCapture({ clock: () => new Date(FIXED_TIME), ttlSeconds: 300 }).capture(
    {
      action,
      target,
      parameters: { amountMinor, currency: "USD", orderId: target.split(":").at(-1) ?? target },
    },
    {
      tenantId: "00000000-0000-4000-8000-000000000003",
      actor: { id: "synthetic-managed-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "shopify", operation: "refund" },
      idempotencyKey: `managed-${action}-${target}-${amountMinor}`,
      context: {},
    },
  );
}

function authorityDecision(
  intent: CapturedIntent,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    decision_id: "synthetic-decision-managed-1",
    chain_id: "synthetic-chain-1",
    status: "ESCALATE",
    should_execute: false,
    reason_codes: ["PRESENCE_REQUIRED"],
    action_hash: intent.intentHash,
    policy_version: "synthetic-policy-v1",
    mode: "ENFORCEMENT",
    execution_token: null,
    execution_token_expires_at: null,
    dossier_id: "synthetic-dossier-managed-1",
    dossier_sha256: `sha256:${"a".repeat(64)}`,
    dossier_url: "/v1/protocol/dossiers/synthetic-dossier-managed-1",
    approval_request_id: null,
    ledger_entry_id: "synthetic-ledger-managed-1",
    ...overrides,
  };
}

function managedWire(
  intent: CapturedIntent,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    outcome: "ESCALATE_PENDING",
    escalation_id: "synthetic-escalation-1",
    intent_id: intent.intent.intentId,
    status: "PENDING_PRESENCE",
    expires_at: intent.intent.expiresAt,
    reason_codes: ["PRESENCE_PENDING"],
    ...overrides,
  };
}

function pendingDecision(
  intent: CapturedIntent,
  stateOverrides: Partial<ManagedEscalationState> = {},
): GateDecision {
  return {
    verdict: "ESCALATE",
    decisionId: "synthetic-decision-managed-1",
    dossierId: "synthetic-dossier-managed-1",
    intentHash: intent.intentHash,
    reasonCodes: ["PRESENCE_REQUIRED"],
    authorization: null,
    failClosed: false,
    managedEscalation: {
      escalationId: "synthetic-escalation-1",
      intentId: intent.intent.intentId,
      status: "PENDING_PRESENCE",
      outcome: "ESCALATE_PENDING",
      expiresAt: intent.intent.expiresAt,
      reasonCodes: ["PRESENCE_PENDING"],
      ...stateOverrides,
    },
  };
}

function statusBody(
  intent: CapturedIntent,
  status: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const outcome = status === "GRANT_READY" ? "ALLOW" : status === "FAILED" ? "ERROR" : "BLOCK";
  return {
    escalation_id: "synthetic-escalation-1",
    intent_id: intent.intent.intentId,
    action_hash: intent.intentHash,
    status,
    outcome,
    expires_at: intent.intent.expiresAt,
    reason_codes: [],
    decision: null,
    ...overrides,
  };
}

function pendingStatusBody(
  intent: CapturedIntent,
  status:
    | "PENDING_PRESENCE"
    | "PRESENCE_REQUESTED"
    | "AWAITING_APPROVER"
    | "PRESENCE_VERIFIED"
    | "REAUTHORIZING",
): Record<string, unknown> {
  return statusBody(intent, status, { outcome: "ESCALATE_PENDING" });
}

function readyStatusBody(intent: CapturedIntent): Record<string, unknown> {
  const expiresAt = new Date(FIXED_TIME + 60_000).toISOString();
  return statusBody(intent, "GRANT_READY", {
    outcome: "ALLOW",
    reason_codes: ["PRESENCE_RECEIPT_VERIFIED"],
    decision: authorityDecision(intent, {
      decision_id: "synthetic-decision-managed-2",
      status: "ALLOW",
      should_execute: true,
      reason_codes: ["PRESENCE_RECEIPT_VERIFIED"],
      execution_token: "synthetic-managed-grant",
      execution_token_expires_at: expiresAt,
      dossier_id: "synthetic-dossier-managed-2",
      dossier_url: "/v1/protocol/dossiers/synthetic-dossier-managed-2",
    }),
  });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function gate(fetchMock: typeof fetch, mode?: "ENFORCEMENT" | "SHADOW"): DecionisGate {
  return new DecionisGate({
    baseUrl: "http://127.0.0.1:3001",
    apiKey: "test-key",
    allowInsecureLoopback: true,
    fetch: fetchMock,
    ...(mode === undefined ? {} : { mode }),
  });
}

describe("DecionisGate managed escalation", () => {
  it("adds caller constraints outside the canonical intent and accepts only grant-free pending state", async () => {
    const intent = captured();
    const fetchMock = vi.fn<typeof fetch>(async () =>
      json(authorityDecision(intent, { managed_escalation: managedWire(intent) })),
    );
    const beforeCanonical = intent.canonicalIntent;

    const decision = await gate(fetchMock).evaluate(intent, undefined, {
      escalation: {
        mode: "MANAGED",
        approver: { principal_id: "synthetic-approver-1", role_id: "APPROVER" },
        verification_requirements: { methods: ["WEBAUTHN"], level: "STANDARD" },
      },
    });

    expect(decision).toMatchObject({
      verdict: "ESCALATE",
      authorization: null,
      failClosed: false,
      managedEscalation: {
        outcome: "ESCALATE_PENDING",
        escalationId: "synthetic-escalation-1",
        intentId: intent.intent.intentId,
        status: "PENDING_PRESENCE",
        expiresAt: intent.intent.expiresAt,
      },
    });
    expect(decision.evidence).toBeUndefined();
    expect(Object.isFrozen(decision)).toBe(true);
    expect(Object.isFrozen(decision.managedEscalation)).toBe(true);
    expect(Object.isFrozen(decision.managedEscalation?.reasonCodes)).toBe(true);
    expect(intent.canonicalIntent).toBe(beforeCanonical);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url.endsWith("/v1/authority/enforce-and-bind")).toBe(true);
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body.escalation).toEqual({
      mode: "MANAGED",
      approver: { principal_id: "synthetic-approver-1", role_id: "APPROVER" },
      verification_requirements: { methods: ["WEBAUTHN"], level: "STANDARD" },
    });
    expect(JSON.parse(intent.canonicalIntent)).not.toHaveProperty("escalation");
    expect((init.headers as Record<string, string>)["idempotency-key"]).toBe(
      intent.intent.intentId,
    );
  });

  it("supports FIDO2 plus liveness without accepting duplicate or unknown methods", async () => {
    const intent = captured();
    const fetchMock = vi.fn<typeof fetch>(async () =>
      json(authorityDecision(intent, { managed_escalation: managedWire(intent) })),
    );
    const authority = gate(fetchMock);

    await authority.evaluate(intent, undefined, {
      escalation: {
        mode: "MANAGED",
        verification_requirements: {
          methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
          level: "HIGH_CONFIDENCE",
        },
      },
    });
    const request = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(request.body as string).escalation.verification_requirements).toEqual({
      methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
      level: "HIGH_CONFIDENCE",
    });

    for (const methods of [[], ["WEBAUTHN", "WEBAUTHN"], ["MOBILE_DEVICE"], ["PASSWORD"]]) {
      const invalid = await authority.evaluate(intent, undefined, {
        escalation: {
          mode: "MANAGED",
          verification_requirements: { methods },
        } as never,
      });
      expect(invalid.reasonCodes).toEqual(["MANAGED_ESCALATION_REQUEST_INVALID"]);
    }
    for (const roleId of ["treasury", "A", "APPROVER-ADMIN"]) {
      const invalid = await authority.evaluate(intent, undefined, {
        escalation: { mode: "MANAGED", approver: { role_id: roleId } },
      });
      expect(invalid.reasonCodes).toEqual(["MANAGED_ESCALATION_REQUEST_INVALID"]);
    }
    const emptyApprover = await authority.evaluate(intent, undefined, {
      escalation: { mode: "MANAGED", approver: {} },
    });
    expect(emptyApprover.reasonCodes).toEqual(["MANAGED_ESCALATION_REQUEST_INVALID"]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("resumes an idempotent enforce retry from a terminal Decionis summary", async () => {
    const intent = captured();
    const readySummary = authorityDecision(intent, {
      managed_escalation: managedWire(intent, { status: "GRANT_READY", outcome: "ALLOW" }),
    });
    const readyFetch = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(json(readySummary))
      .mockResolvedValueOnce(json(readyStatusBody(intent)));
    const readyAuthority = gate(readyFetch);

    const readyLocator = await readyAuthority.evaluate(intent, undefined, {
      escalation: { mode: "MANAGED" },
    });
    expect(readyLocator).toMatchObject({
      verdict: "ESCALATE",
      authorization: null,
      managedEscalation: { status: "GRANT_READY", outcome: "ALLOW" },
    });
    await expect(
      readyAuthority.waitForAuthorization(intent, readyLocator, {
        clock: () => FIXED_TIME,
        maxAttempts: 1,
      }),
    ).resolves.toMatchObject({
      verdict: "ALLOW",
      authorization: { token: "synthetic-managed-grant" },
    });

    const expiredSummary = authorityDecision(intent, {
      managed_escalation: managedWire(intent, {
        status: "EXPIRED",
        outcome: "BLOCK",
        reason_codes: ["INTENT_EXPIRED", "RECAPTURE_REQUIRED"],
      }),
    });
    const expiredFetch = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(json(expiredSummary))
      .mockResolvedValueOnce(
        json(
          statusBody(intent, "EXPIRED", {
            outcome: "BLOCK",
            reason_codes: ["INTENT_EXPIRED", "RECAPTURE_REQUIRED"],
          }),
        ),
      );
    const expiredAuthority = gate(expiredFetch);
    const expiredLocator = await expiredAuthority.evaluate(intent, undefined, {
      escalation: { mode: "MANAGED" },
    });
    await expect(
      expiredAuthority.waitForAuthorization(intent, expiredLocator, {
        clock: () => FIXED_TIME,
        maxAttempts: 1,
      }),
    ).resolves.toMatchObject({
      verdict: "BLOCK",
      authorization: null,
      reasonCodes: ["INTENT_EXPIRED", "RECAPTURE_REQUIRED"],
      managedEscalation: { status: "EXPIRED", outcome: "BLOCK" },
    });
  });

  it("keeps ALLOW and BLOCK responses backward compatible and requires managed state for ESCALATE", async () => {
    const intent = captured();
    const responses = [
      authorityDecision(intent, {
        status: "ALLOW",
        should_execute: true,
        reason_codes: ["POLICY_ALLOW"],
        execution_token: "synthetic-grant",
        execution_token_expires_at: new Date(FIXED_TIME + 60_000).toISOString(),
      }),
      authorityDecision(intent, { status: "BLOCK", reason_codes: ["POLICY_BLOCK"] }),
      authorityDecision(intent),
    ];
    const fetchMock = vi.fn<typeof fetch>(async () => json(responses.shift()));
    const authority = gate(fetchMock);
    const escalation = { escalation: { mode: "MANAGED" as const } };

    const allowed = await authority.evaluate(intent, undefined, escalation);
    expect(allowed).toMatchObject({ verdict: "ALLOW" });
    expect(allowed.managedEscalation).toBeUndefined();
    const blocked = await authority.evaluate(intent, undefined, escalation);
    expect(blocked).toMatchObject({ verdict: "BLOCK" });
    expect(blocked.managedEscalation).toBeUndefined();
    expect(await authority.evaluate(intent, undefined, escalation)).toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      reasonCodes: ["MANAGED_ESCALATION_MISSING"],
    });
  });

  it("accepts current execution metadata only when an ALLOW remains authoritative and eligible", async () => {
    const intent = captured();
    const metadata = {
      authority_classification: "AUTHORITATIVE",
      execution_eligible: true,
      execution_binding_digest: `sha256:${"b".repeat(64)}`,
      execution_token_jti: "synthetic-jti-managed-1",
      execution_token_key_id: "synthetic-key-managed-1",
    };
    const valid = readyStatusBody(intent);
    (valid.decision as Record<string, unknown>) = {
      ...(valid.decision as Record<string, unknown>),
      ...metadata,
    };
    const accepted = await gate(async () => json(valid)).waitForAuthorization(
      intent,
      pendingDecision(intent),
      { clock: () => FIXED_TIME, maxAttempts: 1 },
    );
    expect(accepted).toMatchObject({
      verdict: "ALLOW",
      authorization: { token: "synthetic-managed-grant" },
    });

    for (const invalidMetadata of [
      { authority_classification: "OBSERVATIONAL" },
      { execution_eligible: false },
      { execution_binding_digest: null },
      { execution_token_jti: null },
      { execution_token_key_id: null },
    ]) {
      const invalid = readyStatusBody(intent);
      (invalid.decision as Record<string, unknown>) = {
        ...(invalid.decision as Record<string, unknown>),
        ...metadata,
        ...invalidMetadata,
      };
      const refused = await gate(async () => json(invalid)).waitForAuthorization(
        intent,
        pendingDecision(intent),
        { clock: () => FIXED_TIME, maxAttempts: 1 },
      );
      expect(refused).toMatchObject({
        verdict: "BLOCK",
        authorization: null,
        failClosed: true,
        managedEscalation: { status: "FAILED", outcome: "ERROR" },
      });
    }
  });

  it("forbids managed escalation in shadow mode, with client evidence, or with pending grant material", async () => {
    const intent = captured();
    const fetchMock = vi.fn<typeof fetch>(async () =>
      json(
        authorityDecision(intent, {
          should_execute: true,
          execution_token: "forbidden-pending-grant",
          execution_token_expires_at: new Date(FIXED_TIME + 60_000).toISOString(),
          execution_binding_digest: `sha256:${"b".repeat(64)}`,
          managed_escalation: managedWire(intent),
        }),
      ),
    );
    const evidence: DecisionEvidence = {
      humanApproval: {
        provider: "presence",
        requestId: "synthetic-presence-request",
        receiptDossierId: "synthetic-presence-receipt",
      },
    };

    expect(
      await gate(fetchMock, "SHADOW").evaluate(intent, undefined, {
        escalation: { mode: "MANAGED" },
      }),
    ).toMatchObject({ reasonCodes: ["MANAGED_ESCALATION_SHADOW_FORBIDDEN"] });
    expect(
      await gate(fetchMock).evaluate(intent, evidence, { escalation: { mode: "MANAGED" } }),
    ).toMatchObject({ reasonCodes: ["MANAGED_ESCALATION_EVIDENCE_FORBIDDEN"] });
    expect(
      await gate(fetchMock).evaluate(intent, undefined, { escalation: { mode: "MANAGED" } }),
    ).toMatchObject({
      authorization: null,
      failClosed: true,
      reasonCodes: ["MANAGED_ESCALATION_PENDING_GRANT_FORBIDDEN"],
    });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("strictly binds one status lookup to escalation, intent, hash, and expiry", async () => {
    const intent = captured();
    const state = pendingDecision(intent).managedEscalation!;
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ escalation_id: "synthetic-escalation-other" }, "MANAGED_ESCALATION_ID_MISMATCH"],
      [{ intent_id: "synthetic-intent-other" }, "MANAGED_ESCALATION_INTENT_MISMATCH"],
      [{ action_hash: `sha256:${"0".repeat(64)}` }, "AUTHORITY_BINDING_MISMATCH"],
      [
        { expires_at: new Date(Date.parse(intent.intent.expiresAt) - 1_000).toISOString() },
        "MANAGED_ESCALATION_EXPIRY_MISMATCH",
      ],
    ];

    for (const [override, reason] of cases) {
      const authority = gate(async () =>
        json({ ...pendingStatusBody(intent, "AWAITING_APPROVER"), ...override }),
      );
      await expect(
        authority.getManagedEscalationStatus(intent, state, { clock: () => FIXED_TIME }),
      ).resolves.toMatchObject({
        status: "FAILED",
        outcome: "ERROR",
        decision: null,
        reasonCodes: [reason],
      });
    }
  });

  it("polls only Decionis with 500ms, 1s, 2s, 4s, then 5s capped jitter", async () => {
    const intent = captured();
    let now = FIXED_TIME;
    const replies = [
      pendingStatusBody(intent, "PENDING_PRESENCE"),
      pendingStatusBody(intent, "PRESENCE_REQUESTED"),
      pendingStatusBody(intent, "AWAITING_APPROVER"),
      pendingStatusBody(intent, "PRESENCE_VERIFIED"),
      pendingStatusBody(intent, "REAUTHORIZING"),
      readyStatusBody(intent),
    ];
    const fetchMock = vi.fn<typeof fetch>(async () => json(replies.shift()));
    const sleep = vi.fn(async (delayMs: number) => {
      now += delayMs;
    });

    const decision = await gate(fetchMock).waitForAuthorization(intent, pendingDecision(intent), {
      clock: () => now,
      sleep,
      random: () => 1,
    });

    expect(decision).toMatchObject({
      verdict: "ALLOW",
      failClosed: false,
      managedEscalation: { status: "GRANT_READY", outcome: "ALLOW" },
      authorization: { token: "synthetic-managed-grant" },
    });
    expect(decision.evidence).toBeUndefined();
    expect(sleep.mock.calls).toEqual([
      [500, undefined],
      [1_000, undefined],
      [2_000, undefined],
      [4_000, undefined],
      [5_000, undefined],
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(6);
    for (const [url, init] of fetchMock.mock.calls as [string, RequestInit][]) {
      expect(url).toBe("http://127.0.0.1:3001/v1/authority/escalations/synthetic-escalation-1");
      expect(init.method).toBe("GET");
      expect(init.body).toBeUndefined();
      expect(init.headers).toEqual({ authorization: "Bearer test-key" });
    }
  });

  it("uses binding expiry by default even at minimum jitter while retaining an explicit attempt cap", async () => {
    const intent = captured();
    const expiresAt = Date.parse(intent.intent.expiresAt);
    let now = FIXED_TIME;
    const fetchMock = vi.fn<typeof fetch>(async () =>
      json(pendingStatusBody(intent, "AWAITING_APPROVER")),
    );
    const sleep = vi.fn(async (delayMs: number) => {
      expect(now + delayMs).toBeLessThanOrEqual(expiresAt);
      now += delayMs;
    });

    const expired = await gate(fetchMock).waitForAuthorization(intent, pendingDecision(intent), {
      clock: () => now,
      sleep,
      random: () => 0,
    });

    expect(expired).toMatchObject({
      verdict: "BLOCK",
      authorization: null,
      reasonCodes: ["INTENT_EXPIRED", "RECAPTURE_REQUIRED"],
      managedEscalation: { status: "EXPIRED", outcome: "BLOCK" },
    });
    expect(expired.reasonCodes).not.toContain("MANAGED_ESCALATION_TIMEOUT");
    expect(now).toBe(expiresAt);
    expect(fetchMock.mock.calls.length).toBeGreaterThan(100);

    let cappedNow = FIXED_TIME;
    const cappedFetch = vi.fn<typeof fetch>(async () =>
      json(pendingStatusBody(intent, "AWAITING_APPROVER")),
    );
    const capped = await gate(cappedFetch).waitForAuthorization(intent, pendingDecision(intent), {
      clock: () => cappedNow,
      sleep: async (delayMs) => {
        cappedNow += delayMs;
      },
      random: () => 0,
      maxAttempts: 2,
    });

    expect(capped).toMatchObject({
      verdict: "BLOCK",
      authorization: null,
      reasonCodes: ["MANAGED_ESCALATION_TIMEOUT"],
      managedEscalation: { status: "FAILED", outcome: "ERROR" },
    });
    expect(cappedNow).toBeLessThan(expiresAt);
    expect(cappedFetch).toHaveBeenCalledTimes(2);
  });

  it("maps every server terminal state without manufacturing a grant", async () => {
    const intent = captured();
    const cases: Array<{
      status: "EXPIRED" | "REJECTED" | "BLOCKED" | "CANCELLED" | "FAILED";
      outcome: "BLOCK" | "ERROR";
      reason: string;
      failClosed: boolean;
    }> = [
      { status: "EXPIRED", outcome: "BLOCK", reason: "INTENT_EXPIRED", failClosed: false },
      { status: "REJECTED", outcome: "BLOCK", reason: "PRESENCE_REJECTED", failClosed: false },
      {
        status: "BLOCKED",
        outcome: "BLOCK",
        reason: "REAUTHORIZATION_BLOCKED",
        failClosed: false,
      },
      { status: "CANCELLED", outcome: "BLOCK", reason: "CANCELLED", failClosed: false },
      {
        status: "FAILED",
        outcome: "ERROR",
        reason: "PRESENCE_VERIFICATION_FAILED",
        failClosed: true,
      },
    ];

    for (const scenario of cases) {
      const fetchMock = vi.fn<typeof fetch>(async () =>
        json(
          statusBody(intent, scenario.status, {
            outcome: scenario.outcome,
            reason_codes: [scenario.reason],
          }),
        ),
      );
      const decision = await gate(fetchMock).waitForAuthorization(intent, pendingDecision(intent), {
        clock: () => FIXED_TIME,
        maxAttempts: 1,
      });
      expect(decision, scenario.status).toMatchObject({
        verdict: "BLOCK",
        authorization: null,
        failClosed: scenario.failClosed,
        reasonCodes: [scenario.reason],
        managedEscalation: { status: scenario.status, outcome: scenario.outcome },
      });
    }
  });

  it("does not revive an expired intent or accept approval that arrives at the deadline", async () => {
    const intent = captured();
    const escalation = pendingDecision(intent).managedEscalation!;
    const expiresAt = Date.parse(intent.intent.expiresAt);
    const unusedFetch = vi.fn<typeof fetch>();

    await expect(
      gate(unusedFetch).getManagedEscalationStatus(intent, escalation, { clock: () => expiresAt }),
    ).resolves.toMatchObject({
      status: "EXPIRED",
      outcome: "BLOCK",
      decision: null,
      reasonCodes: ["INTENT_EXPIRED", "RECAPTURE_REQUIRED"],
    });
    expect(unusedFetch).not.toHaveBeenCalled();

    let now = expiresAt - 1;
    const lateFetch = vi.fn<typeof fetch>(async () => {
      now = expiresAt;
      return json(readyStatusBody(intent));
    });
    const late = await gate(lateFetch).waitForAuthorization(intent, pendingDecision(intent), {
      clock: () => now,
      maxAttempts: 1,
    });
    expect(late).toMatchObject({
      verdict: "BLOCK",
      authorization: null,
      reasonCodes: ["INTENT_EXPIRED", "RECAPTURE_REQUIRED"],
      managedEscalation: { status: "EXPIRED" },
    });
  });

  it("rejects state regression, malformed status semantics, cancellation, and invalid polling controls", async () => {
    const intent = captured();
    const awaiting = pendingDecision(intent, { status: "AWAITING_APPROVER" });
    const regression = await gate(async () =>
      json(pendingStatusBody(intent, "PENDING_PRESENCE")),
    ).waitForAuthorization(intent, awaiting, { clock: () => FIXED_TIME, maxAttempts: 2 });
    expect(regression.reasonCodes).toEqual(["MANAGED_ESCALATION_STATE_REGRESSION"]);

    const malformed = await gate(async () =>
      json(statusBody(intent, "AWAITING_APPROVER", { outcome: "ALLOW" })),
    ).getManagedEscalationStatus(intent, pendingDecision(intent).managedEscalation!, {
      clock: () => FIXED_TIME,
    });
    expect(malformed).toMatchObject({
      status: "FAILED",
      reasonCodes: ["MANAGED_ESCALATION_RESPONSE_INVALID"],
    });

    const schemaInvalid = await gate(async () =>
      json({ ...pendingStatusBody(intent, "AWAITING_APPROVER"), invitation_token: "forbidden" }),
    ).getManagedEscalationStatus(intent, pendingDecision(intent).managedEscalation!, {
      clock: () => FIXED_TIME,
    });
    expect(schemaInvalid).toMatchObject({
      status: "FAILED",
      reasonCodes: ["MANAGED_ESCALATION_RESPONSE_INVALID"],
    });

    const controller = new AbortController();
    controller.abort();
    const aborted = await gate(vi.fn()).waitForAuthorization(intent, pendingDecision(intent), {
      signal: controller.signal,
    });
    expect(aborted.reasonCodes).toEqual(["MANAGED_ESCALATION_ABORTED"]);

    for (const options of [
      { maxAttempts: 0 },
      { initialDelayMs: 0 },
      { initialDelayMs: 10, maxDelayMs: 9 },
      { maxDelayMs: 5_001 },
      { random: "invalid" },
    ]) {
      const invalid = await gate(vi.fn()).waitForAuthorization(
        intent,
        pendingDecision(intent),
        options as never,
      );
      expect(invalid.reasonCodes).toEqual(["MANAGED_ESCALATION_POLLING_OPTIONS_INVALID"]);
    }
  });

  it("coalesces concurrent default waits for the same exact escalation", async () => {
    const intent = captured();
    const fetchMock = vi.fn<typeof fetch>(async () => json(readyStatusBody(intent)));
    const authority = gate(fetchMock);
    const pending = pendingDecision(intent);

    const decisions = await Promise.all(
      Array.from({ length: 20 }, async () => await authority.waitForAuthorization(intent, pending)),
    );

    expect(decisions.every((decision) => decision.verdict === "ALLOW")).toBe(true);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("rejects applying escalation A to a changed action or target before polling", async () => {
    const approved = captured("shopify:order:synthetic-3001", 50_000);
    const changedTarget = captured("shopify:order:synthetic-3002", 50_000);
    const changedAmount = captured("shopify:order:synthetic-3001", 50_001);
    const changedOperation = captured("shopify:order:synthetic-3001", 50_000, "capture_payment");
    const fetchMock = vi.fn<typeof fetch>();
    const authority = gate(fetchMock);
    const escalation = pendingDecision(approved).managedEscalation!;

    for (const changed of [changedTarget, changedAmount, changedOperation]) {
      const result = await authority.getManagedEscalationStatus(changed, escalation, {
        clock: () => FIXED_TIME,
      });
      expect(result).toMatchObject({
        status: "FAILED",
        outcome: "ERROR",
        decision: null,
        reasonCodes: ["MANAGED_ESCALATION_INTENT_MISMATCH"],
      } satisfies Partial<ManagedEscalationStatusResult>);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
