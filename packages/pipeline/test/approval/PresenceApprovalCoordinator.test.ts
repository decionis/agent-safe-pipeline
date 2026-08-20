import { describe, expect, it, vi } from "vitest";
import {
  PresenceApprovalCoordinator,
  type PresenceApprovalClient,
} from "../../src/approval/PresenceApprovalCoordinator.js";
import type { DecisionAuthority } from "../../src/decision/DecisionAuthority.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

const FIXED_TIME = Date.parse("2026-08-21T10:00:00.000Z");

function captured(clock?: () => number, ttlSeconds = 60) {
  return new IntentCapture({
    ...(clock === undefined ? {} : { clock: () => new Date(clock()) }),
    ttlSeconds,
  }).capture(
    { action: "refund_order", target: "shopify:order:1", parameters: { amount: 350 } },
    {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: { id: "synthetic-refund-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "shopify", operation: "refund" },
      idempotencyKey: "refund-1",
      context: {},
    },
  );
}

describe("PresenceApprovalCoordinator", () => {
  it("polls pending outcomes and requires Decionis re-authorization of the terminal receipt", async () => {
    let now = FIXED_TIME;
    const intent = captured(() => now);
    const gate = vi.fn(
      async (request: Parameters<PresenceApprovalClient["gate"]>[0], idempotencyKey: string) => {
        void request;
        void idempotencyKey;
        return {
          verdict: "HUMAN_REQUIRED" as const,
          request_id: "synthetic-presence-request-1",
          approval_url: "https://presence.example/approve",
        };
      },
    );
    const outcome = vi
      .fn()
      .mockResolvedValueOnce({
        verdict: "HUMAN_REQUIRED" as const,
        request_id: "synthetic-presence-request-1",
      })
      .mockResolvedValueOnce({
        verdict: "HUMAN_REQUIRED" as const,
        request_id: "synthetic-presence-request-1",
      })
      .mockResolvedValueOnce({
        verdict: "PROCEED" as const,
        request_id: "synthetic-presence-request-1",
        receipt_dossier_id: "synthetic-presence-dossier-1",
      });
    const evaluate = vi.fn(async () => ({
      verdict: "ALLOW" as const,
      decisionId: "decionis-2",
      dossierId: "dossier-2",
      intentHash: intent.intentHash,
      reasonCodes: [],
      authorization: { token: "token", expiresAt: "2026-08-21T10:00:30.000Z" },
      failClosed: false,
    }));
    const sleep = vi.fn(async (delayMs: number) => {
      now += delayMs;
    });
    const coordinator = new PresenceApprovalCoordinator(
      { gate, outcome },
      { evaluate } as DecisionAuthority,
      "Acme",
      "synthetic-approver-1",
      {
        maxAttempts: 5,
        initialDelayMs: 100,
        maxDelayMs: 200,
        deadlineMs: 5_000,
        clock: () => now,
        sleep,
        random: () => 0,
      },
    );

    const handoff = await coordinator.request(intent);
    const decision = await coordinator.resolveAndReauthorize(intent, handoff);

    expect(decision.verdict).toBe("ALLOW");
    expect(JSON.stringify(gate.mock.calls[0]?.[0])).toContain(intent.intentHash);
    expect(outcome).toHaveBeenCalledTimes(3);
    expect(sleep.mock.calls).toEqual([
      [50, undefined],
      [100, undefined],
    ]);
    expect(evaluate).toHaveBeenCalledTimes(1);
    expect(evaluate).toHaveBeenCalledWith(intent, {
      humanApproval: {
        provider: "presence",
        requestId: "synthetic-presence-request-1",
        receiptDossierId: "synthetic-presence-dossier-1",
      },
    });
  });

  it("fails closed when the attempt limit is exhausted", async () => {
    let now = FIXED_TIME;
    const intent = captured(() => now);
    const evaluate = vi.fn();
    const outcome = vi.fn(async () => ({
      verdict: "HUMAN_REQUIRED" as const,
      request_id: "synthetic-presence-request-1",
    }));
    const coordinator = new PresenceApprovalCoordinator(
      { gate: vi.fn(), outcome },
      { evaluate },
      "Acme",
      "synthetic-approver-1",
      {
        maxAttempts: 3,
        initialDelayMs: 100,
        maxDelayMs: 200,
        clock: () => now,
        sleep: async (delayMs) => {
          now += delayMs;
        },
        random: () => 0,
      },
    );

    await expect(
      coordinator.resolveAndReauthorize(intent, {
        verdict: "HUMAN_REQUIRED",
        request_id: "synthetic-presence-request-1",
      }),
    ).resolves.toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      reasonCodes: ["PRESENCE_TIMEOUT"],
    });
    expect(outcome).toHaveBeenCalledTimes(3);
    expect(evaluate).not.toHaveBeenCalled();
  });

  it("caps backoff at the configured deadline", async () => {
    let now = FIXED_TIME;
    const intent = captured(() => now);
    const sleep = vi.fn(async (delayMs: number) => {
      now += delayMs;
    });
    const outcome = vi.fn(async () => ({
      verdict: "HUMAN_REQUIRED" as const,
      request_id: "synthetic-presence-request-1",
    }));
    const coordinator = new PresenceApprovalCoordinator(
      { gate: vi.fn(), outcome },
      { evaluate: vi.fn() },
      "Acme",
      "synthetic-approver-1",
      {
        maxAttempts: 10,
        initialDelayMs: 500,
        maxDelayMs: 500,
        deadlineMs: 600,
        clock: () => now,
        sleep,
        random: () => 1,
      },
    );

    await expect(
      coordinator.resolveAndReauthorize(intent, {
        verdict: "HUMAN_REQUIRED",
        request_id: "synthetic-presence-request-1",
      }),
    ).resolves.toMatchObject({ reasonCodes: ["PRESENCE_TIMEOUT"], failClosed: true });
    expect(sleep.mock.calls).toEqual([
      [500, undefined],
      [100, undefined],
    ]);
    expect(outcome).toHaveBeenCalledTimes(2);
  });

  it("bounds an unresponsive Presence outcome lookup", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(FIXED_TIME);
    try {
      const intent = captured(() => Date.now());
      const evaluate = vi.fn();
      const outcome = vi.fn(async () => await new Promise<never>(() => undefined));
      const coordinator = new PresenceApprovalCoordinator(
        { gate: vi.fn(), outcome },
        { evaluate },
        "Acme",
        "synthetic-approver-1",
        { deadlineMs: 1_000 },
      );

      const pending = coordinator.resolveAndReauthorize(intent, {
        verdict: "HUMAN_REQUIRED",
        request_id: "synthetic-presence-request-1",
      });
      await vi.advanceTimersByTimeAsync(1_000);

      await expect(pending).resolves.toMatchObject({
        verdict: "BLOCK",
        failClosed: true,
        reasonCodes: ["PRESENCE_TIMEOUT"],
      });
      expect(outcome).toHaveBeenCalledTimes(1);
      expect(evaluate).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("never polls or authorizes beyond the captured intent expiry", async () => {
    let now = FIXED_TIME;
    const intent = captured(() => now, 1);
    const evaluate = vi.fn();
    const outcome = vi.fn(async () => ({
      verdict: "HUMAN_REQUIRED" as const,
      request_id: "synthetic-presence-request-1",
    }));
    const coordinator = new PresenceApprovalCoordinator(
      { gate: vi.fn(), outcome },
      { evaluate },
      "Acme",
      "synthetic-approver-1",
      {
        maxAttempts: 10,
        initialDelayMs: 1_500,
        maxDelayMs: 1_500,
        deadlineMs: 10_000,
        clock: () => now,
        sleep: async (delayMs) => {
          now += delayMs;
        },
        random: () => 1,
      },
    );

    await expect(
      coordinator.resolveAndReauthorize(intent, {
        verdict: "HUMAN_REQUIRED",
        request_id: "synthetic-presence-request-1",
      }),
    ).resolves.toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      reasonCodes: ["PRESENCE_INTENT_EXPIRED"],
    });
    expect(outcome).toHaveBeenCalledTimes(1);
    expect(evaluate).not.toHaveBeenCalled();
  });

  it("stops immediately when the caller aborts an in-flight outcome lookup", async () => {
    const intent = captured();
    const controller = new AbortController();
    const evaluate = vi.fn();
    const outcome = vi.fn(async () => await new Promise<never>(() => undefined));
    const coordinator = new PresenceApprovalCoordinator(
      { gate: vi.fn(), outcome },
      { evaluate },
      "Acme",
      "synthetic-approver-1",
    );

    const pending = coordinator.resolveAndReauthorize(
      intent,
      { verdict: "HUMAN_REQUIRED", request_id: "synthetic-presence-request-1" },
      { signal: controller.signal },
    );
    controller.abort();

    await expect(pending).resolves.toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      reasonCodes: ["PRESENCE_ABORTED"],
    });
    expect(outcome).toHaveBeenCalledTimes(1);
    expect(evaluate).not.toHaveBeenCalled();
  });

  it("fails closed when the injected backoff sleeper fails", async () => {
    const intent = captured();
    const evaluate = vi.fn();
    const coordinator = new PresenceApprovalCoordinator(
      {
        gate: vi.fn(),
        outcome: vi.fn(async () => ({
          verdict: "HUMAN_REQUIRED" as const,
          request_id: "synthetic-presence-request-1",
        })),
      },
      { evaluate },
      "Acme",
      "synthetic-approver-1",
      {
        sleep: async () => {
          throw new Error("raw sleeper response");
        },
        random: () => 0,
      },
    );

    await expect(
      coordinator.resolveAndReauthorize(intent, {
        verdict: "HUMAN_REQUIRED",
        request_id: "synthetic-presence-request-1",
      }),
    ).resolves.toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      reasonCodes: ["PRESENCE_UNAVAILABLE"],
    });
    expect(evaluate).not.toHaveBeenCalled();
  });

  it("cancels even when an injected backoff sleeper ignores the signal", async () => {
    const intent = captured();
    const controller = new AbortController();
    const evaluate = vi.fn();
    const sleep = vi.fn(async () => await new Promise<never>(() => undefined));
    const coordinator = new PresenceApprovalCoordinator(
      {
        gate: vi.fn(),
        outcome: vi.fn(async () => ({
          verdict: "HUMAN_REQUIRED" as const,
          request_id: "synthetic-presence-request-1",
        })),
      },
      { evaluate },
      "Acme",
      "synthetic-approver-1",
      { sleep, random: () => 0 },
    );

    const pending = coordinator.resolveAndReauthorize(
      intent,
      { verdict: "HUMAN_REQUIRED", request_id: "synthetic-presence-request-1" },
      { signal: controller.signal },
    );
    await vi.waitFor(() => expect(sleep).toHaveBeenCalledTimes(1));
    controller.abort();

    await expect(pending).resolves.toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      reasonCodes: ["PRESENCE_ABORTED"],
    });
    expect(evaluate).not.toHaveBeenCalled();
  });

  it("uses the default bounded backoff sleeper between pending outcomes", async () => {
    const intent = captured();
    const outcome = vi
      .fn()
      .mockResolvedValueOnce({
        verdict: "HUMAN_REQUIRED" as const,
        request_id: "synthetic-presence-request-1",
      })
      .mockResolvedValueOnce({
        verdict: "PROCEED" as const,
        request_id: "synthetic-presence-request-1",
        receipt_dossier_id: "synthetic-presence-dossier-1",
      });
    const evaluate = vi.fn(async () => ({
      verdict: "BLOCK" as const,
      decisionId: "decionis-policy-block",
      dossierId: "dossier-policy-block",
      intentHash: intent.intentHash,
      reasonCodes: ["POLICY_BLOCK"],
      authorization: null,
      failClosed: false,
    }));
    const coordinator = new PresenceApprovalCoordinator(
      { gate: vi.fn(), outcome },
      { evaluate },
      "Acme",
      "synthetic-approver-1",
      {
        maxAttempts: 2,
        initialDelayMs: 1,
        maxDelayMs: 1,
        random: () => 0,
      },
    );

    await expect(
      coordinator.resolveAndReauthorize(intent, {
        verdict: "HUMAN_REQUIRED",
        request_id: "synthetic-presence-request-1",
      }),
    ).resolves.toMatchObject({ verdict: "BLOCK", failClosed: false });
    expect(outcome).toHaveBeenCalledTimes(2);
    expect(evaluate).toHaveBeenCalledTimes(1);
  });

  it("discards an authority response received after intent expiry", async () => {
    let now = FIXED_TIME;
    const intent = captured(() => now, 1);
    const evaluate = vi.fn(async () => {
      now += 1_000;
      return {
        verdict: "ALLOW" as const,
        decisionId: "decionis-too-late",
        dossierId: "dossier-too-late",
        intentHash: intent.intentHash,
        reasonCodes: [],
        authorization: { token: "stale-token", expiresAt: "2026-08-21T10:00:30.000Z" },
        failClosed: false,
      };
    });
    const coordinator = new PresenceApprovalCoordinator(
      { gate: vi.fn(), outcome: vi.fn() },
      { evaluate },
      "Acme",
      "synthetic-approver-1",
      { clock: () => now },
    );

    await expect(
      coordinator.resolveAndReauthorize(intent, {
        verdict: "PROCEED",
        request_id: "synthetic-presence-request-1",
        receipt_dossier_id: "synthetic-presence-dossier-1",
      }),
    ).resolves.toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      reasonCodes: ["PRESENCE_INTENT_EXPIRED"],
    });
    expect(evaluate).toHaveBeenCalledTimes(1);
  });

  it("stops immediately when the caller aborts in-flight re-authorization", async () => {
    const intent = captured();
    const controller = new AbortController();
    const evaluate = vi.fn(async () => await new Promise<never>(() => undefined));
    const coordinator = new PresenceApprovalCoordinator(
      { gate: vi.fn(), outcome: vi.fn() },
      { evaluate },
      "Acme",
      "synthetic-approver-1",
    );

    const pending = coordinator.resolveAndReauthorize(
      intent,
      {
        verdict: "PROCEED",
        request_id: "synthetic-presence-request-1",
        receipt_dossier_id: "synthetic-presence-dossier-1",
      },
      { signal: controller.signal },
    );
    await vi.waitFor(() => expect(evaluate).toHaveBeenCalledTimes(1));
    controller.abort();

    await expect(pending).resolves.toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      reasonCodes: ["PRESENCE_ABORTED"],
    });
    expect(evaluate).toHaveBeenCalledTimes(1);
  });

  it("fails closed when Presence denies or returns no independently verifiable proof", async () => {
    const intent = captured();
    const evaluate = vi.fn();
    const denied = new PresenceApprovalCoordinator(
      {
        gate: async () => ({ verdict: "DENIED" }),
        outcome: async () => ({ verdict: "DENIED" }),
      },
      { evaluate } as DecisionAuthority,
      "Acme",
      "synthetic-approver-1",
    );
    expect(await denied.resolveAndReauthorize(intent, { verdict: "DENIED" })).toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
    });

    expect(await denied.resolveAndReauthorize(intent, { verdict: "PROCEED" })).toMatchObject({
      verdict: "BLOCK",
      reasonCodes: ["PRESENCE_PROOF_MISSING"],
    });
    expect(evaluate).not.toHaveBeenCalled();
  });

  it("rejects proof-only approval evidence because the authority requires a receipt", async () => {
    const intent = captured();
    const evaluate = vi.fn(async () => ({
      verdict: "BLOCK" as const,
      decisionId: "decionis-3",
      dossierId: "dossier-3",
      intentHash: intent.intentHash,
      reasonCodes: ["POLICY_BLOCK"],
      authorization: null,
      failClosed: false,
    }));
    const coordinator = new PresenceApprovalCoordinator(
      { gate: vi.fn(), outcome: vi.fn() },
      { evaluate } as DecisionAuthority,
      "Acme",
      "synthetic-approver-1",
    );
    const result = await coordinator.resolveAndReauthorize(intent, {
      verdict: "PROCEED",
      decision_id: "presence-decision-1",
      proof: "signed-presence-proof",
    });

    expect(result).toMatchObject({
      verdict: "BLOCK",
      failClosed: true,
      reasonCodes: ["PRESENCE_PROOF_MISSING"],
    });
    expect(evaluate).not.toHaveBeenCalled();
  });

  it("uses stable fail-closed outcomes for Presence and authority failures", async () => {
    const intent = captured();
    const requestFailure = new PresenceApprovalCoordinator(
      {
        gate: async () => {
          throw new Error("raw Presence response");
        },
        outcome: vi.fn(),
      },
      { evaluate: vi.fn() },
      "Acme",
      "synthetic-approver-1",
    );
    await expect(requestFailure.request(intent)).rejects.toThrow("PRESENCE_REQUEST_FAILED");
    const invalidRequest = new PresenceApprovalCoordinator(
      { gate: async () => ({ verdict: "BYPASS" }) as never, outcome: vi.fn() },
      { evaluate: vi.fn() },
      "Acme",
      "synthetic-approver-1",
    );
    await expect(invalidRequest.request(intent)).rejects.toThrow("PRESENCE_REQUEST_FAILED");
    const malformedHandoff = new PresenceApprovalCoordinator(
      { gate: async () => ({ verdict: "HUMAN_REQUIRED" }), outcome: vi.fn() },
      { evaluate: vi.fn() },
      "Acme",
      "synthetic-approver-1",
    );
    await expect(malformedHandoff.request(intent)).rejects.toThrow("PRESENCE_REQUEST_FAILED");

    const outcomeFailure = new PresenceApprovalCoordinator(
      {
        gate: vi.fn(),
        outcome: async () => {
          throw new Error("raw Presence response");
        },
      },
      { evaluate: vi.fn() },
      "Acme",
      "synthetic-approver-1",
    );
    await expect(
      outcomeFailure.resolveAndReauthorize(intent, {
        verdict: "HUMAN_REQUIRED",
        request_id: "synthetic-presence-request-1",
      }),
    ).resolves.toMatchObject({ reasonCodes: ["PRESENCE_UNAVAILABLE"], failClosed: true });

    const authorityFailure = new PresenceApprovalCoordinator(
      { gate: vi.fn(), outcome: vi.fn() },
      {
        evaluate: async () => {
          throw new Error("raw authority response");
        },
      },
      "Acme",
      "synthetic-approver-1",
    );
    await expect(
      authorityFailure.resolveAndReauthorize(intent, {
        verdict: "PROCEED",
        request_id: "synthetic-presence-request-1",
        receipt_dossier_id: "synthetic-presence-dossier-1",
      }),
    ).resolves.toMatchObject({ reasonCodes: ["AUTHORITY_UNAVAILABLE"], failClosed: true });
  });

  it("rejects unknown verdicts, changed request binding, and unbounded receipt identifiers", async () => {
    const intent = captured();
    const evaluate = vi.fn();
    const coordinator = new PresenceApprovalCoordinator(
      {
        gate: vi.fn(),
        outcome: vi.fn(async () => ({
          verdict: "PROCEED" as const,
          request_id: "synthetic-different-presence-request",
          receipt_dossier_id: "synthetic-presence-dossier-1",
        })),
      },
      { evaluate },
      "Acme",
      "synthetic-approver-1",
    );

    await expect(
      coordinator.resolveAndReauthorize(intent, { verdict: "BYPASS" } as never),
    ).resolves.toMatchObject({ reasonCodes: ["PRESENCE_RESPONSE_INVALID"] });
    await expect(
      coordinator.resolveAndReauthorize(intent, {
        verdict: "HUMAN_REQUIRED",
        request_id: "synthetic-presence-request-1",
      }),
    ).resolves.toMatchObject({ reasonCodes: ["PRESENCE_RESPONSE_INVALID"] });
    await expect(
      coordinator.resolveAndReauthorize(intent, {
        verdict: "PROCEED",
        request_id: "synthetic-r".repeat(21),
        receipt_dossier_id: "synthetic-presence-dossier-1",
      }),
    ).resolves.toMatchObject({ reasonCodes: ["PRESENCE_PROOF_MISSING"] });
    expect(evaluate).not.toHaveBeenCalled();
  });

  it("rejects polling settings that do not preserve bounded behavior", () => {
    expect(
      () =>
        new PresenceApprovalCoordinator(
          { gate: vi.fn(), outcome: vi.fn() },
          { evaluate: vi.fn() },
          "Acme",
          "synthetic-approver-1",
          { maxAttempts: 0 },
        ),
    ).toThrow("PRESENCE_POLLING_OPTIONS_INVALID");
    expect(
      () =>
        new PresenceApprovalCoordinator(
          { gate: vi.fn(), outcome: vi.fn() },
          { evaluate: vi.fn() },
          "Acme",
          "synthetic-approver-1",
          { initialDelayMs: 2_000, maxDelayMs: 1_000 },
        ),
    ).toThrow("PRESENCE_POLLING_OPTIONS_INVALID");
  });

  it("fails closed when injected scheduling controls return invalid values", async () => {
    const intent = captured();
    const evaluate = vi.fn();
    const invalidClock = new PresenceApprovalCoordinator(
      { gate: vi.fn(), outcome: vi.fn() },
      { evaluate },
      "Acme",
      "synthetic-approver-1",
      { clock: () => Number.NaN },
    );
    await expect(
      invalidClock.resolveAndReauthorize(intent, {
        verdict: "PROCEED",
        request_id: "synthetic-presence-request-1",
        receipt_dossier_id: "synthetic-presence-dossier-1",
      }),
    ).resolves.toMatchObject({ reasonCodes: ["PRESENCE_CLOCK_INVALID"], failClosed: true });

    const invalidRandom = new PresenceApprovalCoordinator(
      {
        gate: vi.fn(),
        outcome: vi.fn(async () => ({
          verdict: "HUMAN_REQUIRED" as const,
          request_id: "synthetic-presence-request-1",
        })),
      },
      { evaluate },
      "Acme",
      "synthetic-approver-1",
      {
        random: () => {
          throw new Error("invalid random source");
        },
      },
    );
    await expect(
      invalidRandom.resolveAndReauthorize(intent, {
        verdict: "HUMAN_REQUIRED",
        request_id: "synthetic-presence-request-1",
      }),
    ).resolves.toMatchObject({
      reasonCodes: ["PRESENCE_POLLING_RANDOM_INVALID"],
      failClosed: true,
    });
    expect(evaluate).not.toHaveBeenCalled();
  });
});
