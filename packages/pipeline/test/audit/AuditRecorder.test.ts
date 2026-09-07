import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import {
  AuditPolicyRevisionVerifier,
  AuditRecorder,
  type AuditEventV1,
} from "../../src/audit/AuditRecorder.js";
import type { GateDecision } from "../../src/decision/DecisionAuthority.js";
import { ActionRegistry } from "../../src/execution/ActionRegistry.js";
import { SafeExecutor } from "../../src/execution/SafeExecutor.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

const fixedDate = new Date("2026-09-07T10:00:00.000Z");

function captured() {
  return new IntentCapture({
    clock: () => fixedDate,
    createId: () => "00000000-0000-4000-8000-000000000001",
  }).capture(
    {
      action: "refund_order",
      target: "shopify:order:1",
      parameters: { amount: 10, secret: "must-not-appear" },
    },
    {
      tenantId: "00000000-0000-4000-8000-000000000002",
      actor: { id: "synthetic-audit-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "shopify", operation: "refund" },
      correlationId: "correlation-1",
      idempotencyKey: "refund-audit-1",
      context: { credential: "must-not-appear" },
    },
  );
}

function decision(intentHash: string): GateDecision {
  return {
    verdict: "ALLOW",
    decisionId: "decision-1",
    dossierId: "dossier-1",
    intentHash,
    reasonCodes: ["POLICY_ALLOW"],
    authorization: { token: "must-not-appear", expiresAt: "2026-09-07T10:00:30.000Z" },
    failClosed: false,
  };
}

describe("AuditRecorder", () => {
  it("emits an immutable policy-pinned event without raw intent or authorization data", async () => {
    const events: AuditEventV1[] = [];
    const policy = {
      policyId: "refund-policy",
      revisionId: "revision-17",
      version: "2026.09",
      digest: `sha256:${"1".repeat(64)}` as const,
    };
    const recorder = new AuditRecorder({
      sink: {
        write: (event) => {
          events.push(event);
        },
      },
      clock: () => fixedDate,
      createId: () => "audit-event-1",
    });
    const intent = captured();

    await expect(
      recorder.record({
        eventType: "AUTHORITY_DECISION",
        captured: intent,
        decision: decision(intent.intentHash),
        evaluation: { policy },
      }),
    ).resolves.toBe(true);
    policy.revisionId = "revision-18";

    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      schemaVersion: "agent-safe.audit/1",
      authority: "AUTHORITATIVE",
      evaluation: {
        evaluationId: "decision-1",
        materialInputDigest: intent.intentHash,
        policy: { revisionId: "revision-17" },
        evidenceReference: "dossier-1",
      },
    });
    expect(Object.isFrozen(events[0])).toBe(true);
    expect(Object.isFrozen(events[0]?.evaluation?.policy)).toBe(true);
    const serialized = JSON.stringify(events[0]);
    expect(serialized).not.toContain("must-not-appear");
    expect(serialized).not.toContain("parameters");
    expect(serialized).not.toContain("shopify:order:1");
  });

  it("requires immutable policy revision identities", async () => {
    const sink = { write: vi.fn() };
    const recorder = new AuditRecorder({ sink });
    const intent = captured();

    await expect(
      recorder.record({
        eventType: "AUTHORITY_DECISION",
        captured: intent,
        decision: decision(intent.intentHash),
        evaluation: {
          policy: {
            policyId: "refund-policy",
            revisionId: "latest",
            digest: `sha256:${"1".repeat(64)}`,
          },
        },
      }),
    ).resolves.toBe(false);
    expect(sink.write).not.toHaveBeenCalled();
  });

  it("detects missing or mutated retained policy evidence and resolves replay by pinned revision", async () => {
    const events: AuditEventV1[] = [];
    const recorder = new AuditRecorder({
      sink: {
        write: (event) => {
          events.push(event);
        },
      },
    });
    const intent = captured();
    const firstPolicy = {
      policyId: "refund-policy",
      revisionId: "revision-17",
      digest: `sha256:${"1".repeat(64)}` as const,
    };
    const hotfixPolicy = {
      policyId: "refund-policy",
      revisionId: "revision-18",
      digest: `sha256:${"2".repeat(64)}` as const,
    };
    await recorder.record({
      eventType: "AUTHORITY_DECISION",
      captured: intent,
      decision: decision(intent.intentHash),
      evaluation: { policy: firstPolicy },
    });
    await recorder.record({
      eventType: "AUTHORITY_DECISION",
      captured: intent,
      decision: { ...decision(intent.intentHash), decisionId: "decision-2" },
      evaluation: { policy: hotfixPolicy },
    });

    expect(events[0]?.evaluation?.policy).not.toEqual(events[1]?.evaluation?.policy);
    expect(Reflect.set(events[0]?.evaluation?.policy ?? {}, "digest", hotfixPolicy.digest)).toBe(
      false,
    );

    const resolve = vi.fn(async (policyId: string, revisionId: string) => ({
      policyId,
      revisionId,
      digest: firstPolicy.digest,
      artifactReference: "archive-version-17",
    }));
    const verifier = new AuditPolicyRevisionVerifier({ resolve });
    await expect(verifier.verify(events[0]!)).resolves.toMatchObject({
      status: "VERIFIED",
      artifact: { revisionId: "revision-17" },
    });
    expect(resolve).toHaveBeenCalledWith("refund-policy", "revision-17");

    await expect(
      new AuditPolicyRevisionVerifier({ resolve: async () => null }).verify(events[0]!),
    ).resolves.toEqual({ status: "MISSING", artifact: null });
    await expect(
      new AuditPolicyRevisionVerifier({
        resolve: async () => ({
          ...firstPolicy,
          digest: hotfixPolicy.digest,
          artifactReference: "mutated-archive",
        }),
      }).verify(events[0]!),
    ).resolves.toEqual({ status: "DIGEST_MISMATCH", artifact: null });
  });

  it("allowlists, redacts, and bounds consumer metadata", async () => {
    const events: AuditEventV1[] = [];
    const recorder = new AuditRecorder({
      sink: {
        write: (event) => {
          events.push(event);
        },
      },
      metadataAllowlist: ["region", "note", "token"],
      redactMetadata: (key, value) => (key === "note" ? "[redacted]" : value),
    });
    const intent = captured();

    await expect(
      recorder.record({
        eventType: "INTENT_CAPTURED",
        captured: intent,
        metadata: {
          region: "eu-north-1",
          note: "sensitive support note",
          token: "forbidden-even-when-allowlisted",
          ignored: "not allowlisted",
        },
      }),
    ).resolves.toBe(true);
    expect(events[0]?.metadata).toEqual({ region: "eu-north-1", note: "[redacted]" });

    await expect(
      recorder.record({
        eventType: "INTENT_CAPTURED",
        captured: intent,
        metadata: { region: "x".repeat(501) },
      }),
    ).resolves.toBe(false);
    expect(events).toHaveLength(1);
  });

  it("bounds sink timeouts and exceptions without retrying", async () => {
    const stalled = vi.fn(async () => await new Promise<never>(() => undefined));
    const timeoutRecorder = new AuditRecorder({ sink: { write: stalled }, timeoutMs: 1 });
    await expect(
      timeoutRecorder.record({ eventType: "INTENT_CAPTURED", captured: captured() }),
    ).resolves.toBe(false);
    expect(stalled).toHaveBeenCalledTimes(1);

    const rejected = vi.fn(() => {
      throw new Error("sink secret");
    });
    const rejectionRecorder = new AuditRecorder({ sink: { write: rejected } });
    await expect(
      rejectionRecorder.record({ eventType: "INTENT_CAPTURED", captured: captured() }),
    ).resolves.toBe(false);
    expect(rejected).toHaveBeenCalledTimes(1);
  });

  it("rejects malformed bounded fields and metadata before calling the sink", async () => {
    expect(
      () =>
        new AuditRecorder({
          sink: { write: vi.fn() },
          metadataAllowlist: Array.from({ length: 51 }, (_, index) => `field-${index}`),
        }),
    ).toThrow("AUDIT_METADATA_ALLOWLIST_TOO_LARGE");

    const write = vi.fn();
    const recorder = new AuditRecorder({
      sink: { write },
      metadataAllowlist: ["value"],
    });
    const intent = captured();
    const tooDeep = { child: { child: { child: { child: { child: "x" } } } } };
    const cases = [
      { durationMs: -1 },
      { reasonCodes: Array.from({ length: 51 }, () => "REASON") },
      { authority: "INVALID" },
      { metadata: { value: Number.NaN } },
      { metadata: { value: Array.from({ length: 21 }, () => 1) } },
      { metadata: { value: tooDeep } },
      { metadata: { value: new Date() } },
    ];
    for (const candidate of cases) {
      await expect(
        recorder.record({
          eventType: "INTENT_CAPTURED",
          captured: intent,
          ...(candidate as unknown as {
            durationMs?: number;
            reasonCodes?: string[];
            authority?: "AUTHORITATIVE";
            metadata?: Record<string, never>;
          }),
        }),
      ).resolves.toBe(false);
    }
    expect(write).not.toHaveBeenCalled();
  });

  it("omits metadata when the redaction hook returns undefined", async () => {
    const events: AuditEventV1[] = [];
    const recorder = new AuditRecorder({
      sink: {
        write: (event) => {
          events.push(event);
        },
      },
      metadataAllowlist: ["region"],
      redactMetadata: () => undefined,
    });

    await recorder.record({
      eventType: "INTENT_CAPTURED",
      captured: captured(),
      metadata: { region: "eu-north-1" },
    });
    expect(events[0]?.metadata).toEqual({});
  });

  it("reports every retained-policy resolution failure without falling back to latest", async () => {
    const events: AuditEventV1[] = [];
    const recorder = new AuditRecorder({
      sink: {
        write: (event) => {
          events.push(event);
        },
      },
    });
    const intent = captured();
    await recorder.record({ eventType: "INTENT_CAPTURED", captured: intent });
    await recorder.record({
      eventType: "AUTHORITY_DECISION",
      captured: intent,
      decision: decision(intent.intentHash),
      evaluation: {
        policy: {
          policyId: "refund-policy",
          revisionId: "revision-17",
          digest: `sha256:${"1".repeat(64)}`,
        },
      },
    });

    await expect(
      new AuditPolicyRevisionVerifier({ resolve: async () => null }).verify(events[0]!),
    ).resolves.toEqual({ status: "NOT_REFERENCED", artifact: null });
    await expect(
      new AuditPolicyRevisionVerifier({
        resolve: async () => ({
          policyId: "refund-policy",
          revisionId: "revision-18",
          digest: `sha256:${"1".repeat(64)}`,
          artifactReference: "archive-version-18",
        }),
      }).verify(events[1]!),
    ).resolves.toEqual({ status: "IDENTITY_MISMATCH", artifact: null });
    await expect(
      new AuditPolicyRevisionVerifier({
        resolve: async () => {
          throw new Error("archive unavailable");
        },
      }).verify(events[1]!),
    ).resolves.toEqual({ status: "UNAVAILABLE", artifact: null });
    await expect(
      new AuditPolicyRevisionVerifier({
        resolve: async () => ({
          policyId: "refund-policy",
          revisionId: "revision-17",
          digest: `sha256:${"1".repeat(64)}`,
          artifactReference: "",
        }),
      }).verify(events[1]!),
    ).resolves.toEqual({ status: "UNAVAILABLE", artifact: null });
  });

  it("keeps a serialized shadow ALLOW observational and unusable as execution authority", async () => {
    const events: AuditEventV1[] = [];
    const recorder = new AuditRecorder({
      sink: {
        write: (event) => {
          events.push(event);
        },
      },
    });
    const intent = captured();
    await recorder.record({
      eventType: "AUTHORITY_DECISION",
      authority: "OBSERVATIONAL",
      captured: intent,
      decision: decision(intent.intentHash),
    });
    const persisted = JSON.parse(JSON.stringify(events[0])) as GateDecision;
    const execute = vi.fn();
    const registry = new ActionRegistry()
      .register("refund_order", {
        parametersSchema: z.object({
          amount: z.number(),
          secret: z.string(),
        }),
        execute,
      })
      .seal();
    const verifyAndConsume = vi.fn();

    expect(events[0]?.authority).toBe("OBSERVATIONAL");
    await expect(
      new SafeExecutor(registry, { verifyAndConsume }).run(intent, persisted),
    ).resolves.toMatchObject({
      outcome: "BLOCKED",
      reason: "INTENT_BINDING_MISMATCH",
    });
    expect(verifyAndConsume).not.toHaveBeenCalled();
    expect(execute).not.toHaveBeenCalled();
  });
});
