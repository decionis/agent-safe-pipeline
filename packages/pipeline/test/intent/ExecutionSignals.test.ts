import { describe, expect, it } from "vitest";
import {
  RESERVED_CONTEXT_BOUNDARY,
  RESERVED_CONTEXT_WORKLOAD,
  boundaryOf,
  signalContext,
  workloadOf,
  type EnforcementBoundarySignal,
  type WorkloadSignal,
} from "../../src/intent/ExecutionSignals.js";
import { CanonicalIntentHasher } from "../../src/intent/CanonicalIntentHasher.js";
import type { JsonValue } from "../../src/intent/JsonValue.js";
import { IntentCapture } from "../../src/intent/IntentCapture.js";

const BOUNDARY: EnforcementBoundarySignal = {
  boundary_id: "prod-payments-eu",
  agentsafe_version: "0.0.0-test",
  protocol_version: "agent-safe.intent/1",
  deployment_type: "docker",
  environment: "production",
  conformance_version: "agent-safe-intent-v1",
  placement: { cluster_id: "eu-1", namespace: "payments" },
};

const WORKLOAD: WorkloadSignal = {
  runtime: "docker",
  artifact_type: "oci",
  image: "ghcr.io/example/payments-agent:1.4.2",
  digest: `sha256:${"a".repeat(64)}`,
  provenance: { source: "docker", trust_level: "supplied" },
};

function capture(signals?: { boundary?: EnforcementBoundarySignal; workload?: WorkloadSignal }) {
  return new IntentCapture({ ttlSeconds: 120 }).capture(
    { action: "payment.send", target: "core:payment:1", parameters: { amount: 50_000 } },
    {
      tenantId: "00000000-0000-4000-8000-000000000003",
      actor: { id: "synthetic-treasury-agent", type: "AI_AGENT" },
      downstreamTarget: { system: "core", operation: "payment.send" },
      idempotencyKey: "payment-1",
      context: {},
      ...(signals === undefined ? {} : { signals }),
    },
  );
}

describe("execution signals", () => {
  it("contributes nothing for a signal that is absent", () => {
    expect(signalContext({})).toEqual({});
    expect(signalContext({ boundary: BOUNDARY })).toEqual({
      [RESERVED_CONTEXT_BOUNDARY]: BOUNDARY,
    });
    expect(signalContext({ workload: WORKLOAD })).toEqual({
      [RESERVED_CONTEXT_WORKLOAD]: WORKLOAD,
    });
    expect(signalContext({ boundary: BOUNDARY, workload: WORKLOAD })).toEqual({
      [RESERVED_CONTEXT_BOUNDARY]: BOUNDARY,
      [RESERVED_CONTEXT_WORKLOAD]: WORKLOAD,
    });
    // A workload nobody reported is an absent key, never a placeholder saying
    // there is none: a policy requiring provenance must refuse, not match.
    expect(Object.hasOwn(signalContext({ boundary: BOUNDARY }), RESERVED_CONTEXT_WORKLOAD)).toBe(
      false,
    );
  });

  it("refuses a signal the schema does not name", () => {
    expect(() =>
      signalContext({
        boundary: { ...BOUNDARY, tenant: "someone-else" } as unknown as EnforcementBoundarySignal,
      }),
    ).toThrow();
    expect(() =>
      signalContext({
        workload: {
          ...WORKLOAD,
          digest: "sha256:not-a-digest",
        } as unknown as WorkloadSignal,
      }),
    ).toThrow();
  });

  it("reads back only a signal that parses whole", () => {
    const bound = signalContext({ boundary: BOUNDARY, workload: WORKLOAD });
    expect(boundaryOf(bound)).toEqual(BOUNDARY);
    expect(workloadOf(bound)).toEqual(WORKLOAD);
    expect(boundaryOf({})).toBeNull();
    expect(workloadOf({})).toBeNull();
    // A context edited to resemble a boundary is no boundary at all.
    expect(
      boundaryOf({ [RESERVED_CONTEXT_BOUNDARY]: { boundary_id: "prod-payments-eu" } }),
    ).toBeNull();
    expect(workloadOf({ [RESERVED_CONTEXT_WORKLOAD]: { image: "x" } })).toBeNull();
    expect(boundaryOf({ [RESERVED_CONTEXT_BOUNDARY]: "prod-payments-eu" })).toBeNull();
  });
});

describe("signals on a captured intent", () => {
  it("binds every signal inside the canonical hash", () => {
    const withBoundary = capture({ boundary: BOUNDARY });
    const elsewhere = capture({
      boundary: { ...BOUNDARY, boundary_id: "staging-payments-us" },
    });

    expect(boundaryOf(withBoundary.intent.context)).toEqual(BOUNDARY);
    expect(withBoundary.canonicalIntent).toContain(RESERVED_CONTEXT_BOUNDARY);
    // One field of the boundary changed, so the authority would be issued
    // against different bytes: substitution cannot be silent.
    expect(elsewhere.intentHash).not.toBe(withBoundary.intentHash);
  });

  it("leaves an intent without signals hashing exactly as it did before", () => {
    const plain = capture();
    const binding = CanonicalIntentHasher.bindingOf(plain.intent);

    expect(Object.hasOwn(binding.context, RESERVED_CONTEXT_BOUNDARY)).toBe(false);
    expect(Object.hasOwn(binding.context, RESERVED_CONTEXT_WORKLOAD)).toBe(false);
    expect(plain.canonicalIntent).toBe(
      CanonicalIntentHasher.stringify(binding as unknown as JsonValue),
    );
  });

  it("refuses a caller that writes a reserved key by hand", () => {
    const capture = new IntentCapture({ ttlSeconds: 120 });
    for (const key of [RESERVED_CONTEXT_BOUNDARY, RESERVED_CONTEXT_WORKLOAD, "idempotency_key"]) {
      expect(() =>
        capture.capture(
          { action: "payment.send", target: "core:payment:1", parameters: {} },
          {
            tenantId: "00000000-0000-4000-8000-000000000003",
            actor: { id: "synthetic-treasury-agent", type: "AI_AGENT" },
            downstreamTarget: { system: "core", operation: "payment.send" },
            idempotencyKey: "payment-1",
            context: { [key]: "claimed-by-the-caller" },
          },
        ),
      ).toThrow("INTENT_CONTEXT_KEY_RESERVED");
    }
  });
});
