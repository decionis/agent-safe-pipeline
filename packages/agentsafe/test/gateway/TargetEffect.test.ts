import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Rfc8785, type TargetPrecondition } from "@decionis/agent-safe-pipeline";
import {
  effectDigest,
  effectRecord,
  expectEffect,
  GATEWAY_EFFECT_PROFILE,
  refusalOutcome,
} from "../../src/gateway/TargetEffect.js";

const OPERATION = "example/api/v1#items.update";
const sha256 = (text: string): string =>
  `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;

describe("the effect digest", () => {
  it("is SHA-256 over the RFC 8785 form of the operation and the projection", () => {
    expect(effectDigest(OPERATION, { "/body/status": "retired", "/body/sku": 7 })).toBe(
      sha256(
        '{"effect":{"/body/sku":7,"/body/status":"retired"},"operation":"example/api/v1#items.update"}',
      ),
    );
  });

  it("tells projections and operations apart, and has one digest for a lone surrogate", () => {
    const base = effectDigest(OPERATION, { "/body/status": "retired" });
    expect(effectDigest(OPERATION, { "/body/status": "active" })).not.toBe(base);
    expect(effectDigest("example/api/v1#items.create", { "/body/status": "retired" })).not.toBe(
      base,
    );
    const lone = { "/body/name": "\ud800" };
    expect(effectDigest(OPERATION, lone)).toBe(
      sha256(Rfc8785.stringify({ effect: lone, operation: OPERATION })),
    );
  });
});

describe("what a call lets the grant commit to", () => {
  it("is nothing when the operation names no effect, under facts-only privacy, or when the call states none", () => {
    expect(expectEffect(OPERATION, null, false)).toBe("EFFECT_UNDECLARED");
    expect(expectEffect(OPERATION, null, true)).toBe("EFFECT_UNDECLARED");
    expect(expectEffect(OPERATION, { "/body/status": "retired" }, true)).toBe("EFFECT_NOT_BOUND");
    expect(expectEffect(OPERATION, {}, false)).toBe("EFFECT_UNSTATED");
  });

  it("is the expectation and its digest otherwise", () => {
    const expected = { "/body/status": "retired" };
    expect(expectEffect(OPERATION, expected, false)).toEqual({
      expected,
      digest: effectDigest(OPERATION, expected),
    });
  });
});

describe("the record of a read after a write", () => {
  const expected = { "/body/status": "retired", "/body/price": 12 };
  const effect = { expected, digest: effectDigest(OPERATION, expected) };
  const observedAt = "2026-10-31T12:00:00.000Z";

  it("confirms a read that states what the call asked, and carries no value", () => {
    const { record, statement } = effectRecord({
      operation: OPERATION,
      effect,
      observed: { "/body/status": "retired", "/body/price": 12 },
      observedAt,
    });
    const evidence = {
      profile: GATEWAY_EFFECT_PROFILE,
      type: "EFFECT_EVIDENCE",
      operation: OPERATION,
      observation_method: "READ_AFTER_WRITE",
      expected_effect_digest: effect.digest,
      observed_effect_digest: effect.digest,
      comparison: "MATCH",
      mismatched_fields: [],
      confirmation: { status: "CONFIRMED" },
      evidence_status: "COMPLETE",
      observed_at: observedAt,
    };
    expect(GATEWAY_EFFECT_PROFILE).toBe("agent-safe.gateway-effect/1");
    expect(record).toEqual({
      evidence,
      outcome: "COMMITTED",
      comparison: "MATCH",
      mismatched: [],
      confirmation: "CONFIRMED",
      observedEffectDigest: effect.digest,
      expectedEffectDigest: effect.digest,
      responseDigest: null,
      providerReference: null,
      observationMethod: "READ_AFTER_WRITE",
      evidenceDigest: sha256(Rfc8785.stringify(evidence)),
      reasonCodes: [],
      receipt: { comparison: "ABSENT", status: null, digest: null },
    });
    expect(statement).toEqual({ confirmation: "CONFIRMED", reasonCodes: [] });
    expect(JSON.stringify(record)).not.toContain("retired");
  });

  it("calls a difference UNKNOWN with EFFECT_MISMATCH, naming the pointers and the observed digest", () => {
    const observed = { "/body/status": "active" };
    const { record, statement } = effectRecord({
      operation: OPERATION,
      effect,
      observed,
      observedAt,
    });
    expect(record).toMatchObject({
      comparison: "MISMATCH",
      mismatched: ["/body/status", "/body/price"],
      confirmation: "UNKNOWN",
      observedEffectDigest: effectDigest(OPERATION, observed),
      reasonCodes: ["EFFECT_MISMATCH"],
      evidence: {
        comparison: "MISMATCH",
        mismatched_fields: ["/body/status", "/body/price"],
        confirmation: { status: "UNKNOWN" },
        evidence_status: "COMPLETE",
      },
    });
    expect(statement).toEqual({ confirmation: "UNKNOWN", reasonCodes: ["EFFECT_MISMATCH"] });
  });

  it("leaves a read that did not answer PENDING, with no observed digest", () => {
    const { record, statement } = effectRecord({
      operation: OPERATION,
      effect,
      observed: null,
      observedAt,
    });
    expect(record).toMatchObject({
      comparison: "PENDING",
      mismatched: [],
      confirmation: "PENDING",
      observedEffectDigest: null,
      reasonCodes: ["EFFECT_UNREADABLE"],
      evidence: {
        observed_effect_digest: null,
        comparison: "PENDING",
        confirmation: { status: "PENDING" },
        evidence_status: "INCOMPLETE",
      },
    });
    expect(statement).toEqual({ confirmation: "PENDING", reasonCodes: ["EFFECT_UNREADABLE"] });
  });
});

describe("a read after a refusal", () => {
  const before: TargetPrecondition = {
    version: 'W/"4"',
    source: "example/api/v1#items.get",
    read_at: "2026-10-31T12:00:00.000Z",
  };

  it("is unchanged at the same version, changed at another, and unreadable without one", () => {
    expect(refusalOutcome(before, { ...before, read_at: "2026-10-31T12:00:01.000Z" })).toBe(
      "UNCHANGED",
    );
    expect(refusalOutcome(before, { ...before, version: 'W/"5"' })).toBe("CHANGED");
    expect(refusalOutcome(before, null)).toBe("UNREADABLE");
  });
});
