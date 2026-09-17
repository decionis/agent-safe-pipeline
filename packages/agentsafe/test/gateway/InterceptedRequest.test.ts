import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  bodyDigest,
  normalizeRequest,
  type InterceptedRequest,
} from "../../src/gateway/InterceptedRequest.js";

const options = { maxEmbeddedBodyBytes: 64, principalHeader: null };

function request(overrides: Partial<InterceptedRequest> = {}): InterceptedRequest {
  return {
    method: "post",
    path: "/payments",
    search: "",
    headers: { "content-type": "application/json" },
    body: Buffer.from('{"amount": 5, "to": "acct-1"}', "utf8"),
    remoteAddress: null,
    encrypted: false,
    ...overrides,
  };
}

describe("request normalization", () => {
  it("embeds a small JSON body so policy sees the fields, and binds the raw bytes by digest either way", () => {
    const normalized = normalizeRequest(request(), "payment.create", options);
    expect(normalized.proposal).toEqual({
      action: "payment.create",
      target: "POST /payments",
      parameters: {
        method: "POST",
        path: "/payments",
        query: {},
        body: { amount: 5, to: "acct-1" },
      },
    });
    expect(normalized.context).toEqual({
      body_sha256: `sha256:${createHash("sha256").update('{"amount": 5, "to": "acct-1"}').digest("hex")}`,
      body_bytes: 29,
      content_type: "application/json",
      body_embedded: true,
    });
    expect(normalized.idempotencyKey).toBeNull();
    expect(normalized.correlationId).toBeNull();
    expect(normalized.principal).toBeNull();
    expect(bodyDigest(Buffer.alloc(0))).toBe(
      `sha256:${createHash("sha256").update("").digest("hex")}`,
    );
  });

  it("keeps a body it cannot embed out of the parameters: too large, not JSON, or unreadable", () => {
    const large = normalizeRequest(
      request({ body: Buffer.from(JSON.stringify({ note: "x".repeat(100) })) }),
      "a",
      options,
    );
    expect(large.proposal.parameters["body"]).toBeUndefined();
    expect(large.context["body_embedded"]).toBe(false);
    const form = normalizeRequest(
      request({
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: Buffer.from("amount=5"),
      }),
      "a",
      options,
    );
    expect(form.proposal.parameters["body"]).toBeUndefined();
    expect(form.context["content_type"]).toBe("application/x-www-form-urlencoded");
    const broken = normalizeRequest(request({ body: Buffer.from("{oops") }), "a", options);
    expect(broken.context).toMatchObject({ body_embedded: false, body_bytes: 5 });
    const empty = normalizeRequest(request({ body: Buffer.alloc(0), headers: {} }), "a", options);
    expect(empty.context).toMatchObject({
      body_embedded: false,
      body_bytes: 0,
      content_type: null,
    });
    const vendor = normalizeRequest(
      request({ headers: { "content-type": "application/vnd.api+json; charset=utf-8" } }),
      "a",
      options,
    );
    expect(vendor.context["body_embedded"]).toBe(true);
  });

  it("carries the query as sorted keys, with a list where a key repeats", () => {
    const normalized = normalizeRequest(request({ search: "?z=1&a=2&a=3&empty=" }), "a", options);
    expect(normalized.proposal.parameters["query"]).toEqual({ a: ["2", "3"], empty: "", z: "1" });
  });

  it("takes the client's idempotency key, correlation id and claimed principal from bounded headers", () => {
    const normalized = normalizeRequest(
      request({
        headers: {
          "content-type": "application/json",
          "idempotency-key": " pay-7 ",
          "x-request-id": "req-1",
          "x-agent-id": "synthetic-agent",
        },
      }),
      "a",
      { ...options, principalHeader: "x-agent-id" },
    );
    expect(normalized.idempotencyKey).toBe("pay-7");
    expect(normalized.correlationId).toBe("req-1");
    expect(normalized.principal).toBe("synthetic-agent");
    const preferred = normalizeRequest(
      request({ headers: { "x-correlation-id": "corr", "x-request-id": "req" } }),
      "a",
      options,
    );
    expect(preferred.correlationId).toBe("corr");
    const over = normalizeRequest(
      request({ headers: { "idempotency-key": "k".repeat(181), "x-request-id": "" } }),
      "a",
      options,
    );
    expect(over.idempotencyKey).toBeNull();
    expect(over.correlationId).toBeNull();
  });

  it("refuses a target the intent contract cannot carry", () => {
    expect(() => normalizeRequest(request({ path: `/${"p".repeat(500)}` }), "a", options)).toThrow(
      "TARGET_TOO_LONG",
    );
  });
});
