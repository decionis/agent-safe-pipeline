import { describe, expect, it } from "vitest";
import { ApiProfile, type ApiRequest, type JsonObject } from "@decionis/agent-safe-pipeline";
import { effectDigest } from "../../src/gateway/TargetEffect.js";
import { TargetReader } from "../../src/gateway/TargetReader.js";
import { Upstream } from "../../src/gateway/Upstream.js";

const NOW = Date.parse("2026-10-31T12:00:00.000Z");
const AT = "2026-10-31T12:00:00.000Z";

/**
 * A 1.1 profile with two writes: one whose read states its version in a
 * header and carries exact query values, and one that names no read.
 */
const profile = ApiProfile.parse({
  profile: "agent-safe.profile.api/1.1",
  id: "example/api/v1",
  platform: "example",
  title: "Example API",
  prefixes: [""],
  operations: [
    {
      id: "items.update",
      method: "PATCH",
      path: "/items/{itemId}",
      action: "item.update",
      summary: "Change an item.",
      facts: {},
      policy_projection: null,
      precondition: { read: "items.get", version: "/headers/etag", state: "/body/status" },
      effect: [{ answer: "/body/status", request: "/body/status" }],
    },
    {
      id: "items.create",
      method: "POST",
      path: "/items",
      action: "item.create",
      summary: "Create an item.",
      facts: {},
      policy_projection: null,
    },
    {
      id: "items.get",
      method: "GET",
      path: "/items/{itemId}",
      query: { view: "full", "api-version": "2 0" },
      action: "item.read",
      summary: "Read one item.",
      facts: {},
      policy_projection: null,
      subject: { response: "/body/owner" },
    },
  ],
});

/** A profile whose read names no query, so its call carries none. */
const bare = ApiProfile.parse({
  ...profile.definition,
  operations: profile.definition.operations.map((operation) =>
    operation.id === "items.get" ? { ...operation, query: undefined } : operation,
  ),
});

interface Sent {
  readonly url: string;
  readonly init: RequestInit;
}

type Answer = Response | Error;

function reader(answers: Answer[], options: { profile?: ApiProfile } = {}) {
  const sent: Sent[] = [];
  const upstream = new Upstream({
    url: "http://127.0.0.1:1/base",
    timeoutMs: 1_000,
    maxResponseBytes: 10_000,
    fetch: (async (url: string | URL | Request, init?: RequestInit) => {
      sent.push({ url: String(url), init: init ?? {} });
      const next = answers.shift();
      if (next === undefined || next instanceof Error) throw next ?? new Error("no answer");
      return next;
    }) as typeof fetch,
    credential: { header: "authorization", value: () => "Bearer synthetic-gateway-credential" },
    gatewayToken: () => "synthetic-gateway-token",
  });
  const target = new TargetReader({
    profile: options.profile ?? profile,
    upstream,
    clock: () => NOW,
    failure: (error) => `FAILED_${(error as Error).message}`,
  });
  return { target, sent };
}

const json = (status: number, body: unknown, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

const write = (body: JsonObject): ApiRequest => ({
  method: "PATCH",
  path: "/items/A-1",
  query: {},
  body,
});

describe("the read before the decision", () => {
  it("is made as the gateway itself, with the read's exact query, and binds the version", async () => {
    const { target, sent } = reader([json(200, { status: "active" }, { etag: '"4"' })]);
    const plan = await target.plan("items.update", write({ status: "retired" }), false);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toBe("http://127.0.0.1:1/base/items/A-1?view=full&api-version=2%200");
    expect(sent[0]?.init.method).toBe("GET");
    expect(sent[0]?.init.body).toBeUndefined();
    expect(sent[0]?.init.headers).toEqual({
      accept: "application/json",
      "accept-encoding": "identity",
      authorization: "Bearer synthetic-gateway-credential",
      "agentsafe-gateway-token": "synthetic-gateway-token",
    });
    expect(plan).toEqual({
      operation: "items.update",
      read: {
        method: "GET",
        path: "/items/A-1",
        query: { view: "full", "api-version": "2 0" },
      },
      precondition: {
        version: '"4"',
        state: "active",
        source: "example/api/v1#items.get",
        read_at: AT,
      },
      effect: {
        expected: { "/body/status": "retired" },
        digest: effectDigest("example/api/v1#items.update", { "/body/status": "retired" }),
      },
    });
  });

  it("sends no query at all for a read that names none, and says why an effect is not bound", async () => {
    const { target, sent } = reader([json(200, {}, { etag: '"4"' })], { profile: bare });
    const plan = await target.plan("items.update", write({ status: "retired" }), true);
    expect(sent[0]?.url).toBe("http://127.0.0.1:1/base/items/A-1");
    expect(plan).toMatchObject({ effect: "EFFECT_NOT_BOUND" });
  });

  it("is not made for a write whose operation names no read", async () => {
    const { target, sent } = reader([]);
    expect(
      await target.plan("items.create", { method: "POST", path: "/items", body: {} }, false),
    ).toBeNull();
    expect(sent).toEqual([]);
  });

  it("refuses rather than bind no version: a failed send, an answer past 2xx, an answer that states none", async () => {
    const { target } = reader([
      new Error("RESET"),
      json(300, {}, { etag: '"4"' }),
      json(404, {}, { etag: '"4"' }),
      json(200, { status: "active" }),
    ]);
    const plan = (): ReturnType<TargetReader["plan"]> =>
      target.plan("items.update", write({ status: "retired" }), false);
    expect(await plan()).toEqual({ reasonCodes: ["TARGET_STATE_UNREADABLE", "FAILED_RESET"] });
    expect(await plan()).toEqual({
      reasonCodes: ["TARGET_STATE_UNREADABLE", "UPSTREAM_STATUS_300"],
    });
    expect(await plan()).toEqual({
      reasonCodes: ["TARGET_STATE_UNREADABLE", "UPSTREAM_STATUS_404"],
    });
    expect(await plan()).toEqual({
      reasonCodes: ["TARGET_STATE_UNREADABLE", "TARGET_VERSION_UNSTATED"],
    });
  });

  it("reads a version from the headers of an answer whose body is not JSON, at the last 2xx", async () => {
    const { target } = reader([
      new Response("not json", { status: 299, headers: { etag: '"9"' } }),
    ]);
    expect(await target.plan("items.update", write({ status: "retired" }), false)).toMatchObject({
      precondition: { version: '"9"', source: "example/api/v1#items.get", read_at: AT },
    });
  });
});

describe("the read after a write", () => {
  async function planned(target: TargetReader) {
    const plan = await target.plan("items.update", write({ status: "retired" }), false);
    if (plan === null || "reasonCodes" in plan || typeof plan.effect === "string") {
      throw new Error("expected a plan with an effect");
    }
    return { plan, effect: plan.effect };
  }

  it("confirms an answer that states what the call asked", async () => {
    const { target, sent } = reader([
      json(200, { status: "active" }, { etag: '"4"' }),
      json(200, { status: "retired" }, { etag: '"5"' }),
    ]);
    const { plan, effect } = await planned(target);
    const observed = await target.effect(plan, effect);
    expect(sent[1]?.url).toBe(sent[0]?.url);
    expect(observed.statement).toEqual({ confirmation: "CONFIRMED", reasonCodes: [] });
    expect(observed.record).toMatchObject({
      observedEffectDigest: effect.digest,
      evidence: { operation: "example/api/v1#items.update", observed_at: AT },
    });
  });

  it("reports an answer that states something else, and leaves one that never came pending", async () => {
    const { target } = reader([
      json(200, { status: "active" }, { etag: '"4"' }),
      json(200, { status: "active" }, { etag: '"5"' }),
      json(503, {}),
    ]);
    const { plan, effect } = await planned(target);
    expect((await target.effect(plan, effect)).statement).toEqual({
      confirmation: "UNKNOWN",
      reasonCodes: ["EFFECT_MISMATCH"],
    });
    expect((await target.effect(plan, effect)).statement).toEqual({
      confirmation: "PENDING",
      reasonCodes: ["EFFECT_UNREADABLE"],
    });
  });
});

describe("the read after a refusal", () => {
  it("finds the target where it was, moved, or not stated", async () => {
    const { target } = reader([
      json(200, { status: "active" }, { etag: '"4"' }),
      json(200, { status: "active" }, { etag: '"4"' }),
      json(200, { status: "active" }, { etag: '"5"' }),
      json(200, { status: "active" }),
      new Error("RESET"),
    ]);
    const plan = await target.plan("items.update", write({ status: "retired" }), false);
    if (plan === null || "reasonCodes" in plan) throw new Error("expected a plan");
    expect(await target.refusal(plan)).toEqual({
      outcome: "UNCHANGED",
      version: '"4"',
      readAt: AT,
    });
    expect(await target.refusal(plan)).toEqual({ outcome: "CHANGED", version: '"5"', readAt: AT });
    expect(await target.refusal(plan)).toEqual({
      outcome: "UNREADABLE",
      version: null,
      readAt: AT,
    });
    expect(await target.refusal(plan)).toEqual({
      outcome: "UNREADABLE",
      version: null,
      readAt: AT,
    });
  });
});
