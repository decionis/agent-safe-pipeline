import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ActionRegistry,
  ProviderRefusal,
  type CapturedIntent,
  type ProviderDispatch,
  type VerifiedAuthorization,
} from "@decionis/agent-safe-pipeline";
import {
  httpForwardHandler,
  HttpActionParametersSchema,
  registerHttpActions,
  RequestHolder,
} from "../../src/gateway/ForwardHandler.js";
import { bodyDigest, type InterceptedRequest } from "../../src/gateway/InterceptedRequest.js";
import { Upstream } from "../../src/gateway/Upstream.js";
import { RECEIPT, UpstreamDouble } from "../support/GatewayHarness.js";

const body = Buffer.from('{"amount": 5}', "utf8");
const request = (overrides: Partial<InterceptedRequest> = {}): InterceptedRequest => ({
  method: "POST",
  path: "/payments",
  search: "",
  headers: { "content-type": "application/json" },
  body,
  remoteAddress: null,
  encrypted: false,
  ...overrides,
});
const intent = (overrides: Partial<CapturedIntent["intent"]> = {}): CapturedIntent =>
  ({
    intent: {
      intentId: "00000000-0000-4000-8000-000000000001",
      context: { body_sha256: bodyDigest(body), body_bytes: body.length },
      ...overrides,
    },
    intentHash: "sha256:abc",
  }) as unknown as CapturedIntent;
const authorization: VerifiedAuthorization = {
  decisionId: "d1",
  dossierId: "dss1",
  grantId: "g1",
  intentHash: "sha256:abc",
  expiresAt: new Date(Date.now() + 60_000).toISOString(),
};
const parameters = { method: "POST" as const, path: "/payments", query: {} };
let dispatched = 0;
let receipts: string[] = [];
const dispatch: ProviderDispatch = {
  idempotencyKey: "k",
  run: async <T>(operation: (idempotencyKey: string) => Promise<T> | T): Promise<T> => {
    dispatched += 1;
    return await operation("k");
  },
  receipt: (token) => {
    receipts.push(token);
  },
};

describe("the exact-forward handler", () => {
  const double = new UpstreamDouble();
  let upstream: Upstream;
  beforeAll(async () => {
    await double.start();
    upstream = new Upstream({
      url: double.baseUrl,
      timeoutMs: 1_000,
      maxResponseBytes: 1024,
      fetch,
    });
  });
  afterAll(() => double.stop());

  it("validates the parameter shape strictly", () => {
    expect(HttpActionParametersSchema.safeParse({ ...parameters, body: { a: 1 } }).success).toBe(
      true,
    );
    expect(HttpActionParametersSchema.safeParse({ ...parameters, extra: 1 }).success).toBe(false);
    expect(HttpActionParametersSchema.safeParse({ ...parameters, method: "GET" }).success).toBe(
      false,
    );
  });

  it("forwards the held bytes once the intent's digest matches, with the evidence headers", async () => {
    const holder = new RequestHolder();
    const handler = httpForwardHandler(upstream, holder);
    holder.hold("00000000-0000-4000-8000-000000000001", request(), { "x-extra": "yes" });
    dispatched = 0;
    const result = await handler.execute({ intent: intent(), parameters, authorization, dispatch });
    expect(result.status).toBe(201);
    expect(dispatched).toBe(1);
    expect(double.seen.at(-1)).toMatchObject({ body: '{"amount": 5}' });
    expect(double.seen.at(-1)?.headers).toMatchObject({
      "x-agent-safe-intent-hash": "sha256:abc",
      "x-agent-safe-decision-id": "d1",
      "x-agent-safe-dossier-id": "dss1",
      "x-extra": "yes",
    });
    expect(holder.release("00000000-0000-4000-8000-000000000001")).toEqual({
      response: result,
      failure: null,
    });
    expect(holder.release("00000000-0000-4000-8000-000000000001")).toEqual({
      response: null,
      failure: null,
    });
  });

  it("fails before dispatch when nothing is held, or when the bytes are not the bound bytes", async () => {
    const holder = new RequestHolder();
    const handler = httpForwardHandler(upstream, holder);
    dispatched = 0;
    await expect(
      handler.execute({ intent: intent(), parameters, authorization, dispatch }),
    ).rejects.toThrow("REQUEST_NOT_HELD");
    holder.hold(
      "00000000-0000-4000-8000-000000000001",
      request({ body: Buffer.from('{"amount": 6}') }),
      {},
    );
    await expect(
      handler.execute({ intent: intent(), parameters, authorization, dispatch }),
    ).rejects.toThrow("PAYLOAD_BINDING_MISMATCH");
    holder.hold("00000000-0000-4000-8000-000000000001", request({ method: "PUT" }), {});
    await expect(
      handler.execute({ intent: intent(), parameters, authorization, dispatch }),
    ).rejects.toThrow("PAYLOAD_BINDING_MISMATCH");
    holder.hold("00000000-0000-4000-8000-000000000001", request({ path: "/other" }), {});
    await expect(
      handler.execute({ intent: intent(), parameters, authorization, dispatch }),
    ).rejects.toThrow("PAYLOAD_BINDING_MISMATCH");
    holder.hold("00000000-0000-4000-8000-000000000001", request(), {});
    await expect(
      handler.execute({
        intent: intent({ context: { body_sha256: bodyDigest(body), body_bytes: 1 } }),
        parameters,
        authorization,
        dispatch,
      }),
    ).rejects.toThrow("PAYLOAD_BINDING_MISMATCH");
    expect(dispatched).toBe(0);
  });

  it("reports the upstream's refusal, error and absence after dispatch, keeping the answer for the relay", async () => {
    const holder = new RequestHolder();
    const handler = httpForwardHandler(upstream, holder);
    const at = (path: string) => ({
      intent: intent(),
      parameters: { ...parameters, path },
      authorization,
      dispatch,
    });
    holder.hold("00000000-0000-4000-8000-000000000001", request({ path: "/refuse" }), {});
    await expect(handler.execute(at("/refuse"))).rejects.toBeInstanceOf(ProviderRefusal);
    expect(holder.release("00000000-0000-4000-8000-000000000001")).toMatchObject({
      failure: "UPSTREAM_REFUSED",
      response: { status: 422 },
    });
    holder.hold("00000000-0000-4000-8000-000000000001", request({ path: "/fail" }), {});
    await expect(handler.execute(at("/fail"))).rejects.toThrow("UPSTREAM_STATUS_5XX");
    expect(holder.release("00000000-0000-4000-8000-000000000001")).toMatchObject({
      failure: "UPSTREAM_ERROR",
      response: { status: 500 },
    });
    holder.hold("00000000-0000-4000-8000-000000000001", request({ path: "/big" }), {});
    await expect(handler.execute(at("/big"))).rejects.toThrow("UPSTREAM_RESPONSE_TOO_LARGE");
    expect(holder.release("00000000-0000-4000-8000-000000000001")).toEqual({
      response: null,
      failure: "RESPONSE_TOO_LARGE",
    });
    holder.hold("00000000-0000-4000-8000-000000000001", request({ path: "/slow" }), {});
    const expired = { ...authorization, expiresAt: new Date(Date.now() - 1).toISOString() };
    await expect(handler.execute({ ...at("/slow"), authorization: expired })).rejects.toThrow();
    expect(holder.release("00000000-0000-4000-8000-000000000001")).toEqual({
      response: null,
      failure: "TRANSPORT",
    });
  });

  it("hands the upstream's effect receipt to the dispatch, on a commit and on a refusal alike", async () => {
    const holder = new RequestHolder();
    const handler = httpForwardHandler(upstream, holder);
    const at = (path: string) => ({
      intent: intent(),
      parameters: { ...parameters, path },
      authorization,
      dispatch,
    });
    receipts = [];
    holder.hold("00000000-0000-4000-8000-000000000001", request({ path: "/payments" }), {});
    await handler.execute(at("/payments"));
    expect(receipts).toEqual([]);
    holder.hold("00000000-0000-4000-8000-000000000001", request({ path: "/receipt" }), {});
    const result = await handler.execute(at("/receipt"));
    expect(receipts).toEqual([RECEIPT]);
    // The relay carries it to the caller like any other upstream header.
    expect(result.headers).toContainEqual(["x-agent-safe-effect-receipt", RECEIPT]);
    holder.hold("00000000-0000-4000-8000-000000000001", request({ path: "/receipt/refuse" }), {});
    await expect(handler.execute(at("/receipt/refuse"))).rejects.toBeInstanceOf(ProviderRefusal);
    expect(receipts).toEqual([RECEIPT, RECEIPT]);
  });

  it("registers the one handler under every name and seals the registry", () => {
    const registry = registerHttpActions(
      new ActionRegistry(),
      ["http.post", "payment.create"],
      httpForwardHandler(upstream, new RequestHolder()),
    );
    expect(registry.has("http.post")).toBe(true);
    expect(registry.has("payment.create")).toBe(true);
    expect(() =>
      registry.register("late", httpForwardHandler(upstream, new RequestHolder())),
    ).toThrow("ACTION_REGISTRY_SEALED");
  });
});
