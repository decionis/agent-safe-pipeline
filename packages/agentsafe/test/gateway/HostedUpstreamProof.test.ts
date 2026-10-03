import { afterEach, describe, expect, it, vi } from "vitest";
import { Gateway, type GatewayContinuation } from "../../src/gateway/Gateway.js";
import {
  PROOF_GRACE_MS,
  PROOF_MISSING_RECHECK_MS,
  PROOF_PENDING_RETRY_MS,
  PROOF_RECHECK_MS,
  proofToken,
  UPSTREAM_PROOF_HEADER,
  UPSTREAM_PROOF_PATH,
  type TxtResolver,
} from "../../src/gateway/UpstreamProof.js";
import { GatewayHttpServer } from "../../src/http/GatewayHttpServer.js";
import {
  collectedIo,
  testConfig,
  TENANT_KEY,
  TENANT_KEY_DIGEST,
  type CollectedIo,
} from "../support/GatewayHarness.js";

const WORKSPACE = "00000000-0000-4000-8000-000000000009";
const UPSTREAM = "https://api.acme.example/v2";
const ORIGIN = "https://api.acme.example";
const PROOF_URL = `${ORIGIN}${UPSTREAM_PROOF_PATH}`;
const GLOBEX = "https://api.globex.example";
/** An origin assembled from its parts, so no literal scheme sits beside a template hole. */
const origin = (scheme: "http" | "https", host: string, port: number): string =>
  `${scheme}://${host}:${port}`;
const TOKEN = proofToken({ tenant: "acme", org: WORKSPACE, origin: ORIGIN }, 1_759_492_800);

/** A hosted gateway for tenant `acme` that requires its upstream's proof. */
const hostedEnv = (): Record<string, string> => ({
  AGENTSAFE_HOSTED_GATEWAY: "true",
  AGENTSAFE_HOSTED_TENANT: "acme",
  AGENTSAFE_TENANT_KEY_DIGESTS: TENANT_KEY_DIGEST,
  AGENTSAFE_UPSTREAM_PROOF_REQUIRED: "true",
  DECIONIS_API_KEY: "synthetic-workspace-key",
  DECIONIS_API_URL: "https://api.decionis.example",
  DECIONIS_TENANT_ID: WORKSPACE,
});

interface Upstream {
  /** What the proof's path answers; null is a 404, and a promise is an answer that comes when it settles. */
  proof: string | null | Promise<Response>;
  readonly seen: string[];
}

interface Running {
  readonly gateway: Gateway;
  readonly io: CollectedIo;
  readonly upstream: Upstream;
  readonly port: number;
  readonly server: GatewayHttpServer;
}

const running: Running[] = [];

afterEach(async () => {
  for (const entry of running.splice(0)) {
    await entry.server.close(0);
    await entry.gateway.close();
  }
});

interface BuildOptions {
  readonly proof?: string | null | Promise<Response>;
  readonly txt?: TxtResolver;
  readonly continues?: GatewayContinuation;
  readonly upstream?: string;
  /** Settings of this gateway's own, over the hosted tenant's. */
  readonly env?: Record<string, string>;
  readonly clock?: () => number;
}

/** A hosted gateway for `acme` whose upstream answers from `upstream`, with no listener. */
async function build(
  options: BuildOptions = {},
): Promise<{ gateway: Gateway; io: CollectedIo; upstream: Upstream }> {
  const upstream: Upstream = { proof: options.proof ?? null, seen: [] };
  const io = collectedIo();
  const env = { ...hostedEnv(), ...(options.env ?? {}) };
  const gateway = await Gateway.create(testConfig(options.upstream ?? UPSTREAM, { env }), {
    env,
    io,
    upstreamFetch: async (input) => {
      const url = String(input);
      upstream.seen.push(url);
      if (url.endsWith(UPSTREAM_PROOF_PATH)) {
        const proof = upstream.proof;
        if (proof instanceof Promise) return await proof;
        return proof === null
          ? new Response("not here", { status: 404 })
          : new Response(proof, { status: 200 });
      }
      return new Response('{"orders":[]}', {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
    upstreamResolveTxt:
      options.txt ??
      (async () => {
        throw Object.assign(new Error("no record"), { code: "ENODATA" });
      }),
    ...(options.continues === undefined ? {} : { continues: options.continues }),
    ...(options.clock === undefined ? {} : { clock: options.clock }),
  });
  return { gateway, io, upstream };
}

async function start(options: BuildOptions = {}): Promise<Running> {
  const { gateway, io, upstream } = await build(options);
  return await serve(gateway, io, upstream);
}

/** A listener in front of a gateway already built. */
async function serve(gateway: Gateway, io: CollectedIo, upstream: Upstream): Promise<Running> {
  const server = new GatewayHttpServer(gateway);
  const { port } = await server.listen(0, "127.0.0.1");
  const entry = { gateway, io, upstream, port, server };
  running.push(entry);
  return entry;
}

/** An answer the test hands the proof's path when it chooses. */
function later(): { promise: Promise<Response>; answer: (body: string | null) => void } {
  let answer: (body: string | null) => void = () => undefined;
  const promise = new Promise<Response>((resolve) => {
    answer = (body) =>
      resolve(
        body === null
          ? new Response("not here", { status: 404 })
          : new Response(body, { status: 200 }),
      );
  });
  return { promise, answer };
}

/** Waits for the gateway's first look at its upstream's proof to end. */
async function looked(gateway: Gateway): Promise<void> {
  for (let attempt = 0; attempt < 200 && !gateway.upstreamProofSettled; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  expect(gateway.upstreamProofSettled).toBe(true);
}

async function get(
  port: number,
  key: string | null,
  path = "/orders",
): Promise<{ status: number; headers: Headers; body: Record<string, unknown> | string }> {
  const response = await fetch(new URL(path, origin("http", "127.0.0.1", port)), {
    headers: key === null ? {} : { "agentsafe-tenant-key": key },
  });
  const text = await response.text();
  let body: Record<string, unknown> | string = text;
  try {
    body = JSON.parse(text) as Record<string, unknown>;
  } catch {
    // not JSON: kept as text
  }
  return { status: response.status, headers: response.headers, body };
}

const securityLines = (io: CollectedIo): Record<string, unknown>[] =>
  [...io.out, ...io.err]
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter(
      (line) => typeof line["event"] === "string" && String(line["event"]).startsWith("UPSTREAM_"),
    );

describe("a hosted gateway that requires its upstream's proof", () => {
  it("forwards nothing while the proof is not served, and says so only after the tenant key admits the request", async () => {
    const { gateway, io, upstream, port } = await start();
    await looked(gateway);
    expect(upstream.seen).toEqual([PROOF_URL]);

    // A caller without the tenant's key learns nothing about the proof.
    const missing = await get(port, null);
    expect([missing.status, missing.body]).toEqual([401, { code: "TENANT_KEY_MISSING" }]);
    const wrong = await get(port, "synthetic-wrong-key");
    expect([wrong.status, wrong.body]).toEqual([401, { code: "TENANT_KEY_INVALID" }]);

    const refused = await get(port, TENANT_KEY);
    expect(refused.status).toBe(503);
    expect(refused.body).toEqual({
      version: "agent-safe.gateway/1",
      state: "ERROR",
      verdict: null,
      reason_codes: ["UPSTREAM_UNVERIFIED"],
      execution: "NOT_FORWARDED",
      fallback: UPSTREAM,
    });
    expect(refused.headers.get("agentsafe-execution")).toBe("NOT_FORWARDED");
    expect(refused.headers.get("agentsafe-state")).toBe("ERROR");
    expect(refused.headers.get("retry-after")).toBe("60");
    // Nothing went to the upstream but the look for the proof.
    expect(upstream.seen).toEqual([PROOF_URL]);
    // The gateway's own routes are not the tenant's traffic.
    expect((await get(port, null, "/_agentsafe/healthz")).status).toBe(200);

    expect(securityLines(io)).toMatchObject([
      { event: "UPSTREAM_UNVERIFIED", origin: ORIGIN, code: "UPSTREAM_PROOF_NOT_SERVED" },
    ]);
    expect(gateway.status().hosted?.upstream_proof).toMatchObject({
      state: "unverified",
      method: null,
      stops_at: null,
      code: null,
    });
    expect(gateway.status().counts["upstream_unverified"]).toBe(1);
  });

  it("forwards once the origin serves a token bound to the tenant, its workspace and the origin", async () => {
    const { gateway, upstream, port } = await start({ proof: `# acme\n${TOKEN}\n` });
    await looked(gateway);
    expect(gateway.upstreamProof()).toBe("FORWARD");
    const answer = await get(port, TENANT_KEY);
    expect([answer.status, answer.body]).toEqual([200, { orders: [] }]);
    expect(answer.headers.get("agentsafe-execution")).toBe("PASSTHROUGH");
    expect(answer.headers.get(UPSTREAM_PROOF_HEADER)).toBeNull();
    expect(upstream.seen).toEqual([PROOF_URL, `${UPSTREAM}/orders`]);
    expect(gateway.status().hosted?.upstream_proof).toMatchObject({
      state: "verified",
      method: "file",
    });
  });

  it("takes a TXT record once the origin has answered, and never a token bound to another tenant", async () => {
    const other = proofToken({ tenant: "globex", org: WORKSPACE, origin: ORIGIN }, 1_759_492_800);
    const names: string[] = [];
    const byDns = await start({
      proof: other,
      txt: async (name) => {
        names.push(name);
        return [[TOKEN]];
      },
    });
    await looked(byDns.gateway);
    expect(names).toEqual(["_agentsafe-challenge.api.acme.example"]);
    expect(byDns.gateway.status().hosted?.upstream_proof).toMatchObject({
      state: "verified",
      method: "dns",
    });
    expect((await get(byDns.port, TENANT_KEY)).status).toBe(200);

    const neither = await start({ proof: other });
    await looked(neither.gateway);
    expect((await get(neither.port, TENANT_KEY)).status).toBe(503);
  });

  it("takes the proof over at the swap when rebuilt for the same tenant, organization and origin: no look, no refusal, no wait", async () => {
    const proven = await start({ proof: TOKEN });
    await looked(proven.gateway);
    const checkedAt = proven.gateway.status().hosted?.upstream_proof?.checked_at;
    expect(checkedAt).toEqual(expect.any(String));

    // Built to replace it: nothing is looked at, or taken, before the swap.
    const rebuilt = await start({ continues: proven.gateway.continuation() });
    expect(rebuilt.gateway.upstreamProofSettled).toBe(false);
    rebuilt.gateway.takeOver(proven.gateway);
    expect(rebuilt.gateway.upstreamProofSettled).toBe(true);
    expect((await get(rebuilt.port, TENANT_KEY)).status).toBe(200);
    expect(rebuilt.upstream.seen).toEqual([`${UPSTREAM}/orders`]);
    // The last look is still the last one, not a blank.
    expect(rebuilt.gateway.status().hosted?.upstream_proof).toMatchObject({
      state: "verified",
      method: "file",
      checked_at: checkedAt,
    });
  });

  it("looks from the start when rebuilt for another origin, organization or tenant, and refuses until that binding is proved", async () => {
    for (const [change, other] of [
      [{ upstream: GLOBEX }, { proof: TOKEN }],
      [{ env: { DECIONIS_TENANT_ID: "00000000-0000-4000-8000-00000000000a" } }, {}],
      [{ env: { AGENTSAFE_HOSTED_TENANT: "acme2" } }, {}],
    ] as const) {
      const proven = await start({ proof: TOKEN });
      await looked(proven.gateway);
      // The origin still serves acme's token for the first workspace, and only that.
      const moved = await start({
        ...change,
        ...other,
        proof: TOKEN,
        continues: proven.gateway.continuation(),
      });
      moved.gateway.takeOver(proven.gateway);
      await looked(moved.gateway);
      const origin = "upstream" in change ? GLOBEX : ORIGIN;
      expect([change, moved.upstream.seen]).toEqual([change, [`${origin}${UPSTREAM_PROOF_PATH}`]]);
      expect([change, (await get(moved.port, TENANT_KEY)).status]).toEqual([change, 503]);
      expect(moved.gateway.status().hosted?.upstream_proof?.state).toBe("unverified");
    }
  });

  it("refuses before it spends the tenant's rate: a 503 for want of a proof never leaves a 429 behind", async () => {
    const look = later();
    const limited = await start({
      proof: look.promise,
      env: { AGENTSAFE_RATE_LIMIT_RPS: "0.001", AGENTSAFE_RATE_LIMIT_BURST: "1" },
    });
    expect(limited.gateway.upstreamProofSettled).toBe(false);
    for (let request = 0; request < 3; request += 1) {
      expect((await get(limited.port, TENANT_KEY)).status).toBe(503);
    }
    look.answer(TOKEN);
    await looked(limited.gateway);
    const forwarded = await get(limited.port, TENANT_KEY);
    expect([forwarded.status, forwarded.body]).toEqual([200, { orders: [] }]);
    // The one request the burst holds is spent now, and only now.
    const next = await get(limited.port, TENANT_KEY);
    expect([next.status, next.body]).toEqual([429, { code: "RATE_LIMITED" }]);
  });
});

describe("a hosted gateway's proof, handed on", () => {
  let now = 0;
  const clock = (): number => now;

  /** Moves the clock and the timers together, so the monitor's times and its looks agree. */
  async function pass(ms: number): Promise<void> {
    now += ms;
    await vi.advanceTimersByTimeAsync(ms);
  }

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  const events = (io: CollectedIo): Record<string, unknown>[] => securityLines(io);

  it("stops the gateway it replaces from looking: no request and no event from it, ever after", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    vi.spyOn(Math, "random").mockReturnValue(0.5);
    now = Date.parse("2026-10-03T12:00:00.000Z");
    const old = await build({ proof: TOKEN, clock });
    await pass(0);
    expect(old.gateway.upstreamProofSettled).toBe(true);
    expect(old.upstream.seen).toEqual([PROOF_URL]);
    // The origin stops serving the proof: a gateway still looking would find it missing.
    old.upstream.proof = null;
    const next = await build({ proof: null, clock, continues: old.gateway.continuation() });
    next.gateway.takeOver(old.gateway);
    await pass(PROOF_RECHECK_MS);
    // One look, the new gateway's, a day after the old one's; none of the old one's.
    expect(old.upstream.seen).toEqual([PROOF_URL]);
    expect(next.upstream.seen).toEqual([PROOF_URL]);
    expect(events(old.io)).toEqual([]);
    expect(events(next.io)).toMatchObject([{ event: "UPSTREAM_PROOF_MISSING", origin: ORIGIN }]);
    await pass(PROOF_RECHECK_MS * 2);
    expect(old.upstream.seen).toEqual([PROOF_URL]);
    expect(events(old.io)).toEqual([]);
    await next.gateway.close();
    await old.gateway.close();
  });

  it("discards a look the replaced gateway has in flight, and the new one looks at once instead", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    now = Date.parse("2026-10-03T12:00:00.000Z");
    const look = later();
    const old = await build({ proof: look.promise, clock });
    await pass(0);
    expect(old.upstream.seen).toEqual([PROOF_URL]);
    expect(old.gateway.upstreamProofSettled).toBe(false);
    const next = await build({ proof: null, clock, continues: old.gateway.continuation() });
    next.gateway.takeOver(old.gateway);
    // The old look ends with a proof after the swap: it changes nothing, anywhere.
    look.answer(TOKEN);
    await pass(PROOF_PENDING_RETRY_MS * 3);
    expect(old.upstream.seen).toEqual([PROOF_URL]);
    expect(old.gateway.status().hosted?.upstream_proof).toMatchObject({
      state: "pending",
      checked_at: null,
    });
    expect(events(old.io)).toEqual([]);
    // The new gateway looked at once, found nothing, and looks every minute.
    expect(next.upstream.seen).toEqual([PROOF_URL, PROOF_URL, PROOF_URL, PROOF_URL]);
    expect(next.gateway.upstreamProof()).toBe("REFUSE");
    expect(events(next.io)).toMatchObject([
      { event: "UPSTREAM_UNVERIFIED", code: "UPSTREAM_PROOF_NOT_SERVED" },
    ]);
    await next.gateway.close();
    await old.gateway.close();
  });

  it("takes over a missing proof as it stands: forwarded and marked, its grace and its next look unchanged", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    vi.spyOn(Math, "random").mockReturnValue(0.5);
    const t0 = Date.parse("2026-10-03T12:00:00.000Z");
    now = t0;
    const old = await build({ proof: TOKEN, clock });
    await pass(0);
    old.upstream.proof = null;
    await pass(PROOF_RECHECK_MS);
    const since = t0 + PROOF_RECHECK_MS;
    expect(old.gateway.upstreamProof()).toBe("MISSING");
    // Half an hour into the hour between looks, a rebuild.
    await pass(PROOF_MISSING_RECHECK_MS / 2);
    const next = await build({ proof: null, clock, continues: old.gateway.continuation() });
    next.gateway.takeOver(old.gateway);
    expect(next.gateway.upstreamProof()).toBe("MISSING");
    expect(next.gateway.status().hosted?.upstream_proof).toEqual({
      state: "missing",
      method: null,
      checked_at: new Date(since).toISOString(),
      stops_at: new Date(since + PROOF_GRACE_MS).toISOString(),
      code: null,
    });
    // Its next look is when the old one's was due, not an hour from the rebuild.
    await pass(PROOF_MISSING_RECHECK_MS / 2 - 1);
    expect(next.upstream.seen).toEqual([]);
    await pass(1);
    expect(next.upstream.seen).toEqual([PROOF_URL]);
    // The miss was reported once, by the gateway that saw it.
    expect([...events(old.io), ...events(next.io)]).toMatchObject([
      { event: "UPSTREAM_PROOF_MISSING" },
    ]);
    vi.useRealTimers();
    const served = await serve(next.gateway, next.io, next.upstream);
    const answer = await get(served.port, TENANT_KEY);
    expect(answer.status).toBe(200);
    expect(answer.headers.get(UPSTREAM_PROOF_HEADER)).toBe("missing");
    await old.gateway.close();
  });
});

describe("a gateway that requires no proof", () => {
  it("forwards as it always did, and has nothing to wait for", async () => {
    const env = { ...hostedEnv(), AGENTSAFE_UPSTREAM_PROOF_REQUIRED: "false" };
    const gateway = await Gateway.create(testConfig(UPSTREAM, { env }), {
      env,
      io: collectedIo(),
      upstreamFetch: async () => new Response("ok"),
    });
    expect(gateway.upstreamProofSettled).toBe(true);
    expect(gateway.upstreamProof()).toBe("FORWARD");
    expect(gateway.status().hosted?.upstream_proof).toBeNull();
    // Nothing to take over, either way.
    const next = await Gateway.create(testConfig(UPSTREAM, { env }), {
      env,
      io: collectedIo(),
      upstreamFetch: async () => new Response("ok"),
      continues: gateway.continuation(),
    });
    next.takeOver(gateway);
    expect(next.upstreamProof()).toBe("FORWARD");
    await next.close();
    await gateway.close();
  });
});
