import {
  createServer as createHttpServer,
  type RequestListener,
  type Server as HttpServer,
} from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { EgressError } from "../../src/egress/EgressError.js";
import { EgressPolicy, type EgressDestination } from "../../src/egress/EgressPolicy.js";
import { GuardedFetch, type GuardedFetchOptions } from "../../src/egress/GuardedFetch.js";
import { collectedEvents } from "../support/Environment.js";
import { TestCertificateAuthority } from "../support/TestCertificateAuthority.js";

interface Seen {
  readonly method: string;
  readonly url: string;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly body: string;
}

const authority = new TestCertificateAuthority("Synthetic Authority CA");
const stranger = new TestCertificateAuthority("Synthetic Stranger CA");
const seen: Seen[] = [];
let connections = 0;
let tls: HttpsServer;
let plain: HttpServer;
let foreign: HttpsServer;
let tlsOrigin = "";
let plainOrigin = "";
let foreignOrigin = "";
let serverPin = "";

/** Reads a body the way the pipeline's bounded reader does: through the stream's reader. */
async function streamed(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (reader === undefined) return "";
  const chunks: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** The peer under test: echoes what it saw, and misbehaves on request. */
const handler: RequestListener = (request, response): void => {
  const chunks: Buffer[] = [];
  request.on("data", (chunk: Buffer) => chunks.push(chunk));
  request.on("end", () => {
    const url = request.url ?? "/";
    seen.push({
      method: request.method ?? "",
      url,
      headers: request.headers,
      body: Buffer.concat(chunks).toString("utf8"),
    });
    if (url.startsWith("/v1/redirect-away")) {
      response.writeHead(302, { location: "https://elsewhere.example/landing" });
      return response.end();
    }
    if (url.startsWith("/v1/redirect-home")) {
      response.writeHead(307, { location: "/v1/echo" });
      return response.end();
    }
    if (url.startsWith("/v1/redirect-broken")) {
      response.writeHead(301, { location: "//[bad" });
      return response.end();
    }
    if (url.startsWith("/v1/large-declared")) {
      const body = "x".repeat(4_000);
      response.writeHead(200, { "content-length": String(body.length) });
      return response.end(body);
    }
    if (url.startsWith("/v1/large-streamed")) {
      response.writeHead(200, { "content-type": "text/plain" });
      response.write("y".repeat(1_500));
      response.write("y".repeat(1_500));
      return response.end("y".repeat(1_500));
    }
    if (url.startsWith("/v1/slow")) {
      setTimeout(() => response.end("late"), 400);
      return;
    }
    if (url.startsWith("/v1/empty")) {
      response.writeHead(204);
      return response.end();
    }
    if (url.startsWith("/v1/odd-status")) {
      response.writeHead(999);
      return response.end("odd");
    }
    response.writeHead(200, {
      "content-type": "application/json",
      "set-cookie": ["a=1", "b=2"],
      "x-echo": "yes",
    });
    response.end(JSON.stringify({ ok: true, path: url }));
  });
};

/** An origin assembled from its parts, so no literal scheme sits beside a template hole. */
const origin = (scheme: "http" | "https", host: string, port: number): string =>
  `${scheme}://${host}:${port}`;

async function listen(server: HttpServer | HttpsServer): Promise<number> {
  server.on("connection", () => {
    connections += 1;
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  return typeof address === "object" && address !== null ? address.port : 0;
}

function destinations(overrides: Partial<EgressDestination> = {}): EgressDestination[] {
  return [
    { origin: tlsOrigin, pathPrefixes: ["/v1"], ca: authority.certificate, pins: [], ...overrides },
    { origin: plainOrigin, pathPrefixes: ["/v1"], ca: null, pins: [] },
    { origin: foreignOrigin, pathPrefixes: ["/v1"], ca: authority.certificate, pins: [] },
  ];
}

function guard(
  options: Partial<GuardedFetchOptions> & {
    readonly lines?: string[];
    readonly policy?: EgressPolicy;
  } = {},
): { readonly fetch: typeof fetch; readonly lines: string[]; readonly guarded: GuardedFetch } {
  const lines = options.lines ?? [];
  const guarded = new GuardedFetch({
    policy: options.policy ?? new EgressPolicy(destinations()),
    events: collectedEvents(lines),
    maxResponseBytes: options.maxResponseBytes ?? 2_048,
    ...(options.transport === undefined ? {} : { transport: options.transport }),
    ...(options.resolve === undefined ? {} : { resolve: options.resolve }),
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
  });
  return { fetch: guarded.fetch, lines, guarded };
}

const refusals = (lines: string[]): [string | null, string][] =>
  lines
    .map((line) => JSON.parse(line) as { event: string; origin: string | null; code: string })
    .filter((event) => event.event === "EGRESS_REFUSED")
    .map((event) => [event.origin, event.code]);

async function refused(work: Promise<unknown>): Promise<EgressError> {
  try {
    await work;
  } catch (error) {
    if (error instanceof EgressError) return error;
    throw error;
  }
  throw new Error("expected an egress refusal");
}

beforeAll(async () => {
  const server = authority.issueServer(["localhost"], ["127.0.0.1"]);
  serverPin = server.pin;
  tls = createHttpsServer({ cert: server.cert, key: server.key }, handler);
  plain = createHttpServer(handler);
  const other = stranger.issueServer(["localhost"], ["127.0.0.1"]);
  foreign = createHttpsServer({ cert: other.cert, key: other.key }, handler);
  tlsOrigin = origin("https", "localhost", await listen(tls));
  plainOrigin = origin("http", "127.0.0.1", await listen(plain));
  foreignOrigin = origin("https", "localhost", await listen(foreign));
});

afterAll(async () => {
  for (const server of [tls, plain, foreign]) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

describe("GuardedFetch over TLS", () => {
  it("reaches an allowed origin, verifies it against its own anchor, and returns a whole Response", async () => {
    const { fetch, lines, guarded } = guard();
    const before = connections;
    const response = await fetch(`${tlsOrigin}/v1/echo?x=1`, {
      method: "POST",
      headers: { "content-type": "application/json", "idempotency-key": "k-1" },
      body: '{"amount":1}',
      signal: AbortSignal.timeout(2_000),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("x-echo")).toBe("yes");
    expect(response.headers.get("set-cookie")).toContain("a=1");
    expect(response.headers.get("set-cookie")).toContain("b=2");
    expect(await streamed(response)).toBe('{"ok":true,"path":"/v1/echo?x=1"}');
    const request = seen.at(-1);
    expect(request).toMatchObject({ method: "POST", url: "/v1/echo?x=1", body: '{"amount":1}' });
    expect(request?.headers["idempotency-key"]).toBe("k-1");
    expect(request?.headers["content-length"]).toBe("12");
    expect(request?.headers["host"]).toBe(new URL(tlsOrigin).host);
    const again = await fetch(`${tlsOrigin}/v1/echo`, {
      headers: new Headers({ "x-second": "2" }),
    });
    expect(await again.json()).toEqual({ ok: true, path: "/v1/echo" });
    expect(seen.at(-1)?.headers["x-second"]).toBe("2");
    expect(connections - before).toBe(1);
    expect(refusals(lines)).toEqual([]);
    guarded.close();
    await fetch(`${tlsOrigin}/v1/echo`);
    expect(connections - before).toBe(2);
    guarded.close();
  });

  it("refuses a peer whose certificate its anchor did not sign, and one whose key is not pinned", async () => {
    const { fetch, lines } = guard();
    const rejected = await refused(fetch(`${foreignOrigin}/v1/echo`));
    expect(rejected.code).toBe("EGRESS_TLS_REJECTED");
    expect(rejected.origin).toBe(foreignOrigin);
    const pinned = guard({
      policy: new EgressPolicy(
        destinations({ pins: [`sha256/${"A".repeat(43)}=`, `sha256/${"B".repeat(43)}=`] }),
      ),
      lines,
    });
    const mismatch = await refused(pinned.fetch(`${tlsOrigin}/v1/echo`));
    expect(mismatch.code).toBe("EGRESS_TLS_PIN_MISMATCH");
    expect(refusals(lines)).toEqual([
      [foreignOrigin, "EGRESS_TLS_REJECTED"],
      [tlsOrigin, "EGRESS_TLS_PIN_MISMATCH"],
    ]);
    const matching = guard({
      policy: new EgressPolicy(destinations({ pins: [`sha256/${"A".repeat(43)}=`, serverPin] })),
    });
    expect((await matching.fetch(`${tlsOrigin}/v1/echo`)).status).toBe(200);
    expect(matching.lines).toEqual([]);
    matching.guarded.close();
    pinned.guarded.close();
  });

  it("never follows a redirect, and reports one that leaves the origin", async () => {
    const { fetch, lines, guarded } = guard();
    const count = seen.length;
    const away = await fetch(`${tlsOrigin}/v1/redirect-away`);
    expect(away.status).toBe(302);
    expect(away.headers.get("location")).toBe("https://elsewhere.example/landing");
    const home = await fetch(`${tlsOrigin}/v1/redirect-home`);
    expect(home.status).toBe(307);
    const broken = await fetch(`${tlsOrigin}/v1/redirect-broken`);
    expect(broken.status).toBe(301);
    expect(seen.length - count).toBe(3);
    expect(refusals(lines)).toEqual([
      [tlsOrigin, "EGRESS_REDIRECT_REFUSED"],
      [tlsOrigin, "EGRESS_REDIRECT_REFUSED"],
    ]);
    const follow = await refused(fetch(`${tlsOrigin}/v1/echo`, { redirect: "follow" }));
    expect(follow.code).toBe("EGRESS_INIT_UNSUPPORTED");
    expect((await fetch(`${tlsOrigin}/v1/echo`, { redirect: "manual" })).status).toBe(200);
    expect((await fetch(`${tlsOrigin}/v1/echo`, { redirect: "error" })).status).toBe(200);
    guarded.close();
  });

  it("bounds the body whether the peer declares its length or streams it", async () => {
    const { fetch, lines, guarded } = guard();
    const declared = await refused(fetch(`${tlsOrigin}/v1/large-declared`));
    expect(declared.code).toBe("EGRESS_BODY_TOO_LARGE");
    const streamed = await refused(fetch(`${tlsOrigin}/v1/large-streamed`));
    expect(streamed.code).toBe("EGRESS_BODY_TOO_LARGE");
    expect(refusals(lines)).toEqual([
      [tlsOrigin, "EGRESS_BODY_TOO_LARGE"],
      [tlsOrigin, "EGRESS_BODY_TOO_LARGE"],
    ]);
    const roomy = guard({ maxResponseBytes: 8_192 });
    expect((await roomy.fetch(`${tlsOrigin}/v1/large-streamed`)).status).toBe(200);
    expect(await (await roomy.fetch(`${tlsOrigin}/v1/large-declared`)).text()).toHaveLength(4_000);
    roomy.guarded.close();
    guarded.close();
  });

  it("honours the caller's abort as fetch would, and enforces its own ceiling as a refusal", async () => {
    const { fetch, lines, guarded } = guard();
    await expect(
      fetch(`${tlsOrigin}/v1/slow`, { signal: AbortSignal.timeout(50) }),
    ).rejects.toMatchObject({
      name: "TimeoutError",
    });
    const controller = new AbortController();
    controller.abort();
    await expect(
      fetch(`${tlsOrigin}/v1/echo`, { signal: controller.signal }),
    ).rejects.toMatchObject({
      name: "AbortError",
    });
    const plainReason = new AbortController();
    plainReason.abort("stop");
    await expect(
      fetch(`${tlsOrigin}/v1/echo`, { signal: plainReason.signal }),
    ).rejects.toMatchObject({
      name: "AbortError",
    });
    expect(refusals(lines)).toEqual([]);
    const ceiling = guard({ timeoutMs: 50, lines });
    const late = await refused(ceiling.fetch(`${tlsOrigin}/v1/slow`));
    expect(late.code).toBe("EGRESS_TIMEOUT");
    expect(refusals(lines)).toEqual([[tlsOrigin, "EGRESS_TIMEOUT"]]);
    ceiling.guarded.close();
    guarded.close();
  });

  it("returns a body-less Response for a status that has none, and refuses a status that is not one", async () => {
    const { fetch, lines, guarded } = guard();
    const empty = await fetch(`${tlsOrigin}/v1/empty`);
    expect(empty.status).toBe(204);
    expect(empty.body).toBeNull();
    const odd = await refused(fetch(`${tlsOrigin}/v1/odd-status`));
    expect(odd.code).toBe("EGRESS_RESPONSE_INVALID");
    expect(refusals(lines)).toEqual([[tlsOrigin, "EGRESS_RESPONSE_INVALID"]]);
    guarded.close();
  });
});

describe("GuardedFetch policy", () => {
  it("refuses an unlisted origin, a forbidden scheme, and a path outside the prefix before any socket exists", async () => {
    const resolve = vi.fn(async () => [{ address: "127.0.0.1", family: 4 as const }]);
    const { fetch, lines, guarded } = guard({ resolve });
    const before = connections;
    expect((await refused(fetch("https://elsewhere.example/v1/x"))).code).toBe(
      "EGRESS_ORIGIN_NOT_ALLOWED",
    );
    expect((await refused(fetch("http://authority.decionis.example/v1/x"))).code).toBe(
      "EGRESS_SCHEME_NOT_ALLOWED",
    );
    expect((await refused(fetch("ftp://localhost/v1/x"))).code).toBe("EGRESS_SCHEME_NOT_ALLOWED");
    expect((await refused(fetch(`${tlsOrigin}/admin`))).code).toBe("EGRESS_PATH_NOT_ALLOWED");
    expect((await refused(fetch("not a url"))).code).toBe("EGRESS_ORIGIN_NOT_ALLOWED");
    expect((await refused(fetch(new Request("https://elsewhere.example/v1/x")))).code).toBe(
      "EGRESS_INIT_UNSUPPORTED",
    );
    expect(connections).toBe(before);
    expect(resolve).not.toHaveBeenCalled();
    expect(refusals(lines)).toEqual([
      ["https://elsewhere.example", "EGRESS_ORIGIN_NOT_ALLOWED"],
      ["http://authority.decionis.example", "EGRESS_SCHEME_NOT_ALLOWED"],
      ["ftp://localhost", "EGRESS_SCHEME_NOT_ALLOWED"],
      [tlsOrigin, "EGRESS_PATH_NOT_ALLOWED"],
      [null, "EGRESS_ORIGIN_NOT_ALLOWED"],
      [null, "EGRESS_INIT_UNSUPPORTED"],
    ]);
    guarded.close();
  });

  it("resolves a name once and refuses an answer the policy forbids, so no socket is opened", async () => {
    const named = origin("https", "authority.decionis.example", Number(new URL(tlsOrigin).port));
    const policy = new EgressPolicy([
      { origin: named, pathPrefixes: ["/"], ca: authority.certificate, pins: [] },
    ]);
    const answers: Record<string, { address: string; family: 4 | 6 }[]> = {
      "authority.decionis.example": [{ address: "169.254.169.254", family: 4 }],
    };
    const resolve = vi.fn(async (hostname: string) => answers[hostname] ?? []);
    const { fetch, lines, guarded } = guard({ policy, resolve });
    const before = connections;
    expect((await refused(fetch(`${named}/v1/echo`))).code).toBe("EGRESS_ADDRESS_REFUSED");
    answers["authority.decionis.example"] = [{ address: "127.0.0.1", family: 4 }];
    expect((await refused(fetch(`${named}/v1/echo`))).code).toBe("EGRESS_ADDRESS_REFUSED");
    answers["authority.decionis.example"] = [
      { address: "10.0.0.5", family: 4 },
      { address: "::1", family: 6 },
    ];
    expect((await refused(fetch(`${named}/v1/echo`))).code).toBe("EGRESS_ADDRESS_REFUSED");
    answers["authority.decionis.example"] = [];
    expect((await refused(fetch(`${named}/v1/echo`))).code).toBe("EGRESS_ADDRESS_REFUSED");
    expect(connections).toBe(before);
    expect(resolve).toHaveBeenCalledTimes(4);
    expect(
      resolve.mock.calls.every(([hostname]) => hostname === "authority.decionis.example"),
    ).toBe(true);
    expect(refusals(lines)).toEqual(Array(4).fill([named, "EGRESS_ADDRESS_REFUSED"]));
    resolve.mockRejectedValueOnce(
      Object.assign(new Error("getaddrinfo ENOTFOUND"), { code: "ENOTFOUND" }),
    );
    await expect(fetch(`${named}/v1/echo`)).rejects.toMatchObject({ code: "ENOTFOUND" });
    guarded.close();
  });

  it("connects a loopback origin to what it resolves to, trying each admitted address in order, over TLS and over plain HTTP", async () => {
    // A dual-stack host answers `localhost` with ::1 first; the peers here
    // listen on 127.0.0.1 only, so the first address refuses and the second
    // connects, both from the one resolution.
    const resolve = vi.fn(async (hostname: string) =>
      hostname === "localhost"
        ? [
            { address: "::1", family: 6 as const },
            { address: "127.0.0.1", family: 4 as const },
          ]
        : [],
    );
    const { fetch, lines, guarded } = guard({ resolve });
    expect((await fetch(`${tlsOrigin}/v1/echo`)).status).toBe(200);
    expect(resolve).toHaveBeenCalledWith("localhost");
    expect(resolve).toHaveBeenCalledTimes(1);
    expect((await fetch(`${plainOrigin}/v1/echo`, { method: "PUT", body: "plain" })).status).toBe(
      200,
    );
    expect(seen.at(-1)).toMatchObject({ method: "PUT", body: "plain" });
    expect(refusals(lines)).toEqual([]);
    guarded.close();
  });

  it("sends every body shape a caller may hand it, and refuses one it cannot bound", async () => {
    const { fetch, guarded, lines } = guard();
    await fetch(`${plainOrigin}/v1/echo`, {
      method: "POST",
      body: new TextEncoder().encode("bytes"),
    });
    expect(seen.at(-1)?.body).toBe("bytes");
    await fetch(`${plainOrigin}/v1/echo`, {
      method: "POST",
      body: new TextEncoder().encode("buffer").buffer,
    });
    expect(seen.at(-1)?.body).toBe("buffer");
    await fetch(`${plainOrigin}/v1/echo`, {
      method: "POST",
      body: new URLSearchParams({ a: "1" }),
    });
    expect(seen.at(-1)?.body).toBe("a=1");
    await fetch(`${plainOrigin}/v1/echo`, { method: "POST", body: null });
    expect(seen.at(-1)?.body).toBe("");
    const stream = await refused(
      fetch(`${plainOrigin}/v1/echo`, { method: "POST", body: new ReadableStream() }),
    );
    expect(stream.code).toBe("EGRESS_INIT_UNSUPPORTED");
    expect(refusals(lines)).toEqual([[plainOrigin, "EGRESS_INIT_UNSUPPORTED"]]);
    guarded.close();
  });

  it("checks an injected transport's requests against the policy and watches its answers", async () => {
    const transport = vi.fn(async (input: string | URL | Request) =>
      String(input).includes("away")
        ? new Response(null, { status: 302, headers: { location: "https://elsewhere.example/x" } })
        : new Response('{"ok":true}', { status: 200 }),
    );
    const { fetch, lines, guarded } = guard({ transport });
    expect((await fetch(`${tlsOrigin}/v1/echo`, { method: "POST" })).status).toBe(200);
    expect(transport).toHaveBeenCalledWith(`${tlsOrigin}/v1/echo`, { method: "POST" });
    expect((await fetch(`${tlsOrigin}/v1/away`)).status).toBe(302);
    expect((await refused(fetch("https://elsewhere.example/v1/echo"))).code).toBe(
      "EGRESS_ORIGIN_NOT_ALLOWED",
    );
    expect((await refused(fetch(`${tlsOrigin}/v1/echo`, { redirect: "follow" }))).code).toBe(
      "EGRESS_INIT_UNSUPPORTED",
    );
    expect(transport).toHaveBeenCalledTimes(2);
    expect(refusals(lines)).toEqual([
      [tlsOrigin, "EGRESS_REDIRECT_REFUSED"],
      ["https://elsewhere.example", "EGRESS_ORIGIN_NOT_ALLOWED"],
      [tlsOrigin, "EGRESS_INIT_UNSUPPORTED"],
    ]);
    guarded.close();
  });
});
