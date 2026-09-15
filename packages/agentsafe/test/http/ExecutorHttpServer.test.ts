import { createConnection, createServer } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ExecutorHttpServer } from "../../src/http/ExecutorHttpServer.js";
import { RequestContext } from "../../src/http/RequestContext.js";
import { MAX_BODY_BYTES, RESPONSE_HEADERS, ROUTES } from "../../src/http/Routes.js";
import { SecretHandle } from "../../src/secrets/SecretHandle.js";
import { ServiceError } from "../../src/service/ServiceError.js";
import type { TrustedExecutorService } from "../../src/service/TrustedExecutorService.js";
import { CALLER_TOKEN, LOOPBACK_ORIGIN, collectedEvents } from "../support/Environment.js";
import { legacyAuthenticator, mixedAuthenticator, OPERATOR_TOKEN } from "../support/Principals.js";

const propose = vi.fn();
const reconcile = vi.fn();
const resume = vi.fn();
const halt = vi.fn(() => ({
  halted: true,
  trigger: "OPERATOR",
  reason: "stopping",
  since: "1970-01-01T00:00:00.000Z",
}));
const resumeWork = vi.fn(() => ({ halted: false, trigger: null, reason: null, since: null }));
const openAttempts = vi.fn(() => ({ attempts: [], unknown: 0 }));
const exportEvidence = vi.fn(
  (): Promise<{
    directory: string;
    signature: string | null;
    manifest: Record<string, unknown>;
  }> =>
    Promise.resolve({
      directory: "/var/lib/agent-safe/evidence/2026-03-02T10-00-00-000Z",
      signature: null,
      manifest: { version: "agent-safe.evidence-bundle/1", files: [] },
    }),
);
const readiness = vi.fn(() => ({
  ready: true,
  body: {
    status: "ready",
    mode: "ENFORCEMENT",
    escalation: "NONE",
    actions: ["forward_request"],
    open_attempts: 0,
  } as Record<string, unknown>,
}));
const service = {
  mode: "ENFORCEMENT",
  escalationMode: "NONE",
  actions: ["forward_request"],
  propose,
  reconcile,
  resume,
  readiness,
  halt,
  resumeWork,
  openAttempts,
  exportEvidence,
} as unknown as TrustedExecutorService;

let callerToken = SecretHandle.fromString("EXECUTOR_CALLER_TOKEN", CALLER_TOKEN);
let server: ExecutorHttpServer;
let port = 0;
let baseUrl = "";

interface Reply {
  readonly status: number;
  readonly headers: Headers;
  readonly body: Record<string, unknown>;
}

async function call(
  path: string,
  init: {
    readonly method?: string;
    readonly body?: string;
    readonly token?: string | null;
    readonly authorization?: string;
  } = {},
): Promise<Reply> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  const token = init.token === undefined ? CALLER_TOKEN : init.token;
  if (init.authorization !== undefined) headers["authorization"] = init.authorization;
  else if (token !== null) headers["authorization"] = `Bearer ${token}`;
  const response = await fetch(`${baseUrl}${path}`, {
    method: init.method ?? "POST",
    headers,
    ...(init.body === undefined ? {} : { body: init.body }),
  });
  const text = await response.text();
  return { status: response.status, headers: response.headers, body: JSON.parse(text) };
}

interface RawReply {
  readonly status: number;
  readonly body: string;
}

/**
 * A request written byte by byte and never finished, for the cases a client
 * library would refuse to send. Resolves with whatever the server answered
 * within the timeout, plus a short grace after the headers for the body.
 */
function raw(
  head: string,
  body: string,
  options: { readonly timeoutMs: number },
): Promise<RawReply> {
  return new Promise((resolve) => {
    const socket = createConnection({ host: "127.0.0.1", port });
    let received = "";
    let done = false;
    let grace: ReturnType<typeof setTimeout> | null = null;
    const finish = (): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (grace !== null) clearTimeout(grace);
      socket.destroy();
      const [status = "", ...rest] = received.split("\r\n\r\n");
      resolve({ status: Number(status.split(" ")[1] ?? "0"), body: rest.join("\r\n\r\n") });
    };
    const timer = setTimeout(finish, options.timeoutMs);
    socket.on("data", (chunk: Buffer) => {
      received += chunk.toString("utf8");
      if (received.includes("\r\n\r\n") && grace === null) grace = setTimeout(finish, 250);
    });
    socket.on("close", finish);
    socket.on("connect", () => {
      socket.write(head);
      socket.write(body);
    });
  });
}

describe("ExecutorHttpServer", () => {
  beforeAll(async () => {
    server = new ExecutorHttpServer(
      service,
      legacyAuthenticator(() => callerToken),
    );
    const address = await server.listen(0, "127.0.0.1");
    port = address.port;
    baseUrl = `${LOOPBACK_ORIGIN}:${port}`;
  });
  afterAll(async () => {
    await server.close();
  });
  beforeEach(() => {
    callerToken = SecretHandle.fromString("EXECUTOR_CALLER_TOKEN", CALLER_TOKEN);
    propose.mockReset();
    reconcile.mockReset();
    resume.mockReset();
    propose.mockResolvedValue({ outcome: "COMPLETED" });
    reconcile.mockResolvedValue({ outcome: "COMPLETED", recovered: true });
    resume.mockResolvedValue({ outcome: "ESCALATE_PENDING" });
  });

  it("declares two public routes, three proposer routes, and six operator routes with their scopes", () => {
    expect(ROUTES.map((route) => `${route.method} ${route.path}`)).toEqual([
      "GET /health",
      "GET /ready",
      "POST /v1/actions",
      "POST /v1/reconciliations",
      "POST /v1/escalations",
      "GET /v1/control/status",
      "POST /v1/control/halt",
      "POST /v1/control/resume",
      "GET /v1/control/open-attempts",
      "POST /v1/control/secrets/reload",
      "POST /v1/control/evidence-export",
      "GET /metrics",
    ]);
    expect(ROUTES.filter((route) => route.public).map((route) => route.path)).toEqual([
      "/health",
      "/ready",
    ]);
    expect(
      ROUTES.filter((route) => "role" in route && route.role === "PROPOSER").map(
        (route) => route.path,
      ),
    ).toEqual(["/v1/actions", "/v1/reconciliations", "/v1/escalations"]);
    expect(
      ROUTES.flatMap((route) =>
        "role" in route && route.role === "OPERATOR" ? [`${route.path}:${route.scope}`] : [],
      ),
    ).toEqual([
      "/v1/control/status:status",
      "/v1/control/halt:halt",
      "/v1/control/resume:resume",
      "/v1/control/open-attempts:status",
      "/v1/control/secrets/reload:secrets.reload",
      "/v1/control/evidence-export:evidence",
      "/metrics:metrics",
    ]);
  });

  it("refuses every operator route to the legacy caller, who holds no operator role", async () => {
    for (const [path, method] of [
      ["/metrics", "GET"],
      ["/v1/control/status", "GET"],
      ["/v1/control/halt", "POST"],
      ["/v1/control/resume", "POST"],
      ["/v1/control/open-attempts", "GET"],
      ["/v1/control/secrets/reload", "POST"],
    ] as const) {
      const reply = await call(path, method === "POST" ? { method, body: "{}" } : { method });
      expect([path, reply.status, reply.body]).toEqual([path, 403, { code: "ROLE_FORBIDDEN" }]);
    }
    const anonymous = await call("/metrics", { method: "GET", token: null });
    expect(anonymous.status).toBe(401);
  });

  it("runs each authenticated request inside a scope that names the caller, and reports refusals at the door", async () => {
    const lines: string[] = [];
    const own = new ExecutorHttpServer(
      service,
      legacyAuthenticator(() => callerToken, { events: collectedEvents(lines) }),
    );
    const bound = await own.listen(0, "127.0.0.1");
    propose.mockImplementation(async () => ({
      principal: RequestContext.current()?.principal ?? null,
    }));
    const origin = `${LOOPBACK_ORIGIN}:${bound.port}`;
    const accepted = await fetch(`${origin}/v1/actions`, {
      method: "POST",
      headers: { authorization: `Bearer ${CALLER_TOKEN}`, "content-type": "application/json" },
      body: "{}",
    });
    expect(await accepted.json()).toEqual({ principal: "legacy-caller" });
    expect(RequestContext.current()).toBeNull();
    const anonymous = await fetch(`${origin}/v1/actions`, { method: "POST", body: "{}" });
    expect(anonymous.status).toBe(401);
    const wrong = await fetch(`${origin}/v1/actions`, {
      method: "POST",
      headers: { authorization: "Bearer wrong" },
      body: "{}",
    });
    expect(wrong.status).toBe(401);
    expect(lines.map((line) => JSON.parse(line) as Record<string, unknown>)).toEqual([
      expect.objectContaining({
        event: "AUTH_FAILED",
        method: "bearer",
        code: "CALLER_NOT_AUTHENTICATED",
      }),
      expect.objectContaining({
        event: "AUTH_FAILED",
        method: "bearer",
        code: "CALLER_NOT_AUTHENTICATED",
      }),
    ]);
    own.rotateTls();
    await own.close();
  });

  it("answers health without a token and with every protective header", async () => {
    const reply = await call("/health", { method: "GET", token: null });
    expect(reply.status).toBe(200);
    expect(reply.body).toEqual({ status: "ok" });
    for (const [name, value] of Object.entries(RESPONSE_HEADERS)) {
      expect(reply.headers.get(name)).toBe(value);
    }
  });

  it("reports readiness, the mode, the escalation shape, the actions, and what it does not know", async () => {
    const reply = await call("/ready", { method: "GET", token: null });
    expect(reply.status).toBe(200);
    expect(reply.body).toEqual({
      status: "ready",
      mode: "ENFORCEMENT",
      escalation: "NONE",
      actions: ["forward_request"],
      open_attempts: 0,
    });
  });

  it("hands the operator routes their bodies, and the operator alone", async () => {
    const operated = new ExecutorHttpServer(service, mixedAuthenticator());
    const bound = await operated.listen(0, "127.0.0.1");
    const origin = `${LOOPBACK_ORIGIN}:${bound.port}`;
    const send = async (
      path: string,
      token: string,
      body?: string,
    ): Promise<{ status: number; body: Record<string, unknown> }> => {
      const response = await fetch(`${origin}${path}`, {
        method: body === undefined ? "GET" : "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        ...(body === undefined ? {} : { body }),
      });
      return { status: response.status, body: (await response.json()) as Record<string, unknown> };
    };
    const stopped = await send(
      "/v1/control/halt",
      OPERATOR_TOKEN,
      JSON.stringify({ reason: "stopping" }),
    );
    expect(stopped.status).toBe(200);
    expect(stopped.body).toMatchObject({ halted: true, trigger: "OPERATOR" });
    expect(halt).toHaveBeenCalledWith(
      { reason: "stopping" },
      expect.objectContaining({ id: "synthetic-ops-oncall" }),
    );
    const resumed = await send(
      "/v1/control/resume",
      OPERATOR_TOKEN,
      JSON.stringify({ reason: "cause cleared" }),
    );
    expect(resumed.body).toMatchObject({ halted: false });
    expect(resumeWork).toHaveBeenCalledWith(
      { reason: "cause cleared" },
      expect.objectContaining({ id: "synthetic-ops-oncall" }),
    );
    expect((await send("/v1/control/open-attempts", OPERATOR_TOKEN)).body).toEqual({
      attempts: [],
      unknown: 0,
    });
    // The proposer holds no operator scope, and its own route still works.
    expect((await send("/v1/control/halt", CALLER_TOKEN, "{}")).body).toEqual({
      code: "ROLE_FORBIDDEN",
    });
    propose.mockResolvedValueOnce({ outcome: "COMPLETED" });
    expect((await send("/v1/actions", CALLER_TOKEN, "{}")).status).toBe(200);
    await operated.close();
  });

  it("returns a bundle's manifest and where it was written, never its files", async () => {
    const operated = new ExecutorHttpServer(service, mixedAuthenticator(), { tls: null });
    const bound = await operated.listen(0, "127.0.0.1");
    const origin = `${LOOPBACK_ORIGIN}:${bound.port}`;
    const post = async (
      token: string,
      body: string,
    ): Promise<{ status: number; body: Record<string, unknown> }> => {
      const response = await fetch(`${origin}/v1/control/evidence-export`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body,
      });
      return { status: response.status, body: (await response.json()) as Record<string, unknown> };
    };
    const exported = await post(OPERATOR_TOKEN, JSON.stringify({ reason: "on-call took one" }));
    expect(exported.status).toBe(200);
    expect(exported.body).toEqual({
      directory: "/var/lib/agent-safe/evidence/2026-03-02T10-00-00-000Z",
      signed: false,
      manifest: { version: "agent-safe.evidence-bundle/1", files: [] },
    });
    expect(exportEvidence).toHaveBeenCalledWith(
      { reason: "on-call took one" },
      expect.objectContaining({ id: "synthetic-ops-oncall" }),
    );
    // Signed is the manifest's own fact, reported rather than assumed.
    exportEvidence.mockResolvedValueOnce({
      directory: "/evidence/one",
      signature: "eyJ.signed.value",
      manifest: { version: "agent-safe.evidence-bundle/1", files: [] },
    });
    const signed = await post(OPERATOR_TOKEN, JSON.stringify({ reason: "again" }));
    expect(signed.body["signed"]).toBe(true);
    // The signature itself is not in the answer: it is a file in the bundle.
    expect(JSON.stringify(signed.body)).not.toContain("eyJ.signed.value");
    // A proposer cannot ask, and a refusal from the service is passed through.
    expect((await post(CALLER_TOKEN, "{}")).body).toEqual({ code: "ROLE_FORBIDDEN" });
    exportEvidence.mockRejectedValueOnce(new ServiceError(409, "EVIDENCE_DIR_NOT_CONFIGURED"));
    const refused = await post(OPERATOR_TOKEN, JSON.stringify({ reason: "nowhere to write" }));
    expect([refused.status, refused.body["code"]]).toEqual([409, "EVIDENCE_DIR_NOT_CONFIGURED"]);
    await operated.close();
  });

  it("answers a halted refusal in the shape the caller parses, with the seconds to wait", async () => {
    propose.mockRejectedValueOnce(
      new ServiceError(
        503,
        "EXECUTOR_HALTED",
        { verdict: "BLOCK", outcome: "BLOCKED", reason_codes: ["EXECUTOR_HALTED"] },
        30,
      ),
    );
    const refused = await call("/v1/actions", { body: "{}" });
    expect(refused.status).toBe(503);
    expect(refused.headers.get("retry-after")).toBe("30");
    expect(refused.body).toEqual({
      verdict: "BLOCK",
      outcome: "BLOCKED",
      reason_codes: ["EXECUTOR_HALTED"],
    });
    // A refusal with no body of its own is still just a code, and no
    // Retry-After is invented for it.
    propose.mockRejectedValueOnce(new ServiceError(422, "HARD_LIMIT_EXCEEDED"));
    const limited = await call("/v1/actions", { body: "{}" });
    expect(limited.status).toBe(422);
    expect(limited.body).toEqual({ code: "HARD_LIMIT_EXCEEDED" });
    expect(limited.headers.get("retry-after")).toBeNull();
  });

  it("answers readiness with 503 while halted, and liveness with 200 all the same", async () => {
    readiness.mockReturnValueOnce({
      ready: false,
      body: { status: "halted", halt: { trigger: "OPERATOR", since: "1970-01-01T00:00:00.000Z" } },
    });
    const halted = await call("/ready", { method: "GET", token: null });
    expect(halted.status).toBe(503);
    expect(halted.body).toMatchObject({ status: "halted" });
    expect((await call("/health", { method: "GET", token: null })).status).toBe(200);
  });

  it("refuses an unknown route and a wrong method with the same headers", async () => {
    const missing = await call("/v1/nothing", { method: "GET", token: null });
    expect(missing.status).toBe(404);
    expect(missing.body).toEqual({ code: "NOT_FOUND" });
    expect(missing.headers.get("x-frame-options")).toBe("DENY");
    const wrongMethod = await call("/health", { method: "POST", token: null });
    expect(wrongMethod.status).toBe(405);
    expect(wrongMethod.body).toEqual({ code: "METHOD_NOT_ALLOWED" });
    const wrongMethodTwo = await call("/v1/actions", { method: "GET" });
    expect(wrongMethodTwo.status).toBe(405);
  });

  it("refuses a caller without the token, with the wrong token, or with another scheme", async () => {
    const body = JSON.stringify({ proposal: {} });
    const anonymous = await call("/v1/actions", { body, token: null });
    const wrong = await call("/v1/actions", { body, token: "not-it" });
    const basic = await call("/v1/actions", { body, authorization: `Basic ${CALLER_TOKEN}` });
    // Seven characters like "Bearer ", so only the scheme itself can refuse it.
    const scheme = await call("/v1/actions", { body, authorization: `Token: ${CALLER_TOKEN}` });
    const empty = await call("/v1/actions", { body, authorization: "Bearer " });
    for (const reply of [anonymous, wrong, basic, scheme, empty]) {
      expect(reply.status).toBe(401);
      expect(reply.body).toEqual({ code: "CALLER_NOT_AUTHENTICATED" });
      expect(reply.headers.get("content-security-policy")).toBe(
        RESPONSE_HEADERS["content-security-policy"],
      );
    }
    expect(propose).not.toHaveBeenCalled();
  });

  it("accepts the token with surrounding whitespace", async () => {
    const reply = await call("/v1/actions", {
      body: JSON.stringify({ proposal: {} }),
      authorization: `Bearer  ${CALLER_TOKEN} `,
    });
    expect(reply.status).toBe(200);
    expect(propose).toHaveBeenCalledOnce();
  });

  it("honours a rotated token from the next request and refuses the old one", async () => {
    const body = JSON.stringify({ proposal: {} });
    expect((await call("/v1/actions", { body })).status).toBe(200);
    callerToken = SecretHandle.fromString("EXECUTOR_CALLER_TOKEN", "synthetic-rotated-token-0000");
    expect((await call("/v1/actions", { body })).status).toBe(401);
    expect(
      (await call("/v1/actions", { body, token: "synthetic-rotated-token-0000" })).status,
    ).toBe(200);
  });

  it("hands each authenticated route its parsed body and returns the service's answer", async () => {
    const actions = await call("/v1/actions", { body: JSON.stringify({ proposal: { a: 1 } }) });
    expect(actions.status).toBe(200);
    expect(actions.body).toEqual({ outcome: "COMPLETED" });
    expect(propose).toHaveBeenCalledWith(
      { proposal: { a: 1 } },
      expect.objectContaining({ id: "legacy-caller" }),
    );
    const reconciliations = await call("/v1/reconciliations", {
      body: JSON.stringify({ intent: {}, reference: {} }),
    });
    expect(reconciliations.body).toEqual({ outcome: "COMPLETED", recovered: true });
    expect(reconcile).toHaveBeenCalledWith(
      { intent: {}, reference: {} },
      expect.objectContaining({ id: "legacy-caller" }),
    );
    const escalations = await call("/v1/escalations", { body: JSON.stringify({ mode: "DIRECT" }) });
    expect(escalations.body).toEqual({ outcome: "ESCALATE_PENDING" });
    expect(resume).toHaveBeenCalledWith(
      { mode: "DIRECT" },
      expect.objectContaining({ id: "legacy-caller" }),
    );
  });

  it("maps a refusal the service meant to its status and code, and nothing else", async () => {
    propose.mockRejectedValueOnce(new ServiceError(422, "ACTION_NOT_REGISTERED"));
    const refused = await call("/v1/actions", { body: JSON.stringify({ proposal: {} }) });
    expect(refused.status).toBe(422);
    expect(refused.body).toEqual({ code: "ACTION_NOT_REGISTERED" });
  });

  it("answers an unexpected failure with a bare internal error", async () => {
    propose.mockRejectedValueOnce(new Error("the provider said something sensitive"));
    const failed = await call("/v1/actions", { body: JSON.stringify({ proposal: {} }) });
    expect(failed.status).toBe(500);
    expect(failed.body).toEqual({ code: "INTERNAL_ERROR" });
  });

  it("refuses an empty, blank, or malformed body without an echo", async () => {
    const empty = await call("/v1/actions", { body: "" });
    expect(empty.status).toBe(400);
    expect(empty.body).toEqual({ code: "BODY_REQUIRED" });
    const blank = await call("/v1/actions", { body: "  \n " });
    expect(blank.status).toBe(400);
    expect(blank.body).toEqual({ code: "BODY_REQUIRED" });
    const malformed = await call("/v1/actions", { body: "{not json" });
    expect(malformed.status).toBe(400);
    expect(malformed.body).toEqual({ code: "BODY_NOT_JSON" });
    expect(propose).not.toHaveBeenCalled();
  });

  it("accepts a body of exactly the limit and refuses one byte more", async () => {
    const frame = '{"pad":""}';
    const exact = `{"pad":"${"x".repeat(MAX_BODY_BYTES - frame.length)}"}`;
    expect(Buffer.byteLength(exact)).toBe(MAX_BODY_BYTES);
    const accepted = await call("/v1/actions", { body: exact });
    expect(accepted.status).toBe(200);
    const refused = await call("/v1/actions", { body: `${exact} ` });
    expect(refused.status).toBe(413);
    expect(refused.body).toEqual({ code: "BODY_TOO_LARGE" });
  });

  it("refuses an oversized declared body before reading it", async () => {
    const head =
      `POST /v1/actions HTTP/1.1\r\nHost: executor.invalid\r\n` +
      `Authorization: Bearer ${CALLER_TOKEN}\r\nContent-Type: application/json\r\n` +
      `Content-Length: ${MAX_BODY_BYTES * 2}\r\n\r\n`;
    const response = await raw(head, '{"partial":true}', { timeoutMs: 2_000 });
    expect(response.status).toBe(413);
    expect(response.body).toContain("BODY_TOO_LARGE");
    expect(propose).not.toHaveBeenCalled();
  });

  it("refuses an oversized streamed body once the limit is crossed", async () => {
    const chunk = "x".repeat(64 * 1024);
    const head =
      `POST /v1/actions HTTP/1.1\r\nHost: executor.invalid\r\n` +
      `Authorization: Bearer ${CALLER_TOKEN}\r\nContent-Type: application/json\r\n` +
      `Transfer-Encoding: chunked\r\n\r\n`;
    const chunked = `${chunk.length.toString(16)}\r\n${chunk}\r\n`.repeat(2);
    const response = await raw(head, chunked, { timeoutMs: 2_000 });
    expect(response.status).toBe(413);
    expect(response.body).toContain("BODY_TOO_LARGE");
    expect(propose).not.toHaveBeenCalled();
  });

  it("rejects listening on a port that is taken, and refuses connections once closed", async () => {
    const taken = createServer();
    await new Promise<void>((resolve) => taken.listen(0, "127.0.0.1", () => resolve()));
    const address = taken.address();
    const takenPort = typeof address === "object" && address !== null ? address.port : 0;
    const second = new ExecutorHttpServer(
      service,
      legacyAuthenticator(() => callerToken),
    );
    await expect(second.listen(takenPort, "127.0.0.1")).rejects.toThrow();
    await new Promise<void>((resolve) => taken.close(() => resolve()));

    const third = new ExecutorHttpServer(
      service,
      legacyAuthenticator(() => callerToken),
    );
    const bound = await third.listen(0, "127.0.0.1");
    await third.close();
    await expect(fetch(`${LOOPBACK_ORIGIN}:${bound.port}/health`)).rejects.toThrow();
  });
});

describe("ExecutorHttpServer shutdown", () => {
  it("closes promptly even while a request is still being read", async () => {
    const own = new ExecutorHttpServer(
      service,
      legacyAuthenticator(() => callerToken),
    );
    const bound = await own.listen(0, "127.0.0.1");
    const active = createConnection({ host: "127.0.0.1", port: bound.port });
    active.on("error", () => undefined);
    await new Promise<void>((resolve) => active.once("connect", () => resolve()));
    // Headers complete, body never arrives: the server is inside the read.
    active.write(
      `POST /v1/actions HTTP/1.1\r\nHost: executor.invalid\r\n` +
        `Authorization: Bearer ${CALLER_TOKEN}\r\nContent-Type: application/json\r\n` +
        `Content-Length: 100\r\n\r\n{"partial":`,
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("close waited for the open request")), 1_500);
    });
    deadline.catch(() => undefined);
    await Promise.race([own.close(), deadline]);
    clearTimeout(timer);
    active.destroy();
  });
});
