import { createConnection, createServer } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ExecutorHttpServer } from "../../src/http/ExecutorHttpServer.js";
import { MAX_BODY_BYTES, RESPONSE_HEADERS, ROUTES } from "../../src/http/Routes.js";
import { ServiceError } from "../../src/service/ServiceError.js";
import type { TrustedExecutorService } from "../../src/service/TrustedExecutorService.js";
import { CALLER_TOKEN, LOOPBACK_ORIGIN } from "../support/Environment.js";

const propose = vi.fn();
const reconcile = vi.fn();
const resume = vi.fn();
const service = {
  mode: "ENFORCEMENT",
  escalationMode: "NONE",
  actions: ["forward_request"],
  propose,
  reconcile,
  resume,
} as unknown as TrustedExecutorService;

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
    server = new ExecutorHttpServer(service, CALLER_TOKEN);
    const address = await server.listen(0, "127.0.0.1");
    port = address.port;
    baseUrl = `${LOOPBACK_ORIGIN}:${port}`;
  });
  afterAll(async () => {
    await server.close();
  });
  beforeEach(() => {
    propose.mockReset();
    reconcile.mockReset();
    resume.mockReset();
    propose.mockResolvedValue({ outcome: "COMPLETED" });
    reconcile.mockResolvedValue({ outcome: "COMPLETED", recovered: true });
    resume.mockResolvedValue({ outcome: "ESCALATE_PENDING" });
  });

  it("declares two public routes and three authenticated ones", () => {
    expect(ROUTES.map((route) => `${route.method} ${route.path}`)).toEqual([
      "GET /health",
      "GET /ready",
      "POST /v1/actions",
      "POST /v1/reconciliations",
      "POST /v1/escalations",
    ]);
    expect(ROUTES.filter((route) => route.public).map((route) => route.path)).toEqual([
      "/health",
      "/ready",
    ]);
  });

  it("answers health without a token and with every protective header", async () => {
    const reply = await call("/health", { method: "GET", token: null });
    expect(reply.status).toBe(200);
    expect(reply.body).toEqual({ status: "ok" });
    for (const [name, value] of Object.entries(RESPONSE_HEADERS)) {
      expect(reply.headers.get(name)).toBe(value);
    }
  });

  it("reports readiness, the mode, the escalation shape, and the actions", async () => {
    const reply = await call("/ready", { method: "GET", token: null });
    expect(reply.status).toBe(200);
    expect(reply.body).toEqual({
      status: "ready",
      mode: "ENFORCEMENT",
      escalation: "NONE",
      actions: ["forward_request"],
    });
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

  it("hands each authenticated route its parsed body and returns the service's answer", async () => {
    const actions = await call("/v1/actions", { body: JSON.stringify({ proposal: { a: 1 } }) });
    expect(actions.status).toBe(200);
    expect(actions.body).toEqual({ outcome: "COMPLETED" });
    expect(propose).toHaveBeenCalledWith({ proposal: { a: 1 } });
    const reconciliations = await call("/v1/reconciliations", {
      body: JSON.stringify({ intent: {}, reference: {} }),
    });
    expect(reconciliations.body).toEqual({ outcome: "COMPLETED", recovered: true });
    expect(reconcile).toHaveBeenCalledWith({ intent: {}, reference: {} });
    const escalations = await call("/v1/escalations", { body: JSON.stringify({ mode: "DIRECT" }) });
    expect(escalations.body).toEqual({ outcome: "ESCALATE_PENDING" });
    expect(resume).toHaveBeenCalledWith({ mode: "DIRECT" });
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
    const second = new ExecutorHttpServer(service, CALLER_TOKEN);
    await expect(second.listen(takenPort, "127.0.0.1")).rejects.toThrow();
    await new Promise<void>((resolve) => taken.close(() => resolve()));

    const third = new ExecutorHttpServer(service, CALLER_TOKEN);
    const bound = await third.listen(0, "127.0.0.1");
    await third.close();
    await expect(fetch(`${LOOPBACK_ORIGIN}:${bound.port}/health`)).rejects.toThrow();
  });
});

describe("ExecutorHttpServer shutdown", () => {
  it("closes promptly even while a request is still being read", async () => {
    const own = new ExecutorHttpServer(service, CALLER_TOKEN);
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
