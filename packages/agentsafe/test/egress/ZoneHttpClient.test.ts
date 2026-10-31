import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { zoneHttp } from "../../src/egress/ZoneHttpClient.js";

const LOOPBACK_URL = "http://127.0.0.1";

describe("zoneHttp", () => {
  let server: Server;
  let base: string;
  const seen: { method: string; url: string; headers: IncomingHttpHeaders; body: string }[] = [];

  beforeAll(async () => {
    server = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        seen.push({
          method: request.method ?? "",
          url: request.url ?? "",
          headers: request.headers,
          body: Buffer.concat(chunks).toString(),
        });
        if (request.url === "/slow") return;
        if (request.url === "/redirect") {
          response.writeHead(302, { location: "/elsewhere" });
          response.end();
          return;
        }
        if (request.url === "/broken") {
          response.writeHead(200, { "content-length": "100" });
          response.write("partial");
          response.socket?.destroy();
          return;
        }
        response.writeHead(201, { "content-type": "text/plain" });
        response.end("0123456789");
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const address = server.address();
    base = `${LOOPBACK_URL}:${typeof address === "object" && address !== null ? address.port : 0}`;
  });

  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const request = (path: string, overrides: Partial<Parameters<typeof zoneHttp>[0]> = {}) =>
    zoneHttp({
      method: "GET",
      url: `${base}${path}`,
      headers: {},
      body: null,
      timeoutMs: 2_000,
      maxBodyBytes: 64,
      ...overrides,
    });

  it("answers with the status and the body, sending only the headers it is given", async () => {
    expect(await request("/plain", { headers: { "x-probe": "one" } })).toEqual({
      status: 201,
      body: "0123456789",
    });
    const sent = seen.at(-1);
    expect(sent?.headers["x-probe"]).toBe("one");
    expect(Object.keys(sent?.headers ?? {}).sort()).toEqual(["connection", "host", "x-probe"]);
  });

  it("sends a body with its length, and the method it is given", async () => {
    await request("/write", { method: "PATCH", body: '{"blocked":"ü"}' });
    expect(seen.at(-1)).toMatchObject({
      method: "PATCH",
      body: '{"blocked":"ü"}',
      headers: { "content-length": "16" },
    });
  });

  it("reads at most the bytes it is told to, and none when told none", async () => {
    expect(await request("/plain", { maxBodyBytes: 4 })).toEqual({ status: 201, body: "0123" });
    expect(await request("/plain", { maxBodyBytes: 0 })).toEqual({ status: 201, body: "" });
  });

  it("follows no redirect", async () => {
    expect((await request("/redirect")).status).toBe(302);
    expect(seen.at(-1)?.url).toBe("/redirect");
  });

  it("names a failure by its code: a timeout, a refusal, a broken answer", async () => {
    await expect(request("/slow", { timeoutMs: 50 })).rejects.toMatchObject({ code: "ETIMEDOUT" });
    await expect(
      zoneHttp({
        method: "GET",
        url: "http://127.0.0.1:9/",
        headers: {},
        body: null,
        timeoutMs: 2_000,
        maxBodyBytes: 0,
      }),
    ).rejects.toMatchObject({ code: "ECONNREFUSED" });
    await expect(request("/broken", { maxBodyBytes: 1_000 })).rejects.toMatchObject({
      code: expect.stringMatching(/^E[A-Z]+$/) as string,
    });
  });

  it("speaks TLS to an https URL", async () => {
    await expect(
      zoneHttp({
        method: "GET",
        url: base.replace("http:", "https:"),
        headers: {},
        body: null,
        timeoutMs: 2_000,
        maxBodyBytes: 0,
      }),
    ).rejects.toMatchObject({ code: expect.stringMatching(/^E[A-Z_]+$/) as string });
  });
});
