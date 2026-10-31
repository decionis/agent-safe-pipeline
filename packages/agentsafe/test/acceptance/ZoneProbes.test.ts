import type * as Crypto from "node:crypto";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import {
  createServer,
  request as httpRequest,
  type IncomingHttpHeaders,
  type Server,
  type ServerResponse,
} from "node:http";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CREDENTIAL_KINDS,
  METADATA_URL,
  ZONE_LIMITS,
  probeMcp,
  probeMetadata,
  probeOrigin,
  probeProvider,
  scanCredentials,
  zoneFindingsSchema,
  type CredentialFinding,
  type ProviderTarget,
  type ZoneDial,
  type ZoneFindings,
  type ZoneHttp,
  type ZoneRequest,
  type ZoneResponse,
} from "../../src/acceptance/ZoneProbes.js";
import { SignedRequestCredential } from "../../src/credential/SignedRequestCredential.js";
import { dial } from "../../src/egress/TcpProbe.js";
import { refusalBody, verifyProviderRequest } from "../../src/verify/VerifyingProvider.js";

// Every Ed25519 key the module generates passes through here, so a test can
// check the signature it made with the public half the module never exports.
const generated = vi.hoisted(() => ({ publicKeys: [] as string[] }));
vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof Crypto>();
  const original = actual.generateKeyPairSync as unknown as (...args: unknown[]) => {
    publicKey: KeyObject;
    privateKey: KeyObject;
  };
  return {
    ...actual,
    generateKeyPairSync: (...args: unknown[]) => {
      const pair = original(...args);
      generated.publicKeys.push(String(pair.publicKey.export({ type: "spki", format: "pem" })));
      return pair;
    },
  };
});

const LOOPBACK = "127.0.0.1";
const LOOPBACK_URL = "http://127.0.0.1";
const NOW = "2026-10-31T12:00:00.000Z";
const clock = (): Date => new Date(NOW);

interface Seen {
  readonly method: string;
  readonly url: string;
  readonly headers: IncomingHttpHeaders;
  readonly body: string;
}

interface Loopback {
  readonly url: string;
  readonly port: number;
  readonly seen: Seen[];
}

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers
      .splice(0)
      .map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
  );
});

beforeEach(() => {
  generated.publicKeys.length = 0;
});

/** A loopback HTTP server that records every request and answers with `answer`. */
async function serve(answer: (seen: Seen, response: ServerResponse) => void): Promise<Loopback> {
  const seen: Seen[] = [];
  const server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const entry = {
        method: request.method ?? "",
        url: request.url ?? "",
        headers: request.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      seen.push(entry);
      answer(entry, response);
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, LOOPBACK, resolve));
  const port = (server.address() as { port: number }).port;
  return { url: `${LOOPBACK_URL}:${String(port)}`, port, seen };
}

const status =
  (code: number, body = "") =>
  (_seen: Seen, response: ServerResponse): void => {
    response.writeHead(code, { "content-type": "application/json" });
    response.end(body);
  };

/** A port nothing listens on: loopback answers it with an RST. */
async function closedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, LOOPBACK, resolve));
  const port = (server.address() as { port: number }).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

/**
 * A client of the shape `ZoneHttp` asks for, over `node:http`: a fresh agent
 * per request (so no proxy the environment names), no redirect followed, a
 * timeout that rejects with `ETIMEDOUT`, and at most `maxBodyBytes` read.
 */
const loopbackHttp: ZoneHttp = (zoneRequest) =>
  new Promise<ZoneResponse>((resolve, reject) => {
    const request = httpRequest(
      zoneRequest.url,
      { method: zoneRequest.method, headers: zoneRequest.headers, agent: false },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          const room = zoneRequest.maxBodyBytes - size;
          if (room <= 0) return;
          chunks.push(chunk.subarray(0, room));
          size += Math.min(room, chunk.length);
        });
        response.on("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
      },
    );
    request.setTimeout(zoneRequest.timeoutMs, () =>
      request.destroy(Object.assign(new Error("timed out"), { code: "ETIMEDOUT" })),
    );
    request.on("error", reject);
    request.end(zoneRequest.body ?? undefined);
  });

/** Records every request a probe makes, and answers each with `answer`. */
function recording(answer: (request: ZoneRequest) => Promise<ZoneResponse>): {
  readonly http: ZoneHttp;
  readonly requests: ZoneRequest[];
} {
  const requests: ZoneRequest[] = [];
  return {
    requests,
    http: async (request) => {
      requests.push(request);
      return await answer(request);
    },
  };
}

const answering =
  (code: number, body = "") =>
  async (): Promise<ZoneResponse> =>
    await Promise.resolve({ status: code, body });

const coded = (code: unknown, message = "failed"): Error =>
  Object.assign(new Error(message), { code });

const failing = (error: unknown) => async (): Promise<ZoneResponse> =>
  await Promise.reject(error as Error);

const silent: ZoneDial = async () => await Promise.resolve({ state: "TIMED_OUT" });
const connected: ZoneDial = async () => await Promise.resolve({ state: "CONNECTED" });

describe("probeOrigin", () => {
  it("reads directly with nothing of the gateway's, and through the gateway with its path and query", async () => {
    const origin = await serve(status(403));
    const gateway = await serve(status(200));
    const { http, requests } = recording(loopbackHttp);
    const finding = await probeOrigin(
      { name: "ledger", url: `${origin.url}/v1/accounts/canary?view=balance#top` },
      {
        dial,
        http,
        clock,
        timeoutMs: 1_500,
        gateway: `${gateway.url}/tenant/`,
        gatewayHeaders: { "agentsafe-tenant-key": "tenant-key-label" },
      },
    );
    // Any HTTP answer from the origin is a hole, a 403 included: the packet
    // got there, and something answered it.
    expect(finding).toEqual({
      name: "ledger",
      address: `${LOOPBACK}:${String(origin.port)}`,
      direct: { status: 403, detail: "ANSWERED" },
      control: { status: 200, detail: "ANSWERED" },
      verdict: "REACHABLE",
      at: NOW,
    });
    expect(requests).toEqual([
      {
        method: "GET",
        url: `${origin.url}/v1/accounts/canary?view=balance#top`,
        headers: {},
        body: null,
        timeoutMs: 1_500,
        maxBodyBytes: 0,
      },
      {
        method: "GET",
        url: `${gateway.url}/tenant/v1/accounts/canary?view=balance`,
        headers: { "agentsafe-tenant-key": "tenant-key-label" },
        body: null,
        timeoutMs: 1_500,
        maxBodyBytes: 0,
      },
    ]);
    expect(origin.seen.map((seen) => [seen.method, seen.url])).toEqual([
      ["GET", "/v1/accounts/canary?view=balance"],
    ]);
    expect(Object.keys(origin.seen[0]!.headers).sort()).toEqual(["connection", "host"]);
    expect(gateway.seen.map((seen) => seen.url)).toEqual([
      "/tenant/v1/accounts/canary?view=balance",
    ]);
    expect(gateway.seen[0]!.headers["agentsafe-tenant-key"]).toBe("tenant-key-label");
  });

  it("joins the gateway's path whether or not it ends in a slash, and sends no headers it was not given", async () => {
    const { http, requests } = recording(answering(200));
    for (const gateway of ["http://gateway.example", "http://gateway.example/base"]) {
      await probeOrigin(
        { name: "ledger", url: "http://ledger.example/v1/read?x=1" },
        { dial: connected, http, clock, gateway },
      );
    }
    expect(requests.filter((_, index) => index % 2 === 1)).toEqual([
      expect.objectContaining({ url: "http://gateway.example/v1/read?x=1", headers: {} }),
      expect.objectContaining({ url: "http://gateway.example/base/v1/read?x=1", headers: {} }),
    ]);
  });

  it("counts an RST as an answer, and sends no read where the dial was refused", async () => {
    const port = await closedPort();
    const { http, requests } = recording(answering(200));
    const finding = await probeOrigin(
      { name: "ledger", url: `${LOOPBACK_URL}:${String(port)}/v1/read` },
      { dial, http, clock, timeoutMs: 2_000, gateway: "http://gateway.example" },
    );
    expect(finding.verdict).toBe("REACHABLE");
    expect(finding.direct).toEqual({ status: null, detail: "REFUSED_NOT_DROPPED" });
    expect(requests.map((request) => request.url)).toEqual(["http://gateway.example/v1/read"]);
  });

  it("calls a connection that answered a hole even when the read after it failed", async () => {
    const { http } = recording(failing(coded("ECONNRESET", "reset by origin.internal")));
    const finding = await probeOrigin(
      { name: "ledger", url: "http://ledger.example/v1/read" },
      { dial: connected, http, clock, gateway: "http://gateway.example" },
    );
    expect(finding.verdict).toBe("REACHABLE");
    expect(finding.direct).toEqual({ status: null, detail: "ECONNRESET" });
    expect(finding.control).toEqual({ status: null, detail: "ECONNRESET" });
    expect(JSON.stringify(finding)).not.toContain("origin.internal");
  });

  it("calls silence contained only when the gateway's path answered 2xx", async () => {
    const run = async (dialled: ZoneDial, answer: () => Promise<ZoneResponse>) =>
      await probeOrigin(
        { name: "ledger", url: "http://ledger.example/v1/read" },
        { dial: dialled, http: recording(answer).http, clock, gateway: "http://gateway.example" },
      );
    const timedOut = await run(silent, answering(200));
    expect(timedOut).toMatchObject({
      direct: { status: null, detail: "TIMED_OUT" },
      control: { status: 200, detail: "ANSWERED" },
      verdict: "CONTAINED",
    });
    const unreachable: ZoneDial = async () =>
      await Promise.resolve({ state: "UNREACHABLE", code: "EHOSTUNREACH" });
    expect(await run(unreachable, answering(299))).toMatchObject({
      direct: { status: null, detail: "EHOSTUNREACH" },
      verdict: "CONTAINED",
    });
    // A control that did not succeed cannot tell a drop from an outage.
    for (const control of [199, 300, 403, 503]) {
      expect((await run(silent, answering(control))).verdict).toBe("INCONCLUSIVE");
    }
    const failed = await run(silent, failing(coded("ECONNREFUSED")));
    expect(failed.control).toEqual({ status: null, detail: "ECONNREFUSED" });
    expect(failed.verdict).toBe("INCONCLUSIVE");
  });

  it("calls a name that did not resolve inconclusive, whatever the control did", async () => {
    const unresolved: ZoneDial = async () =>
      await Promise.resolve({ state: "UNRESOLVED", code: "ENOTFOUND" });
    const { http, requests } = recording(answering(200));
    const finding = await probeOrigin(
      { name: "ledger", url: "http://ledger.example/v1/read" },
      { dial: unresolved, http, clock, gateway: "http://gateway.example" },
    );
    expect(finding.direct).toEqual({ status: null, detail: "ENOTFOUND" });
    expect(finding.verdict).toBe("INCONCLUSIVE");
    expect(requests).toHaveLength(1);
  });

  it("keeps a code and nothing else of a failure", async () => {
    const run = async (error: unknown, dialled: ZoneDial = connected) =>
      (
        await probeOrigin(
          { name: "ledger", url: "http://ledger.example/v1/read" },
          {
            dial: dialled,
            http: recording(failing(error)).http,
            clock,
            gateway: "http://g.example",
          },
        )
      ).direct.detail;
    expect(await run(coded("E"))).toBe("E");
    expect(await run(coded("E".repeat(64)))).toBe("E".repeat(64));
    expect(await run(coded(`ERR_TLS_${"X".repeat(48)}_9`))).toBe(`ERR_TLS_${"X".repeat(48)}_9`);
    for (const error of [
      new Error("no code at all"),
      coded("connect failed: secret.internal"),
      coded("econnreset"),
      coded("9E"),
      coded(" ECONNRESET"),
      coded("ECONNRESET "),
      coded("E".repeat(65)),
      coded(["ECONNRESET"]),
      null,
      undefined,
    ]) {
      expect(await run(error)).toBe("UNKNOWN");
    }
    const strange: ZoneDial = async () =>
      await Promise.resolve({ state: "OTHER", code: "weird: secret.internal" });
    expect(await run(null, strange)).toBe("UNKNOWN");
  });

  it("dials the host and port the URL names", async () => {
    const dialled: string[] = [];
    const recordDial: ZoneDial = async (host, port, timeoutMs) => {
      dialled.push(`${host}|${String(port)}|${String(timeoutMs)}`);
      return await Promise.resolve({ state: "TIMED_OUT" });
    };
    const addresses: string[] = [];
    for (const url of [
      "https://ledger.example/x",
      "http://ledger.example/x",
      "http://[::1]:8443/x",
    ]) {
      const finding = await probeOrigin(
        { name: "ledger", url },
        { dial: recordDial, http: recording(answering(200)).http, gateway: "http://g.example" },
      );
      addresses.push(finding.address);
    }
    expect(dialled).toEqual(["ledger.example|443|5000", "ledger.example|80|5000", "::1|8443|5000"]);
    expect(addresses).toEqual(["ledger.example:443", "ledger.example:80", "[::1]:8443"]);
  });

  it("defaults the timeout and the clock", async () => {
    const { http, requests } = recording(answering(200));
    const finding = await probeOrigin(
      { name: "ledger", url: "http://ledger.example/x" },
      { dial: connected, http, gateway: "http://g.example" },
    );
    expect(requests.map((request) => request.timeoutMs)).toEqual([5_000, 5_000]);
    expect(Date.parse(finding.at)).not.toBeNaN();
  });

  it("refuses a target it cannot probe without a credential, and never names the URL", async () => {
    const password = ["planted", "pass", "word"].join("-");
    const options = {
      dial: connected,
      http: recording(answering(200)).http,
      gateway: "http://g.example",
    };
    for (const url of [
      "not a url",
      "ftp://ledger.example/x",
      `http://agent:${password}@ledger.example/x`,
      `http://:${password}@ledger.example/x`,
      `https://${password}@ledger.example/x`,
    ]) {
      const error = await probeOrigin({ name: "ledger", url }, options).catch(
        (caught: unknown) => caught,
      );
      expect(error).toEqual(new Error("ZONE_TARGET_INVALID: ledger"));
    }
    await expect(
      probeOrigin(
        { name: "ledger", url: "http://ledger.example/x" },
        { ...options, gateway: "gateway" },
      ),
    ).rejects.toThrow(/^ZONE_TARGET_INVALID: gateway$/);
  });
});

describe("probeProvider", () => {
  const executor = generateKeyPairSync("ed25519");
  const providerOptions = {
    effects: true,
    // The executor's real key: the provider knows it, and the zone never holds it.
    executorKeys: [
      {
        keyId: "executor",
        algorithm: "ed25519" as const,
        publicKeyPem: String(executor.publicKey.export({ type: "spki", format: "pem" })),
      },
    ],
    authorityJwks: { keys: [] },
    authorityIssuer: "https://decionis.example",
    clockWindowSeconds: 300,
    replay: { record: () => true },
    now: () => Date.parse(NOW),
  };

  const flat = (headers: IncomingHttpHeaders): Record<string, string> =>
    Object.fromEntries(Object.entries(headers).map(([name, value]) => [name, String(value)]));

  /** A verifying provider at the reference procedure, refusing as the profile says. */
  const verifying = (seen: Seen, response: ServerResponse): void => {
    const verdict = verifyProviderRequest(
      {
        method: seen.method,
        path: new URL(seen.url, "http://provider.example").pathname,
        body: seen.body,
        headers: flat(seen.headers),
      },
      providerOptions,
    );
    if (verdict.accepted) {
      response.writeHead(201);
      response.end("{}");
      return;
    }
    response.writeHead(409, { "content-type": "application/json" });
    response.end(refusalBody(verdict.reasonCode));
  };

  const write = { method: "post", path: "/v1/payments/canary?dry=0", body: '{"amount":"1.00"}' };

  it("is refused twice by a verifying provider: unattested, then signed with a key it cannot know", async () => {
    const provider = await serve(verifying);
    const { http, requests } = recording(loopbackHttp);
    const finding = await probeProvider(
      { name: "payments", url: `${provider.url}/base/`, write },
      { dial: connected, http, clock, timeoutMs: 1_500 },
    );
    const keyId = finding.signed?.key_id ?? "";
    expect(keyId).toMatch(/^agentsafe-acceptance-[0-9a-f]{32}$/);
    expect(finding).toEqual({
      name: "payments",
      unattested: {
        status: 409,
        reason_code: "SIGNATURE_INVALID_OR_INCOMPLETE",
        detail: "ANSWERED",
      },
      signed: {
        status: 409,
        reason_code: "SIGNATURE_INVALID_OR_INCOMPLETE",
        detail: "ANSWERED",
        key_id: keyId,
      },
      verdict: "REFUSED",
      at: NOW,
    });
    expect(provider.seen.map((seen) => [seen.method, seen.url, seen.body])).toEqual([
      ["POST", "/base/v1/payments/canary?dry=0", '{"amount":"1.00"}'],
      ["POST", "/base/v1/payments/canary?dry=0", '{"amount":"1.00"}'],
    ]);
    expect(requests.map((request) => [request.timeoutMs, request.maxBodyBytes])).toEqual([
      [1_500, 4_096],
      [1_500, 4_096],
    ]);
    // The first carries nothing an executor would send.
    expect(requests[0]!.headers).toEqual({ "content-type": "application/json" });
    const signed = requests[1]!.headers;
    expect(Object.keys(signed).sort()).toEqual([
      "content-digest",
      "content-type",
      "idempotency-key",
      "signature",
      "signature-input",
      "x-agent-safe-intent-hash",
    ]);
    expect(signed["content-type"]).toBe("application/json");
    expect(signed["idempotency-key"]).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(signed["x-agent-safe-intent-hash"]).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(signed["signature-input"]).toBe(
      `agentsafe=("@method" "@path" "content-digest" "idempotency-key" "x-agent-safe-intent-hash");created=${String(Date.parse(NOW) / 1_000)};keyid="${keyId}";alg="ed25519"`,
    );
    // The signature is good; only the key is unknown. Checked with the public
    // half the module generated and never exported.
    expect(generated.publicKeys).toHaveLength(1);
    const received = {
      method: "POST",
      path: "/base/v1/payments/canary",
      body: '{"amount":"1.00"}',
      headers: flat(provider.seen[1]!.headers),
    };
    expect(
      SignedRequestCredential.verify(
        SignedRequestCredential.materialFrom(received),
        received.headers,
        { publicKeyPem: generated.publicKeys[0]! },
      ),
    ).toBe(true);
  });

  it("signs the method the plan names, and a fresh key every time", async () => {
    const { http, requests } = recording(answering(409));
    const findings = [];
    for (let run = 0; run < 2; run += 1) {
      findings.push(
        await probeProvider(
          { name: "payments", url: "https://provider.example", write: { ...write, method: "put" } },
          { dial: connected, http, clock },
        ),
      );
    }
    expect(requests.map((request) => [request.method, request.url])).toEqual(
      Array.from({ length: 4 }, () => ["PUT", "https://provider.example/v1/payments/canary?dry=0"]),
    );
    const signed = requests[1]!;
    const received = {
      method: "PUT",
      path: "/v1/payments/canary",
      body: write.body,
      headers: signed.headers,
    };
    expect(
      SignedRequestCredential.verify(
        SignedRequestCredential.materialFrom(received),
        received.headers,
        { publicKeyPem: generated.publicKeys[0]! },
      ),
    ).toBe(true);
    expect(generated.publicKeys).toHaveLength(2);
    expect(generated.publicKeys[0]).not.toBe(generated.publicKeys[1]);
    expect(findings[0]!.signed?.key_id).not.toBe(findings[1]!.signed?.key_id);
  });

  it("sends a write with no body bare, and signs the empty body", async () => {
    const { http, requests } = recording(answering(409));
    await probeProvider(
      {
        name: "payments",
        url: "https://provider.example",
        write: { ...write, method: "DELETE", body: null },
      },
      { dial: connected, http, clock },
    );
    expect(requests.map((request) => request.body)).toEqual([null, null]);
    expect(requests[0]!.headers).toEqual({});
    expect(requests[1]!.headers["content-type"]).toBeUndefined();
    expect(requests[1]!.headers["content-digest"]).toBe(
      SignedRequestCredential.contentDigest(null),
    );
    const received = {
      method: "DELETE",
      path: "/v1/payments/canary",
      body: null,
      headers: requests[1]!.headers,
    };
    expect(
      SignedRequestCredential.verify(
        SignedRequestCredential.materialFrom(received),
        received.headers,
        { publicKeyPem: generated.publicKeys[0]! },
      ),
    ).toBe(true);
  });

  it("sends nothing more once the unattested write was accepted", async () => {
    const { http, requests } = recording(answering(204));
    const finding = await probeProvider(
      { name: "payments", url: "https://provider.example", write },
      { dial: connected, http, clock },
    );
    expect(finding).toEqual({
      name: "payments",
      unattested: { status: 204, reason_code: null, detail: "ANSWERED" },
      signed: null,
      verdict: "ACCEPTED",
      at: NOW,
    });
    expect(requests).toHaveLength(1);
  });

  it("decides from the two statuses, and refuses only on two 4xx", async () => {
    const run = async (first: number | Error, second: number | Error) => {
      const answers = [first, second];
      const finding = await probeProvider(
        { name: "payments", url: "https://provider.example", write },
        {
          dial: connected,
          clock,
          http: async () => {
            const answer = answers.shift()!;
            if (answer instanceof Error) throw answer;
            return await Promise.resolve({ status: answer, body: "" });
          },
        },
      );
      return finding.verdict;
    };
    expect(await run(400, 499)).toBe("REFUSED");
    expect(await run(409, 200)).toBe("ACCEPTED");
    expect(await run(409, 299)).toBe("ACCEPTED");
    expect(await run(200, 409)).toBe("ACCEPTED");
    expect(await run(299, 409)).toBe("ACCEPTED");
    for (const [first, second] of [
      [409, 500],
      [500, 409],
      [399, 409],
      [409, 399],
      [409, 300],
      [300, 409],
      [409, 199],
    ] as const) {
      expect(await run(first, second)).toBe("INCONCLUSIVE");
    }
    expect(await run(coded("ETIMEDOUT"), 409)).toBe("INCONCLUSIVE");
    expect(await run(409, coded("ECONNRESET"))).toBe("INCONCLUSIVE");
  });

  it("records why a write had no answer", async () => {
    const finding = await probeProvider(
      { name: "payments", url: "https://provider.example", write },
      { dial: connected, clock, http: failing(coded("ECONNREFUSED", "refused by 10.0.0.9")) },
    );
    expect(finding.unattested).toEqual({ status: null, reason_code: null, detail: "ECONNREFUSED" });
    expect(finding.signed).toMatchObject({
      status: null,
      reason_code: null,
      detail: "ECONNREFUSED",
    });
    expect(finding.verdict).toBe("INCONCLUSIVE");
    expect(JSON.stringify(finding)).not.toContain("10.0.0.9");
  });

  it("keeps a reason code from a JSON body and nothing else of the body", async () => {
    const secret = ["planted", "body", "value"].join("-");
    const reason = async (body: string) =>
      (
        await probeProvider(
          { name: "payments", url: "https://provider.example", write },
          { dial: connected, clock, http: answering(409, body) },
        )
      ).unattested.reason_code;
    expect(
      await reason(`{"status":"REJECTED","reason_code":"GRANT_REPLAYED","echo":"${secret}"}`),
    ).toBe("GRANT_REPLAYED");
    for (const body of [
      "",
      "not json",
      "null",
      "[]",
      '{"status":"REJECTED"}',
      '{"reason_code":42}',
      `{"reason_code":"refused because ${secret}"}`,
      `{"reason_code":"${"R".repeat(65)}"}`,
    ]) {
      expect(await reason(body)).toBeNull();
    }
    const finding = await probeProvider(
      { name: "payments", url: "https://provider.example", write },
      { dial: connected, clock, http: answering(409, `{"reason_code":"X","echo":"${secret}"}`) },
    );
    expect(JSON.stringify(finding)).not.toContain(secret);
  });

  it("defaults the timeout and the clock", async () => {
    const { http, requests } = recording(answering(409));
    const before = Math.floor(Date.now() / 1_000);
    const finding = await probeProvider(
      { name: "payments", url: "https://provider.example", write },
      { dial: connected, http },
    );
    const after = Math.ceil(Date.now() / 1_000);
    expect(requests.map((request) => request.timeoutMs)).toEqual([5_000, 5_000]);
    expect(Date.parse(finding.at)).not.toBeNaN();
    const created = Number(
      /;created=(\d+);/.exec(requests[1]!.headers["signature-input"] ?? "")?.[1],
    );
    expect(created).toBeGreaterThanOrEqual(before);
    expect(created).toBeLessThanOrEqual(after);
  });

  it("refuses a provider or a path it cannot spell", async () => {
    const options = { dial: connected, clock, http: answering(409) };
    const target = (url: string, path: string): ProviderTarget => ({
      name: "payments",
      url,
      write: { ...write, path },
    });
    await expect(
      probeProvider(target("https://provider.example", "v1/x"), options),
    ).rejects.toThrow(/^ZONE_TARGET_INVALID: payments$/);
    await expect(
      probeProvider(target("https://agent:pw@provider.example", "/v1/x"), options),
    ).rejects.toThrow(/^ZONE_TARGET_INVALID: payments$/);
  });
});

describe("probeMcp", () => {
  it("dials each server in order, and reports host and port only", async () => {
    const listening = await serve(status(200));
    const closed = await closedPort();
    const findings = await probeMcp(
      [
        { name: "tools", url: `${listening.url}/mcp` },
        { name: "files", url: `${LOOPBACK_URL}:${String(closed)}/sse` },
      ],
      { dial, clock, timeoutMs: 2_000 },
    );
    expect(findings).toEqual([
      {
        name: "tools",
        address: `${LOOPBACK}:${String(listening.port)}`,
        verdict: "REACHABLE",
        detail: "CONNECTED",
        at: NOW,
      },
      {
        name: "files",
        address: `${LOOPBACK}:${String(closed)}`,
        verdict: "REACHABLE",
        detail: "REFUSED_NOT_DROPPED",
        at: NOW,
      },
    ]);
    // A dial writes nothing: no MCP message reached the server.
    expect(listening.seen).toEqual([]);
  });

  it("reads silence as contained and an unresolved name as inconclusive, with the default timeout", async () => {
    const dialled: string[] = [];
    const outcomes = new Map<string, Awaited<ReturnType<ZoneDial>>>([
      ["a.example", { state: "TIMED_OUT" }],
      ["b.example", { state: "UNRESOLVED", code: "ENOTFOUND" }],
      ["c.example", { state: "OTHER", code: "not a code" }],
    ]);
    const findings = await probeMcp(
      [
        { name: "a", url: "https://a.example/mcp" },
        { name: "b", url: "http://b.example:9000/mcp" },
        { name: "c", url: "http://c.example/mcp" },
      ],
      {
        dial: async (host, port, timeoutMs) => {
          dialled.push(`${host}|${String(port)}|${String(timeoutMs)}`);
          return await Promise.resolve(outcomes.get(host)!);
        },
      },
    );
    expect(dialled).toEqual(["a.example|443|5000", "b.example|9000|5000", "c.example|80|5000"]);
    expect(findings.map((finding) => [finding.verdict, finding.detail])).toEqual([
      ["CONTAINED", "TIMED_OUT"],
      ["INCONCLUSIVE", "ENOTFOUND"],
      ["INCONCLUSIVE", "UNKNOWN"],
    ]);
    expect(Date.parse(findings[0]!.at)).not.toBeNaN();
    expect(await probeMcp([], { dial })).toEqual([]);
  });

  it("refuses a server it cannot spell", async () => {
    await expect(probeMcp([{ name: "tools", url: "mcp" }], { dial: connected })).rejects.toThrow(
      /^ZONE_TARGET_INVALID: tools$/,
    );
  });
});

describe("probeMetadata", () => {
  it("refuses an endpoint it cannot spell", async () => {
    await expect(
      probeMetadata({ dial: connected, http: answering(200), url: "metadata" }),
    ).rejects.toThrow(/^ZONE_TARGET_INVALID: metadata$/);
  });

  it("reads the endpoint bare, and any answer is a hole", async () => {
    const metadata = await serve(status(401));
    const { http, requests } = recording(loopbackHttp);
    const finding = await probeMetadata({
      dial,
      http,
      clock,
      url: `${metadata.url}/`,
      timeoutMs: 1_000,
    });
    expect(finding).toEqual({
      address: `${LOOPBACK}:${String(metadata.port)}`,
      status: 401,
      detail: "ANSWERED",
      verdict: "REACHABLE",
      at: NOW,
    });
    expect(requests).toEqual([
      {
        method: "GET",
        url: `${metadata.url}/`,
        headers: {},
        body: null,
        timeoutMs: 1_000,
        maxBodyBytes: 0,
      },
    ]);
    expect(Object.keys(metadata.seen[0]!.headers).sort()).toEqual(["connection", "host"]);
  });

  it("dials the link-local address with a short timeout by default, and reads nothing after silence", async () => {
    const dialled: string[] = [];
    const { http, requests } = recording(answering(200));
    const finding = await probeMetadata({
      dial: async (host, port, timeoutMs) => {
        dialled.push(`${host}|${String(port)}|${String(timeoutMs)}`);
        return await Promise.resolve({ state: "TIMED_OUT" });
      },
      http,
    });
    expect(METADATA_URL).toBe("http://169.254.169.254/");
    expect(dialled).toEqual(["169.254.169.254|80|2000"]);
    expect(requests).toEqual([]);
    expect(finding).toMatchObject({
      address: "169.254.169.254:80",
      status: null,
      detail: "TIMED_OUT",
      verdict: "CONTAINED",
    });
    expect(Date.parse(finding.at)).not.toBeNaN();
    const unresolved = await probeMetadata({
      dial: async () => await Promise.resolve({ state: "UNRESOLVED", code: "EAI_AGAIN" }),
      http,
      clock,
    });
    expect(unresolved).toMatchObject({ detail: "EAI_AGAIN", verdict: "INCONCLUSIVE" });
  });
});

/** Fake credentials, built at run time so that no line of this file looks like one. */
const fake = {
  jwt: `${"e"}yJ${"a1_-".repeat(6)}.${"b2-_".repeat(6)}.${"c3-".repeat(5)}`,
  unsignedJwt: `${"e"}yJhbGc.${"e"}yJzdWI.`,
  pem: [
    ["-----BEGIN", " PRIVATE", " KEY-----"].join(""),
    "Zm9vYmFy".repeat(8),
    ["-----END", " PRIVATE", " KEY-----"].join(""),
  ].join("\n"),
  awsKeyId: `${["AK", "IA"].join("")}${"Z7".repeat(8)}`,
  stsKeyId: `${["AS", "IA"].join("")}${"Q4".repeat(8)}`,
  password: ["planted", "pass", "word"].join("-"),
  opaque: ["planted", "opaque", "value"].join("-"),
};

const kinds = (findings: readonly CredentialFinding[]): Record<string, string> =>
  Object.fromEntries(findings.map((finding) => [finding.name, finding.kind]));

const noFiles = (): boolean => false;

describe("scanCredentials", () => {
  it("reads a credential from a variable's name, word by word", () => {
    const named = [
      "SERVICE_TOKEN",
      "SLACK_BOT_TOKEN2",
      "npm_config__authToken",
      "authToken",
      "CLIENT_SECRET",
      "K8S_SECRETS",
      "DB_PASSWORD",
      "SMTP_PASSWORDS",
      "FTP_PASSWD",
      "SERVICE_CREDENTIAL",
      "APP_CREDENTIALS",
      "MAPS_APIKEY",
      "OPENAI_API_KEY",
      "x-api--key",
      "MINIO_ACCESSKEY",
      "STORAGE_ACCESS_KEY",
      "SIGNING_PRIVATEKEY",
      "privateKeyPath",
      "FLASK_SESSION_KEY",
      "APP_SESSION",
      "LOGIN_COOKIE",
      "BROWSER_COOKIES",
      "BASIC_AUTH",
      "OAUTH2_CLIENT_ID",
      "HTTP_AUTHORIZATION",
    ];
    const ordinary = [
      "PATH",
      "HOME",
      "PWD",
      "MAX_TOKENS",
      "TOKENIZERS_PARALLELISM",
      "GIT_AUTHOR_NAME",
      "TERM_SESSION_ID",
      "XDG_SESSION_TYPE",
      "API_KEYBOARD",
      "PRIVATE_KEYS_DIR",
      "AUTHOR",
      "SESSIONS",
    ];
    const env = Object.fromEntries([...named, ...ordinary].map((name) => [name, fake.opaque]));
    const findings = scanCredentials({ env, home: "/home/agent", exists: noFiles });
    expect(findings.map((finding) => finding.name)).toEqual([...named].sort());
    expect(new Set(findings.map((finding) => finding.kind))).toEqual(new Set(["secret-like"]));
  });

  it("reads a credential from a value's shape, whatever the name", () => {
    const env = {
      A_JWT: fake.jwt,
      B_UNSIGNED: fake.unsignedJwt,
      C_PEM: fake.pem,
      D_AWS: fake.awsKeyId,
      E_STS: fake.stsKeyId,
      F_URL: `postgres://agent:${fake.password}@db.internal.example/app`,
      G_USER_ONLY: `https://${fake.password}@git.internal.example/repo`,
      H_PASS_ONLY: `redis://:${fake.password}@cache.internal.example:6379`,
    };
    expect(kinds(scanCredentials({ env, home: "/home/agent", exists: noFiles }))).toEqual({
      A_JWT: "jwt",
      B_UNSIGNED: "jwt",
      C_PEM: "pem-private-key",
      D_AWS: "aws-access-key",
      E_STS: "aws-access-key",
      F_URL: "url-with-userinfo",
      G_USER_ONLY: "url-with-userinfo",
      H_PASS_ONLY: "url-with-userinfo",
    });
  });

  it("does not read a near miss as a credential", () => {
    const env = {
      A: `x${fake.jwt}`,
      B: `${fake.jwt}!`,
      C: `${"e"}yJ.${"b".repeat(4)}.c`,
      D: `${"e"}yJabc.${"b".repeat(4)}`,
      E: `${"e"}yJab!c.de.f`,
      F: `${"e"}yJabc.d!e.f`,
      G: `${"e"}yJabc.de.f!g`,
      H: ["-----END", " PRIVATE", " KEY-----"].join(""),
      I: ["-----BEGIN", " PUBLIC", " KEY-----"].join(""),
      J: `x${fake.awsKeyId}`,
      K: `${fake.awsKeyId}Z`,
      L: fake.awsKeyId.slice(0, -1),
      M: fake.awsKeyId.toLowerCase(),
      N: `${["AK", "IA"].join("")}${"z7".repeat(8)}`,
      O: `${["AK", "IB"].join("")}${"Z7".repeat(8)}`,
      P: "https://git.internal.example/repo",
      Q: "mailto:agent@internal.example",
      R: "not a url",
    };
    expect(scanCredentials({ env, home: "/home/agent", exists: noFiles })).toEqual([]);
  });

  it("names the kind a well-known variable holds, and lets a value's shape win", () => {
    const env = {
      AWS_ACCESS_KEY_ID: fake.opaque,
      AWS_SECRET_ACCESS_KEY: fake.opaque,
      AWS_SESSION_TOKEN: fake.opaque,
      AZURE_CLIENT_SECRET: fake.opaque,
      GITHUB_TOKEN: fake.opaque,
      GH_TOKEN: fake.opaque,
      GOOGLE_APPLICATION_CREDENTIALS: "/var/secrets/gcp.json",
      AWS_SHARED_CREDENTIALS_FILE: "/var/secrets/aws",
      AWS_WEB_IDENTITY_TOKEN_FILE: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
      AZURE_FEDERATED_TOKEN_FILE: "/var/run/secrets/azure/tokens/azure-identity-token",
      SERVICE_TOKEN: fake.jwt,
    };
    expect(kinds(scanCredentials({ env, home: "/home/agent", exists: noFiles }))).toEqual({
      AWS_ACCESS_KEY_ID: "aws-access-key",
      AWS_SECRET_ACCESS_KEY: "aws-secret-key",
      AWS_SESSION_TOKEN: "aws-session-token",
      AZURE_CLIENT_SECRET: "azure-client-secret",
      GITHUB_TOKEN: "github-token",
      GH_TOKEN: "github-token",
      GOOGLE_APPLICATION_CREDENTIALS: "credential-file-path",
      AWS_SHARED_CREDENTIALS_FILE: "credential-file-path",
      AWS_WEB_IDENTITY_TOKEN_FILE: "credential-file-path",
      AZURE_FEDERATED_TOKEN_FILE: "credential-file-path",
      SERVICE_TOKEN: "jwt",
    });
  });

  it("skips a variable that holds nothing, and a name the prototype owns", () => {
    const env = {
      GITHUB_TOKEN: "",
      DB_PASSWORD: undefined,
      constructor: fake.opaque,
      toString: fake.opaque,
      hasOwnProperty: fake.opaque,
    };
    expect(scanCredentials({ env, home: "/home/agent", exists: noFiles })).toEqual([]);
  });

  it("reports the run's own credentials like any other, and marks them", () => {
    const env = {
      AGENTSAFE_ACCEPTANCE_TOKEN: fake.opaque,
      AGENTSAFE_OPERATOR: fake.opaque,
      AGENTSAFE_UNUSED: "",
      GITHUB_TOKEN: fake.opaque,
      KUBECONFIG: "/etc/agent/kubeconfig",
    };
    const findings = scanCredentials({
      env,
      home: "/home/agent",
      exists: (path) => path === "/home/agent/.netrc" || path === "/etc/agent/kubeconfig",
      own: [
        "AGENTSAFE_ACCEPTANCE_TOKEN",
        "AGENTSAFE_OPERATOR",
        "AGENTSAFE_UNUSED",
        "~/.netrc",
        "$KUBECONFIG",
      ],
    });
    expect(findings).toEqual([
      { source: "environment", name: "AGENTSAFE_ACCEPTANCE_TOKEN", kind: "secret-like", own: true },
      { source: "environment", name: "AGENTSAFE_OPERATOR", kind: "secret-like", own: true },
      { source: "environment", name: "GITHUB_TOKEN", kind: "github-token", own: false },
      { source: "file", name: "~/.netrc", kind: "netrc", own: true },
      { source: "file", name: "$KUBECONFIG", kind: "kubeconfig", own: true },
    ]);
  });

  it("reports every well-known file that exists, in a fixed order, without opening it", () => {
    const home = "/home/agent";
    const present = new Set([
      "/var/run/secrets/kubernetes.io/serviceaccount/token",
      join(home, ".aws/credentials"),
      join(home, ".config/gcloud/application_default_credentials.json"),
      join(home, ".azure/msal_token_cache.json"),
      join(home, ".azure/accessTokens.json"),
      join(home, ".azure/service_principal_entries.json"),
      join(home, ".kube/config"),
      join(home, ".docker/config.json"),
      join(home, ".netrc"),
      join(home, ".npmrc"),
      "/secrets/gcp.json",
      "/secrets/aws",
      "/secrets/eks-token",
      "/secrets/azure-token",
      "/etc/kube/b",
    ]);
    const asked: string[] = [];
    const findings = scanCredentials({
      env: {
        GOOGLE_APPLICATION_CREDENTIALS: "/secrets/gcp.json",
        AWS_SHARED_CREDENTIALS_FILE: "/secrets/aws",
        AWS_WEB_IDENTITY_TOKEN_FILE: "/secrets/eks-token",
        AZURE_FEDERATED_TOKEN_FILE: "/secrets/azure-token",
        KUBECONFIG: ["/etc/kube/a", "/etc/kube/b"].join(delimiter),
      },
      home,
      exists: (path) => {
        asked.push(path);
        return present.has(path);
      },
    });
    expect(findings.filter((finding) => finding.source === "file")).toEqual([
      {
        source: "file",
        name: "/var/run/secrets/kubernetes.io/serviceaccount/token",
        kind: "service-account-token",
        own: false,
      },
      { source: "file", name: "~/.aws/credentials", kind: "aws-credentials", own: false },
      {
        source: "file",
        name: "~/.config/gcloud/application_default_credentials.json",
        kind: "gcp-credentials",
        own: false,
      },
      {
        source: "file",
        name: "~/.azure/msal_token_cache.json",
        kind: "azure-cli-credentials",
        own: false,
      },
      {
        source: "file",
        name: "~/.azure/accessTokens.json",
        kind: "azure-cli-credentials",
        own: false,
      },
      {
        source: "file",
        name: "~/.azure/service_principal_entries.json",
        kind: "azure-cli-credentials",
        own: false,
      },
      { source: "file", name: "~/.kube/config", kind: "kubeconfig", own: false },
      { source: "file", name: "~/.docker/config.json", kind: "docker-config", own: false },
      { source: "file", name: "~/.netrc", kind: "netrc", own: false },
      { source: "file", name: "~/.npmrc", kind: "npmrc", own: false },
      {
        source: "file",
        name: "$GOOGLE_APPLICATION_CREDENTIALS",
        kind: "gcp-credentials",
        own: false,
      },
      { source: "file", name: "$AWS_SHARED_CREDENTIALS_FILE", kind: "aws-credentials", own: false },
      {
        source: "file",
        name: "$AWS_WEB_IDENTITY_TOKEN_FILE",
        kind: "web-identity-token",
        own: false,
      },
      {
        source: "file",
        name: "$AZURE_FEDERATED_TOKEN_FILE",
        kind: "web-identity-token",
        own: false,
      },
      { source: "file", name: "$KUBECONFIG", kind: "kubeconfig", own: false },
    ]);
    // Only existence is asked; a list in KUBECONFIG is read path by path.
    expect(asked).toContain("/etc/kube/a");
    expect(asked).toContain("/etc/kube/b");
  });

  it("reports a variable's file only when it exists, and nothing when the variable is unset", () => {
    const findings = scanCredentials({
      env: { GOOGLE_APPLICATION_CREDENTIALS: "/missing.json", KUBECONFIG: "" },
      home: "/home/agent",
      exists: (path) => path === "/elsewhere",
    });
    expect(findings.filter((finding) => finding.source === "file")).toEqual([]);
    expect(scanCredentials({ env: {}, home: "/home/agent", exists: () => true })).toHaveLength(10);
  });

  it("lists the environment in name order", () => {
    const env = { Z_TOKEN: fake.opaque, A_TOKEN: fake.opaque, M_TOKEN: fake.opaque };
    expect(
      scanCredentials({ env, home: "/home/agent", exists: noFiles }).map((finding) => finding.name),
    ).toEqual(["A_TOKEN", "M_TOKEN", "Z_TOKEN"]);
  });

  it("asks the file system itself when no check is given", () => {
    const home = mkdtempSync(join(tmpdir(), "zone-probes-"));
    try {
      writeFileSync(join(home, ".netrc"), "machine example.test\n");
      const findings = scanCredentials({ env: {}, home });
      expect(findings).toContainEqual({
        source: "file",
        name: "~/.netrc",
        kind: "netrc",
        own: false,
      });
      expect(findings.map((finding) => finding.name)).not.toContain("~/.npmrc");
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  it("never holds a value, or any part of one", () => {
    const planted = {
      SERVICE_TOKEN: fake.jwt,
      SIGNING_KEY_PEM: fake.pem,
      AWS_ACCESS_KEY_ID: fake.awsKeyId,
      DATABASE_URL: `postgres://agent:${fake.password}@db.internal.example/app`,
      GOOGLE_APPLICATION_CREDENTIALS: `{"type":"service_account","private_key":"${fake.opaque}"}`,
      DB_PASSWORD: fake.opaque,
    };
    const findings = scanCredentials({
      env: planted,
      home: "/home/agent",
      exists: () => true,
      own: ["DB_PASSWORD"],
    });
    expect(findings.map((finding) => finding.name)).toEqual(
      expect.arrayContaining(Object.keys(planted)),
    );
    const text = JSON.stringify(findings);
    for (const value of [
      ...Object.values(planted),
      fake.password,
      fake.opaque,
      fake.awsKeyId.slice(4),
      fake.jwt.split(".")[1]!,
      "Zm9vYmFy",
      "db.internal.example",
    ]) {
      expect(text).not.toContain(value);
    }
  });
});

describe("zoneFindingsSchema", () => {
  async function everything(): Promise<ZoneFindings> {
    const http = recording(
      answering(409, '{"reason_code":"SIGNATURE_INVALID_OR_INCOMPLETE"}'),
    ).http;
    return {
      origins: [
        await probeOrigin(
          { name: "ledger", url: "http://ledger.example/x" },
          {
            dial: silent,
            http: recording(answering(200)).http,
            clock,
            gateway: "http://g.example",
          },
        ),
        await probeOrigin(
          { name: "orders", url: "http://orders.example/x" },
          { dial: connected, http: answering(403), clock, gateway: "http://g.example" },
        ),
        await probeOrigin(
          { name: "billing", url: "http://billing.example/x" },
          {
            dial: async () => await Promise.resolve({ state: "UNRESOLVED", code: "ENOTFOUND" }),
            http: answering(200),
            clock,
            gateway: "http://g.example",
          },
        ),
      ],
      providers: [
        await probeProvider(
          {
            name: "payments",
            url: "https://provider.example",
            write: { method: "POST", path: "/p", body: "{}" },
          },
          { dial: connected, http, clock },
        ),
        await probeProvider(
          {
            name: "refunds",
            url: "https://provider.example",
            write: { method: "POST", path: "/r", body: "{}" },
          },
          { dial: connected, http: answering(200), clock },
        ),
        await probeProvider(
          {
            name: "transfers",
            url: "https://provider.example",
            write: { method: "POST", path: "/t", body: null },
          },
          { dial: connected, http: answering(503), clock },
        ),
      ],
      mcp: await probeMcp([{ name: "tools", url: "http://mcp.example/" }], {
        dial: connected,
        clock,
      }),
      credentials: scanCredentials({
        env: {
          A_JWT: fake.jwt,
          B_PEM: fake.pem,
          C_URL: `https://${fake.password}@x.example/`,
          AWS_ACCESS_KEY_ID: fake.opaque,
          AWS_SECRET_ACCESS_KEY: fake.opaque,
          AWS_SESSION_TOKEN: fake.opaque,
          AZURE_CLIENT_SECRET: fake.opaque,
          GITHUB_TOKEN: fake.opaque,
          GOOGLE_APPLICATION_CREDENTIALS: "/secrets/gcp.json",
          AWS_WEB_IDENTITY_TOKEN_FILE: "/secrets/token",
          DB_PASSWORD: fake.opaque,
        },
        home: "/home/agent",
        exists: () => true,
      }),
      metadata: await probeMetadata({ dial: connected, http: answering(200), clock }),
    };
  }

  it("parses everything the probes produce, every kind included", async () => {
    const findings = await everything();
    expect(new Set(findings.credentials.map((finding) => finding.kind))).toEqual(
      new Set(CREDENTIAL_KINDS),
    );
    // Every verdict each finding can carry, so the schema is held to all of them.
    expect(findings.origins.map((finding) => finding.verdict)).toEqual([
      "CONTAINED",
      "REACHABLE",
      "INCONCLUSIVE",
    ]);
    expect(findings.providers.map((finding) => finding.verdict)).toEqual([
      "REFUSED",
      "ACCEPTED",
      "INCONCLUSIVE",
    ]);
    expect(zoneFindingsSchema.parse(findings)).toEqual(findings);
    expect(zoneFindingsSchema.parse({ ...findings, metadata: null }).metadata).toBeNull();
  });

  it("refuses anything outside the closed shape, its bounds and its codes", async () => {
    const findings = await everything();
    const origin = findings.origins[0]!;
    const provider = findings.providers[0]!;
    const credential = findings.credentials[0]!;
    const refused = (changed: unknown): void => {
      expect(zoneFindingsSchema.safeParse(changed).success).toBe(false);
    };
    refused({ ...findings, extra: true });
    refused({ ...findings, origins: [{ ...origin, url: "http://ledger.example/x" }] });
    refused({ ...findings, origins: [{ ...origin, name: "" }] });
    refused({ ...findings, origins: [{ ...origin, name: "n".repeat(ZONE_LIMITS.name + 1) }] });
    refused({ ...findings, origins: [{ ...origin, address: "" }] });
    refused({
      ...findings,
      origins: [{ ...origin, address: "a".repeat(ZONE_LIMITS.address + 1) }],
    });
    refused({ ...findings, origins: [{ ...origin, direct: { status: 99, detail: "ANSWERED" } }] });
    refused({
      ...findings,
      origins: [{ ...origin, direct: { status: 1_000, detail: "ANSWERED" } }],
    });
    refused({
      ...findings,
      origins: [{ ...origin, direct: { status: 200.5, detail: "ANSWERED" } }],
    });
    refused({
      ...findings,
      origins: [{ ...origin, direct: { status: null, detail: "socket hang up" } }],
    });
    refused({ ...findings, origins: [{ ...origin, verdict: "SAFE" }] });
    refused({ ...findings, origins: [{ ...origin, at: "yesterday" }] });
    refused({
      ...findings,
      origins: Array.from({ length: ZONE_LIMITS.targets + 1 }, () => origin),
    });
    refused({ ...findings, providers: [{ ...provider, verdict: "PASSED" }] });
    refused({
      ...findings,
      providers: [{ ...provider, unattested: { ...provider.unattested, body: "{}" } }],
    });
    refused({
      ...findings,
      providers: [
        { ...provider, unattested: { ...provider.unattested, reason_code: "refused: bad key" } },
      ],
    });
    refused({
      ...findings,
      providers: [{ ...provider, signed: { ...provider.signed, key_id: "executor" } }],
    });
    refused({ ...findings, mcp: [{ ...findings.mcp[0], detail: "" }] });
    refused({ ...findings, credentials: [{ ...credential, kind: fake.opaque }] });
    refused({ ...findings, credentials: [{ ...credential, value: fake.opaque }] });
    refused({ ...findings, credentials: [{ ...credential, source: "memory" }] });
    refused({ ...findings, credentials: [{ ...credential, own: "yes" }] });
    refused({ ...findings, credentials: [{ ...credential, name: "" }] });
    refused({
      ...findings,
      credentials: [{ ...credential, name: "N".repeat(ZONE_LIMITS.credentialName + 1) }],
    });
    refused({
      ...findings,
      credentials: Array.from({ length: ZONE_LIMITS.credentials + 1 }, () => credential),
    });
    refused({ ...findings, metadata: { ...findings.metadata, token: "x" } });
    // At the bounds, not past them.
    expect(
      zoneFindingsSchema.safeParse({
        ...findings,
        origins: Array.from({ length: ZONE_LIMITS.targets }, () => ({
          ...origin,
          name: "n".repeat(ZONE_LIMITS.name),
          direct: { status: 999, detail: "E" },
          control: { status: 100, detail: `E${"_".repeat(63)}` },
        })),
        credentials: Array.from({ length: ZONE_LIMITS.credentials }, () => ({
          ...credential,
          name: "N".repeat(ZONE_LIMITS.credentialName),
        })),
      }).success,
    ).toBe(true);
  });

  it("holds a key id only of the form the probe mints", async () => {
    const findings = await everything();
    const provider = findings.providers[0]!;
    const signed = provider.signed!;
    const withKey = (key_id: string) => ({
      ...findings,
      providers: [{ ...provider, signed: { ...signed, key_id } }],
    });
    expect(
      zoneFindingsSchema.safeParse(withKey(`agentsafe-acceptance-${"0a".repeat(16)}`)).success,
    ).toBe(true);
    for (const key of [
      `xagentsafe-acceptance-${"0a".repeat(16)}`,
      `agentsafe-acceptance-${"0a".repeat(16)}x`,
      `agentsafe-acceptance-${"0a".repeat(15)}0`,
      `agentsafe-acceptance-${"0a".repeat(16)}0`,
      `agentsafe-acceptance-${"0A".repeat(16)}`,
    ]) {
      expect(zoneFindingsSchema.safeParse(withKey(key)).success).toBe(false);
    }
  });
});
