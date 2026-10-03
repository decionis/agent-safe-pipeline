import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { proofToken, UPSTREAM_PROOF_PATH } from "../../src/gateway/UpstreamProof.js";
import { TenantHost } from "../../src/hosted/TenantHost.js";
import { GatewayHttpServer } from "../../src/http/GatewayHttpServer.js";
import { collectedIo, TENANT_KEY, TENANT_KEY_DIGEST } from "../support/GatewayHarness.js";

/**
 * What a hosted gateway writes down is ids, digests, verdicts, codes, paths
 * and timings; never a header value, a query, a request or response body, or
 * a cookie. Each of those is given a marker no record could contain by
 * chance, the tenant's traffic is driven through every path a request can
 * take, and every line the process printed and every file it wrote is read
 * back for any marker.
 */
const MARKERS = {
  authorization: "synthetic-authz-7731",
  cookie: "synthetic-cookie-4410",
  header: "synthetic-header-9921",
  query: "synthetic-query-8812",
  body: "synthetic-body-5566",
  response: "synthetic-response-3321",
  setCookie: "synthetic-set-cookie-6604",
  wrongKey: "synthetic-wrong-key-2290",
} as const;

const WORKSPACE = "00000000-0000-4000-8000-000000000009";
const UPSTREAM = "https://acme.shop.example";
const authority = new LocalAuthority();
const root = mkdtempSync(join(tmpdir(), "agentsafe-hygiene-"));
const keyFile = join(root, "decionis-api-key");
const evidenceDir = join(root, "evidence");

beforeAll(async () => {
  await authority.start();
  writeFileSync(keyFile, LOCAL_AUTHORITY_API_KEY, { mode: 0o600 });
});
afterAll(async () => {
  await authority.stop();
  rmSync(root, { recursive: true, force: true });
});

function send(
  port: number,
  method: string,
  path: string,
  headers: Record<string, string>,
  body?: string,
): Promise<number> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path,
        method,
        headers: { host: "acme.decionisedge.example", ...headers },
      },
      (response) => {
        response.resume();
        response.on("end", () => resolve(response.statusCode ?? 0));
      },
    );
    request.on("error", reject);
    if (body !== undefined) request.write(body);
    request.end();
  });
}

/** Every file under a directory, as text. */
function filesUnder(directory: string): string[] {
  let names: string[];
  try {
    names = readdirSync(directory);
  } catch {
    return [];
  }
  return names.flatMap((name) => {
    const path = join(directory, name);
    return statSync(path).isDirectory() ? filesUnder(path) : [readFileSync(path, "utf8")];
  });
}

describe("what a hosted gateway records", () => {
  it("never holds a header value, a query, a body or a cookie, on any path a request takes", async () => {
    let failNext = false;
    const io = collectedIo();
    const host = await TenantHost.start({
      registryPath: "/etc/agentsafe/tenants.json",
      env: { DECIONIS_API_URL: authority.baseUrl, DECIONIS_ALLOW_INSECURE_LOOPBACK: "true" },
      io,
      readFile: () =>
        JSON.stringify({
          version: 1,
          domain: "decionisedge.example",
          evidenceDir,
          tenants: [
            {
              id: "acme",
              upstream: UPSTREAM,
              tenantKeyDigests: [TENANT_KEY_DIGEST],
              workspace: { tenantId: WORKSPACE, apiKeyFile: keyFile },
              interception: {
                routes: [{ path: "/payments/**", action: "payment.create", methods: ["POST"] }],
              },
            },
          ],
        }),
      dependencies: {
        upstreamFetch: async () => {
          if (failNext) {
            failNext = false;
            throw new Error(`upstream down ${MARKERS.response}`);
          }
          const headers = new Headers({ "content-type": "application/json" });
          headers.append(
            "set-cookie",
            `sid=${MARKERS.setCookie}; Domain=decionisedge.example; Path=/`,
          );
          return new Response(JSON.stringify({ note: MARKERS.response }), { status: 201, headers });
        },
      },
    });
    const server = new GatewayHttpServer(host.select, {
      metricsToken: "synthetic-operator-token",
      probe: { ready: () => true },
    });
    const { port } = await server.listen(0, "127.0.0.1");
    const carried = {
      "agentsafe-tenant-key": TENANT_KEY,
      authorization: `Bearer ${MARKERS.authorization}`,
      cookie: `session=${MARKERS.cookie}`,
      "x-note": MARKERS.header,
      "content-type": "application/json",
      "idempotency-key": "synthetic-idempotency-0001",
    };
    const body = JSON.stringify({ amount: 25, memo: MARKERS.body });

    // Governed and observed in shadow, a passthrough, a failed upstream, and refused keys.
    expect(await send(port, "POST", `/payments/new?ref=${MARKERS.query}`, carried, body)).toBe(201);
    expect(await send(port, "GET", `/orders?ref=${MARKERS.query}`, carried)).toBe(201);
    failNext = true;
    expect(await send(port, "POST", `/payments/new?ref=${MARKERS.query}`, carried, body)).toBe(502);
    expect(
      await send(
        port,
        "POST",
        "/payments/new",
        { ...carried, "agentsafe-tenant-key": MARKERS.wrongKey },
        body,
      ),
    ).toBe(401);
    expect(
      await send(port, "GET", "/orders", { authorization: `Bearer ${MARKERS.authorization}` }),
    ).toBe(401);

    // The shadow observation settles on its own; wait for its report.
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (io.out.filter((line) => line.includes('"state":"SHADOW"')).length >= 2) break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    await server.close(100);
    await host.close();

    const printed = [...io.out, ...io.err];
    const written = filesUnder(evidenceDir);
    // The records exist, and say what happened, so their silence below means something.
    expect(printed.some((line) => line.includes('"state":"SHADOW"'))).toBe(true);
    expect(printed.some((line) => line.includes('"upstream_status":null'))).toBe(true);
    expect(printed.some((line) => line.includes('"tenant_key"'))).toBe(true);
    expect(written.length).toBeGreaterThan(0);
    expect(written.join("\n")).toContain('"event":"SHADOW_EVALUATED"');

    const everything = [...printed, ...written].join("\n");
    for (const [name, marker] of Object.entries({ ...MARKERS, tenantKey: TENANT_KEY })) {
      expect([name, everything.includes(marker)]).toEqual([name, false]);
    }
  });

  it("never holds a word of what an upstream serves as its proof, whether it proves or not", async () => {
    const proofMarkers = {
      comment: "synthetic-proof-comment-1180",
      stray: "synthetic-proof-stray-2271",
      record: "synthetic-proof-record-3362",
    };
    const token = proofToken({ tenant: "acme", org: WORKSPACE, origin: UPSTREAM }, 1_759_492_800);
    const io = collectedIo();
    const tenants = [
      ["acme", UPSTREAM],
      ["globex", "https://globex.shop.example"],
    ].map(([id, upstream]) => ({
      id,
      upstream,
      tenantKeyDigests: [TENANT_KEY_DIGEST],
      workspace: { tenantId: WORKSPACE, apiKeyFile: keyFile },
    }));
    const host = await TenantHost.start({
      registryPath: "/etc/agentsafe/tenants.json",
      env: { DECIONIS_API_URL: authority.baseUrl, DECIONIS_ALLOW_INSECURE_LOOPBACK: "true" },
      io,
      readFile: () =>
        JSON.stringify({ version: 1, domain: "decionisedge.example", evidenceDir, tenants }),
      requireUpstreamProof: true,
      dependencies: {
        upstreamFetch: async (input) => {
          const url = new URL(String(input));
          if (url.pathname !== UPSTREAM_PROOF_PATH) return new Response("{}", { status: 200 });
          // acme proves with its file; globex serves only text that proves nothing.
          return url.host === "acme.shop.example"
            ? new Response(`# ${proofMarkers.comment}\n${token}\n`)
            : new Response(`${proofMarkers.stray}\n`);
        },
        upstreamResolveTxt: async () => [[proofMarkers.record]],
      },
    });
    const server = new GatewayHttpServer(host.select, { probe: { ready: () => true } });
    const { port } = await server.listen(0, "127.0.0.1");
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (host.ready()) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(await send(port, "GET", "/orders", { "agentsafe-tenant-key": TENANT_KEY })).toBe(200);
    expect(
      await send(port, "GET", "/orders", {
        host: "globex.decionisedge.example",
        "agentsafe-tenant-key": TENANT_KEY,
      }),
    ).toBe(503);
    await server.close(100);
    await host.close();

    const printed = [...io.out, ...io.err];
    // The records say what happened, so their silence below means something.
    expect(printed.some((line) => line.includes('"UPSTREAM_UNVERIFIED"'))).toBe(true);
    const everything = [...printed, ...filesUnder(evidenceDir)].join("\n");
    for (const [name, marker] of Object.entries({ ...proofMarkers, token })) {
      expect([name, everything.includes(marker)]).toEqual([name, false]);
    }
  });
});
