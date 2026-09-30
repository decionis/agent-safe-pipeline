import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { TenantHost } from "../../src/hosted/TenantHost.js";
import { TenantRegistryError } from "../../src/hosted/TenantRegistry.js";
import { GatewayHttpServer } from "../../src/http/GatewayHttpServer.js";
import { verifyAuditChain } from "../../src/verify/VerifyAuditChain.js";
import {
  collectedIo,
  TENANT_KEY,
  TENANT_KEY_DIGEST,
  type CollectedIo,
} from "../support/GatewayHarness.js";

const WORKSPACE = "00000000-0000-4000-8000-000000000009";
/** Each tenant's upstream, written whole: the fixture check reads URLs as they are written. */
const UPSTREAMS: Readonly<Record<string, string>> = {
  acme: "https://acme.shop.example",
  globex: "https://globex.shop.example",
  initech: "https://initech.shop.example",
};
const upstreamOf = (id: string): string => UPSTREAMS[id] ?? "https://tenant.shop.example";
const OTHER_KEY = "synthetic-tenant-key-0002";
const OTHER_DIGEST =
  "sha256:" +
  (await import("node:crypto")).createHash("sha256").update(OTHER_KEY, "utf8").digest("hex");

const authority = new LocalAuthority();
const secrets = mkdtempSync(join(tmpdir(), "agentsafe-tenants-"));
const keyFile = join(secrets, "decionis-api-key");

beforeAll(async () => {
  await authority.start();
  writeFileSync(keyFile, LOCAL_AUTHORITY_API_KEY, { mode: 0o600 });
});
afterAll(async () => {
  await authority.stop();
  rmSync(secrets, { recursive: true, force: true });
});

const tenant = (id: string, digest: string, overrides: Record<string, unknown> = {}) => ({
  id,
  upstream: upstreamOf(id),
  tenantKeyDigests: [digest],
  workspace: { tenantId: WORKSPACE, apiKeyFile: keyFile },
  ...overrides,
});

interface Harness {
  readonly host: TenantHost;
  readonly io: CollectedIo;
  readonly files: Map<string, string>;
  readonly forwarded: { host: string; url: string }[];
}

async function start(tenants: unknown[], drainMs = 50): Promise<Harness> {
  const files = new Map([["/etc/agentsafe/tenants.json", registry(tenants)]]);
  const io = collectedIo();
  const forwarded: { host: string; url: string }[] = [];
  const host = await TenantHost.start({
    registryPath: "/etc/agentsafe/tenants.json",
    env: {
      DECIONIS_API_URL: authority.baseUrl,
      DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
      // The host's own credentials must never reach a tenant.
      DECIONIS_API_KEY: "synthetic-operator-key",
      AGENTSAFE_METRICS_TOKEN: "synthetic-operator-token",
    },
    io,
    readFile: (path) => files.get(path) ?? null,
    drainMs,
    dependencies: {
      upstreamFetch: async (input) => {
        const url = new URL(String(input));
        forwarded.push({ host: url.host, url: String(input) });
        return new Response(`from ${url.host}`, { status: 200 });
      },
    },
  });
  return { host, io, files, forwarded };
}

const registry = (tenants: unknown[]): string =>
  JSON.stringify({ version: 1, domain: "decionisedge.example", tenants });

function get(
  port: number,
  hostHeader: string,
  path: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      { host: "127.0.0.1", port, path, method: "GET", headers: { host: hostHeader, ...headers } },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
      },
    );
    request.on("error", reject);
    request.end();
  });
}

const reports = (io: CollectedIo): Record<string, unknown>[] =>
  io.out
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((line) => String(line["event"]).startsWith("TENANT_REGISTRY"));

describe("the tenant host", () => {
  it("serves each tenant at its own host, admits only that tenant's key there, and tags its output", async () => {
    const { host, io, forwarded } = await start([
      tenant("acme", TENANT_KEY_DIGEST),
      tenant("globex", OTHER_DIGEST),
    ]);
    expect(host.hostnames()).toEqual(["acme.decionisedge.example", "globex.decionisedge.example"]);
    expect(reports(io)).toEqual([
      expect.objectContaining({
        event: "TENANT_REGISTRY_LOADED",
        served: 2,
        built: ["acme", "globex"],
        failed: [],
      }),
    ]);
    const server = new GatewayHttpServer(host.select, {
      metricsToken: "synthetic-operator-token",
      probe: { ready: () => true },
    });
    const { port } = await server.listen(0, "127.0.0.1");

    const acme = await get(port, "acme.decionisedge.example", "/orders", {
      "agentsafe-tenant-key": TENANT_KEY,
    });
    expect(acme).toEqual({ status: 200, body: "from acme.shop.example" });
    const globex = await get(port, "globex.decionisedge.example:443", "/orders", {
      "agentsafe-tenant-key": OTHER_KEY,
    });
    expect(globex).toEqual({ status: 200, body: "from globex.shop.example" });
    // One tenant's key is nothing at another tenant's host.
    expect(
      (
        await get(port, "globex.decionisedge.example", "/orders", {
          "agentsafe-tenant-key": TENANT_KEY,
        })
      ).status,
    ).toBe(401);
    expect(forwarded.map((entry) => entry.host)).toEqual([
      "acme.shop.example",
      "globex.shop.example",
    ]);

    // A host no tenant has is refused, except the platform's probes.
    expect((await get(port, "unknown.decionisedge.example", "/orders")).status).toBe(421);
    expect((await get(port, "decionisedge.example", "/orders")).status).toBe(421);
    expect((await get(port, "10.0.0.8:8080", "/_agentsafe/healthz")).status).toBe(200);
    expect(await get(port, "10.0.0.8:8080", "/_agentsafe/readyz")).toEqual({
      status: 200,
      body: '{"ready":true}',
    });
    expect((await get(port, "10.0.0.8:8080", "/_agentsafe/status")).status).toBe(421);

    // Every line a tenant's gateway writes names its tenant: a chained line in
    // its envelope, covered by its hash; any other line first.
    const printed = [...io.out, ...io.err].map(
      (line) => JSON.parse(line) as Record<string, unknown>,
    );
    const tenantLines = printed.filter((line) => "tenant" in line);
    expect(tenantLines.length).toBeGreaterThan(0);
    expect(
      tenantLines.every((line) => line["tenant"] === "acme" || line["tenant"] === "globex"),
    ).toBe(true);
    expect(
      printed.some(
        (line) => line["tenant"] === "globex" && line["method"] === "tenant_key" && "hash" in line,
      ),
    ).toBe(true);
    expect([...io.out, ...io.err].join("\n")).not.toContain(TENANT_KEY);
    // And the whole of it verifies offline, both tenants' chains in one stream.
    const verified = verifyAuditChain([...io.out, ...io.err]);
    expect(verified.findings).toEqual([]);
    expect(verified.ok).toBe(true);
    expect(Object.keys(verified.streams)).toContain("globex/agent-safe.security/1");
    await server.close(100);
    await host.close();
  });

  it("rebuilds only the tenant that changed, retires a removed one after it drains, and keeps serving through a bad registry", async () => {
    const { host, io, files } = await start(
      [tenant("acme", TENANT_KEY_DIGEST), tenant("globex", OTHER_DIGEST)],
      20,
    );
    const acme = host.select("acme.decionisedge.example");
    const globex = host.select("globex.decionisedge.example");

    files.set(
      "/etc/agentsafe/tenants.json",
      registry([
        tenant("acme", TENANT_KEY_DIGEST),
        tenant("globex", OTHER_DIGEST, { upstream: "https://globex-v2.shop.example" }),
      ]),
    );
    expect(await host.reload()).toMatchObject({
      built: ["globex"],
      kept: 1,
      retired: 1,
      failed: [],
    });
    expect(host.select("acme.decionisedge.example")).toBe(acme);
    expect(host.select("globex.decionisedge.example")).not.toBe(globex);
    expect(host.select("globex.decionisedge.example")?.config.upstream.url).toBe(
      "https://globex-v2.shop.example",
    );

    files.set("/etc/agentsafe/tenants.json", "version: 1\ndomain: [");
    expect(await host.reload()).toMatchObject({
      event: "TENANT_REGISTRY_REFUSED",
      code: "REGISTRY_UNREADABLE",
      served: 2,
    });
    files.delete("/etc/agentsafe/tenants.json");
    expect(await host.reload()).toMatchObject({ event: "TENANT_REGISTRY_REFUSED", served: 2 });
    expect(host.hostnames()).toHaveLength(2);

    files.set("/etc/agentsafe/tenants.json", registry([tenant("acme", TENANT_KEY_DIGEST)]));
    expect(await host.reload()).toMatchObject({ served: 1, kept: 1, retired: 1 });
    expect(host.select("globex.decionisedge.example")).toBeNull();
    expect(reports(io).map((report) => report["event"])).toEqual([
      "TENANT_REGISTRY_LOADED",
      "TENANT_REGISTRY_LOADED",
      "TENANT_REGISTRY_REFUSED",
      "TENANT_REGISTRY_REFUSED",
      "TENANT_REGISTRY_LOADED",
    ]);
    await host.close();
  });

  it("serves the tenants it can build, reports the ones it cannot by code, and keeps a tenant's last good gateway", async () => {
    const { host } = await start([
      tenant("acme", TENANT_KEY_DIGEST),
      tenant("globex", OTHER_DIGEST, { upstream: "http://globex.shop.example" }),
      tenant("initech", OTHER_DIGEST, {
        workspace: { tenantId: WORKSPACE, apiKeyFile: join(secrets, "absent") },
      }),
    ]);
    expect(host.hostnames()).toEqual(["acme.decionisedge.example"]);
    const acme = host.select("acme.decionisedge.example");
    const report = await host.reload();
    expect(report).toMatchObject({ kept: 1, built: [] });
    expect(report.failed).toEqual([
      { tenant: "globex", code: "CONFIG_INVALID:upstream" },
      { tenant: "initech", code: expect.stringMatching(/^[A-Z_]+:DECIONIS_API_KEY$/) as unknown },
    ]);
    expect(host.select("acme.decionisedge.example")).toBe(acme);
    await host.close();
  });

  it("gives each tenant its own rate, or the registry's, or the hosted default", async () => {
    const files = new Map([
      [
        "/etc/agentsafe/tenants.json",
        JSON.stringify({
          version: 1,
          domain: "decionisedge.example",
          rateLimit: { requestsPerSecond: 20, burst: 40 },
          tenants: [
            tenant("acme", TENANT_KEY_DIGEST, { rateLimit: { requestsPerSecond: 5, burst: 10 } }),
            tenant("globex", OTHER_DIGEST),
          ],
        }),
      ],
    ]);
    const host = await TenantHost.start({
      registryPath: "/etc/agentsafe/tenants.json",
      env: { DECIONIS_API_URL: authority.baseUrl, DECIONIS_ALLOW_INSECURE_LOOPBACK: "true" },
      io: collectedIo(),
      readFile: (path) => files.get(path) ?? null,
    });
    expect(host.select("acme.decionisedge.example")?.config.rateLimit).toEqual({
      requestsPerSecond: 5,
      burst: 10,
    });
    expect(host.select("globex.decionisedge.example")?.config.rateLimit).toEqual({
      requestsPerSecond: 20,
      burst: 40,
    });
    files.set(
      "/etc/agentsafe/tenants.json",
      JSON.stringify({
        version: 1,
        domain: "decionisedge.example",
        tenants: [tenant("globex", OTHER_DIGEST)],
      }),
    );
    await host.reload();
    expect(host.select("globex.decionisedge.example")?.config.rateLimit).toEqual({
      requestsPerSecond: 50,
      burst: 100,
    });
    await host.close();
  });

  it("refuses to start on a registry it cannot serve", async () => {
    await expect(
      TenantHost.start({
        registryPath: "/etc/agentsafe/tenants.json",
        env: {},
        io: collectedIo(),
        readFile: () => null,
      }),
    ).rejects.toBeInstanceOf(TenantRegistryError);
  });

  it("gives a tenant the shared settings and its own entry, and never the host's credentials", () => {
    const env = TenantHost.tenantEnvironment(
      {
        NODE_ENV: "production",
        DECIONIS_API_URL: "https://authority.decionis.example",
        DECIONIS_API_KEY: "synthetic-operator-key",
        DECIONIS_API_KEY_FILE: "/run/secrets/operator",
        AGENTSAFE_METRICS_TOKEN: "synthetic-operator-token",
        PRESENCE_API_KEY: "synthetic-presence-key",
      },
      tenant("acme", TENANT_KEY_DIGEST) as never,
    );
    expect(env).toEqual({
      NODE_ENV: "production",
      DECIONIS_API_URL: "https://authority.decionis.example",
      AGENTSAFE_HOSTED_GATEWAY: "true",
      AGENTSAFE_HOSTED_TENANT: "acme",
      AGENTSAFE_MODE: "shadow",
      AGENTSAFE_UPSTREAM: "https://acme.shop.example",
      AGENTSAFE_TENANT_KEY_DIGESTS: TENANT_KEY_DIGEST,
      DECIONIS_TENANT_ID: WORKSPACE,
      DECIONIS_API_KEY_FILE: keyFile,
    });
  });

  it("tags a JSON line in place, leaves a line that already names its tenant alone, and wraps anything else", () => {
    const io = collectedIo();
    const tagged = TenantHost.taggedIo(io, "acme");
    tagged.stdout('{"event":"INTERCEPTED"}');
    tagged.stdout('{"stream":"agent-safe.security/1","tenant":"acme","seq":1,"hash":"sha256:x"}');
    tagged.stderr("plain text");
    tagged.stdout("{}");
    tagged.stdout("[1,2]");
    tagged.stdout("{not json");
    expect(io.out).toEqual([
      '{"tenant":"acme","event":"INTERCEPTED"}',
      '{"stream":"agent-safe.security/1","tenant":"acme","seq":1,"hash":"sha256:x"}',
      '{"tenant":"acme","line":"{}"}',
      '{"tenant":"acme","line":"[1,2]"}',
      '{"tenant":"acme","line":"{not json"}',
    ]);
    expect(io.err).toEqual(['{"tenant":"acme","line":"plain text"}']);
    expect(tagged.color).toBe(false);
  });
});
