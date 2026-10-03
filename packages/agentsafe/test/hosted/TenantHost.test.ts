import { mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { ChainJournal } from "../../src/audit/ChainJournal.js";
import { EVIDENCE_STREAM } from "../../src/audit/HashChainedAuditSink.js";
import { GATEWAY_STREAM } from "../../src/gateway/Gateway.js";
import { TenantHost } from "../../src/hosted/TenantHost.js";
import { registryRevision, TenantRegistryError } from "../../src/hosted/TenantRegistry.js";
import { GatewayHttpServer } from "../../src/http/GatewayHttpServer.js";
import { SECURITY_STREAM } from "../../src/incident/SecurityEvents.js";
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

async function start(
  tenants: unknown[],
  drainMs = 50,
  settings: Record<string, unknown> = {},
): Promise<Harness> {
  const files = new Map([["/etc/agentsafe/tenants.json", registry(tenants, settings)]]);
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

const registry = (tenants: unknown[], settings: Record<string, unknown> = {}): string =>
  JSON.stringify({ version: 1, domain: "decionisedge.example", ...settings, tenants });

const ACME = "acme.decionisedge.example";
const REGISTRY_PATH = "/etc/agentsafe/tenants.json";

const get = (
  port: number,
  hostHeader: string,
  path: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: string }> => send(port, "GET", hostHeader, path, headers);

function send(
  port: number,
  method: string,
  hostHeader: string,
  path: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      { host: "127.0.0.1", port, path, method, headers: { host: hostHeader, ...headers } },
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

/** Every line printed, parsed. */
const printed = (io: CollectedIo): Record<string, unknown>[] =>
  [...io.out, ...io.err].map((line) => JSON.parse(line) as Record<string, unknown>);
/** One tenant's lines on one chained stream, in order. */
const chained = (io: CollectedIo, tenant: string, stream: string): Record<string, unknown>[] =>
  printed(io).filter((line) => line["tenant"] === tenant && line["stream"] === stream);
/** One tenant's report lines (not chained), in order. */
const reportedBy = (io: CollectedIo, tenant: string): Record<string, unknown>[] =>
  io.out
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((line) => line["tenant"] === tenant && !("stream" in line));

async function until(condition: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 200 && !condition(); attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  expect(condition()).toBe(true);
}

async function serve(host: TenantHost): Promise<{ port: number; server: GatewayHttpServer }> {
  const server = new GatewayHttpServer(host.select, {
    metricsToken: "synthetic-operator-token",
    probe: { ready: () => host.ready() },
  });
  const { port } = await server.listen(0, "127.0.0.1");
  return { port, server };
}

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

  it("takes a rotated workspace key from its file without a rebuild", async () => {
    const rotating = join(secrets, "rotating-key");
    writeFileSync(rotating, LOCAL_AUTHORITY_API_KEY, { mode: 0o600 });
    const files = new Map([
      [
        "/etc/agentsafe/tenants.json",
        registry([
          tenant("acme", TENANT_KEY_DIGEST, {
            workspace: { tenantId: WORKSPACE, apiKeyFile: rotating },
          }),
        ]),
      ],
    ]);
    const io = collectedIo();
    const host = await TenantHost.start({
      registryPath: "/etc/agentsafe/tenants.json",
      env: { DECIONIS_API_URL: authority.baseUrl, DECIONIS_ALLOW_INSECURE_LOOPBACK: "true" },
      io,
      readFile: (path) => files.get(path) ?? null,
    });
    const gateway = host.select("acme.decionisedge.example");
    // A Secret volume swaps the file; the rotation is the tenant's, on its chain.
    writeFileSync(`${rotating}.next`, "synthetic-rotated-key", { mode: 0o600 });
    renameSync(`${rotating}.next`, rotating);
    const rotated = (): boolean =>
      io.err.some((line) => line.includes('"SECRET_ROTATED"') && line.includes('"tenant":"acme"'));
    for (let attempt = 0; attempt < 100 && !rotated(); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    expect(rotated()).toBe(true);
    expect(host.select("acme.decionisedge.example")).toBe(gateway);
    expect(io.err.join("\n")).not.toContain("synthetic-rotated-key");
    await host.close();
  });

  it("knows which tenants it could not build, and builds them once they can be", async () => {
    const late = join(secrets, "late-key");
    const files = new Map([
      [
        "/etc/agentsafe/tenants.json",
        registry([
          tenant("acme", TENANT_KEY_DIGEST),
          tenant("globex", OTHER_DIGEST, { workspace: { tenantId: WORKSPACE, apiKeyFile: late } }),
        ]),
      ],
    ]);
    const host = await TenantHost.start({
      registryPath: "/etc/agentsafe/tenants.json",
      env: { DECIONIS_API_URL: authority.baseUrl, DECIONIS_ALLOW_INSECURE_LOOPBACK: "true" },
      io: collectedIo(),
      readFile: (path) => files.get(path) ?? null,
    });
    expect(host.failures()).toEqual(["globex"]);
    const acme = host.select("acme.decionisedge.example");
    writeFileSync(late, LOCAL_AUTHORITY_API_KEY, { mode: 0o600 });
    // The same registry again builds exactly the tenant that was missing.
    expect(await host.reload()).toMatchObject({ built: ["globex"], kept: 1, failed: [] });
    expect(host.failures()).toEqual([]);
    expect(host.select("acme.decionisedge.example")).toBe(acme);
    expect(host.select("globex.decionisedge.example")).not.toBeNull();
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

  it("takes a tenant's new keys in place: no rebuild, and its chains go on", async () => {
    const { host, io, files } = await start([tenant("acme", TENANT_KEY_DIGEST)]);
    const { port, server } = await serve(host);
    const gateway = host.select(ACME);
    const status = async (key: string): Promise<number> =>
      (await get(port, ACME, "/orders", { "agentsafe-tenant-key": key })).status;

    // rotate-key: the new key beside the old.
    files.set(
      REGISTRY_PATH,
      registry([
        tenant("acme", TENANT_KEY_DIGEST, { tenantKeyDigests: [TENANT_KEY_DIGEST, OTHER_DIGEST] }),
      ]),
    );
    expect(await host.reload()).toMatchObject({
      built: [],
      kept: 1,
      rekeyed: ["acme"],
      retired: 0,
      failed: [],
    });
    expect(host.select(ACME)).toBe(gateway);
    expect([await status(TENANT_KEY), await status(OTHER_KEY)]).toEqual([200, 200]);

    // retire-key: only the new one.
    files.set(REGISTRY_PATH, registry([tenant("acme", OTHER_DIGEST)]));
    expect(await host.reload()).toMatchObject({ built: [], kept: 1, rekeyed: ["acme"] });
    expect(host.select(ACME)).toBe(gateway);
    expect([await status(TENANT_KEY), await status(OTHER_KEY)]).toEqual([401, 200]);
    expect(await host.reload()).toMatchObject({ kept: 1, rekeyed: [] });

    // One chain per stream, from one start: a rotation restarted nothing.
    const verified = verifyAuditChain([...io.out, ...io.err]);
    expect(verified.findings).toEqual([]);
    expect(verified.streams[`acme/${SECURITY_STREAM}`]).toMatchObject({ starts: 1 });
    await server.close(100);
    await host.close();
  });

  it("never leaves a key the registry dropped admitted because the rest of the entry cannot be applied", async () => {
    const { host, files } = await start([
      tenant("acme", TENANT_KEY_DIGEST, { tenantKeyDigests: [TENANT_KEY_DIGEST, OTHER_DIGEST] }),
    ]);
    const { port, server } = await serve(host);
    const gateway = host.select(ACME);
    const status = async (key: string): Promise<number> =>
      (await get(port, ACME, "/orders", { "agentsafe-tenant-key": key })).status;

    // The old key retired in the same edit as an upstream no gateway can be built with.
    files.set(
      REGISTRY_PATH,
      registry([tenant("acme", OTHER_DIGEST, { upstream: "http://acme.shop.example" })]),
    );
    expect(await host.reload()).toMatchObject({
      served: 1,
      built: [],
      kept: 0,
      rekeyed: ["acme"],
      failed: [{ tenant: "acme", code: "CONFIG_INVALID:upstream" }],
    });
    expect(host.select(ACME)).toBe(gateway);
    expect([await status(TENANT_KEY), await status(OTHER_KEY)]).toEqual([401, 200]);

    // Digests the gateway refuses leave it the keys it admits that the entry still lists.
    files.set(
      REGISTRY_PATH,
      registry([
        tenant("acme", OTHER_DIGEST, {
          tenantKeyDigests: [OTHER_DIGEST, "sha256:not-a-digest"],
        }),
      ]),
    );
    expect(await host.reload()).toMatchObject({
      served: 1,
      kept: 1,
      rekeyed: [],
      failed: [{ tenant: "acme", code: "CONFIG_INVALID:tenantKeyDigests" }],
    });
    expect(host.failures()).toEqual(["acme"]);
    expect([await status(TENANT_KEY), await status(OTHER_KEY)]).toEqual([401, 200]);

    // And when it lists none of them, the tenant is not served at all.
    files.set(REGISTRY_PATH, registry([tenant("acme", "sha256:not-a-digest")]));
    expect(await host.reload()).toMatchObject({
      served: 0,
      kept: 0,
      retired: 1,
      failed: [{ tenant: "acme", code: "CONFIG_INVALID:tenantKeyDigests" }],
    });
    expect(host.select(ACME)).toBeNull();
    expect(await status(OTHER_KEY)).toBe(421);
    await server.close(100);
    await host.close();
  });

  it("hands a rebuilt tenant's chains to its new gateway, which persists their heads from then on", async () => {
    const evidenceDir = mkdtempSync(join(tmpdir(), "agentsafe-tenant-evidence-"));
    const { host, io, files } = await start([tenant("acme", TENANT_KEY_DIGEST)], 20, {
      evidenceDir,
    });
    host.listening("https");
    const { port, server } = await serve(host);
    const key = { "agentsafe-tenant-key": TENANT_KEY };
    const intercepted = (): number =>
      reportedBy(io, "acme").filter((line) => line["event"] === "INTERCEPTED").length;

    expect((await send(port, "POST", ACME, "/orders", key)).status).toBe(200);
    await until(() => intercepted() === 1);
    expect((await get(port, ACME, "/orders")).status).toBe(401);
    const old = host.select(ACME);

    files.set(
      REGISTRY_PATH,
      registry([tenant("acme", TENANT_KEY_DIGEST, { upstream: "https://acme-v2.shop.example" })], {
        evidenceDir,
      }),
    );
    expect(await host.reload()).toMatchObject({ built: ["acme"], retired: 1 });
    expect(host.select(ACME)).not.toBe(old);
    // From the swap the new gateway persists the heads; the old one, draining, no longer does.
    const checkpoints = (): number =>
      chained(io, "acme", SECURITY_STREAM).filter((line) => line["event"] === "CHAIN_CHECKPOINT")
        .length;
    expect(checkpoints()).toBe(3);
    expect((await send(port, "POST", ACME, "/orders", key)).status).toBe(200);
    await until(() => intercepted() === 2);
    // The replaced gateway drains, then stops with its own tally.
    const stops = (): Record<string, unknown>[] =>
      reportedBy(io, "acme").filter((line) => line["event"] === "GATEWAY_STOPPED");
    await until(() => stops().length === 1);
    expect(stops()[0]).toMatchObject({ signal: "RELOAD" });
    expect(checkpoints()).toBe(3);
    await server.close(100);
    await host.close("SIGTERM");
    expect(stops().map((line) => line["signal"])).toEqual(["RELOAD", "SIGTERM"]);
    expect(
      reportedBy(io, "acme")
        .filter((line) => line["event"] === "SHADOW_REPORT")
        .map((line) => (line["shadow"] as { observed: number }).observed),
    ).toEqual([1, 1]);

    // Every stream is one chain from one start, the rebuild marked on it.
    const verified = verifyAuditChain([...io.out, ...io.err]);
    expect(verified.findings).toEqual([]);
    for (const stream of [SECURITY_STREAM, EVIDENCE_STREAM, GATEWAY_STREAM]) {
      expect(verified.streams[`acme/${stream}`]).toMatchObject({ starts: 1 });
    }
    const resumed = chained(io, "acme", SECURITY_STREAM).filter(
      (line) => line["event"] === "CHAIN_RESUMED",
    );
    expect(resumed.map((line) => line["chain"])).toEqual([
      SECURITY_STREAM,
      EVIDENCE_STREAM,
      GATEWAY_STREAM,
    ]);
    expect(chained(io, "acme", GATEWAY_STREAM).map((line) => [line["seq"], line["event"]])).toEqual(
      [
        [1, "GATEWAY_STARTED"],
        [2, "GATEWAY_STARTED"],
      ],
    );
    // Each milestone once, though two gateways served the tenant.
    const milestones = reportedBy(io, "acme")
      .filter((line) => line["event"] === "ACTIVATION")
      .map((line) => line["milestone"]);
    expect(new Set(milestones).size).toBe(milestones.length);
    expect(milestones).toContain("gateway_started");

    // The heads persisted last are the live chains', so the next process goes on from them.
    const journal = new ChainJournal(join(evidenceDir, "acme"), { checkpointLines: 100 });
    for (const stream of [SECURITY_STREAM, EVIDENCE_STREAM, GATEWAY_STREAM]) {
      const last = chained(io, "acme", stream).at(-1);
      expect(journal.restore(stream)).toEqual({ seq: last?.["seq"], hash: last?.["hash"] });
    }
    const next = await start([tenant("acme", TENANT_KEY_DIGEST)], 20, { evidenceDir });
    await next.host.close();
    expect(chained(next.io, "acme", SECURITY_STREAM)[0]).toMatchObject({
      event: "CHAIN_RESUMED",
      chain: SECURITY_STREAM,
      head: chained(io, "acme", SECURITY_STREAM).at(-1)?.["seq"],
    });
    const across = verifyAuditChain([...io.out, ...io.err, ...next.io.out, ...next.io.err]);
    expect(across.findings).toEqual([]);
    expect(across.streams[`acme/${SECURITY_STREAM}`]).toMatchObject({ starts: 1 });
    rmSync(evidenceDir, { recursive: true, force: true });
  });

  it("is ready once one load has served every tenant the registry names, and stays ready", async () => {
    const late = join(secrets, "ready-late-key");
    const { host, files } = await start([
      tenant("acme", TENANT_KEY_DIGEST),
      tenant("globex", OTHER_DIGEST, { workspace: { tenantId: WORKSPACE, apiKeyFile: late } }),
    ]);
    expect(host.ready()).toBe(false);
    writeFileSync(late, LOCAL_AUTHORITY_API_KEY, { mode: 0o600 });
    expect(await host.reload()).toMatchObject({ built: ["globex"], failed: [] });
    expect(host.ready()).toBe(true);

    // A tenant added later that cannot be built yet takes no other tenant out of service.
    files.set(
      REGISTRY_PATH,
      registry([
        tenant("acme", TENANT_KEY_DIGEST),
        tenant("globex", OTHER_DIGEST, { workspace: { tenantId: WORKSPACE, apiKeyFile: late } }),
        tenant("initech", OTHER_DIGEST, {
          workspace: { tenantId: WORKSPACE, apiKeyFile: join(secrets, "absent") },
        }),
      ]),
    );
    expect(await host.reload()).toMatchObject({ served: 2, failed: [{ tenant: "initech" }] });
    expect(host.ready()).toBe(true);
    await host.close();
  });

  it("reads back to the operator which registry and which keys a tenant's gateway serves, never a digest", async () => {
    const { host, files } = await start([tenant("acme", TENANT_KEY_DIGEST)]);
    const gateway = host.select(ACME);
    const short = (digest: string): string => digest.slice(0, "sha256:".length + 12);
    const first = gateway?.status().hosted;
    expect(first).toEqual({
      tenant: "acme",
      tenant_keys: [short(TENANT_KEY_DIGEST)],
      registry: {
        revision: short(registryRevision(files.get(REGISTRY_PATH) ?? "")),
        entry: expect.stringMatching(/^sha256:[0-9a-f]{12}$/) as unknown,
      },
    });
    expect(JSON.stringify(gateway?.status())).not.toContain(TENANT_KEY_DIGEST);

    files.set(
      REGISTRY_PATH,
      registry([
        tenant("acme", TENANT_KEY_DIGEST, { tenantKeyDigests: [TENANT_KEY_DIGEST, OTHER_DIGEST] }),
      ]),
    );
    const report = await host.reload();
    expect(report.revision).toBe(short(registryRevision(files.get(REGISTRY_PATH) ?? "")));
    expect(report.revision).not.toBe(first?.registry?.revision);
    expect(gateway?.status().hosted).toEqual({
      tenant: "acme",
      tenant_keys: [short(TENANT_KEY_DIGEST), short(OTHER_DIGEST)],
      registry: { revision: report.revision, entry: first?.registry?.entry },
    });

    files.set(REGISTRY_PATH, "version: 1\ndomain: [");
    expect(await host.reload()).toMatchObject({
      event: "TENANT_REGISTRY_REFUSED",
      revision: short(registryRevision("version: 1\ndomain: [")),
    });
    files.delete(REGISTRY_PATH);
    expect(await host.reload()).toMatchObject({ event: "TENANT_REGISTRY_REFUSED", revision: null });
    await host.close();
  });
});
