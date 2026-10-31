import { mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { ChainJournal } from "../../src/audit/ChainJournal.js";
import { EVIDENCE_STREAM } from "../../src/audit/HashChainedAuditSink.js";
import { Gateway, GATEWAY_STREAM } from "../../src/gateway/Gateway.js";
import {
  PROOF_GRACE_MS,
  PROOF_MISSING_RECHECK_MS,
  PROOF_RECHECK_MS,
  proofToken,
  UPSTREAM_PROOF_PATH,
} from "../../src/gateway/UpstreamProof.js";
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
const credentialFile = join(secrets, "upstream-credential");
const UPSTREAM_CREDENTIAL = "Bearer synthetic-upstream-credential";
const tokenFile = join(secrets, "gateway-token");
const GATEWAY_TOKEN = "synthetic-gateway-token-0001";

beforeAll(async () => {
  await authority.start();
  writeFileSync(keyFile, LOCAL_AUTHORITY_API_KEY, { mode: 0o600 });
  writeFileSync(credentialFile, `${UPSTREAM_CREDENTIAL}\n`, { mode: 0o600 });
  writeFileSync(tokenFile, `${GATEWAY_TOKEN}\n`, { mode: 0o600 });
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

  it("sends a tenant's gateway token to its upstream on every request, from a watched file, and never a caller's", async () => {
    const rotating = join(secrets, "rotating-gateway-token");
    writeFileSync(rotating, `${GATEWAY_TOKEN}\n`, { mode: 0o600 });
    const sent: { host: string; token: string | null }[] = [];
    const files = new Map([
      [
        REGISTRY_PATH,
        registry([
          tenant("acme", TENANT_KEY_DIGEST, {
            gatewayToken: { file: rotating },
            interception: {
              routes: [{ path: "/payments/**", action: "payment.create", methods: ["POST"] }],
            },
          }),
          tenant("globex", OTHER_DIGEST),
        ]),
      ],
    ]);
    const io = collectedIo();
    const host = await TenantHost.start({
      registryPath: REGISTRY_PATH,
      env: {
        DECIONIS_API_URL: authority.baseUrl,
        DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
        AGENTSAFE_METRICS_TOKEN: "synthetic-operator-token",
      },
      io,
      readFile: (path) => files.get(path) ?? null,
      dependencies: {
        upstreamFetch: async (input, init) => {
          const url = new URL(String(input));
          sent.push({
            host: url.host,
            token: new Headers(init?.headers).get("agentsafe-gateway-token"),
          });
          return new Response(`from ${url.host}`);
        },
      },
    });
    const gateway = host.select(ACME);
    expect(gateway?.config.authority.mode).toBe("SHADOW");
    expect(gateway?.status().hosted).toMatchObject({ gateway_token: true });
    expect(host.select("globex.decionisedge.example")?.status().hosted).toMatchObject({
      gateway_token: false,
    });
    const before = authority.requests.length;
    const { port, server } = await serve(host);
    const forged = { "agentsafe-gateway-token": "synthetic-forged-token" };
    expect(
      (await get(port, ACME, "/orders", { "agentsafe-tenant-key": TENANT_KEY, ...forged })).status,
    ).toBe(200);
    expect(
      (
        await send(port, "POST", ACME, "/payments/new", {
          "agentsafe-tenant-key": TENANT_KEY,
          ...forged,
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await get(port, "globex.decionisedge.example", "/orders", {
          "agentsafe-tenant-key": OTHER_KEY,
          ...forged,
        })
      ).status,
    ).toBe(200);
    expect(sent).toEqual([
      { host: "acme.shop.example", token: GATEWAY_TOKEN },
      { host: "acme.shop.example", token: GATEWAY_TOKEN },
      { host: "globex.shop.example", token: null },
    ]);

    // A Secret volume swaps the file: the next request carries the new token, from the same gateway.
    writeFileSync(`${rotating}.next`, "synthetic-gateway-token-0002\n", { mode: 0o600 });
    renameSync(`${rotating}.next`, rotating);
    await until(() =>
      io.err.some((line) => line.includes('"SECRET_ROTATED"') && line.includes('"tenant":"acme"')),
    );
    expect(host.select(ACME)).toBe(gateway);
    await get(port, ACME, "/orders", { "agentsafe-tenant-key": TENANT_KEY });
    expect(sent[sent.length - 1]).toEqual({
      host: "acme.shop.example",
      token: "synthetic-gateway-token-0002",
    });

    // The authority hears of the governed request, never of either token, and nothing is printed of them.
    const heard = (): string => JSON.stringify(authority.requests.slice(before));
    await until(() => heard().includes("payment.create"));
    const printed = [...io.out, ...io.err].join("\n");
    for (const value of [GATEWAY_TOKEN, "synthetic-gateway-token-0002", "synthetic-forged-token"]) {
      expect(heard()).not.toContain(value);
      expect(printed).not.toContain(value);
    }
    await server.close();
    await host.close();
  });

  it("refuses a tenant whose gateway token cannot be read or sent as one header, by code", async () => {
    const empty = join(secrets, "empty-gateway-token");
    const large = join(secrets, "large-gateway-token");
    const control = join(secrets, "control-gateway-token");
    writeFileSync(empty, "\n", { mode: 0o600 });
    writeFileSync(large, "x".repeat(8193), { mode: 0o600 });
    writeFileSync(control, "synthetic\u0007token", { mode: 0o600 });
    const failed = async (file: string): Promise<readonly string[]> => {
      const { host } = await start([tenant("acme", TENANT_KEY_DIGEST, { gatewayToken: { file } })]);
      const codes = (await host.reload()).failed.map((failure) => failure.code);
      await host.close();
      return codes;
    };
    expect(await failed(join(secrets, "absent"))).toEqual([
      "CONFIG_SECRET_FILE_UNREADABLE:AGENTSAFE_GATEWAY_TOKEN",
    ]);
    expect(await failed(empty)).toEqual(["CONFIG_SECRET_EMPTY:AGENTSAFE_GATEWAY_TOKEN"]);
    expect(await failed(large)).toEqual(["CONFIG_SECRET_INVALID:AGENTSAFE_GATEWAY_TOKEN"]);
    expect(await failed(control)).toEqual(["CONFIG_SECRET_INVALID:AGENTSAFE_GATEWAY_TOKEN"]);
    expect(await failed(tokenFile)).toEqual([]);
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
    // The host's `--require-upstream-proof` reaches every tenant as one setting.
    const proved = TenantHost.tenantEnvironment({}, tenant("acme", TENANT_KEY_DIGEST) as never, {
      upstreamProof: true,
    });
    expect(proved["AGENTSAFE_UPSTREAM_PROOF_REQUIRED"]).toBe("true");
    expect(
      TenantHost.tenantEnvironment({}, tenant("acme", TENANT_KEY_DIGEST) as never, {
        upstreamProof: false,
      }),
    ).not.toHaveProperty("AGENTSAFE_UPSTREAM_PROOF_REQUIRED");
  });

  it("gives an enforcing tenant enforcement, fail-closed whatever the host says, and its upstream credential's file, never its value", () => {
    const enforcing = tenant("acme", TENANT_KEY_DIGEST, {
      mode: "enforcement",
      upstreamCredential: { header: "authorization", file: "/run/custody/upstream-credential" },
    });
    const env = TenantHost.tenantEnvironment(
      { AGENTSAFE_FAILURE_POLICY: "failOpen", DECIONIS_API_URL: "https://authority.example" },
      enforcing as never,
      { upstreamProof: true, dedicated: true },
    );
    expect(env).toMatchObject({
      AGENTSAFE_MODE: "enforcement",
      AGENTSAFE_FAILURE_POLICY: "failClosed",
      AGENTSAFE_HOSTED_DEDICATED: "true",
      AGENTSAFE_UPSTREAM_PROOF_REQUIRED: "true",
      AGENTSAFE_UPSTREAM_CREDENTIAL_HEADER: "authorization",
      AGENTSAFE_UPSTREAM_CREDENTIAL_FILE: "/run/custody/upstream-credential",
    });
    // A shadow tenant keeps the host's failure policy, and is dedicated only on a host of its own.
    const shadow = TenantHost.tenantEnvironment(
      { AGENTSAFE_FAILURE_POLICY: "failOpen" },
      tenant("acme", TENANT_KEY_DIGEST) as never,
    );
    expect(shadow).toMatchObject({
      AGENTSAFE_MODE: "shadow",
      AGENTSAFE_FAILURE_POLICY: "failOpen",
    });
    expect(shadow).not.toHaveProperty("AGENTSAFE_HOSTED_DEDICATED");
    expect(shadow).not.toHaveProperty("AGENTSAFE_UPSTREAM_CREDENTIAL_FILE");
    expect(shadow).not.toHaveProperty("AGENTSAFE_GATEWAY_TOKEN_FILE");
    // The gateway token is any tenant's, in shadow or enforcement, and only ever its file.
    for (const entry of [
      tenant("acme", TENANT_KEY_DIGEST, { gatewayToken: { file: "/run/custody/gateway-token" } }),
      { ...enforcing, gatewayToken: { file: "/run/custody/gateway-token" } },
    ]) {
      expect(
        TenantHost.tenantEnvironment({ AGENTSAFE_GATEWAY_TOKEN_FILE: "/host/own" }, entry as never)[
          "AGENTSAFE_GATEWAY_TOKEN_FILE"
        ],
      ).toBe("/run/custody/gateway-token");
    }
    // A host's own setting never reaches a tenant without one.
    expect(
      TenantHost.tenantEnvironment(
        { AGENTSAFE_GATEWAY_TOKEN_FILE: "/host/own" },
        tenant("acme", TENANT_KEY_DIGEST) as never,
      ),
    ).not.toHaveProperty("AGENTSAFE_GATEWAY_TOKEN_FILE");
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

  it("reads a tenant's digests as its build does, so a reload of the same entry changes no key", async () => {
    // Padding and an empty value build: the gateway's loader trims and drops them.
    const { host, files } = await start([
      tenant("acme", TENANT_KEY_DIGEST, { tenantKeyDigests: [` ${TENANT_KEY_DIGEST}`, ""] }),
    ]);
    const { port, server } = await serve(host);
    const gateway = host.select(ACME);
    const status = async (key: string): Promise<number> =>
      (await get(port, ACME, "/orders", { "agentsafe-tenant-key": key })).status;
    expect(gateway?.tenantKeys).toEqual([TENANT_KEY_DIGEST]);
    const unchanged = { served: 1, built: [], kept: 1, rekeyed: [], retired: 0, failed: [] };
    expect(await host.reload()).toMatchObject(unchanged);
    expect(host.select(ACME)).toBe(gateway);
    expect(host.failures()).toEqual([]);
    expect(await status(TENANT_KEY)).toBe(200);

    // Two digests in one value are two keys, taken in place as a build would take them.
    files.set(
      REGISTRY_PATH,
      registry([
        tenant("acme", TENANT_KEY_DIGEST, {
          tenantKeyDigests: [`${TENANT_KEY_DIGEST}, ${OTHER_DIGEST} `],
        }),
      ]),
    );
    expect(await host.reload()).toMatchObject({ kept: 1, rekeyed: ["acme"], failed: [] });
    expect(await host.reload()).toMatchObject(unchanged);
    expect([await status(TENANT_KEY), await status(OTHER_KEY)]).toEqual([200, 200]);

    files.set(
      REGISTRY_PATH,
      registry([tenant("acme", OTHER_DIGEST, { tenantKeyDigests: [`${OTHER_DIGEST} `] })]),
    );
    expect(await host.reload()).toMatchObject({ kept: 1, rekeyed: ["acme"], failed: [] });
    expect(await host.reload()).toMatchObject(unchanged);
    expect(host.select(ACME)).toBe(gateway);
    expect([await status(TENANT_KEY), await status(OTHER_KEY)]).toEqual([401, 200]);
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
    // The rebuilt entry is another deployment, so its fingerprint is recorded too.
    expect(chained(io, "acme", GATEWAY_STREAM).map((line) => [line["seq"], line["event"]])).toEqual(
      [
        [1, "GATEWAY_STARTED"],
        [2, "DEPLOYMENT_FINGERPRINT"],
        [3, "GATEWAY_STARTED"],
        [4, "DEPLOYMENT_FINGERPRINT"],
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

  it("continues a tenant's chains by its id: across a new domain, and when it is added back while it drains", async () => {
    const evidenceDir = mkdtempSync(join(tmpdir(), "agentsafe-tenant-evidence-"));
    const { host, io, files } = await start([tenant("acme", TENANT_KEY_DIGEST)], 60_000, {
      evidenceDir,
    });
    host.listening("https");
    const { port, server } = await serve(host);
    const key = { "agentsafe-tenant-key": TENANT_KEY };
    const intercepted = (): number =>
      reportedBy(io, "acme").filter((line) => line["event"] === "INTERCEPTED").length;
    const checkpoints = (): number =>
      chained(io, "acme", SECURITY_STREAM).filter((line) => line["event"] === "CHAIN_CHECKPOINT")
        .length;
    const moved = { evidenceDir, domain: "tenants.example" };
    const MOVED = "acme.tenants.example";
    expect((await send(port, "POST", ACME, "/orders", key)).status).toBe(200);
    await until(() => intercepted() === 1);

    // A new domain moves every tenant to a new host; its gateway still takes up the chains.
    files.set(REGISTRY_PATH, registry([tenant("acme", TENANT_KEY_DIGEST)], moved));
    expect(await host.reload()).toMatchObject({ built: ["acme"], retired: 1 });
    expect(host.select(ACME)).toBeNull();
    expect(host.select(MOVED)).not.toBeNull();
    // From the swap the new gateway persists the heads; the old one, draining, no longer does.
    expect(checkpoints()).toBe(3);
    expect((await send(port, "POST", MOVED, "/orders", key)).status).toBe(200);
    await until(() => intercepted() === 2);

    // Removed, then added back before its old gateway has drained.
    files.set(REGISTRY_PATH, registry([], moved));
    expect(await host.reload()).toMatchObject({ served: 0, retired: 1 });
    files.set(REGISTRY_PATH, registry([tenant("acme", TENANT_KEY_DIGEST)], moved));
    expect(await host.reload()).toMatchObject({ built: ["acme"], retired: 0 });
    expect(checkpoints()).toBe(6);
    expect((await send(port, "POST", MOVED, "/orders", key)).status).toBe(200);
    await until(() => intercepted() === 3);
    await server.close(100);
    await host.close("SIGTERM");

    const verified = verifyAuditChain([...io.out, ...io.err]);
    expect(verified.findings).toEqual([]);
    for (const stream of [SECURITY_STREAM, EVIDENCE_STREAM, GATEWAY_STREAM]) {
      expect(verified.streams[`acme/${stream}`]).toMatchObject({ starts: 1 });
    }
    // A new domain and a return change nothing the gateway runs on: one fingerprint.
    expect(chained(io, "acme", GATEWAY_STREAM).map((line) => [line["seq"], line["event"]])).toEqual(
      [
        [1, "GATEWAY_STARTED"],
        [2, "DEPLOYMENT_FINGERPRINT"],
        [3, "GATEWAY_STARTED"],
        [4, "GATEWAY_STARTED"],
      ],
    );
    // The heads persisted last are the live chains', not a drained gateway's.
    const journal = new ChainJournal(join(evidenceDir, "acme"), { checkpointLines: 100 });
    for (const stream of [SECURITY_STREAM, EVIDENCE_STREAM, GATEWAY_STREAM]) {
      const last = chained(io, "acme", stream).at(-1);
      expect(journal.restore(stream)).toEqual({ seq: last?.["seq"], hash: last?.["hash"] });
    }
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
      upstream_proof: null,
      dedicated: false,
      upstream_credential: null,
      gateway_token: false,
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
      upstream_proof: null,
      dedicated: false,
      upstream_credential: null,
      gateway_token: false,
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

  it("gives a tenant its own upstream timeout, over the host's", async () => {
    const files = new Map([
      [
        REGISTRY_PATH,
        registry([
          tenant("acme", TENANT_KEY_DIGEST, { upstreamTimeoutMs: 45_000 }),
          tenant("globex", OTHER_DIGEST),
        ]),
      ],
    ]);
    const host = await TenantHost.start({
      registryPath: REGISTRY_PATH,
      env: {
        DECIONIS_API_URL: authority.baseUrl,
        DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
        AGENTSAFE_UPSTREAM_TIMEOUT_MS: "20000",
      },
      io: collectedIo(),
      readFile: (path) => files.get(path) ?? null,
    });
    expect(host.select(ACME)?.config.upstream.timeoutMs).toBe(45_000);
    expect(host.select("globex.decionisedge.example")?.config.upstream.timeoutMs).toBe(20_000);
    await host.close();
  });

  it("with the upstream's proof required, forwards a tenant's traffic only once its origin serves the proof, and is ready after each first look or 30 seconds", async () => {
    const token = proofToken(
      { tenant: "acme", org: WORKSPACE, origin: upstreamOf("acme") },
      1_759_492_800,
    );
    const proofs: string[] = [];
    const forwarded: string[] = [];
    let now = 1_000;
    const files = new Map([
      [
        REGISTRY_PATH,
        registry([tenant("acme", TENANT_KEY_DIGEST), tenant("globex", OTHER_DIGEST)]),
      ],
    ]);
    const io = collectedIo();
    const host = await TenantHost.start({
      registryPath: REGISTRY_PATH,
      env: { DECIONIS_API_URL: authority.baseUrl, DECIONIS_ALLOW_INSECURE_LOOPBACK: "true" },
      io,
      readFile: (path) => files.get(path) ?? null,
      requireUpstreamProof: true,
      clock: () => now,
      dependencies: {
        upstreamFetch: async (input) => {
          const url = new URL(String(input));
          if (url.pathname === UPSTREAM_PROOF_PATH) {
            proofs.push(url.host);
            // acme serves its proof; globex's origin never answers at all.
            return url.host === "acme.shop.example"
              ? new Response(`${token}\n`)
              : new Promise<Response>(() => undefined);
          }
          forwarded.push(url.host);
          return new Response(`from ${url.host}`);
        },
        upstreamResolveTxt: async () => [],
      },
    });
    await until(() => host.select(ACME)?.upstreamProofSettled === true);
    expect(proofs.sort()).toEqual(["acme.shop.example", "globex.shop.example"]);
    // Every tenant is served, but globex has not had its first look yet.
    expect(host.ready()).toBe(false);
    now += 29_999;
    expect(host.ready()).toBe(false);
    now += 1;
    expect(host.ready()).toBe(true);

    const { port, server } = await serve(host);
    expect(await get(port, ACME, "/orders", { "agentsafe-tenant-key": TENANT_KEY })).toEqual({
      status: 200,
      body: "from acme.shop.example",
    });
    const globex = await get(port, "globex.decionisedge.example", "/orders", {
      "agentsafe-tenant-key": OTHER_KEY,
    });
    expect(globex.status).toBe(503);
    expect(JSON.parse(globex.body)).toMatchObject({ reason_codes: ["UPSTREAM_UNVERIFIED"] });
    expect(forwarded).toEqual(["acme.shop.example"]);

    // A rebuild for another reason keeps where acme's proof stood: no new look, no refusal.
    files.set(
      REGISTRY_PATH,
      registry([
        tenant("acme", TENANT_KEY_DIGEST, { rateLimit: { requestsPerSecond: 5, burst: 20 } }),
        tenant("globex", OTHER_DIGEST),
      ]),
    );
    expect(await host.reload()).toMatchObject({ built: ["acme"] });
    expect(await get(port, ACME, "/orders", { "agentsafe-tenant-key": TENANT_KEY })).toEqual({
      status: 200,
      body: "from acme.shop.example",
    });
    expect(proofs.filter((origin) => origin === "acme.shop.example")).toHaveLength(1);
    expect(host.select(ACME)?.status().hosted?.upstream_proof).toMatchObject({
      state: "verified",
      method: "file",
    });
    await server.close();
    await host.close();
  });

  it("with the upstream's proof required, hands a rebuilt tenant its proof as it stands at the swap: a look that ends while the registry loads counts once, and the next look stays when it was due", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    vi.spyOn(Math, "random").mockReturnValue(0.5);
    try {
      const t0 = Date.parse("2026-10-03T12:00:00.000Z");
      let now = t0;
      const clock = (): number => now;
      const pass = async (ms: number): Promise<void> => {
        now += ms;
        await vi.advanceTimersByTimeAsync(ms);
      };
      const token = proofToken(
        { tenant: "acme", org: WORKSPACE, origin: upstreamOf("acme") },
        1_759_492_800,
      );
      // What acme's origin serves at the proof's path; a promise answers when it settles.
      let serving: string | null | Promise<Response> = `${token}\n`;
      const looks: number[] = [];
      let duringRebuild: (() => Promise<void>) | null = null;
      const files = new Map([[REGISTRY_PATH, registry([tenant("acme", TENANT_KEY_DIGEST)])]]);
      const io = collectedIo();
      const host = await TenantHost.start({
        registryPath: REGISTRY_PATH,
        env: { DECIONIS_API_URL: authority.baseUrl, DECIONIS_ALLOW_INSECURE_LOOPBACK: "true" },
        io,
        readFile: (path) => files.get(path) ?? null,
        requireUpstreamProof: true,
        clock,
        createGateway: async (config, dependencies) => {
          if (dependencies.continues !== undefined) await duringRebuild?.();
          return await Gateway.create(config, dependencies);
        },
        dependencies: {
          clock,
          upstreamFetch: async (input) => {
            const url = new URL(String(input));
            if (url.pathname !== UPSTREAM_PROOF_PATH) return new Response(`from ${url.host}`);
            looks.push(now);
            const answer = serving;
            if (answer instanceof Promise) return await answer;
            return answer === null
              ? new Response("gone", { status: 404 })
              : new Response(answer, { status: 200 });
          },
          upstreamResolveTxt: async () => [],
        },
      });
      await pass(0);
      const old = host.select(ACME);
      expect(old?.upstreamProof()).toBe("FORWARD");

      // A day later the old gateway looks again, and the origin answers only when told.
      let answer: (response: Response) => void = () => undefined;
      serving = new Promise<Response>((resolve) => {
        answer = resolve;
      });
      await pass(PROOF_RECHECK_MS);
      expect(looks).toEqual([t0, t0 + PROOF_RECHECK_MS]);
      // A change to acme's entry rebuilds it, and the look ends, without the proof, mid-reload.
      duringRebuild = async () => {
        answer(new Response("gone", { status: 404 }));
        while (old?.upstreamProof() !== "MISSING") {
          await new Promise((resolve) => setImmediate(resolve));
        }
      };
      files.set(
        REGISTRY_PATH,
        registry([
          tenant("acme", TENANT_KEY_DIGEST, { rateLimit: { requestsPerSecond: 5, burst: 20 } }),
        ]),
      );
      expect(await host.reload()).toMatchObject({ built: ["acme"] });
      const rebuilt = host.select(ACME);
      expect(rebuilt).not.toBe(old);
      const since = t0 + PROOF_RECHECK_MS;
      expect(rebuilt?.upstreamProof()).toBe("MISSING");
      expect(rebuilt?.status().hosted?.upstream_proof).toEqual({
        state: "missing",
        method: null,
        checked_at: new Date(since).toISOString(),
        stops_at: new Date(since + PROOF_GRACE_MS).toISOString(),
        code: null,
      });
      const proofEvents = (): Record<string, unknown>[] =>
        printed(io).filter(
          (line) => line["tenant"] === "acme" && String(line["event"]).startsWith("UPSTREAM_"),
        );
      expect(proofEvents()).toMatchObject([{ event: "UPSTREAM_PROOF_MISSING" }]);

      // The next look is an hour after the miss, and the new gateway's alone.
      serving = null;
      await pass(PROOF_MISSING_RECHECK_MS - 1);
      expect(looks).toHaveLength(2);
      await pass(1);
      expect(looks).toEqual([t0, since, since + PROOF_MISSING_RECHECK_MS]);
      await pass(PROOF_MISSING_RECHECK_MS);
      expect(looks).toHaveLength(4);
      expect(proofEvents()).toHaveLength(1);
      await host.close();
    } finally {
      vi.useRealTimers();
      vi.restoreAllMocks();
    }
  });

  it("leaves an enforcing tenant to a host of its own: a shared host skips it, keeps the rest, and is ready", async () => {
    const enforcing = tenant("acme", TENANT_KEY_DIGEST, {
      mode: "enforcement",
      upstreamCredential: { header: "authorization", file: credentialFile },
    });
    const { host, io, files } = await start([
      tenant("acme", TENANT_KEY_DIGEST),
      tenant("globex", OTHER_DIGEST),
    ]);
    expect(host.hostnames()).toEqual([ACME, "globex.decionisedge.example"]);

    // The tenant opts in: the shared host retires its gateway, and says why, without a failure.
    files.set(REGISTRY_PATH, registry([enforcing, tenant("globex", OTHER_DIGEST)]));
    expect(await host.reload()).toMatchObject({
      event: "TENANT_REGISTRY_LOADED",
      served: 1,
      retired: 1,
      dedicated: ["acme"],
      failed: [],
    });
    expect(host.hostnames()).toEqual(["globex.decionisedge.example"]);
    expect(host.select(ACME)).toBeNull();
    expect(host.failures()).toEqual([]);
    expect(reports(io)[0]).toMatchObject({ dedicated: [] });
    await host.close();

    // A shared host started on such a registry is ready once it serves the others.
    const fresh = await start([enforcing, tenant("globex", OTHER_DIGEST)]);
    expect(fresh.host.hostnames()).toEqual(["globex.decionisedge.example"]);
    expect(fresh.host.ready()).toBe(true);
    await fresh.host.close();
  });

  it("serves an enforcing tenant on a host of its own, which presents the tenant's upstream credential in place of the caller's", async () => {
    const token = proofToken(
      { tenant: "acme", org: WORKSPACE, origin: upstreamOf("acme") },
      1_759_492_800,
    );
    const sent: { path: string; headers: Headers }[] = [];
    const files = new Map([
      [
        REGISTRY_PATH,
        registry([
          tenant("acme", TENANT_KEY_DIGEST, {
            mode: "enforcement",
            upstreamCredential: { header: "Authorization", file: credentialFile },
          }),
          tenant("globex", OTHER_DIGEST),
        ]),
      ],
    ]);
    const io = collectedIo();
    const host = await TenantHost.start({
      registryPath: REGISTRY_PATH,
      env: {
        DECIONIS_API_URL: authority.baseUrl,
        DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
        // The host's shared setting never makes an enforcing tenant fail open.
        AGENTSAFE_FAILURE_POLICY: "failOpen",
      },
      io,
      readFile: (path) => files.get(path) ?? null,
      requireUpstreamProof: true,
      tenant: "acme",
      dependencies: {
        upstreamFetch: async (input, init) => {
          const url = new URL(String(input));
          sent.push({ path: url.pathname, headers: new Headers(init?.headers) });
          if (url.pathname === UPSTREAM_PROOF_PATH) return new Response(`${token}\n`);
          return new Response(`from ${url.host}`);
        },
        upstreamResolveTxt: async () => [],
      },
    });
    expect(host.hostnames()).toEqual([ACME]);
    await until(() => host.select(ACME)?.upstreamProofSettled === true);
    expect(host.ready()).toBe(true);
    const gateway = host.select(ACME);
    expect(gateway?.config.authority).toMatchObject({
      mode: "ENFORCEMENT",
      failurePolicy: "FAIL_CLOSED",
    });
    expect(gateway?.status().hosted).toMatchObject({
      tenant: "acme",
      dedicated: true,
      upstream_credential: { header: "authorization" },
    });

    const { port, server } = await serve(host);
    const allowed = await send(port, "POST", ACME, "/orders", {
      "agentsafe-tenant-key": TENANT_KEY,
      authorization: "Bearer the-agents-own-credential",
    });
    expect(allowed).toEqual({ status: 200, body: "from acme.shop.example" });
    const forwarded = sent.filter((entry) => entry.path === "/orders");
    expect(forwarded).toHaveLength(1);
    expect(forwarded[0]?.headers.get("authorization")).toBe(UPSTREAM_CREDENTIAL);
    expect(forwarded[0]?.headers.get("agentsafe-tenant-key")).toBeNull();
    // The proof is fetched without it: only forwarded requests carry the credential.
    expect(
      sent.find((entry) => entry.path === UPSTREAM_PROOF_PATH)?.headers.get("authorization"),
    ).toBeNull();

    // Its held requests are the tenant's: the escalation routes ask for its key too.
    const escalation = "/_agentsafe/v1/escalations/00000000-0000-4000-8000-0000000000aa";
    expect((await get(port, ACME, escalation)).status).toBe(401);
    expect((await get(port, ACME, escalation, { "agentsafe-tenant-key": TENANT_KEY })).status).toBe(
      404,
    );

    const printed = [...io.out, ...io.err].join("\n");
    expect(printed).not.toContain("synthetic-upstream-credential");
    expect(printed).not.toContain("the-agents-own-credential");
    await server.close();
    await host.close();
  });

  it("refuses an enforcing tenant whose controls are not all on, by the missing setting, and a host for a tenant the registry lacks", async () => {
    const enforcing = (overrides: Record<string, unknown> = {}) =>
      tenant("acme", TENANT_KEY_DIGEST, {
        mode: "enforcement",
        upstreamCredential: { header: "authorization", file: credentialFile },
        ...overrides,
      });
    const failure = async (
      entry: unknown,
      options: { readonly requireUpstreamProof?: boolean } = {},
    ): Promise<readonly { tenant: string; code: string }[]> => {
      const files = new Map([[REGISTRY_PATH, registry([entry])]]);
      const host = await TenantHost.start({
        registryPath: REGISTRY_PATH,
        env: { DECIONIS_API_URL: authority.baseUrl, DECIONIS_ALLOW_INSECURE_LOOPBACK: "true" },
        io: collectedIo(),
        readFile: (path) => files.get(path) ?? null,
        requireUpstreamProof: options.requireUpstreamProof ?? true,
        tenant: "acme",
        dependencies: {
          upstreamFetch: async () => new Promise<Response>(() => undefined),
          upstreamResolveTxt: async () => [],
        },
      });
      const report = await host.reload();
      expect(host.ready()).toBe(false);
      await host.close();
      return report.failed;
    };
    expect(await failure(enforcing(), { requireUpstreamProof: false })).toEqual([
      { tenant: "acme", code: "CONFIG_MISSING:AGENTSAFE_UPSTREAM_PROOF_REQUIRED" },
    ]);
    expect(
      await failure(
        enforcing({
          upstreamCredential: { header: "authorization", file: join(secrets, "absent") },
        }),
      ),
    ).toEqual([{ tenant: "acme", code: "CONFIG_SECRET_FILE_UNREADABLE:DOWNSTREAM_CREDENTIAL" }]);
    expect(
      await failure(
        enforcing({ upstreamCredential: { header: "content-type", file: credentialFile } }),
      ),
    ).toEqual([{ tenant: "acme", code: "CONFIG_INVALID:upstream.credential.header" }]);
    expect(
      await failure(enforcing({ interception: { principalHeader: "authorization" } })),
    ).toEqual([{ tenant: "acme", code: "CONFIG_INVALID:upstream.credential.header" }]);
    expect(await failure(tenant("globex", OTHER_DIGEST))).toEqual([
      { tenant: "acme", code: "TENANT_NOT_IN_REGISTRY" },
    ]);
  });
});
