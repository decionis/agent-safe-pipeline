import { X509Certificate } from "node:crypto";
import { mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { TLSSocket } from "node:tls";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { runHost } from "../../src/cli/Host.js";
import { proofToken, UPSTREAM_PROOF_PATH } from "../../src/gateway/UpstreamProof.js";
import { closedPort } from "../support/Environment.js";
import { TestCertificateAuthority } from "../support/TestCertificateAuthority.js";
import { fakeProcess, TENANT_KEY, TENANT_KEY_DIGEST } from "../support/GatewayHarness.js";

const WORKSPACE = "00000000-0000-4000-8000-000000000009";
/** Each tenant's upstream, written whole: the fixture check reads URLs as they are written. */
const UPSTREAMS: Readonly<Record<string, string>> = {
  acme: "https://acme.shop.example",
  globex: "https://globex.shop.example",
  initech: "https://initech.shop.example",
};
const upstreamOf = (id: string): string => UPSTREAMS[id] ?? "https://tenant.shop.example";
const REGISTRY = "/etc/agentsafe/tenants.yaml";
const authority = new LocalAuthority();
const secrets = mkdtempSync(join(tmpdir(), "agentsafe-host-cli-"));
const keyFile = join(secrets, "decionis-api-key");

beforeAll(async () => {
  await authority.start();
  writeFileSync(keyFile, LOCAL_AUTHORITY_API_KEY, { mode: 0o600 });
});
afterAll(async () => {
  await authority.stop();
  rmSync(secrets, { recursive: true, force: true });
});

const registry = (ids: readonly string[]): string =>
  JSON.stringify({
    version: 1,
    domain: "decionisedge.example",
    tenants: ids.map((id) => ({
      id,
      upstream: upstreamOf(id),
      tenantKeyDigests: [TENANT_KEY_DIGEST],
      workspace: { tenantId: WORKSPACE, apiKeyFile: keyFile },
    })),
  });

const settle = (ms = 30): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
/** The host's own lines; every line a tenant's gateway prints names its tenant. */
const own = (out: readonly string[]): Record<string, unknown>[] =>
  out
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((line) => !("tenant" in line));
const events = (out: readonly string[]): string[] =>
  own(out).map((line) => String(line["event"] ?? ""));
/** What one tenant's gateway reported, by event, in order. */
const reported = (out: readonly string[], tenant: string): Record<string, unknown>[] =>
  out
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((line) => line["tenant"] === tenant && !("stream" in line));

function get(
  port: number,
  host: string,
  path: string,
  headers: Record<string, string> = {},
): Promise<number> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      { host: "127.0.0.1", port, path, headers: { host, ...headers } },
      (response) => {
        response.resume();
        resolve(response.statusCode ?? 0);
      },
    );
    request.on("error", reject);
    request.end();
  });
}

describe("agentsafe host", () => {
  it("refuses to start without a registry, with a bad address, or on a registry it cannot serve", async () => {
    const unnamed = fakeProcess();
    await runHost(unnamed, []);
    expect(unnamed.exits).toEqual([2]);
    expect(unnamed.err[0]).toContain("CONFIG_MISSING: registry");

    const badPort = fakeProcess({ env: { AGENTSAFE_TENANT_REGISTRY: REGISTRY } });
    await runHost(badPort, ["--port", "0"]);
    expect(badPort.exits).toEqual([2]);

    const unreadable = fakeProcess();
    await runHost(unreadable, ["--registry", REGISTRY]);
    expect(unreadable.exits).toEqual([1]);
    expect(JSON.parse(unreadable.err[0] ?? "{}")).toEqual({
      event: "REFUSED_TO_START",
      reason: "REGISTRY_UNREADABLE",
    });
  });

  it("serves the registry's tenants, reloads on a change and on SIGHUP, and stops on a signal", async () => {
    const port = await closedPort();
    const io = fakeProcess({
      env: {
        AGENTSAFE_TENANT_REGISTRY: REGISTRY,
        DECIONIS_API_URL: authority.baseUrl,
        DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
      },
      files: { [REGISTRY]: registry(["acme"]) },
    });
    await runHost(
      io,
      ["--listen", `127.0.0.1:${port}`],
      { upstreamFetch: async () => new Response("ok", { status: 200 }) },
      20,
    );
    expect(io.exits).toEqual([]);
    expect(events(io.out)).toEqual(["TENANT_REGISTRY_LOADED", "TENANT_HOST_STARTED"]);
    expect(own(io.out)[1]).toMatchObject({
      listen: `127.0.0.1:${port}`,
      tenants: 1,
      upstream_proof: false,
    });
    // Each tenant's gateway starts once the listener is bound, at its own host.
    expect(
      reported(io.out, "acme").find((line) => line["event"] === "GATEWAY_STARTED"),
    ).toMatchObject({ gateway: "http://acme.decionisedge.example", mode: "SHADOW" });
    expect(await get(port, "10.0.0.8:8080", "/_agentsafe/readyz")).toBe(200);
    expect(
      await get(port, "acme.decionisedge.example", "/orders", {
        "agentsafe-tenant-key": TENANT_KEY,
      }),
    ).toBe(200);
    expect(await get(port, "globex.decionisedge.example", "/orders")).toBe(421);

    // A change to the file is picked up without a signal.
    io.stored.set(REGISTRY, { text: registry(["acme", "globex"]), mode: undefined });
    for (let attempt = 0; attempt < 40 && events(io.out).length < 3; attempt += 1) await settle();
    expect(events(io.out)[2]).toBe("TENANT_REGISTRY_LOADED");
    expect(
      await get(port, "globex.decionisedge.example", "/orders", {
        "agentsafe-tenant-key": TENANT_KEY,
      }),
    ).toBe(200);

    // And SIGHUP reads it again on demand.
    io.signals.get("SIGHUP")?.();
    for (let attempt = 0; attempt < 40 && events(io.out).length < 4; attempt += 1) await settle();
    expect(own(io.out)[3]).toMatchObject({
      event: "TENANT_REGISTRY_LOADED",
      kept: 2,
      built: [],
    });

    io.signals.get("SIGTERM")?.();
    io.signals.get("SIGINT")?.();
    for (let attempt = 0; attempt < 40 && io.exits.length === 0; attempt += 1) await settle();
    expect(io.exits).toEqual([0]);
    expect(events(io.out).at(-1)).toBe("TENANT_HOST_STOPPED");
    // Every tenant's gateway stops with the signal, and its shadow tally.
    for (const tenant of ["acme", "globex"]) {
      expect(reported(io.out, tenant).slice(-2)).toEqual([
        expect.objectContaining({ event: "SHADOW_REPORT" }),
        expect.objectContaining({ event: "GATEWAY_STOPPED", signal: "SIGTERM" }),
      ]);
    }
    expect(io.out.join("")).not.toContain(TENANT_KEY);
  });

  it("requires every tenant's upstream proof with --require-upstream-proof, and says so when it starts", async () => {
    const port = await closedPort();
    const io = fakeProcess({
      env: {
        AGENTSAFE_TENANT_REGISTRY: REGISTRY,
        DECIONIS_API_URL: authority.baseUrl,
        DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
      },
      files: { [REGISTRY]: registry(["acme", "globex"]) },
    });
    const token = proofToken(
      { tenant: "acme", org: WORKSPACE, origin: upstreamOf("acme") },
      1_759_492_800,
    );
    await runHost(
      io,
      ["--listen", `127.0.0.1:${port}`, "--require-upstream-proof"],
      {
        // acme's origin serves its proof; globex's does not.
        upstreamFetch: async (input) => {
          const url = new URL(String(input));
          if (url.pathname !== UPSTREAM_PROOF_PATH) return new Response("ok", { status: 200 });
          return url.host === "acme.shop.example"
            ? new Response(token, { status: 200 })
            : new Response("not here", { status: 404 });
        },
        upstreamResolveTxt: async () => [],
      },
      0,
    );
    expect(io.exits).toEqual([]);
    expect(own(io.out)[1]).toMatchObject({ event: "TENANT_HOST_STARTED", upstream_proof: true });
    let ready = 0;
    for (let attempt = 0; attempt < 40 && ready !== 200; attempt += 1) {
      ready = await get(port, "10.0.0.8:8080", "/_agentsafe/readyz");
      if (ready !== 200) await settle();
    }
    expect(ready).toBe(200);
    const key = { "agentsafe-tenant-key": TENANT_KEY };
    expect(await get(port, "acme.decionisedge.example", "/orders", key)).toBe(200);
    expect(await get(port, "globex.decionisedge.example", "/orders", key)).toBe(503);
    // A flag is a flag: it takes no value.
    const valued = fakeProcess({ env: { AGENTSAFE_TENANT_REGISTRY: REGISTRY } });
    await runHost(valued, ["--require-upstream-proof=true"]);
    expect(valued.exits).toEqual([2]);
    io.signals.get("SIGTERM")?.();
    for (let attempt = 0; attempt < 40 && io.exits.length === 0; attempt += 1) await settle();
    expect(io.exits).toEqual([0]);
  });

  it("tries a tenant it could not build again, until its key arrives, with the registry unchanged", async () => {
    const port = await closedPort();
    const late = join(secrets, "arrives-later");
    const io = fakeProcess({
      env: {
        AGENTSAFE_TENANT_REGISTRY: REGISTRY,
        DECIONIS_API_URL: authority.baseUrl,
        DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
      },
      files: {
        [REGISTRY]: JSON.stringify({
          version: 1,
          domain: "decionisedge.example",
          tenants: [
            {
              id: "acme",
              upstream: upstreamOf("acme"),
              tenantKeyDigests: [TENANT_KEY_DIGEST],
              workspace: { tenantId: WORKSPACE, apiKeyFile: late },
            },
          ],
        }),
      },
    });
    await runHost(
      io,
      ["--listen", `127.0.0.1:${port}`],
      { upstreamFetch: async () => new Response("ok", { status: 200 }) },
      20,
      60,
    );
    expect(own(io.out)[0]).toMatchObject({
      event: "TENANT_REGISTRY_LOADED",
      served: 0,
      failed: [{ tenant: "acme" }],
    });
    // A process that cannot serve every tenant yet is not ready for traffic.
    expect(await get(port, "10.0.0.8:8080", "/_agentsafe/readyz")).toBe(503);
    writeFileSync(late, LOCAL_AUTHORITY_API_KEY, { mode: 0o600 });
    const built = (): boolean => io.out.some((line) => line.includes('"built":["acme"]'));
    for (let attempt = 0; attempt < 100 && !built(); attempt += 1) await settle(20);
    expect(built()).toBe(true);
    expect(await get(port, "10.0.0.8:8080", "/_agentsafe/readyz")).toBe(200);
    expect(
      await get(port, "acme.decionisedge.example", "/orders", {
        "agentsafe-tenant-key": TENANT_KEY,
      }),
    ).toBe(200);
    io.signals.get("SIGTERM")?.();
    for (let attempt = 0; attempt < 40 && io.exits.length === 0; attempt += 1) await settle();
    expect(io.exits).toEqual([0]);
  });

  it("refuses half a TLS configuration, and a redirect without TLS", async () => {
    const half = fakeProcess({ env: { AGENTSAFE_TENANT_REGISTRY: REGISTRY } });
    await runHost(half, ["--tls-cert", "/etc/agentsafe/tls.crt"]);
    expect(half.exits).toEqual([2]);
    expect(half.err[0]).toContain("CONFIG_INVALID: tls");
    const plain = fakeProcess({ env: { AGENTSAFE_TENANT_REGISTRY: REGISTRY } });
    await runHost(plain, ["--redirect-listen", "127.0.0.1:8080"]);
    expect(plain.exits).toEqual([2]);
    expect(plain.err[0]).toContain("CONFIG_INVALID: redirect-listen");
  });

  it("terminates TLS itself, redirects plain HTTP, serves the apex, and takes a renewed certificate in place", async () => {
    const ca = new TestCertificateAuthority("Synthetic Edge CA");
    const first = ca.issueServer(["*.decionisedge.example", "decionisedge.example"]);
    const keyFile = join(secrets, "edge-tls.key");
    writeFileSync(keyFile, first.key, { mode: 0o600 });
    const port = await closedPort();
    const redirectPort = await closedPort();
    const io = fakeProcess({
      env: {
        AGENTSAFE_TENANT_REGISTRY: REGISTRY,
        DECIONIS_API_URL: authority.baseUrl,
        DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
      },
      files: {
        [REGISTRY]: registry(["acme"]),
        "/etc/agentsafe/tls.crt": first.cert,
        "/etc/agentsafe/apex.html": "<!doctype html><p>Operated by Decionis.</p>",
      },
    });
    await runHost(
      io,
      [
        "--listen",
        `127.0.0.1:${port}`,
        "--tls-cert",
        "/etc/agentsafe/tls.crt",
        "--tls-key",
        keyFile,
        "--redirect-listen",
        `127.0.0.1:${redirectPort}`,
        "--apex-page",
        "/etc/agentsafe/apex.html",
      ],
      { upstreamFetch: async () => new Response("ok", { status: 200 }) },
      20,
    );
    expect(io.exits).toEqual([]);
    expect(own(io.out)[1]).toMatchObject({
      event: "TENANT_HOST_STARTED",
      tls: true,
      redirect: `127.0.0.1:${redirectPort}`,
    });
    expect(
      reported(io.out, "acme").find((line) => line["event"] === "GATEWAY_STARTED"),
    ).toMatchObject({ gateway: "https://acme.decionisedge.example" });

    const tenant = await secure(port, ca.certificate, "acme.decionisedge.example", "/orders", {
      "agentsafe-tenant-key": TENANT_KEY,
    });
    expect(tenant.status).toBe(200);
    expect(tenant.headers["strict-transport-security"]).toBe("max-age=31536000; includeSubDomains");
    const apex = await secure(port, ca.certificate, "decionisedge.example", "/");
    expect(apex.status).toBe(200);
    expect(apex.body).toContain("Operated by Decionis.");
    expect(apex.headers["content-security-policy"]).toContain("frame-ancestors 'none'");
    expect((await secure(port, ca.certificate, "decionisedge.example", "/elsewhere")).status).toBe(
      404,
    );
    expect(
      (await secure(port, ca.certificate, "decionisedge.example", "/_agentsafe/healthz")).status,
    ).toBe(200);

    const moved = await plain(redirectPort, "GET", "acme.decionisedge.example", "/orders?page=2");
    expect(moved).toMatchObject({
      status: 301,
      location: "https://acme.decionisedge.example/orders?page=2",
    });
    expect(
      (await plain(redirectPort, "POST", "acme.decionisedge.example:80", "/orders")).status,
    ).toBe(308);
    expect((await plain(redirectPort, "GET", "decionisedge.example", "/")).location).toBe(
      "https://decionisedge.example/",
    );
    expect((await plain(redirectPort, "GET", "evil.example", "/")).status).toBe(421);
    expect(
      (await plain(redirectPort, "GET", "decionisedge.example.evil.example", "/")).status,
    ).toBe(421);

    // cert-manager renews: the Secret swaps both files at once.
    const second = ca.issueServer(["*.decionisedge.example", "decionisedge.example"]);
    io.stored.set("/etc/agentsafe/tls.crt", { text: second.cert, mode: undefined });
    writeFileSync(`${keyFile}.next`, second.key, { mode: 0o600 });
    renameSync(`${keyFile}.next`, keyFile);
    const rotated = (): boolean => io.err.some((line) => line.includes("TLS_CONTEXT_ROTATED"));
    for (let attempt = 0; attempt < 100 && !rotated(); attempt += 1) await settle(20);
    expect(rotated()).toBe(true);
    const renewed = await secure(port, ca.certificate, "acme.decionisedge.example", "/orders", {
      "agentsafe-tenant-key": TENANT_KEY,
    });
    expect(renewed.fingerprint).not.toBe(tenant.fingerprint);
    expect(renewed.fingerprint).toBe(new X509Certificate(second.cert).fingerprint256);

    io.signals.get("SIGTERM")?.();
    for (let attempt = 0; attempt < 40 && io.exits.length === 0; attempt += 1) await settle();
    expect(io.exits).toEqual([0]);
  });
});

function secure(
  port: number,
  ca: string,
  host: string,
  path: string,
  headers: Record<string, string> = {},
): Promise<{
  status: number;
  body: string;
  headers: Record<string, unknown>;
  fingerprint: string;
}> {
  return new Promise((resolve, reject) => {
    const request = httpsRequest(
      {
        host: "127.0.0.1",
        port,
        path,
        ca,
        servername: host,
        agent: false,
        headers: { host, ...headers },
      },
      (response) => {
        const chunks: Buffer[] = [];
        const peer = (response.socket as TLSSocket).getPeerCertificate();
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
            headers: response.headers,
            fingerprint: peer.fingerprint256,
          }),
        );
      },
    );
    request.on("error", reject);
    request.end();
  });
}

function plain(
  port: number,
  method: string,
  host: string,
  path: string,
): Promise<{ status: number; location: string | undefined }> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      { host: "127.0.0.1", port, path, method, headers: { host } },
      (response) => {
        response.resume();
        resolve({ status: response.statusCode ?? 0, location: response.headers.location });
      },
    );
    request.on("error", reject);
    request.end();
  });
}
