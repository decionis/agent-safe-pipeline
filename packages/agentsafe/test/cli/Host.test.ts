import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { runHost } from "../../src/cli/Host.js";
import { closedPort } from "../support/Environment.js";
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
const events = (out: readonly string[]): string[] =>
  out.map((line) => String((JSON.parse(line) as { event?: unknown }).event ?? ""));

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
    expect(JSON.parse(io.out[1] ?? "{}")).toMatchObject({
      listen: `127.0.0.1:${port}`,
      tenants: 1,
    });
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
    expect(JSON.parse(io.out[3] ?? "{}")).toMatchObject({
      event: "TENANT_REGISTRY_LOADED",
      kept: 2,
      built: [],
    });

    io.signals.get("SIGTERM")?.();
    io.signals.get("SIGINT")?.();
    for (let attempt = 0; attempt < 40 && io.exits.length === 0; attempt += 1) await settle();
    expect(io.exits).toEqual([0]);
    expect(events(io.out).at(-1)).toBe("TENANT_HOST_STOPPED");
    expect(io.out.join("")).not.toContain(TENANT_KEY);
  });
});
