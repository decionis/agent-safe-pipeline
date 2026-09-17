import { describe, expect, it } from "vitest";
import { runDoctor } from "../../src/cli/Doctor.js";
import { DEFAULT_AUTHORITY_ENDPOINT } from "../../src/gateway/GatewayConfig.js";
import { fakeProcess } from "../support/GatewayHarness.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";

/** A fetch that answers by URL: the upstream, the authority's health, and the credential probe. */
function network(answers: {
  upstream?: number | "down";
  health?: number | "down";
  probe?: number | "down";
}): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const pick = url.includes("/v1/health")
      ? answers.health
      : url.includes("/enforce-and-bind")
        ? answers.probe
        : answers.upstream;
    if (pick === "down" || pick === undefined)
      throw Object.assign(new Error("fetch failed"), { cause: { code: "ECONNREFUSED" } });
    if (url.includes("/enforce-and-bind")) {
      expect(init?.method).toBe("POST");
      expect((init?.headers as Record<string, string>)["authorization"]).toMatch(
        /^Bearer synthetic-/,
      );
    }
    return new Response(null, { status: pick });
  }) as typeof fetch;
}

const byName = (checks: readonly { name: string; ok: boolean; detail: string }[]) =>
  Object.fromEntries(checks.map((check) => [check.name, check]));

describe("agentsafe doctor", () => {
  it("passes on a laptop with the demo authority and a reachable upstream", async () => {
    const io = fakeProcess({ fetch: network({ upstream: 404 }) });
    const checks = byName(
      await runDoctor(io, ["--upstream", "http://localhost:3000"], { nodeVersion: "22.14.0" }),
    );
    expect(io.exits).toEqual([0]);
    expect(checks["AgentSafe binary"]?.ok).toBe(true);
    expect(checks["configuration valid"]).toMatchObject({
      ok: true,
      detail: "flags and environment; no file",
    });
    expect(checks["upstream reachable"]).toMatchObject({
      ok: true,
      detail: "http://localhost:3000 answered 404",
    });
    expect(checks["Decionis reachable"]?.detail).toContain("local/demo");
    expect(checks["credentials valid"]?.ok).toBe(true);
    expect(checks["Presence configuration"]?.detail).toContain("held");
    expect(checks["evidence configuration"]?.detail).toContain("not written");
    expect(io.out.join("")).toContain("Ready to govern.");
  });

  it("explains a rejected key the way the brief asks, and a missing one", async () => {
    const env = { DECIONIS_API_KEY: "synthetic-rejected-key", DECIONIS_TENANT_ID: TENANT_ID };
    const io = fakeProcess({ env, fetch: network({ upstream: 200, health: 200, probe: 401 }) });
    const checks = byName(
      await runDoctor(io, ["--upstream", "https://api.example"], { nodeVersion: "22.14.0" }),
    );
    expect(io.exits).toEqual([1]);
    expect(checks["Decionis reachable"]).toMatchObject({ ok: true });
    expect(checks["credentials valid"]).toMatchObject({
      ok: false,
      detail: "Decionis authentication failed. The configured API key was rejected.",
    });
    const text = io.out.join("");
    expect(text).toContain("✗ credentials valid");
    expect(text).toContain("Check DECIONIS_API_KEY");
    expect(text).toContain("or run: agentsafe login");
    expect(text).toContain("1 check(s) need attention.");
    const accepted = byName(
      await runDoctor(
        fakeProcess({ env, fetch: network({ upstream: 200, health: 200, probe: 400 }) }),
        ["--upstream", "https://api.example"],
        { nodeVersion: "22.14.0" },
      ),
    );
    expect(accepted["credentials valid"]).toMatchObject({ ok: true });
    const other = byName(
      await runDoctor(
        fakeProcess({ env, fetch: network({ upstream: 200, health: 200, probe: 500 }) }),
        ["--upstream", "https://api.example"],
        { nodeVersion: "22.14.0" },
      ),
    );
    expect(other["credentials valid"]).toMatchObject({
      ok: false,
      detail: `${DEFAULT_AUTHORITY_ENDPOINT} answered 500`,
    });
    const fromFile = fakeProcess({
      env: { DECIONIS_API_KEY_FILE: "/run/secrets/key", DECIONIS_TENANT_ID: TENANT_ID },
      files: { "/run/secrets/key": "synthetic-file-key\n" },
      fetch: network({ upstream: 200, health: 200, probe: 422 }),
    });
    expect(
      byName(
        await runDoctor(fromFile, ["--upstream", "https://api.example"], {
          nodeVersion: "22.14.0",
        }),
      )["credentials valid"]?.ok,
    ).toBe(true);
    const missingFile = fakeProcess({
      env: { DECIONIS_API_KEY_FILE: "/run/secrets/none", DECIONIS_TENANT_ID: TENANT_ID },
      fetch: network({ upstream: 200, health: 200, probe: 422 }),
    });
    expect(
      byName(
        await runDoctor(missingFile, ["--upstream", "https://api.example"], {
          nodeVersion: "22.14.0",
        }),
      )["credentials valid"],
    ).toMatchObject({ ok: false, detail: "no Decionis key" });
  });

  it("reports an unreachable upstream or authority with what to do, and an old node", async () => {
    const env = { DECIONIS_API_KEY: "synthetic-key", DECIONIS_TENANT_ID: TENANT_ID };
    const io = fakeProcess({
      env,
      fetch: network({ upstream: "down", health: "down", probe: "down" }),
    });
    const checks = byName(
      await runDoctor(io, ["--upstream", "https://api.example", "--json"], {
        nodeVersion: "20.0.0",
      }),
    );
    expect(checks["AgentSafe binary"]?.ok).toBe(false);
    expect(checks["upstream reachable"]).toMatchObject({
      ok: false,
      detail: "https://api.example: ECONNREFUSED",
    });
    expect(checks["Decionis reachable"]).toMatchObject({ ok: false });
    expect(checks["credentials valid"]).toMatchObject({ ok: false });
    const report = JSON.parse(io.out.join("")) as { ok: boolean; checks: unknown[] };
    expect(report.ok).toBe(false);
    expect(report.checks.length).toBeGreaterThan(5);
    expect(io.exits).toEqual([1]);
  });

  it("names the configuration problem instead of probing, and skips the network when asked", async () => {
    const invalid = fakeProcess({ fetch: network({}) });
    const checks = byName(await runDoctor(invalid, [], { nodeVersion: "22.14.0" }));
    expect(checks["configuration valid"]).toMatchObject({ ok: false });
    expect(checks["configuration valid"]?.detail).toContain("CONFIG_MISSING: upstream");
    expect(Object.keys(checks)).not.toContain("upstream reachable");
    expect(invalid.exits).toEqual([1]);
    const offline = fakeProcess({ fetch: network({}) });
    const skipped = byName(
      await runDoctor(offline, ["--upstream", "http://localhost:3000", "--no-network"], {
        nodeVersion: "22.14.0",
      }),
    );
    expect(skipped["network checks"]).toMatchObject({ ok: true, detail: "skipped (--no-network)" });
    expect(offline.exits).toEqual([0]);
    const bad = fakeProcess();
    await runDoctor(bad, ["--nope"], { nodeVersion: "22.14.0" });
    expect(bad.exits).toEqual([2]);
  });

  it("describes evidence and Presence as configured", async () => {
    const env = {
      DECIONIS_API_KEY: "synthetic-key",
      DECIONIS_TENANT_ID: TENANT_ID,
      AGENTSAFE_PRESENCE_MANAGED: "true",
      PRESENCE_APPROVER_ID: "synthetic-approver",
      AGENTSAFE_EVIDENCE_DIR: "/var/lib/agentsafe",
    };
    const io = fakeProcess({ env });
    const checks = byName(
      await runDoctor(
        io,
        ["--upstream", "https://api.example", "--mode", "enforcement", "--no-network"],
        { nodeVersion: "23.1.0" },
      ),
    );
    expect(checks["Presence configuration"]?.detail).toContain("MANAGED");
    expect(checks["evidence configuration"]?.detail).toContain("/var/lib/agentsafe");
    const verbose = byName(
      await runDoctor(
        fakeProcess(),
        ["--upstream", "http://localhost:1", "--no-network", "--verbose"],
        { nodeVersion: "22.14.0" },
      ),
    );
    expect(verbose["evidence configuration"]?.detail).toContain("terminal");
    const disabled = fakeProcess({
      files: {
        "/work/agentsafe.yaml":
          "version: 1\ngateway:\n  upstream: http://localhost:1\nevidence:\n  enabled: false\n",
      },
    });
    const off = byName(await runDoctor(disabled, ["--no-network"], { nodeVersion: "22.14.0" }));
    expect(off["evidence configuration"]).toMatchObject({ ok: false });
    expect(disabled.exits).toEqual([1]);
  });
});
