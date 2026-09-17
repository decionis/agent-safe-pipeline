import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { GatewayConfigError } from "../../src/gateway/GatewayConfig.js";
import { ConfigFileError } from "../../src/cli/ConfigFile.js";
import { explainRefusal, gatewayFlags, resolveGateway, runProxy } from "../../src/cli/Proxy.js";
import { parseArguments } from "../../src/cli/Arguments.js";
import { closedPort } from "../support/Environment.js";
import { fakeProcess, UpstreamDouble, LOOPBACK_ORIGIN } from "../support/GatewayHarness.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";
const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 50));

describe("agentsafe proxy", () => {
  const upstream = new UpstreamDouble();
  beforeAll(() => upstream.start());
  afterAll(() => upstream.stop());

  it("resolves the configuration from flags, environment, file and the stored login", () => {
    const io = fakeProcess({
      env: { AGENTSAFE_MODE: "shadow" },
      files: {
        "/work/agentsafe.yaml": "version: 1\ngateway:\n  upstream: https://api.example\n",
        "/home/synthetic/.config/agentsafe/credentials.json": JSON.stringify({
          version: 1,
          decionis: {
            apiKey: "synthetic-login-key-0123456789",
            tenantId: TENANT_ID,
            endpoint: null,
          },
        }),
      },
    });
    const parsed = parseArguments(
      [
        "--port",
        "9001",
        "--verbose",
        "--json",
        "--failure-policy",
        "failOpen",
        "--authority",
        "decionis",
        "--listen",
        "127.0.0.1:9002",
        "--mode",
        "enforcement",
      ],
      {
        valued: ["port", "failure-policy", "authority", "listen", "mode"],
        flags: ["verbose", "json"],
      },
    );
    expect(gatewayFlags(parsed)).toEqual({
      port: 9001,
      verbose: true,
      json: true,
      failurePolicy: "failOpen",
      authority: "decionis",
      listen: "127.0.0.1:9002",
      mode: "enforcement",
    });
    const resolved = resolveGateway(io, parseArguments([], { valued: [], flags: [] }));
    expect(resolved.configPath).toBe("/work/agentsafe.yaml");
    expect(resolved.config.authority).toMatchObject({
      kind: "DECIONIS",
      mode: "SHADOW",
      tenantId: TENANT_ID,
    });
    expect(resolved.env["DECIONIS_API_KEY"]).toBe("synthetic-login-key-0123456789");
    const own = fakeProcess({
      env: { DECIONIS_API_KEY: "synthetic-env-key", DECIONIS_TENANT_ID: TENANT_ID },
      files: {
        "/home/synthetic/.config/agentsafe/credentials.json": JSON.stringify({
          version: 1,
          decionis: { apiKey: "synthetic-login-key-0123456789", tenantId: null, endpoint: null },
        }),
      },
    });
    expect(
      resolveGateway(
        own,
        parseArguments(["--upstream", "https://api.example"], { valued: ["upstream"], flags: [] }),
      ).env["DECIONIS_API_KEY"],
    ).toBe("synthetic-env-key");
  });

  it("explains every refusal on one line that names the setting", () => {
    expect(explainRefusal(new GatewayConfigError("CONFIG_MISSING", "DECIONIS_API_KEY"))).toContain(
      "agentsafe login",
    );
    expect(explainRefusal(new GatewayConfigError("CONFIG_MISSING", "upstream"))).toContain(
      "--upstream http://localhost:3000",
    );
    expect(
      explainRefusal(new GatewayConfigError("CONFIG_INVALID", "PORT", "an integer")),
    ).toContain("CONFIG_INVALID: PORT (an integer)");
    expect(explainRefusal(new ConfigFileError("CONFIG_FILE_NOT_YAML", "/x.yaml"))).toContain(
      "CONFIG_FILE_NOT_YAML: /x.yaml",
    );
    expect(explainRefusal(new Error("OTHER"))).toContain("OTHER");
    expect(explainRefusal("string")).toContain("UNKNOWN");
  });

  it("starts, prints the banner, governs a request, and stops on a signal", async () => {
    const port = await closedPort();
    const io = fakeProcess();
    await runProxy(io, ["--upstream", upstream.baseUrl, "--port", String(port), "--json"]);
    expect(io.exits).toEqual([]);
    const banner = JSON.parse(io.out[0] ?? "{}") as Record<string, unknown>;
    expect(banner).toMatchObject({
      event: "GATEWAY_STARTED",
      gateway: `${LOOPBACK_ORIGIN}:${port}`,
      mode: "ENFORCEMENT",
    });
    const response = await fetch(`${LOOPBACK_ORIGIN}:${port}/payments`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"amount": 1}',
    });
    expect(response.status).toBe(201);
    expect(response.headers.get("agentsafe-decision")).toBe("ALLOW");
    expect([...io.signals.keys()]).toEqual(["SIGTERM", "SIGINT"]);
    io.signals.get("SIGTERM")?.();
    io.signals.get("SIGINT")?.();
    for (let attempt = 0; attempt < 40 && io.exits.length === 0; attempt += 1) await settle();
    expect(io.exits).toEqual([0]);
    expect(io.out.at(-1)).toContain('"event":"GATEWAY_STOPPED"');
    await expect(fetch(`${LOOPBACK_ORIGIN}:${port}/_agentsafe/healthz`)).rejects.toThrow();
  });

  it("refuses to start on a bad argument, a bad configuration, or a port that is taken", async () => {
    const argument = fakeProcess();
    await runProxy(argument, ["--upstream"]);
    expect(argument.exits).toEqual([2]);
    expect(argument.err.join("")).toContain("VALUE_REQUIRED");
    const config = fakeProcess();
    await runProxy(config, []);
    expect(config.exits).toEqual([2]);
    expect(config.err.join("")).toContain("CONFIG_MISSING: upstream");
    const taken = fakeProcess();
    await runProxy(taken, [
      "--upstream",
      upstream.baseUrl,
      "--listen",
      `127.0.0.1:${new URL(upstream.baseUrl).port}`,
    ]);
    expect(taken.exits).toEqual([1]);
    expect(taken.err.join("")).toContain("EADDRINUSE");
    expect(taken.err.join("")).toContain("--port");
  });

  it("refuses to start when the secrets it needs cannot be opened", async () => {
    const io = fakeProcess({
      env: { DECIONIS_API_KEY_FILE: "/run/secrets/missing", DECIONIS_TENANT_ID: TENANT_ID },
    });
    await runProxy(io, ["--upstream", "https://api.example", "--port", String(await closedPort())]);
    expect(io.exits).toEqual([1]);
    expect(io.err.join("")).toContain("DECIONIS_API_KEY");
  });
});
