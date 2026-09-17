import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { effectiveConfig, runConfig } from "../../src/cli/ConfigCommand.js";
import { GatewayConfigLoader } from "../../src/gateway/GatewayConfig.js";
import { fakeProcess } from "../support/GatewayHarness.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";

describe("agentsafe config", () => {
  it("prints the effective configuration with sources, and never a secret value", () => {
    const io = fakeProcess({
      env: { DECIONIS_API_KEY: "synthetic-secret-value", DECIONIS_TENANT_ID: TENANT_ID },
      files: { "/work/agentsafe.yaml": "version: 1\ngateway:\n  upstream: https://api.example\n" },
    });
    runConfig(io, []);
    expect(io.exits).toEqual([0]);
    const text = io.out.join("");
    expect(text).not.toContain("synthetic-secret-value");
    const document = parse(text) as Record<string, unknown>;
    expect(document["file"]).toBe("/work/agentsafe.yaml");
    expect(document["authority"]).toMatchObject({
      kind: "decionis",
      mode: "shadow",
      failurePolicy: "failClosed",
    });
    expect(document["secrets"]).toEqual({ required: ["DECIONIS_API_KEY"], values: "never shown" });
    expect((document["sources"] as Record<string, string>)["upstream"]).toBe("file");
    const json = fakeProcess({
      env: {
        DECIONIS_API_KEY: "k",
        DECIONIS_TENANT_ID: TENANT_ID,
        AGENTSAFE_PRESENCE_MANAGED: "true",
        PRESENCE_APPROVER_ID: "synthetic-approver",
        PRESENCE_APPROVER_ROLE: "CRO",
      },
    });
    runConfig(json, ["--upstream", "https://api.example", "--mode", "enforcement", "--json"]);
    const parsed = JSON.parse(json.out.join("")) as {
      presence: Record<string, unknown>;
      authority: Record<string, unknown>;
    };
    expect(parsed.presence).toEqual({
      managed: true,
      approverId: "synthetic-approver",
      approverRole: "CRO",
      level: "STANDARD",
      methods: ["WEBAUTHN"],
    });
    expect(parsed.authority["failurePolicy"]).toBe("failClosed");
  });

  it("renders a fail-open, local configuration too", () => {
    const config = GatewayConfigLoader.load({
      env: {},
      flags: { upstream: "http://localhost:1", failurePolicy: "failOpen" },
      version: "0",
    });
    const effective = effectiveConfig(config);
    expect(effective["authority"]).toMatchObject({ kind: "local", failurePolicy: "failOpen" });
    expect(effective["presence"]).toEqual({ managed: false });
  });

  it("explains a configuration it cannot resolve", () => {
    const io = fakeProcess();
    runConfig(io, []);
    expect(io.exits).toEqual([1]);
    expect(io.err.join("")).toContain("cannot resolve the configuration");
    const bad = fakeProcess();
    runConfig(bad, ["--bogus"]);
    expect(bad.exits).toEqual([2]);
  });
});
