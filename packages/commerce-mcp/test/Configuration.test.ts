import { describe, expect, it } from "vitest";

import { CommerceGateConfiguration, DEFAULT_DECIONIS_API_BASE } from "../src/Configuration.js";
import { CommerceGateError } from "../src/Errors.js";

const ORG_ID = "11111111-1111-4111-8111-111111111111";

describe("CommerceGateConfiguration", () => {
  it("starts without credentials and reports only safe configuration state", () => {
    const configuration = new CommerceGateConfiguration({});

    expect(configuration.describe()).toEqual({
      api_base: DEFAULT_DECIONIS_API_BASE,
      connected: false,
      erp_guard_ready: false,
      protocol_tools_ready: false,
      protocol_organization_bound_by_environment: true,
      api_key_configured: false,
      org_id_configured: false,
      configuration_issues: [],
    });
    expect(() => configuration.requireTenantConnection()).toThrowError(CommerceGateError);
    expect(() => configuration.requireTenantConnection()).toThrow("Configure DECIONIS_API_KEY");
  });

  it("binds a valid organization and credential without exposing their values", () => {
    const configuration = new CommerceGateConfiguration({
      DECIONIS_API_KEY: "secret-key",
      DECIONIS_ORG_ID: ORG_ID,
      DECIONIS_API_BASE: "https://api.example.test/",
    });

    expect(configuration.describe()).toMatchObject({
      api_base: "https://api.example.test",
      connected: true,
      erp_guard_ready: true,
      protocol_tools_ready: true,
      api_key_configured: true,
      org_id_configured: true,
    });
    const serialized = JSON.stringify(configuration.describe());
    expect(serialized).not.toContain("secret-key");
    expect(serialized).not.toContain(ORG_ID);
  });

  it("fails closed on an invalid organization UUID", () => {
    const configuration = new CommerceGateConfiguration({
      DECIONIS_API_KEY: "secret-key",
      DECIONIS_ORG_ID: "not-an-org",
    });

    expect(configuration.describe()).toMatchObject({
      connected: false,
      configuration_issues: ["DECIONIS_ORG_ID must be a UUID."],
    });
    expect(() => configuration.requireTenantConnection()).toThrow(
      "CommerceGate Protocol tenant configuration is invalid",
    );
  });

  it("keeps the ERP guard available when only Protocol tenant configuration is invalid", () => {
    const configuration = new CommerceGateConfiguration({
      DECIONIS_API_KEY: "secret-key",
      DECIONIS_ORG_ID: "not-an-org",
    });

    expect(configuration.describe()).toMatchObject({
      connected: false,
      erp_guard_ready: true,
      protocol_tools_ready: false,
    });
    expect(configuration.requireApiConnection()).toMatchObject({
      apiBaseUrl: DEFAULT_DECIONIS_API_BASE,
      apiKey: "secret-key",
    });
    expect(() => configuration.requireTenantConnection()).toThrow(
      "CommerceGate Protocol tenant configuration is invalid",
    );
  });

  it("requires HTTPS except for explicit loopback development", () => {
    const unsafe = new CommerceGateConfiguration({
      DECIONIS_API_BASE: "http://api.example.test",
    });
    const loopback = new CommerceGateConfiguration({
      DECIONIS_API_BASE: "http://127.0.0.1:4319",
    });

    expect(unsafe.describe().connected).toBe(false);
    expect(unsafe.describe().configuration_issues[0]).toContain("must use HTTPS");
    expect(loopback.describe().api_base).toBe("http://127.0.0.1:4319");
    expect(loopback.describe().configuration_issues).toEqual([]);
  });

  it("rejects API bases containing unapproved paths or embedded credentials", () => {
    const withPath = new CommerceGateConfiguration({
      DECIONIS_API_BASE: "https://api.example.test/v1",
    });
    const withCredentials = new CommerceGateConfiguration({
      DECIONIS_API_BASE: "https://user:password@api.example.test",
    });

    expect(withPath.describe().configuration_issues[0]).toContain("exact /aws gateway path");
    expect(withCredentials.describe().configuration_issues[0]).toContain(
      "must not contain credentials",
    );
  });

  it("accepts only the exact Marketplace gateway prefix without URL normalization escapes", () => {
    for (const path of ["/aws", "/aws/"]) {
      expect(
        new CommerceGateConfiguration({
          DECIONIS_API_BASE: `https://api.example.test${path}`,
        }).describe(),
      ).toMatchObject({ api_base: "https://api.example.test/aws", configuration_issues: [] });
    }
    for (const path of [
      "/aws/..",
      "/aws/%2e%2e",
      "/%61ws",
      "/other/../aws",
      "//aws",
      "/aws//",
      "/aws/extra",
      "/aws?key=secret",
      "/aws#fragment",
    ]) {
      expect(
        new CommerceGateConfiguration({
          DECIONIS_API_BASE: `https://api.example.test${path}`,
        }).describe().configuration_issues.length,
      ).toBeGreaterThan(0);
    }
  });
});
