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
      organization_bound_by_environment: true,
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
      "CommerceGate configuration is invalid",
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

  it("rejects API origins containing paths or embedded credentials", () => {
    const withPath = new CommerceGateConfiguration({
      DECIONIS_API_BASE: "https://api.example.test/v1",
    });
    const withCredentials = new CommerceGateConfiguration({
      DECIONIS_API_BASE: "https://user:password@api.example.test",
    });

    expect(withPath.describe().configuration_issues[0]).toContain("without a path");
    expect(withCredentials.describe().configuration_issues[0]).toContain(
      "must not contain credentials",
    );
  });
});
