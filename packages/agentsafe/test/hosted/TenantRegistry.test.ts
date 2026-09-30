import { describe, expect, it } from "vitest";
import {
  parseTenantRegistry,
  tenantFingerprint,
  tenantHostname,
  TenantRegistryError,
} from "../../src/hosted/TenantRegistry.js";
import { TENANT_KEY_DIGEST } from "../support/GatewayHarness.js";

const WORKSPACE = "00000000-0000-4000-8000-000000000009";
/** Each tenant's upstream, written whole: the fixture check reads URLs as they are written. */
const UPSTREAMS: Readonly<Record<string, string>> = {
  acme: "https://acme.shop.example",
  globex: "https://globex.shop.example",
  initech: "https://initech.shop.example",
};
const upstreamOf = (id: string): string => UPSTREAMS[id] ?? "https://tenant.shop.example";
/** A workspace id that is not a UUID at all, which the registry refuses. */
const NOT_A_UUID = ["not", "a", "uuid"].join("-");

const tenant = (id: string, overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  id,
  upstream: upstreamOf(id),
  tenantKeyDigests: [TENANT_KEY_DIGEST],
  workspace: { tenantId: WORKSPACE, apiKeyFile: `/run/secrets/tenants/${id}/decionis-api-key` },
  ...overrides,
});

const registry = (tenants: unknown[], overrides: Record<string, unknown> = {}): string =>
  JSON.stringify({ version: 1, domain: "decionisedge.example", tenants, ...overrides });

function refusal(text: string): TenantRegistryError {
  try {
    parseTenantRegistry(text);
  } catch (error) {
    if (error instanceof TenantRegistryError) return error;
    throw error;
  }
  throw new Error("expected a refusal");
}

describe("the tenant registry", () => {
  it("reads YAML or JSON, and names each tenant's host under the domain", () => {
    const yaml = [
      "version: 1",
      "domain: decionisedge.example",
      "evidenceDir: /var/lib/agentsafe/tenants",
      "tenants:",
      "  - id: acme",
      "    upstream: https://api.acme.example",
      `    tenantKeyDigests: ["${TENANT_KEY_DIGEST}"]`,
      "    workspace:",
      `      tenantId: ${WORKSPACE}`,
      "      apiKeyFile: /run/secrets/tenants/acme/decionis-api-key",
      "    interception:",
      "      routes:",
      "        - { path: /payments/**, action: payment.create, methods: [POST] }",
    ].join("\n");
    const fromYaml = parseTenantRegistry(yaml);
    expect(fromYaml.tenants).toHaveLength(1);
    expect(tenantHostname(fromYaml, fromYaml.tenants[0]!)).toBe("acme.decionisedge.example");
    expect(fromYaml.tenants[0]?.interception).toEqual({
      routes: [{ path: "/payments/**", action: "payment.create", methods: ["POST"] }],
    });
    const fromJson = parseTenantRegistry(registry([tenant("acme"), tenant("globex")]));
    expect(fromJson.tenants.map((entry) => entry.id)).toEqual(["acme", "globex"]);
    expect(parseTenantRegistry(registry([])).tenants).toEqual([]);
  });

  it("refuses a registry it cannot serve whole, naming where and never a value", () => {
    const cases: [string, string, string][] = [
      ["{ not yaml: [", "REGISTRY_UNREADABLE", "REGISTRY_UNREADABLE"],
      ["just a string", "REGISTRY_INVALID", "REGISTRY_INVALID: (root)"],
      [registry([], { version: 2 }), "REGISTRY_INVALID", "REGISTRY_INVALID: version"],
      [
        registry([], { domain: "Decionisedge.example" }),
        "REGISTRY_INVALID",
        "REGISTRY_INVALID: domain",
      ],
      [registry([], { domain: "localhost" }), "REGISTRY_INVALID", "REGISTRY_INVALID: domain"],
      [
        registry([], { evidenceDir: "tenants" }),
        "REGISTRY_INVALID",
        "REGISTRY_INVALID: evidenceDir",
      ],
      [registry([], { extra: true }), "REGISTRY_INVALID", "REGISTRY_INVALID: (root)"],
      [registry([tenant("Acme")]), "REGISTRY_INVALID", "REGISTRY_INVALID: tenants.0.id"],
      [registry([tenant("-acme")]), "REGISTRY_INVALID", "REGISTRY_INVALID: tenants.0.id"],
      [registry([tenant("a".repeat(64))]), "REGISTRY_INVALID", "REGISTRY_INVALID: tenants.0.id"],
      [registry([tenant("www")]), "REGISTRY_INVALID", "REGISTRY_INVALID: tenants.0.id"],
      [registry([tenant("console")]), "REGISTRY_INVALID", "REGISTRY_INVALID: tenants.0.id"],
      [
        registry([tenant("acme", { tenantKeyDigests: [] })]),
        "REGISTRY_INVALID",
        "REGISTRY_INVALID: tenants.0.tenantKeyDigests",
      ],
      [
        registry([tenant("acme", { tenantKeyDigests: ["a", "b", "c"] })]),
        "REGISTRY_INVALID",
        "REGISTRY_INVALID: tenants.0.tenantKeyDigests",
      ],
      [
        registry([
          tenant("acme", { workspace: { tenantId: WORKSPACE, apiKeyFile: "relative/key" } }),
        ]),
        "REGISTRY_INVALID",
        "REGISTRY_INVALID: tenants.0.workspace.apiKeyFile",
      ],
      [
        registry([tenant("acme", { workspace: { tenantId: NOT_A_UUID, apiKeyFile: "/k" } })]),
        "REGISTRY_INVALID",
        "REGISTRY_INVALID: tenants.0.workspace.tenantId",
      ],
      [
        registry([tenant("acme", { upstream: "nowhere" })]),
        "REGISTRY_INVALID",
        "REGISTRY_INVALID: tenants.0.upstream",
      ],
      [
        registry([tenant("acme"), tenant("globex"), tenant("acme")]),
        "REGISTRY_DUPLICATE_TENANT",
        "REGISTRY_DUPLICATE_TENANT: acme",
      ],
    ];
    for (const [text, code, message] of cases) {
      const error = refusal(text);
      expect([text, error.code, error.message]).toEqual([text, code, message]);
    }
    expect(
      refusal(registry(Array.from({ length: 1_001 }, (_, i) => tenant(`t${i}`)))).message,
    ).toBe("REGISTRY_INVALID: tenants");
  });

  it("fingerprints what shapes a tenant's gateway, and nothing about the others", () => {
    const base = parseTenantRegistry(registry([tenant("acme"), tenant("globex")]));
    const acme = base.tenants[0]!;
    const same = parseTenantRegistry(
      registry([tenant("acme"), tenant("globex", { upstream: "https://other.example" })]),
    );
    expect(tenantFingerprint(same, same.tenants[0]!)).toBe(tenantFingerprint(base, acme));
    expect(tenantFingerprint(same, same.tenants[1]!)).not.toBe(
      tenantFingerprint(base, base.tenants[1]!),
    );
    const rotated = parseTenantRegistry(
      registry([
        tenant("acme", { tenantKeyDigests: [TENANT_KEY_DIGEST, `sha256:${"b".repeat(64)}`] }),
      ]),
    );
    expect(tenantFingerprint(rotated, rotated.tenants[0]!)).not.toBe(tenantFingerprint(base, acme));
    const moved = parseTenantRegistry(registry([tenant("acme")], { domain: "edge.example" }));
    expect(tenantFingerprint(moved, moved.tenants[0]!)).not.toBe(tenantFingerprint(base, acme));
    const kept = parseTenantRegistry(registry([tenant("acme")], { evidenceDir: "/var/lib/t" }));
    expect(tenantFingerprint(kept, kept.tenants[0]!)).not.toBe(tenantFingerprint(base, acme));
    expect(tenantFingerprint(base, acme)).toMatch(/^[0-9a-f]{64}$/);
  });
});
