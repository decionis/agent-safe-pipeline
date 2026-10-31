import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Rfc8785, type JsonValue } from "@decionis/agent-safe-pipeline";
import {
  GatewayConfigLoader,
  type GatewayConfig,
  type GatewayConfigInput,
} from "../../src/gateway/GatewayConfig.js";
import {
  changedFields,
  deploymentFingerprint,
  DEPLOYMENT_FINGERPRINT_CONTRACT,
  REDACTED,
  redactedConfiguration,
} from "../../src/posture/DeploymentFingerprint.js";

const UPSTREAM = "http://127.0.0.1:3000";
const TENANT_ID = "00000000-0000-4000-8000-000000000009";
/** Synthetic keys, built when the test runs so no key-shaped literal sits in the source. */
const syntheticKey = (n: number): string => ["synthetic", "decionis", "key", n].join("-");
const API_KEY = syntheticKey(1);
const digestOf = (text: string): string =>
  `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;
const KEY_ONE = digestOf("synthetic-tenant-key-1");
const KEY_TWO = digestOf("synthetic-tenant-key-2");
const KEY_THREE = digestOf("synthetic-tenant-key-3");

function load(input: Partial<GatewayConfigInput> = {}): GatewayConfig {
  return GatewayConfigLoader.load({
    env: {},
    version: "0.0.0-test",
    ...input,
    flags: { upstream: UPSTREAM, port: 8080, ...input.flags },
  });
}
const runtime = { version: "0.0.0-test", imageDigest: null };
const route = (path: string, action: string) => ({ path, action, methods: ["POST"] });

describe("the deployment fingerprint", () => {
  it("is the same document, and digest, for the same configuration on every start", () => {
    const first = deploymentFingerprint(load(), runtime);
    const again = deploymentFingerprint(load(), runtime);
    expect(again).toEqual(first);
    expect(first.digest).toBe(digestOf(Rfc8785.stringify(first.document as unknown as JsonValue)));
    expect(DEPLOYMENT_FINGERPRINT_CONTRACT).toBe("agent-safe.deployment-fingerprint/1");
    expect(first.document).toEqual({
      fingerprint: "agent-safe.deployment-fingerprint/1",
      runtime: { version: "0.0.0-test", image_digest: null },
      configuration_digest: digestOf(Rfc8785.stringify(redactedConfiguration(load()))),
      action_manifest_digest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      routes: ["POST", "PUT", "PATCH", "DELETE"].map((method) => ({
        methods: [method],
        path: "/**",
        action: `http.${method.toLowerCase()}`,
        mode: "ENFORCEMENT",
        failure_policy: "FAIL_CLOSED",
      })),
      principals: { actor: "agentsafe-gateway", header: null, subject_issuer: null },
      upstream_identity: { mode: "CALLER", header: null, gateway_token: false },
      authority: { kind: "LOCAL", endpoint: "local", tenant: TENANT_ID },
      containment: [],
    });
  });

  it("changes with each field it covers, and only that field", () => {
    const base = deploymentFingerprint(load(), runtime);
    const variants: readonly [string, ReturnType<typeof deploymentFingerprint>, string[]][] = [
      ["version", deploymentFingerprint(load(), { ...runtime, version: "0.0.1" }), ["runtime"]],
      [
        "image",
        deploymentFingerprint(load(), { ...runtime, imageDigest: digestOf("image") }),
        ["runtime"],
      ],
      [
        "a setting nothing else names",
        deploymentFingerprint(load({ file: { version: 1, intentTtlSeconds: 60 } }), runtime),
        ["configuration_digest"],
      ],
      [
        "a route",
        deploymentFingerprint(
          load({
            file: { version: 1, interception: { routes: [route("/pay", "payments.create")] } },
          }),
          runtime,
        ),
        ["configuration_digest", "action_manifest_digest", "routes"],
      ],
      [
        "the mode",
        deploymentFingerprint(load({ env: { AGENTSAFE_MODE: "shadow" } }), runtime),
        ["configuration_digest", "routes"],
      ],
      [
        "the failure policy",
        deploymentFingerprint(load({ env: { AGENTSAFE_FAILURE_POLICY: "failOpen" } }), runtime),
        ["configuration_digest", "routes"],
      ],
      [
        "the actor",
        deploymentFingerprint(load({ env: { AGENTSAFE_ACTOR_ID: "refund-gateway" } }), runtime),
        ["configuration_digest", "principals"],
      ],
      [
        "the principal header",
        deploymentFingerprint(load({ env: { AGENTSAFE_PRINCIPAL_HEADER: "x-agent-id" } }), runtime),
        ["configuration_digest", "principals"],
      ],
      [
        "the subject's issuer",
        deploymentFingerprint(
          load({
            file: {
              version: 1,
              subject: {
                issuer: "https://idp.example",
                audience: "agentsafe",
                jwksUrl: "https://idp.example/jwks",
              },
            },
          }),
          runtime,
        ),
        ["configuration_digest", "principals"],
      ],
      [
        "the upstream credential",
        deploymentFingerprint(
          load({
            file: {
              version: 1,
              gateway: { upstreamCredential: { header: "authorization", file: "/run/secrets/u" } },
            },
          }),
          runtime,
        ),
        ["configuration_digest", "upstream_identity"],
      ],
      [
        "the gateway token",
        deploymentFingerprint(
          load({ env: { AGENTSAFE_GATEWAY_TOKEN_FILE: "/run/secrets/t" } }),
          runtime,
        ),
        ["configuration_digest", "upstream_identity"],
      ],
      [
        "the authority and its tenant",
        deploymentFingerprint(
          load({
            env: {
              DECIONIS_API_KEY: API_KEY,
              DECIONIS_API_URL: "https://authority.example",
              DECIONIS_TENANT_ID: "00000000-0000-4000-8000-000000000123",
              // A key alone would start it in shadow, which is the mode's field.
              AGENTSAFE_MODE: "enforcement",
            },
          }),
          runtime,
        ),
        ["configuration_digest", "authority"],
      ],
      [
        "the containment targets",
        deploymentFingerprint(
          load({ env: { AGENTSAFE_CONTAINMENT_TARGETS: "ledger=10.0.0.5:5432" } }),
          runtime,
        ),
        ["configuration_digest", "containment"],
      ],
    ];
    const digests = new Set([base.digest]);
    for (const [name, variant, fields] of variants) {
      expect(changedFields(base.document, variant.document), name).toEqual(fields);
      digests.add(variant.digest);
    }
    expect(digests.size).toBe(variants.length + 1);
    expect(changedFields(base.document, base.document)).toEqual([]);
  });

  it("states each covered field as configured", () => {
    const { document } = deploymentFingerprint(
      load({
        env: {
          DECIONIS_API_KEY: API_KEY,
          DECIONIS_API_URL: "https://authority.example",
          DECIONIS_TENANT_ID: TENANT_ID,
          AGENTSAFE_MODE: "shadow",
          AGENTSAFE_UNMATCHED: "passthrough",
          AGENTSAFE_PRINCIPAL_HEADER: "X-Agent-Id",
          AGENTSAFE_CONTAINMENT_TARGETS: "ledger=10.0.0.5:5432, cards=cards.internal:443",
        },
        file: {
          version: 1,
          gateway: {
            upstreamCredential: { header: "authorization", file: "/run/secrets/u" },
            gatewayToken: { file: "/run/secrets/t" },
          },
          interception: { routes: [route("/pay", "payments.create")] },
        },
      }),
      { version: "0.0.0-test", imageDigest: digestOf("image") },
    );
    expect(document.runtime.image_digest).toBe(digestOf("image"));
    expect(document.routes).toEqual([
      {
        methods: ["POST"],
        path: "/pay",
        action: "payments.create",
        mode: "SHADOW",
        failure_policy: "FAIL_CLOSED",
      },
      {
        methods: ["POST", "PUT", "PATCH", "DELETE"],
        path: "/**",
        action: null,
        mode: "PASSTHROUGH",
        failure_policy: null,
      },
    ]);
    expect(document.principals).toEqual({
      actor: "agentsafe-gateway",
      header: "x-agent-id",
      subject_issuer: null,
    });
    expect(document.upstream_identity).toEqual({
      mode: "GATEWAY_CREDENTIAL",
      header: "authorization",
      gateway_token: true,
    });
    expect(document.authority).toEqual({
      kind: "DECIONIS",
      endpoint: "https://authority.example",
      tenant: TENANT_ID,
    });
    expect(document.containment).toEqual(["ledger=10.0.0.5:5432", "cards=cards.internal:443"]);
    // Facts-only privacy refuses what the profile does not name, asking no one.
    const facts = deploymentFingerprint(
      load({ env: { AGENTSAFE_PROFILE: "walmart/api/v3", AGENTSAFE_PRIVACY: "facts" } }),
      runtime,
    ).document.routes;
    expect(facts.at(-1)).toEqual({
      methods: ["POST", "PUT", "PATCH", "DELETE"],
      path: "/**",
      action: null,
      mode: "REFUSE",
      failure_policy: null,
    });
    expect(facts.slice(0, -1).every((row) => row.mode === "ENFORCEMENT")).toBe(true);
  });

  it("carries no secret, and no value derived from one", () => {
    const keyed = load({
      env: {
        DECIONIS_API_KEY: API_KEY,
        DECIONIS_TENANT_ID: TENANT_ID,
        AGENTSAFE_TENANT_KEY_DIGESTS: `${KEY_ONE},${KEY_TWO}`,
      },
    });
    const { document, digest } = deploymentFingerprint(keyed, runtime);
    const redacted = redactedConfiguration(keyed) as Record<string, JsonValue>;
    for (const text of [JSON.stringify(document), JSON.stringify(redacted)]) {
      for (const secret of [API_KEY, KEY_ONE, KEY_TWO]) expect(text).not.toContain(secret);
    }
    expect(REDACTED).toBe("[REDACTED]");
    expect(redacted["tenantKeys"]).toEqual(["[REDACTED]", "[REDACTED]"]);
    // Where a setting came from is not what the gateway does.
    expect(redacted).not.toHaveProperty("sources");
    // A rotation that keeps the number of keys is the same deployment.
    const rotated = load({
      env: {
        DECIONIS_API_KEY: syntheticKey(2),
        DECIONIS_TENANT_ID: TENANT_ID,
        AGENTSAFE_TENANT_KEY_DIGESTS: `${KEY_TWO},${KEY_THREE}`,
      },
    });
    expect(deploymentFingerprint(rotated, runtime).digest).toBe(digest);
  });

  it("names no action space it cannot list in one manifest", () => {
    const routes = Array.from({ length: 65 }, (_, index) =>
      route(`/pay/${index}`, "payments.create"),
    );
    const { document } = deploymentFingerprint(
      load({ file: { version: 1, interception: { routes } } }),
      runtime,
    );
    expect(document.action_manifest_digest).toBeNull();
    expect(document.routes).toHaveLength(69);
  });

  it("counts a field an older document lacks as changed", () => {
    const { document } = deploymentFingerprint(load(), runtime);
    const { containment: _containment, ...older } = document;
    void _containment;
    expect(changedFields(older as typeof document, document)).toEqual(["containment"]);
  });
});
