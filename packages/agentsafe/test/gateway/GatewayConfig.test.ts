import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import {
  DEFAULT_AUTHORITY_ENDPOINT,
  GatewayConfigError,
  GatewayConfigLoader,
  LOCAL_TENANT_ID,
  renderConfigFile,
  type GatewayConfigInput,
} from "../../src/gateway/GatewayConfig.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";
const CRO = "synthetic-cro";
const load = (input: Partial<GatewayConfigInput>) =>
  GatewayConfigLoader.load({ env: {}, version: "1.2.3", ...input });
const refusal = (input: Partial<GatewayConfigInput>): GatewayConfigError => {
  try {
    load(input);
  } catch (error) {
    if (error instanceof GatewayConfigError) return error;
    throw error;
  }
  throw new Error("expected a refusal");
};

describe("the gateway configuration", () => {
  it("needs only an upstream, and defaults to the demo authority enforcing on loopback", () => {
    const config = load({ flags: { upstream: "http://localhost:3000" } });
    expect(config.listen).toEqual({ host: "127.0.0.1", port: 8080 });
    expect(config.upstream).toMatchObject({
      url: "http://localhost:3000",
      insecure: false,
      system: "localhost:3000",
      environment: "local",
    });
    expect(config.authority).toMatchObject({
      kind: "LOCAL",
      endpoint: "local",
      mode: "ENFORCEMENT",
      failurePolicy: "FAIL_CLOSED",
      tenantId: LOCAL_TENANT_ID,
    });
    expect(config.interception).toMatchObject({
      http: true,
      routes: [],
      unmatched: "GOVERN",
      maxBodyBytes: 1024 * 1024,
      maxEmbeddedBodyBytes: 64 * 1024,
      principalHeader: null,
    });
    expect(config.actor).toEqual({
      id: "agentsafe-gateway",
      type: "GATEWAY",
      runtime: "agentsafe/1.2.3",
    });
    expect(config.escalation).toEqual({ mode: "NONE" });
    expect(config.secrets.required).toEqual([]);
    expect(config.output).toEqual({ format: "HUMAN", verbose: false });
    expect(config.sources["upstream"]).toBe("flag");
    expect(config.sources["authority.mode"]).toBe("default");
  });

  it("refuses to start without an upstream, naming where one goes", () => {
    const error = refusal({});
    expect(error.code).toBe("CONFIG_MISSING");
    expect(error.setting).toBe("upstream");
    expect(error.message).toContain("AGENTSAFE_UPSTREAM");
  });

  it("selects Decionis when a key is present, defaults to shadow, and needs the tenant", () => {
    const env = { DECIONIS_API_KEY: "synthetic-key", DECIONIS_TENANT_ID: TENANT_ID };
    const config = load({ flags: { upstream: "https://api.example" }, env });
    expect(config.authority).toMatchObject({
      kind: "DECIONIS",
      endpoint: DEFAULT_AUTHORITY_ENDPOINT,
      mode: "SHADOW",
      tenantId: TENANT_ID,
    });
    expect(config.secrets.required).toEqual(["DECIONIS_API_KEY"]);
    expect(config.sources["authority.kind"]).toBe("environment");
    const missing = refusal({
      flags: { upstream: "https://api.example" },
      env: { DECIONIS_API_KEY: "synthetic-key" },
    });
    expect(missing.setting).toBe("DECIONIS_TENANT_ID");
    const notUuid = refusal({
      flags: { upstream: "https://api.example" },
      env: { DECIONIS_API_KEY: "synthetic-key", DECIONIS_TENANT_ID: "org" },
    });
    expect(notUuid.code).toBe("CONFIG_INVALID");
    const fileKey = load({
      flags: { upstream: "https://api.example" },
      env: { DECIONIS_API_KEY_FILE: "/run/secrets/key", DECIONIS_TENANT_ID: TENANT_ID },
    });
    expect(fileKey.authority.kind).toBe("DECIONIS");
  });

  it("takes the stored login as the lowest layer for the key, tenant and endpoint, outside production only", () => {
    const credentials = {
      apiKey: "synthetic-key",
      tenantId: TENANT_ID,
      endpoint: "https://staging.decionis.example",
    };
    const config = load({ flags: { upstream: "https://api.example" }, credentials });
    expect(config.authority).toMatchObject({
      kind: "DECIONIS",
      endpoint: "https://staging.decionis.example",
      tenantId: TENANT_ID,
    });
    expect(config.sources["authority.kind"]).toBe("credentials");
    expect(config.sources["authority.tenantId"]).toBe("credentials");
    const overridden = load({
      flags: { upstream: "https://api.example" },
      env: {
        DECIONIS_TENANT_ID: TENANT_ID.replace(/9$/, "8"),
        DECIONIS_API_URL: "https://api.decionis.example",
      },
      credentials,
    });
    expect(overridden.authority.endpoint).toBe("https://api.decionis.example");
    expect(overridden.authority.tenantId).toBe(TENANT_ID.replace(/9$/, "8"));
    const production = refusal({
      flags: { upstream: "https://api.example" },
      env: { NODE_ENV: "production" },
      credentials,
    });
    expect(production.setting).toBe("authority");
    expect(production.message).toContain("production");
    expect(config.authority.provisional).toBe(false);
  });

  it("knows a provisional workspace, runs it in shadow, and refuses to enforce with it", () => {
    const credentials = {
      apiKey: "synthetic-provisional-key",
      tenantId: TENANT_ID,
      endpoint: null,
      provisional: true,
    };
    const shadow = load({ flags: { upstream: "https://api.example" }, credentials });
    expect(shadow.authority).toMatchObject({ kind: "DECIONIS", mode: "SHADOW", provisional: true });
    const enforcing = refusal({
      flags: { upstream: "https://api.example", mode: "enforcement" },
      credentials,
    });
    expect(enforcing.setting).toBe("authority.mode");
    expect(enforcing.message).toContain("provisional workspace");
    // A key in the environment is the operator's own; the stored login is not read for it.
    const owned = load({
      flags: { upstream: "https://api.example", mode: "enforcement" },
      env: { DECIONIS_API_KEY: "synthetic-owned-key", DECIONIS_TENANT_ID: TENANT_ID },
      credentials,
    });
    expect(owned.authority).toMatchObject({ mode: "ENFORCEMENT", provisional: false });
    // The demo authority never has a workspace at all.
    expect(
      load({ flags: { upstream: "https://api.example", authority: "local" }, credentials })
        .authority.provisional,
    ).toBe(false);
  });

  it("applies precedence: flags over environment over file over defaults, per setting", () => {
    const config = load({
      flags: { port: 9000, mode: "enforcement" },
      env: {
        AGENTSAFE_LISTEN: "0.0.0.0:7000",
        AGENTSAFE_MODE: "shadow",
        AGENTSAFE_FAILURE_POLICY: "failOpen",
        DECIONIS_API_KEY: "synthetic-key",
        DECIONIS_TENANT_ID: TENANT_ID,
      },
      file: {
        version: 1,
        gateway: {
          listen: ":6000",
          upstream: "https://payments.example",
          system: "payments",
          environment: "staging",
        },
        authority: { mode: "enforcement", failurePolicy: "failClosed", timeoutMs: 1500 },
        output: { verbose: true },
      },
    });
    expect(config.listen).toEqual({ host: "127.0.0.1", port: 9000 });
    expect(config.sources["listen"]).toBe("flag");
    expect(config.authority.mode).toBe("ENFORCEMENT");
    expect(config.sources["authority.mode"]).toBe("flag");
    expect(config.authority.failurePolicy).toBe("FAIL_OPEN");
    expect(config.sources["authority.failurePolicy"]).toBe("environment");
    expect(config.authority.timeoutMs).toBe(1500);
    expect(config.sources["authority.timeoutMs"]).toBe("file");
    expect(config.upstream).toMatchObject({
      url: "https://payments.example",
      system: "payments",
      environment: "staging",
    });
    expect(config.output.verbose).toBe(true);
    const fileListen = load({
      env: { DECIONIS_API_KEY: "synthetic-key", DECIONIS_TENANT_ID: TENANT_ID },
      file: { version: 1, gateway: { listen: ":6000", upstream: "https://payments.example" } },
    });
    expect(fileListen.listen).toEqual({ host: "0.0.0.0", port: 6000 });
    const portOnly = load({ env: { PORT: "7001" }, flags: { upstream: "http://localhost:1" } });
    expect(portOnly.listen).toEqual({ host: "127.0.0.1", port: 7001 });
    expect(portOnly.sources["listen"]).toBe("environment");
  });

  it("accepts the section under decionis: too, but not both spellings at once", () => {
    const config = load({
      flags: { upstream: "http://localhost:3000" },
      file: { version: 1, decionis: { mode: "shadow" } },
    });
    expect(config.authority.mode).toBe("SHADOW");
    const both = refusal({
      flags: { upstream: "http://localhost:3000" },
      file: { version: 1, decionis: { mode: "shadow" }, authority: { mode: "shadow" } },
    });
    expect(both.setting).toBe("authority");
  });

  it("refuses a file with an unknown key, the wrong version, or a bad route, by name", () => {
    expect(
      refusal({ flags: { upstream: "http://localhost:1" }, file: { version: 2 } }).setting,
    ).toBe("version");
    expect(
      refusal({
        flags: { upstream: "http://localhost:1" },
        file: { version: 1, gateway: { listne: ":1" } },
      }).setting,
    ).toBe("gateway");
    expect(
      refusal({
        flags: { upstream: "http://localhost:1" },
        file: { version: 1, interception: { routes: [{ path: "payments", action: "pay" }] } },
      }).setting,
    ).toBe("interception.routes.0.path");
    expect(
      refusal({
        flags: { upstream: "http://localhost:1" },
        file: { version: 1, interception: { routes: [{ path: "/p", action: "Pay" }] } },
      }).setting,
    ).toBe("interception.routes.0.action");
    expect(refusal({ flags: { upstream: "http://localhost:1" }, file: "not an object" }).code).toBe(
      "CONFIG_INVALID",
    );
  });

  it("reads routes with their methods, and the interception settings", () => {
    const config = load({
      flags: { upstream: "http://localhost:1" },
      env: { AGENTSAFE_UNMATCHED: "passthrough", AGENTSAFE_PRINCIPAL_HEADER: "X-Agent-Id" },
      file: {
        version: 1,
        interception: {
          routes: [
            { path: "/payments/**", action: "payment.create", methods: ["post"] },
            { path: "/orders/:id", action: "order.change" },
          ],
          maxBodyBytes: 4096,
          maxEmbeddedBodyBytes: 1024,
        },
      },
    });
    expect(config.interception.routes).toEqual([
      { path: "/payments/**", action: "payment.create", methods: ["POST"] },
      { path: "/orders/:id", action: "order.change", methods: ["POST", "PUT", "PATCH", "DELETE"] },
    ]);
    expect(config.interception).toMatchObject({
      unmatched: "PASSTHROUGH",
      principalHeader: "x-agent-id",
      maxBodyBytes: 4096,
      maxEmbeddedBodyBytes: 1024,
    });
    expect(config.sources["interception.routes"]).toBe("file");
    const inverted = refusal({
      flags: { upstream: "http://localhost:1" },
      file: { version: 1, interception: { maxBodyBytes: 1024, maxEmbeddedBodyBytes: 4096 } },
    });
    expect(inverted.setting).toBe("interception.maxEmbeddedBodyBytes");
    expect(
      load({
        flags: { upstream: "http://localhost:1" },
        file: { version: 1, interception: { http: false } },
      }).interception.http,
    ).toBe(false);
  });

  it("refuses the values it cannot read, naming the setting", () => {
    const cases: [Partial<GatewayConfigInput>, string][] = [
      [{ flags: { upstream: "http://localhost:1", listen: "nowhere" } }, "--listen"],
      [{ flags: { upstream: "http://localhost:1", mode: "maybe" } }, "--mode"],
      [
        { flags: { upstream: "http://localhost:1", failurePolicy: "sometimes" } },
        "--failure-policy",
      ],
      [{ flags: { upstream: "http://localhost:1", authority: "elsewhere" } }, "--authority"],
      [
        { flags: { upstream: "http://localhost:1" }, env: { AGENTSAFE_UNMATCHED: "ignore" } },
        "AGENTSAFE_UNMATCHED",
      ],
      [
        {
          flags: { upstream: "http://localhost:1" },
          env: { AGENTSAFE_UPSTREAM_INSECURE: "maybe" },
        },
        "AGENTSAFE_UPSTREAM_INSECURE",
      ],
      [{ flags: { upstream: "http://localhost:1" }, env: { PORT: "70000" } }, "PORT"],
      [{ flags: { upstream: "http://localhost:1" }, env: { PORT: "eight" } }, "PORT"],
      [
        { flags: { upstream: "http://localhost:1" }, env: { DECIONIS_TIMEOUT_MS: "0" } },
        "DECIONIS_TIMEOUT_MS",
      ],
      [
        { flags: { upstream: "http://localhost:1" }, env: { DECIONIS_MODE: "loud" } },
        "DECIONIS_MODE",
      ],
      [{ flags: { upstream: "not a url" } }, "upstream"],
      [{ flags: { upstream: "ftp://files.example" } }, "upstream"],
      [{ flags: { upstream: "http://user:secret@api.example" } }, "upstream"],
      [{ flags: { upstream: "http://payments.example:8080" } }, "upstream"],
      [
        {
          flags: { upstream: "https://api.example" },
          env: {
            DECIONIS_API_KEY: "k",
            DECIONIS_TENANT_ID: TENANT_ID,
            DECIONIS_API_URL: "http://api.decionis.example",
          },
        },
        "authority.endpoint",
      ],
      [
        {
          flags: { upstream: "https://api.example" },
          env: { DECIONIS_API_KEY: "k", DECIONIS_TENANT_ID: TENANT_ID, DECIONIS_API_URL: "nope" },
        },
        "authority.endpoint",
      ],
      [
        {
          flags: { upstream: "https://api.example" },
          env: {
            NODE_ENV: "production",
            DECIONIS_API_KEY_FILE: "/k",
            DECIONIS_TENANT_ID: TENANT_ID,
            DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
          },
        },
        "DECIONIS_ALLOW_INSECURE_LOOPBACK",
      ],
      [
        {
          flags: { upstream: "https://api.example" },
          file: { version: 1, authority: { endpoint: "https://api.decionis.example" } },
        },
        "DECIONIS_API_KEY",
      ],
    ];
    for (const [input, setting] of cases) {
      expect(refusal(input).setting, JSON.stringify(input)).toBe(setting);
    }
  });

  it("allows a plain-http upstream off loopback only when the network is declared to protect the hop", () => {
    const config = load({
      flags: { upstream: "http://payments.example:8080/" },
      env: { AGENTSAFE_UPSTREAM_INSECURE: "true" },
    });
    expect(config.upstream).toMatchObject({ url: "http://payments.example:8080", insecure: true });
    const fromFile = load({
      file: {
        version: 1,
        gateway: { upstream: "http://payments.example:8080", upstreamInsecure: true },
      },
    });
    expect(fromFile.upstream.insecure).toBe(true);
    expect(load({ flags: { upstream: "https://payments.example/base/" } }).upstream.url).toBe(
      "https://payments.example/base",
    );
  });

  it("reads the authority's connection settings and the loopback allowance", () => {
    const config = load({
      flags: { upstream: "https://api.example" },
      env: {
        DECIONIS_API_KEY: "k",
        DECIONIS_TENANT_ID: TENANT_ID,
        DECIONIS_API_URL: "http://127.0.0.1:9/",
        DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
        DECIONIS_TIMEOUT_MS: "2500",
        DECIONIS_MODE: "enforce",
      },
    });
    expect(config.authority).toMatchObject({
      endpoint: "http://127.0.0.1:9",
      allowInsecureLoopback: true,
      timeoutMs: 2500,
      mode: "ENFORCEMENT",
    });
    const explicitLocal = load({
      flags: { upstream: "https://api.example", authority: "local" },
      env: { DECIONIS_API_KEY: "k", DECIONIS_TENANT_ID: TENANT_ID },
    });
    expect(explicitLocal.authority.kind).toBe("LOCAL");
    expect(explicitLocal.secrets.required).toEqual([]);
    const fileLocal = load({
      flags: { upstream: "https://api.example" },
      file: { version: 1, authority: { endpoint: "local" } },
    });
    expect(fileLocal.authority.kind).toBe("LOCAL");
    const hosted = load({
      flags: { upstream: "https://api.example", authority: "decionis" },
      env: { DECIONIS_API_KEY: "k", DECIONIS_TENANT_ID: TENANT_ID },
      file: { version: 1, authority: { allowInsecureLoopback: true, tenantId: TENANT_ID } },
    });
    expect(hosted.authority.allowInsecureLoopback).toBe(true);
  });

  it("configures a managed escalation only beside Decionis, in enforcement, naming who approves", () => {
    const env = { DECIONIS_API_KEY: "k", DECIONIS_TENANT_ID: TENANT_ID };
    const config = load({
      flags: { upstream: "https://api.example", mode: "enforcement" },
      env: {
        ...env,
        PRESENCE_VERIFICATION_LEVEL: "high_confidence",
        PRESENCE_VERIFICATION_METHODS: "webauthn,active_liveness",
      },
      file: {
        version: 1,
        presence: {
          managed: true,
          approverId: CRO,
          approverRole: "CRO",
        },
      },
    });
    expect(config.escalation).toEqual({
      mode: "MANAGED",
      approverId: "synthetic-cro",
      approverRole: "CRO",
      requirements: { methods: ["WEBAUTHN", "ACTIVE_LIVENESS"], level: "HIGH_CONFIDENCE" },
    });
    const fromFile = load({
      flags: { upstream: "https://api.example", mode: "enforcement" },
      env,
      file: {
        version: 1,
        presence: {
          managed: true,
          approverId: "synthetic-cro",
          level: "standard",
          methods: ["webauthn"],
        },
      },
    });
    expect(fromFile.escalation).toMatchObject({
      mode: "MANAGED",
      approverRole: null,
      requirements: { methods: ["WEBAUTHN"], level: "STANDARD" },
    });
    expect(
      refusal({
        flags: { upstream: "https://api.example" },
        env,
        file: { version: 1, presence: { managed: true, approverId: "synthetic-cro" } },
      }).setting,
    ).toMatch(/presence\.managed/);
    expect(
      refusal({
        flags: { upstream: "https://api.example", mode: "enforcement" },
        env,
        file: { version: 1, presence: { managed: true } },
      }).setting,
    ).toMatch(/approverId/);
    expect(
      refusal({
        flags: { upstream: "http://localhost:1" },
        file: { version: 1, presence: { managed: true, approverId: "synthetic-cro" } },
      }).message,
    ).toContain("demo authority");
    expect(
      refusal({
        flags: { upstream: "http://localhost:1" },
        file: { version: 1, presence: { approverId: "synthetic-cro" } },
      }).setting,
    ).toMatch(/approverId/);
    expect(
      refusal({
        flags: { upstream: "https://api.example", mode: "enforcement" },
        env: {
          ...env,
          AGENTSAFE_PRESENCE_MANAGED: "true",
          PRESENCE_APPROVER_ID: "synthetic-cro",
          PRESENCE_VERIFICATION_METHODS: "SEANCE",
        },
      }).setting,
    ).toBe("PRESENCE_VERIFICATION_METHODS");
    expect(
      refusal({
        flags: { upstream: "https://api.example", mode: "enforcement" },
        env: {
          ...env,
          AGENTSAFE_PRESENCE_MANAGED: "true",
          PRESENCE_APPROVER_ID: "synthetic-cro",
          PRESENCE_VERIFICATION_METHODS: " , ",
        },
      }).setting,
    ).toBe("PRESENCE_VERIFICATION_METHODS");
    expect(
      refusal({
        flags: { upstream: "https://api.example", mode: "enforcement" },
        env: {
          ...env,
          AGENTSAFE_PRESENCE_MANAGED: "true",
          PRESENCE_APPROVER_ID: "synthetic-cro",
          PRESENCE_VERIFICATION_LEVEL: "LOW",
        },
      }).setting,
    ).toBe("PRESENCE_VERIFICATION_LEVEL");
  });

  it("reads output, evidence, actor and ttl settings from the environment and the file", () => {
    const config = load({
      flags: { upstream: "http://localhost:1" },
      env: {
        AGENTSAFE_LOG_LEVEL: "debug",
        AGENTSAFE_LOG_FORMAT: "json",
        AGENTSAFE_EVIDENCE_DIR: "/var/lib/agentsafe",
        AGENTSAFE_ACTOR_ID: "synthetic-agent",
        AGENTSAFE_ACTOR_TYPE: "AI_AGENT",
        AGENTSAFE_UPSTREAM_TIMEOUT_MS: "2000",
        AGENTSAFE_UPSTREAM_SYSTEM: "ledger",
        AGENTSAFE_ENVIRONMENT: "test",
      },
      file: {
        version: 1,
        intentTtlSeconds: 45,
        evidence: { enabled: false, journalDir: "/elsewhere" },
        output: { format: "human", verbose: false },
        actor: { id: "synthetic-other", type: "OTHER" },
      },
    });
    expect(config.output).toEqual({ format: "JSON", verbose: true });
    expect(config.evidence).toEqual({ enabled: false, journalDir: "/var/lib/agentsafe" });
    expect(config.actor).toMatchObject({ id: "synthetic-agent", type: "AI_AGENT" });
    expect(config.upstream).toMatchObject({
      timeoutMs: 2000,
      system: "ledger",
      environment: "test",
    });
    expect(config.intentTtlSeconds).toBe(45);
    const human = load({
      flags: { upstream: "http://localhost:1" },
      env: { AGENTSAFE_LOG_LEVEL: "info", AGENTSAFE_LOG_FORMAT: "text" },
      file: { version: 1, output: { format: "json" } },
    });
    expect(human.output).toEqual({ format: "HUMAN", verbose: false });
    const fileJson = load({
      flags: { upstream: "http://localhost:1" },
      file: { version: 1, output: { format: "json", verbose: true } },
    });
    expect(fileJson.output).toEqual({ format: "JSON", verbose: true });
    const production = load({
      flags: { upstream: "https://api.example" },
      env: {
        NODE_ENV: "production",
        DECIONIS_API_KEY_FILE: "/run/secrets/key",
        DECIONIS_TENANT_ID: TENANT_ID,
      },
    });
    expect(production.output.format).toBe("JSON");
    expect(production.upstream.environment).toBe("production");
    expect(production.production).toBe(true);
  });

  it("renders the file init writes, with and without routes, and the loader reads it back", () => {
    const empty = renderConfigFile({
      upstream: "http://localhost:3000",
      listen: "127.0.0.1:8080",
      mode: "ENFORCEMENT",
      routes: [],
    });
    expect(empty).toContain("routes: []");
    const config = load({ file: parse(empty) as unknown });
    expect(config.upstream.url).toBe("http://localhost:3000");
    expect(config.authority.mode).toBe("ENFORCEMENT");
    const withRoutes = renderConfigFile({
      upstream: "http://localhost:3000",
      listen: "127.0.0.1:8080",
      mode: "SHADOW",
      routes: [{ path: "/payments/**", action: "payment.create", methods: ["POST"] }],
    });
    const parsed = load({ file: parse(withRoutes) as unknown });
    expect(parsed.interception.routes).toEqual([
      { path: "/payments/**", action: "payment.create", methods: ["POST"] },
    ]);
    expect(parsed.authority.mode).toBe("SHADOW");
  });
});
