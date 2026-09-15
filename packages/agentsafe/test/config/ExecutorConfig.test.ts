import { describe, expect, it } from "vitest";
import { CONFIG_KEYS, SECRET_KEYS } from "../../src/config/ConfigKeys.js";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import { EgressPolicy } from "../../src/egress/EgressPolicy.js";
import { CALLER_TOKEN, DOWNSTREAM_CREDENTIAL, offlineEnvironment } from "../support/Environment.js";

const direct = (): Record<string, string> => ({
  ...offlineEnvironment(),
  EXECUTOR_ESCALATION: "DIRECT",
  PRESENCE_API_URL: "https://presence.decionis.example",
  PRESENCE_API_KEY: "synthetic-presence-key",
  PRESENCE_ORGANIZATION: "Synthetic Treasury",
  PRESENCE_APPROVER_ID: "synthetic-approver",
  PRESENCE_VERIFICATION_LEVEL: "HIGH_CONFIDENCE",
  PRESENCE_VERIFICATION_METHODS: "WEBAUTHN,ACTIVE_LIVENESS",
  PRESENCE_HARDWARE_PKI_REQUIRED: "true",
  PRESENCE_DISALLOW_VIRTUAL_CAMERAS: "false",
});

const managed = (): Record<string, string> => ({
  ...offlineEnvironment(),
  EXECUTOR_ESCALATION: "MANAGED",
  PRESENCE_APPROVER_ID: "synthetic-approver",
  PRESENCE_VERIFICATION_LEVEL: "STANDARD",
  PRESENCE_VERIFICATION_METHODS: "WEBAUTHN",
});

/** A production deployment's shape: every secret a file, every address HTTPS, posture enforced, TLS on. */
const production = (): Record<string, string> => {
  const env = offlineEnvironment();
  delete env["EXECUTOR_POSTURE"];
  delete env["EXECUTOR_ALLOW_PLAINTEXT_LISTENER"];
  delete env["EXECUTOR_JOURNAL_REQUIRED"];
  env["EXECUTOR_JOURNAL_DIR"] = "/var/lib/agent-safe/journal";
  for (const name of ["EXECUTOR_CALLER_TOKEN", "DECIONIS_API_KEY", "DOWNSTREAM_CREDENTIAL"]) {
    delete env[name];
    env[`${name}_FILE`] = `/var/run/agent-safe/secrets/${name.toLowerCase()}`;
  }
  return {
    ...env,
    NODE_ENV: "production",
    EXECUTOR_SECRETS_DIR: "/var/run/agent-safe",
    EXECUTOR_TLS_CERT_FILE: "/var/run/agent-safe/tls/tls.crt",
    EXECUTOR_TLS_KEY_FILE: "/var/run/agent-safe/tls/tls.key",
    // The legacy caller in production is a choice made by name.
    EXECUTOR_ALLOW_LEGACY_CALLER: "true",
  };
};

const refusal = (env: Record<string, string | undefined>): string => {
  try {
    ExecutorConfigLoader.load(env);
    return "";
  } catch (error) {
    return error instanceof Error ? error.message : "unknown";
  }
};

describe("ExecutorConfigLoader", () => {
  it("loads an enforcement configuration and normalises the header name", () => {
    const config = ExecutorConfigLoader.load(offlineEnvironment());
    expect(config.mode).toBe("ENFORCEMENT");
    expect(config.production).toBe(false);
    expect(config.port).toBe(8443);
    expect(config.identity.legacy).toEqual({
      tenantId: "00000000-0000-4000-8000-000000000007",
      actor: { id: "synthetic-payout-agent", type: "AI_AGENT" },
    });
    expect(config.identity.principalsFile).toBeNull();
    expect(config.escalation).toEqual({ mode: "NONE" });
    expect(config.authority.allowInsecureLoopback).toBe(false);
    expect(config.downstream.credential).toEqual({
      kind: "STATIC_HEADER",
      header: "authorization",
    });
    expect(config.downstream.redactedHeaders).toEqual(["authorization"]);
    expect(config.downstream.lookupUrl).toContain("{idempotency_key}");
  });

  it("names the secrets it needs and never holds a value", () => {
    const config = ExecutorConfigLoader.load(offlineEnvironment());
    expect(config.secrets.required).toEqual([
      "EXECUTOR_CALLER_TOKEN",
      "DECIONIS_API_KEY",
      "DOWNSTREAM_CREDENTIAL",
    ]);
    expect(config.posture.secretsInEnvironment).toEqual(config.secrets.required);
    expect(config.posture.secretFiles).toEqual({});
    const serialised = JSON.stringify(config);
    expect(serialised).not.toContain(CALLER_TOKEN);
    expect(serialised).not.toContain(DOWNSTREAM_CREDENTIAL);
    expect(serialised).not.toContain("synthetic-authority-key");
  });

  it("requires the Presence credential only for the direct shape", () => {
    expect(ExecutorConfigLoader.load(direct()).secrets.required).toContain("PRESENCE_API_KEY");
    expect(ExecutorConfigLoader.load(managed()).secrets.required).not.toContain("PRESENCE_API_KEY");
  });

  it("locates a file-backed secret without reading it", () => {
    const env = offlineEnvironment();
    delete env["DECIONIS_API_KEY"];
    const config = ExecutorConfigLoader.load({
      ...env,
      DECIONIS_API_KEY_FILE: "/nowhere/agent-safe/decionis-api-key",
    });
    expect(config.posture.secretFiles).toEqual({
      DECIONIS_API_KEY: "/nowhere/agent-safe/decionis-api-key",
    });
    expect(config.posture.secretsInEnvironment).toEqual([
      "EXECUTOR_CALLER_TOKEN",
      "DOWNSTREAM_CREDENTIAL",
    ]);
  });

  it("refuses a secret given twice, given neither way, or given in the environment under production", () => {
    expect(
      refusal({ ...offlineEnvironment(), DECIONIS_API_KEY_FILE: "/nowhere/decionis-api-key" }),
    ).toBe("CONFIG_SECRET_AMBIGUOUS: DECIONIS_API_KEY");
    const missing = offlineEnvironment();
    delete missing["DOWNSTREAM_CREDENTIAL"];
    expect(refusal(missing)).toBe("CONFIG_SECRET_MISSING: DOWNSTREAM_CREDENTIAL");
    const leaked = production();
    delete leaked["DECIONIS_API_KEY_FILE"];
    leaked["DECIONIS_API_KEY"] = "synthetic-authority-key";
    expect(refusal(leaked)).toBe("CONFIG_SECRET_IN_ENV: DECIONIS_API_KEY");
  });

  it("defaults to enforced posture and refuses development posture in production", () => {
    const env = offlineEnvironment();
    delete env["EXECUTOR_POSTURE"];
    const config = ExecutorConfigLoader.load(env);
    expect(config.posture.mode).toBe("ENFORCED");
    expect(config.posture.intervalSeconds).toBe(60);
    expect(ExecutorConfigLoader.load(offlineEnvironment()).posture.mode).toBe("DEVELOPMENT");
    expect(refusal({ ...production(), EXECUTOR_POSTURE: "DEVELOPMENT" })).toBe(
      "CONFIG_INVALID: EXECUTOR_POSTURE (forbidden in production)",
    );
    expect(refusal({ ...offlineEnvironment(), EXECUTOR_POSTURE_INTERVAL_SECONDS: "5" })).toBe(
      "CONFIG_INVALID: EXECUTOR_POSTURE_INTERVAL_SECONDS",
    );
    expect(
      ExecutorConfigLoader.load({
        ...offlineEnvironment(),
        EXECUTOR_POSTURE_INTERVAL_SECONDS: "120",
      }).posture.intervalSeconds,
    ).toBe(120);
  });

  it("loads a production shape and snapshots only the inspected environment", () => {
    const config = ExecutorConfigLoader.load({
      ...production(),
      HTTPS_PROXY: "https://proxy.corp.example:3128",
      UNRELATED: "value",
    });
    expect(config.production).toBe(true);
    expect(config.posture.secretsDir).toBe("/var/run/agent-safe");
    expect(Object.keys(config.posture.secretFiles).sort()).toEqual([
      "DECIONIS_API_KEY",
      "DOWNSTREAM_CREDENTIAL",
      "EXECUTOR_CALLER_TOKEN",
      "EXECUTOR_TLS_KEY",
    ]);
    expect(config.listener).toEqual({
      tls: {
        certFile: "/var/run/agent-safe/tls/tls.crt",
        clientCaFile: null,
        minVersion: "TLSv1.3",
      },
    });
    expect(config.posture.secretsInEnvironment).toEqual([]);
    expect(config.posture.environment).toEqual({
      NODE_ENV: "production",
      HTTPS_PROXY: "https://proxy.corp.example:3128",
    });
  });

  it("requires an absolute secrets directory in production when files are mounted", () => {
    const env = production();
    delete env["EXECUTOR_SECRETS_DIR"];
    expect(refusal(env)).toBe("CONFIG_INVALID: EXECUTOR_SECRETS_DIR (required in production)");
    expect(refusal({ ...production(), EXECUTOR_SECRETS_DIR: "secrets" })).toBe(
      "CONFIG_INVALID: EXECUTOR_SECRETS_DIR (absolute path)",
    );
  });

  it("keeps the optional actor runtime only when given", () => {
    const withRuntime = ExecutorConfigLoader.load({
      ...offlineEnvironment(),
      EXECUTOR_ACTOR_RUNTIME: "workflow-runner",
    });
    expect(withRuntime.identity.legacy?.actor.runtime).toBe("workflow-runner");
    expect(
      "runtime" in (ExecutorConfigLoader.load(offlineEnvironment()).identity.legacy?.actor ?? {}),
    ).toBe(false);
  });

  it("treats a missing lookup URL as no reconciliation lookup", () => {
    const env = offlineEnvironment();
    delete env["DOWNSTREAM_LOOKUP_URL"];
    expect(ExecutorConfigLoader.load(env).downstream.lookupUrl).toBeNull();
  });

  it("names a missing or invalid variable and never its value", () => {
    const env = offlineEnvironment();
    delete env["DOWNSTREAM_SYSTEM"];
    const reason = refusal({ ...env, PORT: "70000" });
    expect(reason).toBe("CONFIG_INVALID: DOWNSTREAM_SYSTEM, PORT");
    expect(reason).not.toContain(CALLER_TOKEN);
  });

  it("refuses plain HTTP in production even when asked for", () => {
    expect(refusal({ ...production(), DECIONIS_ALLOW_INSECURE_LOOPBACK: "true" })).toBe(
      "CONFIG_INVALID: DECIONIS_ALLOW_INSECURE_LOOPBACK (forbidden in production)",
    );
  });

  it("accepts loopback HTTP only when asked for", () => {
    const loopback = "http://127.0.0.1:1";
    expect(refusal({ ...offlineEnvironment(), DECIONIS_API_URL: loopback })).toBe(
      "CONFIG_INVALID: DECIONIS_API_URL (https required)",
    );
    const config = ExecutorConfigLoader.load({
      ...offlineEnvironment(),
      DECIONIS_API_URL: loopback,
      DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
    });
    expect(config.authority.baseUrl).toBe(loopback);
    expect(config.authority.allowInsecureLoopback).toBe(true);
  });

  it("refuses a URL that is not one, carries credentials, or carries a query", () => {
    expect(refusal({ ...offlineEnvironment(), DOWNSTREAM_URL: "not a url" })).toBe(
      "CONFIG_INVALID: DOWNSTREAM_URL (not a URL)",
    );
    expect(
      refusal({
        ...offlineEnvironment(),
        DOWNSTREAM_URL: "https://user:pw@payouts.provider.example/v1",
      }),
    ).toBe("CONFIG_INVALID: DOWNSTREAM_URL (credentials in URL)");
    expect(
      refusal({ ...offlineEnvironment(), DOWNSTREAM_URL: "https://payouts.provider.example/?x" }),
    ).toBe("CONFIG_INVALID: DOWNSTREAM_URL (query or fragment)");
  });

  it("refuses a lookup URL without the idempotency placeholder", () => {
    expect(
      refusal({
        ...offlineEnvironment(),
        DOWNSTREAM_LOOKUP_URL: "https://payouts.provider.example/v1/payouts",
      }),
    ).toBe("CONFIG_INVALID: DOWNSTREAM_LOOKUP_URL (must contain {idempotency_key})");
  });

  it("refuses an escalation shape in shadow", () => {
    expect(refusal({ ...managed(), EXECUTOR_MODE: "SHADOW" })).toBe(
      "CONFIG_INVALID: EXECUTOR_ESCALATION (shadow never escalates)",
    );
  });

  it("loads the direct shape with its Presence address and flags", () => {
    const config = ExecutorConfigLoader.load(direct());
    expect(config.escalation).toEqual({
      mode: "DIRECT",
      presence: {
        baseUrl: "https://presence.decionis.example",
        organization: "Synthetic Treasury",
      },
      approverId: "synthetic-approver",
      requirements: {
        level: "HIGH_CONFIDENCE",
        methods: ["WEBAUTHN", "ACTIVE_LIVENESS"],
        hardware_pki_required: true,
        disallow_virtual_cameras: false,
      },
    });
  });

  it("names every direct variable that is missing", () => {
    const env = direct();
    delete env["PRESENCE_API_URL"];
    delete env["PRESENCE_ORGANIZATION"];
    expect(refusal(env)).toBe("CONFIG_INVALID: PRESENCE_API_URL, PRESENCE_ORGANIZATION");
  });

  it("loads the managed shape with an optional role", () => {
    expect(ExecutorConfigLoader.load(managed()).escalation).toEqual({
      mode: "MANAGED",
      approverId: "synthetic-approver",
      approverRole: null,
      requirements: { methods: ["WEBAUTHN"], level: "STANDARD" },
    });
    const withRole = ExecutorConfigLoader.load({ ...managed(), PRESENCE_APPROVER_ROLE: "CRO" });
    expect(withRole.escalation).toMatchObject({ approverRole: "CRO" });
  });

  it("refuses unknown, duplicated, or empty verification methods", () => {
    for (const methods of ["WEBAUTHN,BOGUS", "WEBAUTHN,WEBAUTHN", "WEBAUTHN,"]) {
      const reason = refusal({ ...managed(), PRESENCE_VERIFICATION_METHODS: methods });
      expect(reason).toContain("PRESENCE_VERIFICATION_METHODS");
    }
  });

  it("requires TLS material unless plaintext is asked for by name, outside production only", () => {
    expect(ExecutorConfigLoader.load(offlineEnvironment()).listener).toEqual({ tls: null });
    const unnamed = offlineEnvironment();
    delete unnamed["EXECUTOR_ALLOW_PLAINTEXT_LISTENER"];
    expect(refusal(unnamed)).toBe(
      "CONFIG_INVALID: EXECUTOR_TLS_CERT_FILE (required unless EXECUTOR_ALLOW_PLAINTEXT_LISTENER=true)",
    );
    expect(refusal({ ...production(), EXECUTOR_ALLOW_PLAINTEXT_LISTENER: "true" })).toBe(
      "CONFIG_INVALID: EXECUTOR_ALLOW_PLAINTEXT_LISTENER (forbidden in production)",
    );
    expect(
      refusal({
        ...offlineEnvironment(),
        EXECUTOR_TLS_CERT_FILE: "/etc/agent-safe/tls.crt",
        EXECUTOR_TLS_KEY: "not-a-key",
      }),
    ).toBe(
      "CONFIG_INVALID: EXECUTOR_ALLOW_PLAINTEXT_LISTENER (plaintext listener with EXECUTOR_TLS_CERT_FILE, EXECUTOR_TLS_KEY)",
    );
    const tls = ExecutorConfigLoader.load({
      ...unnamed,
      EXECUTOR_TLS_CERT_FILE: "/etc/agent-safe/tls.crt",
      EXECUTOR_TLS_KEY: "synthetic-key-material",
      EXECUTOR_TLS_CLIENT_CA_FILE: "/etc/agent-safe/clients.pem",
      EXECUTOR_TLS_MIN_VERSION: "1.2",
    });
    expect(tls.listener.tls).toEqual({
      certFile: "/etc/agent-safe/tls.crt",
      clientCaFile: "/etc/agent-safe/clients.pem",
      minVersion: "TLSv1.2",
    });
    expect(tls.secrets.required).toContain("EXECUTOR_TLS_KEY");
    expect(refusal({ ...unnamed, EXECUTOR_TLS_CERT_FILE: "relative/tls.crt" })).toBe(
      "CONFIG_INVALID: EXECUTOR_TLS_CERT_FILE",
    );
    expect(refusal({ ...unnamed, EXECUTOR_TLS_CERT_FILE: "/etc/agent-safe/tls.crt" })).toBe(
      "CONFIG_SECRET_MISSING: EXECUTOR_TLS_KEY",
    );
  });

  it("carries the trust anchors and the response bound the egress policy is sealed from", () => {
    const plain = ExecutorConfigLoader.load(offlineEnvironment());
    expect(plain.egress).toEqual({
      maxResponseBytes: 1024 * 1024,
      trust: {
        authority: { caFile: null, pins: [] },
        presence: { caFile: null, pins: [] },
        downstream: { caFile: null, pins: [] },
      },
    });
    expect(plain.evidence).toEqual({
      journalDir: null,
      checkpointLines: 100,
      journalRequired: false,
      journalRetainDays: 7,
      readyRequiresNoUnknownAttempts: false,
    });
    const pinned = ExecutorConfigLoader.load({
      ...direct(),
      DECIONIS_CA_FILE: "/etc/agent-safe/authority-ca.pem",
      DECIONIS_SPKI_PINS: `sha256/${"A".repeat(43)}=,sha256/${"B".repeat(43)}=`,
      PRESENCE_CA_FILE: "/etc/agent-safe/presence-ca.pem",
      DOWNSTREAM_CA_FILE: "/etc/agent-safe/downstream-ca.pem",
      DOWNSTREAM_SPKI_PINS: `sha256/${"C".repeat(43)}=,sha256/${"D".repeat(43)}=,sha256/${"C".repeat(43)}=`,
      EXECUTOR_EGRESS_MAX_RESPONSE_BYTES: "4096",
      EXECUTOR_JOURNAL_DIR: "/var/lib/agent-safe/journal",
      EXECUTOR_AUDIT_CHECKPOINT_LINES: "10",
    });
    expect(pinned.egress).toEqual({
      maxResponseBytes: 4096,
      trust: {
        authority: {
          caFile: "/etc/agent-safe/authority-ca.pem",
          pins: [`sha256/${"A".repeat(43)}=`, `sha256/${"B".repeat(43)}=`],
        },
        presence: { caFile: "/etc/agent-safe/presence-ca.pem", pins: [] },
        downstream: {
          caFile: "/etc/agent-safe/downstream-ca.pem",
          pins: [`sha256/${"C".repeat(43)}=`, `sha256/${"D".repeat(43)}=`],
        },
      },
    });
    expect(pinned.evidence).toEqual({
      journalDir: "/var/lib/agent-safe/journal",
      checkpointLines: 10,
      journalRequired: false,
      journalRetainDays: 7,
      readyRequiresNoUnknownAttempts: false,
    });
    expect(
      refusal({ ...offlineEnvironment(), DECIONIS_SPKI_PINS: `sha256/${"A".repeat(43)}=` }),
    ).toBe("CONFIG_INVALID: DECIONIS_SPKI_PINS (at least two distinct pins)");
    expect(
      refusal({
        ...offlineEnvironment(),
        DOWNSTREAM_SPKI_PINS: `sha256/${"A".repeat(43)}=,sha256/${"A".repeat(43)}=`,
      }),
    ).toBe("CONFIG_INVALID: DOWNSTREAM_SPKI_PINS (at least two distinct pins)");
    expect(refusal({ ...offlineEnvironment(), DOWNSTREAM_SPKI_PINS: "sha256:abc" })).toBe(
      "CONFIG_INVALID: DOWNSTREAM_SPKI_PINS",
    );
    expect(refusal({ ...offlineEnvironment(), PRESENCE_CA_FILE: "/etc/agent-safe/ca.pem" })).toBe(
      "CONFIG_INVALID: PRESENCE_CA_FILE (DIRECT escalation only)",
    );
    expect(refusal({ ...offlineEnvironment(), EXECUTOR_JOURNAL_DIR: "journal" })).toBe(
      "CONFIG_INVALID: EXECUTOR_JOURNAL_DIR",
    );
    expect(
      refusal({
        ...offlineEnvironment(),
        DOWNSTREAM_URL: "https://authority.decionis.example/v1/payouts",
        DOWNSTREAM_LOOKUP_URL: "https://authority.decionis.example/v1/payouts/{idempotency_key}",
        DOWNSTREAM_CA_FILE: "/etc/agent-safe/downstream-ca.pem",
      }),
    ).toBe(
      "CONFIG_INVALID: DOWNSTREAM_CA_FILE, DOWNSTREAM_SPKI_PINS (one origin, one trust anchor)",
    );
    expect(
      ExecutorConfigLoader.load({
        ...offlineEnvironment(),
        DOWNSTREAM_URL: "https://authority.decionis.example/v1/payouts",
        DOWNSTREAM_LOOKUP_URL: "https://authority.decionis.example/v1/payouts/{idempotency_key}",
      }).egress.trust.downstream,
    ).toEqual({ caFile: null, pins: [] });
  });

  it("switches to a principals file, refusing the legacy variables beside it and requiring it in production unless said otherwise", () => {
    const principals = offlineEnvironment();
    for (const key of [
      "EXECUTOR_TENANT_ID",
      "EXECUTOR_ACTOR_ID",
      "EXECUTOR_ACTOR_TYPE",
      "EXECUTOR_CALLER_TOKEN",
    ]) {
      delete principals[key];
    }
    principals["EXECUTOR_PRINCIPALS_FILE"] = "/var/run/agent-safe/principals/principals.json";
    const config = ExecutorConfigLoader.load(principals);
    expect(config.identity).toEqual({
      principalsFile: "/var/run/agent-safe/principals/principals.json",
      allowLegacyCaller: false,
      legacy: null,
      jwt: null,
      unauthenticated: { count: 20, windowSeconds: 60 },
      lockout: { failures: 10, windowSeconds: 60, lockSeconds: 300 },
    });
    expect(config.secrets.required).toEqual(["DECIONIS_API_KEY", "DOWNSTREAM_CREDENTIAL"]);
    expect(config.posture.principalsFile).toBe("/var/run/agent-safe/principals/principals.json");
    expect(
      refusal({ ...principals, EXECUTOR_CALLER_TOKEN: CALLER_TOKEN, EXECUTOR_ACTOR_ID: "x" }),
    ).toBe(
      "CONFIG_INVALID: EXECUTOR_PRINCIPALS_FILE (principals file with EXECUTOR_ACTOR_ID, EXECUTOR_CALLER_TOKEN)",
    );
    expect(refusal({ ...principals, EXECUTOR_PRINCIPALS_FILE: "principals.json" })).toBe(
      "CONFIG_INVALID: EXECUTOR_PRINCIPALS_FILE",
    );
    const legacyInProduction = production();
    delete legacyInProduction["EXECUTOR_ALLOW_LEGACY_CALLER"];
    expect(refusal(legacyInProduction)).toBe(
      "CONFIG_INVALID: EXECUTOR_PRINCIPALS_FILE (required in production unless EXECUTOR_ALLOW_LEGACY_CALLER=true)",
    );
    expect(ExecutorConfigLoader.load(production()).identity.allowLegacyCaller).toBe(true);
    const missing = offlineEnvironment();
    delete missing["EXECUTOR_ACTOR_TYPE"];
    expect(refusal(missing)).toBe("CONFIG_INVALID: EXECUTOR_ACTOR_TYPE");
    expect(refusal({ ...offlineEnvironment(), EXECUTOR_RATE_LIMIT_UNAUTHENTICATED: "20" })).toBe(
      "CONFIG_INVALID: EXECUTOR_RATE_LIMIT_UNAUTHENTICATED (expected <count>/<seconds>)",
    );
    expect(refusal({ ...offlineEnvironment(), EXECUTOR_AUTH_LOCKOUT: "5/60" })).toBe(
      "CONFIG_INVALID: EXECUTOR_AUTH_LOCKOUT (expected <failures>/<seconds>/<lock seconds>)",
    );
    expect(
      ExecutorConfigLoader.load({
        ...offlineEnvironment(),
        EXECUTOR_RATE_LIMIT_UNAUTHENTICATED: "5/30",
        EXECUTOR_AUTH_LOCKOUT: "0/60/300",
      }).identity,
    ).toMatchObject({ unauthenticated: { count: 5, windowSeconds: 30 }, lockout: null });
    expect(refusal({ ...managed(), PRESENCE_APPROVER_ID: "synthetic-payout-agent" })).toBe(
      "CONFIG_INVALID: PRESENCE_APPROVER_ID (separation of duties: also the actor)",
    );
  });

  it("takes the workload token settings together, with an optional refresh address and its anchor", () => {
    const jwt = ExecutorConfigLoader.load({
      ...offlineEnvironment(),
      EXECUTOR_JWT_AUDIENCE: "agentsafe",
      EXECUTOR_JWKS_FILE: "/var/run/agent-safe/jwks/jwks.json",
    }).identity.jwt;
    expect(jwt).toEqual({
      audience: "agentsafe",
      jwksFile: "/var/run/agent-safe/jwks/jwks.json",
      jwksUrl: null,
      jwksCaFile: null,
      refreshSeconds: 300,
      clockToleranceSeconds: 30,
    });
    const refreshed = ExecutorConfigLoader.load({
      ...offlineEnvironment(),
      EXECUTOR_JWT_AUDIENCE: "agentsafe",
      EXECUTOR_JWKS_FILE: "/var/run/agent-safe/jwks/jwks.json",
      EXECUTOR_JWKS_URL: "https://kubernetes.default.svc.cluster.example/openid/v1/jwks",
      EXECUTOR_JWKS_CA_FILE: "/var/run/agent-safe/jwks/ca.pem",
      EXECUTOR_JWKS_REFRESH_SECONDS: "600",
      EXECUTOR_JWT_CLOCK_TOLERANCE_SECONDS: "5",
    }).identity.jwt;
    expect(refreshed).toMatchObject({
      jwksUrl: "https://kubernetes.default.svc.cluster.example/openid/v1/jwks",
      jwksCaFile: "/var/run/agent-safe/jwks/ca.pem",
      refreshSeconds: 600,
      clockToleranceSeconds: 5,
    });
    expect(refusal({ ...offlineEnvironment(), EXECUTOR_JWT_AUDIENCE: "agentsafe" })).toBe(
      "CONFIG_INVALID: EXECUTOR_JWT_AUDIENCE, EXECUTOR_JWKS_FILE (given together or not at all)",
    );
    expect(
      refusal({
        ...offlineEnvironment(),
        EXECUTOR_JWKS_URL: "https://issuer.synthetic.example/jwks",
      }),
    ).toBe("CONFIG_INVALID: EXECUTOR_JWKS_URL (without EXECUTOR_JWKS_FILE)");
    expect(
      refusal({
        ...offlineEnvironment(),
        EXECUTOR_JWT_AUDIENCE: "agentsafe",
        EXECUTOR_JWKS_FILE: "/var/run/agent-safe/jwks/jwks.json",
        EXECUTOR_JWKS_CA_FILE: "/var/run/agent-safe/jwks/ca.pem",
      }),
    ).toBe("CONFIG_INVALID: EXECUTOR_JWKS_CA_FILE (without EXECUTOR_JWKS_URL)");
    expect(
      refusal({
        ...offlineEnvironment(),
        EXECUTOR_JWT_AUDIENCE: "agentsafe",
        EXECUTOR_JWKS_FILE: "/var/run/agent-safe/jwks/jwks.json",
        EXECUTOR_JWKS_URL: "http://issuer.synthetic.example/jwks",
      }),
    ).toBe("CONFIG_INVALID: EXECUTOR_JWKS_URL (https required)");
  });

  it("selects the downstream credential kind and refuses the other kinds' keys beside it", () => {
    const base = offlineEnvironment();
    delete base["DOWNSTREAM_CREDENTIAL"];
    delete base["DOWNSTREAM_CREDENTIAL_HEADER"];
    const jwt = ExecutorConfigLoader.load({
      ...base,
      DOWNSTREAM_CREDENTIAL_KIND: "PRIVATE_KEY_JWT",
      DOWNSTREAM_TOKEN_URL: "https://payouts.provider.example/oauth/token",
      DOWNSTREAM_CLIENT_ID: "synthetic-client",
      DOWNSTREAM_PRIVATE_KEY: "synthetic-key-material",
      DOWNSTREAM_PRIVATE_KEY_ID: "k1",
      DOWNSTREAM_PRIVATE_KEY_ALGORITHM: "PS256",
      DOWNSTREAM_TOKEN_AUDIENCE: "https://payouts.provider.example/",
      DOWNSTREAM_TOKEN_SCOPE: "payouts:write",
    });
    expect(jwt.downstream.credential).toEqual({
      kind: "PRIVATE_KEY_JWT",
      tokenUrl: "https://payouts.provider.example/oauth/token",
      clientId: "synthetic-client",
      keyId: "k1",
      algorithm: "PS256",
      audience: "https://payouts.provider.example/",
      scope: "payouts:write",
    });
    expect(jwt.downstream.redactedHeaders).toEqual(["authorization"]);
    expect(jwt.secrets.required).toContain("DOWNSTREAM_PRIVATE_KEY");
    expect(jwt.secrets.required).not.toContain("DOWNSTREAM_CREDENTIAL");
    const minimal = ExecutorConfigLoader.load({
      ...base,
      DOWNSTREAM_CREDENTIAL_KIND: "PRIVATE_KEY_JWT",
      DOWNSTREAM_TOKEN_URL: "https://payouts.provider.example/oauth/token",
      DOWNSTREAM_CLIENT_ID: "synthetic-client",
      DOWNSTREAM_PRIVATE_KEY: "synthetic-key-material",
    }).downstream.credential;
    expect(minimal).toMatchObject({ keyId: null, algorithm: "ES256", audience: null, scope: null });
    const signed = ExecutorConfigLoader.load({
      ...base,
      DOWNSTREAM_CREDENTIAL_KIND: "SIGNED_REQUEST",
      DOWNSTREAM_SIGNING_KEY: "synthetic-key-material",
      DOWNSTREAM_SIGNING_KEY_ID: "k2",
    });
    expect(signed.downstream.credential).toEqual({
      kind: "SIGNED_REQUEST",
      algorithm: "ed25519",
      keyId: "k2",
    });
    expect(signed.downstream.redactedHeaders).toEqual(["signature"]);
    expect(signed.secrets.required).toContain("DOWNSTREAM_SIGNING_KEY");
    expect(
      ExecutorConfigLoader.load({
        ...base,
        DOWNSTREAM_CREDENTIAL_KIND: "SIGNED_REQUEST",
        DOWNSTREAM_SIGNING_KEY: "synthetic-key-material",
        DOWNSTREAM_SIGNING_KEY_ID: "k2",
        DOWNSTREAM_SIGNING_ALGORITHM: "hmac-sha256",
      }).downstream.credential,
    ).toMatchObject({ algorithm: "hmac-sha256" });
    expect(refusal({ ...offlineEnvironment(), DOWNSTREAM_SIGNING_KEY_ID: "k2" })).toBe(
      "CONFIG_INVALID: DOWNSTREAM_CREDENTIAL_KIND (STATIC_HEADER with DOWNSTREAM_SIGNING_KEY_ID)",
    );
    expect(
      refusal({
        ...base,
        DOWNSTREAM_CREDENTIAL_KIND: "PRIVATE_KEY_JWT",
        DOWNSTREAM_TOKEN_URL: "https://payouts.provider.example/oauth/token",
        DOWNSTREAM_CLIENT_ID: "synthetic-client",
        DOWNSTREAM_PRIVATE_KEY: "synthetic-key-material",
        DOWNSTREAM_CREDENTIAL_HEADER: "Authorization",
      }),
    ).toBe(
      "CONFIG_INVALID: DOWNSTREAM_CREDENTIAL_KIND (PRIVATE_KEY_JWT with DOWNSTREAM_CREDENTIAL_HEADER)",
    );
    expect(
      refusal({
        ...base,
        DOWNSTREAM_CREDENTIAL_KIND: "PRIVATE_KEY_JWT",
        DOWNSTREAM_PRIVATE_KEY: "x",
      }),
    ).toBe("CONFIG_INVALID: DOWNSTREAM_TOKEN_URL, DOWNSTREAM_CLIENT_ID");
    expect(
      refusal({
        ...base,
        DOWNSTREAM_CREDENTIAL_KIND: "SIGNED_REQUEST",
        DOWNSTREAM_SIGNING_KEY: "x",
      }),
    ).toBe("CONFIG_INVALID: DOWNSTREAM_SIGNING_KEY_ID");
    expect(refusal({ ...base, DOWNSTREAM_CREDENTIAL: DOWNSTREAM_CREDENTIAL })).toBe(
      "CONFIG_INVALID: DOWNSTREAM_CREDENTIAL_HEADER",
    );
    expect(
      refusal({
        ...base,
        DOWNSTREAM_CREDENTIAL_KIND: "SIGNED_REQUEST",
        DOWNSTREAM_SIGNING_KEY_ID: "k2",
      }),
    ).toBe("CONFIG_SECRET_MISSING: DOWNSTREAM_SIGNING_KEY");
  });

  it("defaults the banking family and takes the institution's exception policy", () => {
    const defaults = ExecutorConfigLoader.load(offlineEnvironment()).banking;
    expect(defaults).toEqual({
      adapterId: "AGENTSAFE_CORE_BANKING",
      adapterVersion: "0.1.0",
      onEffectMismatch: "HALT",
      lookupByReferenceUrl: null,
    });
    const configured = ExecutorConfigLoader.load({
      ...offlineEnvironment(),
      BANKING_ADAPTER_ID: "SYNTHETIC_CORE",
      BANKING_ADAPTER_VERSION: "1.2.3",
      EXECUTOR_ON_EFFECT_MISMATCH: "ALERT",
      DOWNSTREAM_LOOKUP_BY_REFERENCE_URL:
        "https://payouts.provider.example/v1/by/{provider_reference}",
    }).banking;
    expect(configured).toEqual({
      adapterId: "SYNTHETIC_CORE",
      adapterVersion: "1.2.3",
      onEffectMismatch: "ALERT",
      lookupByReferenceUrl: "https://payouts.provider.example/v1/by/{provider_reference}",
    });
  });

  it("refuses a read-back address with no place to put the provider's reference", () => {
    expect(
      refusal({
        ...offlineEnvironment(),
        DOWNSTREAM_LOOKUP_BY_REFERENCE_URL: "https://payouts.provider.example/v1/by/latest",
      }),
    ).toBe(
      "CONFIG_INVALID: DOWNSTREAM_LOOKUP_BY_REFERENCE_URL (must contain {provider_reference})",
    );
    expect(refusal({ ...offlineEnvironment(), EXECUTOR_ON_EFFECT_MISMATCH: "IGNORE" })).toContain(
      "EXECUTOR_ON_EFFECT_MISMATCH",
    );
  });

  it("admits the read-back address to the sealed egress allowlist, and nothing else", () => {
    const config = ExecutorConfigLoader.load({
      ...offlineEnvironment(),
      DOWNSTREAM_LOOKUP_BY_REFERENCE_URL:
        "https://readback.provider.example/v1/by/{provider_reference}",
    });
    const policy = EgressPolicy.fromConfig(config, () => "");
    expect(
      policy.check(new URL("https://readback.provider.example/v1/by/fixture_ref_1")).allowed,
    ).toBe(true);
    expect(policy.check(new URL("https://readback.provider.example/v2/other")).allowed).toBe(false);
    expect(policy.check(new URL("https://elsewhere.provider.example/v1/by/x")).allowed).toBe(false);
  });

  it("lists every schema key and every secret in CONFIG_KEYS", () => {
    for (const key of Object.keys({ ...direct(), ...production() })) {
      if (key === "NODE_ENV" || key.endsWith("_FILE")) continue;
      expect(CONFIG_KEYS).toContain(key);
    }
    for (const key of SECRET_KEYS) expect(CONFIG_KEYS).toContain(key);
  });
});
