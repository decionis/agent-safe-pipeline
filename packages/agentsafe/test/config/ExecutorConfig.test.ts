import { describe, expect, it } from "vitest";
import { CONFIG_KEYS, SECRET_KEYS } from "../../src/config/ConfigKeys.js";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
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
    expect(config.actor).toEqual({ id: "synthetic-payout-agent", type: "AI_AGENT" });
    expect(config.escalation).toEqual({ mode: "NONE" });
    expect(config.authority.allowInsecureLoopback).toBe(false);
    expect(config.downstream.credentialHeader).toBe("authorization");
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
    expect(withRuntime.actor.runtime).toBe("workflow-runner");
    expect("runtime" in ExecutorConfigLoader.load(offlineEnvironment()).actor).toBe(false);
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
    expect(plain.evidence).toEqual({ journalDir: null, checkpointLines: 100 });
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

  it("lists every schema key and every secret in CONFIG_KEYS", () => {
    for (const key of Object.keys({ ...direct(), ...production() })) {
      if (key === "NODE_ENV" || key.endsWith("_FILE")) continue;
      expect(CONFIG_KEYS).toContain(key);
    }
    for (const key of SECRET_KEYS) expect(CONFIG_KEYS).toContain(key);
  });
});
