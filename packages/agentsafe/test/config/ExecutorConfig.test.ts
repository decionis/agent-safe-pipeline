import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
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

const refusal = (env: Record<string, string | undefined>): string => {
  try {
    ExecutorConfigLoader.load(env);
    return "";
  } catch (error) {
    return error instanceof Error ? error.message : "unknown";
  }
};

describe("ExecutorConfigLoader", () => {
  const directory = mkdtempSync(join(tmpdir(), "agentsafe-config-"));
  afterAll(() => rmSync(directory, { recursive: true, force: true }));

  it("loads an enforcement configuration and normalises the header name", () => {
    const config = ExecutorConfigLoader.load(offlineEnvironment());
    expect(config.mode).toBe("ENFORCEMENT");
    expect(config.port).toBe(8443);
    expect(config.actor).toEqual({ id: "synthetic-payout-agent", type: "AI_AGENT" });
    expect(config.callerToken).toBe(CALLER_TOKEN);
    expect(config.escalation).toEqual({ mode: "NONE" });
    expect(config.authority.allowInsecureLoopback).toBe(false);
    expect(config.downstream.credentialHeader).toBe("authorization");
    expect(config.downstream.credential).toBe(DOWNSTREAM_CREDENTIAL);
    expect(config.downstream.lookupUrl).toContain("{idempotency_key}");
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
    expect(
      refusal({
        ...offlineEnvironment(),
        DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
        NODE_ENV: "production",
      }),
    ).toBe("CONFIG_INVALID: DECIONIS_ALLOW_INSECURE_LOOPBACK (forbidden in production)");
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

  it("loads the direct shape with its Presence credential and flags", () => {
    const config = ExecutorConfigLoader.load(direct());
    expect(config.escalation).toEqual({
      mode: "DIRECT",
      presence: {
        baseUrl: "https://presence.decionis.example",
        apiKey: "synthetic-presence-key",
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

  it("reads a secret from a mounted file and refuses it given twice", () => {
    const path = join(directory, "downstream-credential");
    writeFileSync(path, `${DOWNSTREAM_CREDENTIAL}\n`);
    const env = offlineEnvironment();
    delete env["DOWNSTREAM_CREDENTIAL"];
    const config = ExecutorConfigLoader.load({ ...env, DOWNSTREAM_CREDENTIAL_FILE: path });
    expect(config.downstream.credential).toBe(DOWNSTREAM_CREDENTIAL);
    expect(refusal({ ...offlineEnvironment(), DOWNSTREAM_CREDENTIAL_FILE: path })).toBe(
      "CONFIG_SECRET_AMBIGUOUS: DOWNSTREAM_CREDENTIAL",
    );
  });

  it("lists every schema key and every secret in CONFIG_KEYS", () => {
    for (const key of Object.keys(direct())) expect(CONFIG_KEYS).toContain(key);
    for (const key of SECRET_KEYS) expect(CONFIG_KEYS).toContain(key);
  });
});
