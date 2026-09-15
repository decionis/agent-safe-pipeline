import { readFileSync } from "node:fs";
import { parseAllDocuments } from "yaml";
import { describe, expect, it } from "vitest";
import { CONFIG_KEYS, SECRET_KEYS } from "../../src/config/ConfigKeys.js";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import { repositoryPath } from "../support/RepositoryRoot.js";

/**
 * The kit and the loader have to agree, and a manifest is the one place a
 * disagreement is silent: a misspelled variable is not a refusal to start,
 * it is a default nobody chose. So the manifest's own ConfigMap is read here
 * and held to the loader's vocabulary.
 */
function objects(): Record<string, unknown>[] {
  const path = repositoryPath("deploy", "kubernetes", "TrustedExecutor.yaml");
  return parseAllDocuments(readFileSync(path, "utf8"))
    .map((document) => document.toJS() as Record<string, unknown>)
    .filter((value) => value !== null);
}

function configMap(name: string): Record<string, string> {
  const found = objects().find(
    (object) =>
      object["kind"] === "ConfigMap" &&
      (object["metadata"] as { readonly name?: string } | undefined)?.name === name,
  );
  expect(found, `${name} must exist`).toBeDefined();
  return (found?.["data"] ?? {}) as Record<string, string>;
}

const executorConfig = configMap("agent-safe-executor-config");

describe("the deployment manifest's configuration", () => {
  it("names only variables the loader knows", () => {
    const known = new Set<string>(CONFIG_KEYS);
    // A secret is named by its own key plus `_FILE`; every other `_FILE` key
    // is a variable in its own right and has to be in the list as written.
    for (const secret of SECRET_KEYS) known.add(`${secret}_FILE`);
    for (const key of Object.keys(executorConfig)) {
      expect([...known], key).toContain(key);
    }
  });

  it("gives every secret as a file, never as a value", () => {
    for (const name of SECRET_KEYS) {
      expect(executorConfig[name], `${name} must not be an inline value`).toBeUndefined();
    }
    for (const key of Object.keys(executorConfig)) {
      if (!key.endsWith("_FILE")) continue;
      const base = key.slice(0, -"_FILE".length);
      if (!SECRET_KEYS.includes(base as (typeof SECRET_KEYS)[number])) continue;
      expect(executorConfig[key]).toMatch(/^\/var\/run\/agent-safe\//);
    }
  });

  it("is a configuration the loader accepts, once its secrets exist", () => {
    // The manifest's own values, with each `_FILE` replaced by the value it
    // would name, so the loader's every cross-field rule runs against the
    // shape a deployment actually has rather than against a test's shape.
    const env: Record<string, string> = { NODE_ENV: "production" };
    for (const [key, value] of Object.entries(executorConfig)) {
      env[key] = String(value);
    }
    const config = ExecutorConfigLoader.load(env);
    expect(config.production).toBe(true);
    expect(config.mode).toBe("SHADOW");
    expect(config.escalation.mode).toBe("NONE");
    expect(config.posture.mode).toBe("ENFORCED");
    expect(config.listener.tls).not.toBeNull();
    expect(config.evidence.journalRequired).toBe(true);
    expect(config.banking.onEffectMismatch).toBe("HALT");
    expect(config.banking.lookupByReferenceUrl).not.toBeNull();
    expect(config.limits).not.toBeNull();
  });

  it("is still a configuration the loader accepts at the end of the runbook", () => {
    // The runbook's last step turns this deployment into an enforcing one with
    // a managed ceremony. That is a different set of cross-field rules, and a
    // manifest that only loads in shadow would fail on the day it matters.
    const env: Record<string, string> = {
      NODE_ENV: "production",
      ...executorConfig,
      EXECUTOR_MODE: "ENFORCEMENT",
      EXECUTOR_ESCALATION: "MANAGED",
      PRESENCE_APPROVER_ID: "synthetic-treasury-approver",
      PRESENCE_APPROVER_ROLE: "CRO",
      PRESENCE_VERIFICATION_LEVEL: "HIGH_CONFIDENCE",
      PRESENCE_VERIFICATION_METHODS: "WEBAUTHN,ACTIVE_LIVENESS",
    };
    const config = ExecutorConfigLoader.load(env);
    expect(config.mode).toBe("ENFORCEMENT");
    expect(config.escalation.mode).toBe("MANAGED");
    // And the shipped shape refuses the combination the manifest warns about.
    expect(() => ExecutorConfigLoader.load({ ...env, EXECUTOR_MODE: "SHADOW" })).toThrow(
      "CONFIG_INVALID: EXECUTOR_ESCALATION (shadow never escalates)",
    );
  });

  it("names a principals file whose principals the executor would load", () => {
    const principals = JSON.parse(
      configMap("agent-safe-executor-principals")["principals.json"] ?? "{}",
    ) as {
      readonly version: string;
      readonly principals: {
        readonly id: string;
        readonly role: string;
        readonly credential: Record<string, unknown>;
      }[];
    };
    expect(principals.version).toBe("agent-safe.principals/1");
    expect(principals.principals.length).toBeGreaterThan(1);
    // The file holds digests and identities; a token or a key in a ConfigMap
    // would be a credential in plain sight.
    const text = JSON.stringify(principals);
    expect(text).not.toContain("token_sha256");
    expect(text).not.toContain("BEGIN");
    for (const principal of principals.principals) {
      expect(["PROPOSER", "OPERATOR"]).toContain(principal.role);
      expect(["WORKLOAD_JWT", "MTLS", "BEARER"]).toContain(principal.credential["kind"]);
    }
    expect(principals.principals.some((one) => one.role === "OPERATOR")).toBe(true);
  });

  it("names the audience the agent zone's projected token carries", () => {
    const zone = parseAllDocuments(
      readFileSync(repositoryPath("deploy", "kubernetes", "AgentZone.yaml"), "utf8"),
    )
      .map((document) => document.toJS() as Record<string, unknown>)
      .filter((value) => value !== null);
    const audiences = [...JSON.stringify(zone).matchAll(/"audience":"([^"]+)"/g)].map(
      (match) => match[1],
    );
    expect(audiences.length).toBeGreaterThan(0);
    for (const audience of audiences) {
      expect(audience).toBe(executorConfig["EXECUTOR_JWT_AUDIENCE"]);
    }
  });
});
