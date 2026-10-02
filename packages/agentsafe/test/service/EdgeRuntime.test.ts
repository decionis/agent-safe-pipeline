import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { EdgeDecisionRecord } from "@decionis/agent-safe-pipeline";
import { CompactSign } from "jose";
import { describe, expect, it, vi } from "vitest";
import { HashChain } from "../../src/audit/HashChain.js";
import { EVIDENCE_STREAM } from "../../src/audit/HashChainedAuditSink.js";
import { ExecutorConfigLoader } from "../../src/config/ExecutorConfig.js";
import type { LoadPg, PgPool } from "../../src/edge/EdgeReplay.js";
import { ENTITLEMENT_TYPE } from "../../src/edge/EntitlementEvaluation.js";
import { verifyUsage } from "../../src/edge/UsageCount.js";
import { usagePeriod, type UsagePeriod } from "../../src/edge/UsagePeriod.js";
import { claimedUsage, readUsageReport } from "../../src/edge/UsageReport.js";
import { EdgeRuntime, type EdgeRuntimeOptions } from "../../src/service/EdgeRuntime.js";
import { collectedEvents, offlineEnvironment, openSecrets } from "../support/Environment.js";
import { edgeBundle, edgeModuleDouble } from "../support/EdgeModuleDouble.js";
import { vectorKey, vectorKeyPem } from "../support/UsageReportVector.js";

const signer = generateKeyPairSync("ed25519");
const ENTITLEMENT_KID = "synthetic-entitlement-key-1";

async function signedEntitlement(claims: Record<string, unknown>): Promise<string> {
  return await new CompactSign(new TextEncoder().encode(JSON.stringify(claims)))
    .setProtectedHeader({ alg: "EdDSA", typ: ENTITLEMENT_TYPE, kid: ENTITLEMENT_KID })
    .sign(signer.privateKey);
}

function jwks(): string {
  return JSON.stringify({
    keys: [{ ...signer.publicKey.export({ format: "jwk" }), kid: ENTITLEMENT_KID }],
  });
}

function entitlementClaims(now: number, overrides: Record<string, unknown> = {}) {
  return {
    iss: "decionis-synthetic",
    aud: "org-synthetic",
    iat: Math.floor(now / 1000),
    exp: Math.floor(now / 1000) + 86_400 * 400,
    plan: "enterprise",
    tier: "self_managed",
    included_actions_per_month: null,
    volume_band: null,
    edge: true,
    usage_report_due_days: 35,
    ...overrides,
  };
}

function decision(overrides: Partial<EdgeDecisionRecord> = {}): EdgeDecisionRecord {
  return {
    event: "EDGE_DECISION",
    mode: "ENFORCEMENT",
    intent_id: "intent-synthetic",
    intent_hash: `sha256:${"a".repeat(64)}`,
    decision_id: "edge:synthetic",
    verdict: "ALLOW",
    reason_codes: ["POLICY_ALLOW"],
    policy_version: "policy-2026.10",
    bundle_id: "bundle-1",
    kid: "decionis-policy-bundle-test-v1",
    jti: "jti-1",
    evaluation_digest: `sha256:${"e".repeat(64)}`,
    delegated: false,
    ...overrides,
  } as EdgeDecisionRecord;
}

interface Harness {
  readonly runtime: EdgeRuntime;
  readonly lines: string[];
  readonly security: () => Record<string, unknown>[];
  readonly clock: { now: number };
  readonly directory: string;
}

function harness(
  env: Record<string, string | undefined> = {},
  options: Partial<EdgeRuntimeOptions> = {},
): Harness {
  const directory = mkdtempSync(join(tmpdir(), "edge-runtime-"));
  const bundle = join(directory, "bundle.jws");
  writeFileSync(bundle, edgeBundle());
  const full: Record<string, string> = {
    ...offlineEnvironment(),
    EXECUTOR_DECISION_AUTHORITY: "edge",
    EXECUTOR_EDGE_WASM_PATH: "/opt/decionis/policy_core_edge.wasm",
    EXECUTOR_EDGE_ORG_ID: "org-synthetic",
    EXECUTOR_EDGE_SINGLE_REPLICA: "true",
    EXECUTOR_EDGE_BUNDLE_SOURCE: "file",
    EXECUTOR_EDGE_BUNDLE_FILE: bundle,
    EXECUTOR_JOURNAL_DIR: join(directory, "journal"),
  };
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) delete full[key];
    else full[key] = value;
  }
  const config = ExecutorConfigLoader.load(full);
  const securityLines: string[] = [];
  const events = collectedEvents(securityLines);
  const lines: string[] = [];
  const clock = { now: Date.parse("2026-09-10T00:00:00.000Z") };
  const runtime = EdgeRuntime.create({
    config,
    secrets: openSecrets(full, config, events),
    apiKey: () => "synthetic-api-key",
    fetch: (async () => new Response("", { status: 404 })) as typeof fetch,
    events,
    chain: new HashChain(EVIDENCE_STREAM),
    write: (line) => lines.push(line),
    loadModule: () => edgeModuleDouble(),
    clock: () => clock.now,
    ...options,
  });
  if (runtime === null) throw new Error("expected an edge runtime");
  return {
    runtime,
    lines,
    clock,
    directory,
    security: () => securityLines.map((line) => JSON.parse(line) as Record<string, unknown>),
  };
}

const september = usagePeriod("2026-09") as UsagePeriod;

describe("EdgeRuntime usage reports", () => {
  it("counts each decision as its line is written and writes the month's report for an operator", async () => {
    const reports = join(mkdtempSync(join(tmpdir(), "reports-")), "usage");
    const { runtime, lines, clock, security } = harness({
      EXECUTOR_EDGE_USAGE_SIGNING_KEY: vectorKeyPem(),
      EXECUTOR_EDGE_USAGE_KEY_ID: "synthetic-usage-key-1",
      EXECUTOR_EDGE_USAGE_REPORT_DIR: reports,
      EXECUTOR_EDGE_INSTALLATION_ID: "synthetic-installation-1",
    });
    expect(security()).toContainEqual(
      expect.objectContaining({
        event: "EDGE_USAGE_KEY_LOADED",
        kid: "synthetic-usage-key-1",
        installation_id: "synthetic-installation-1",
      }),
    );
    runtime.record(decision());
    runtime.record({
      event: "EDGE_EXECUTION_FINALIZED",
      intent_id: "intent-synthetic",
      intent_hash: `sha256:${"a".repeat(64)}`,
      decision_id: "edge:synthetic",
      outcome: "COMMITTED",
    });
    runtime.record(decision({ verdict: "ESCALATE", delegated: true, jti: "jti-2" }));
    runtime.record({
      event: "EDGE_UNAVAILABLE",
      mode: "ENFORCEMENT",
      intent_id: "intent-synthetic",
      intent_hash: `sha256:${"a".repeat(64)}`,
      reason: "EDGE_BUNDLE_UNAVAILABLE",
      module_code: null,
      fallback: "HOSTED",
    });
    expect(runtime.usage.governed()).toBe(1);
    clock.now = Date.parse("2026-10-01T00:30:00.000Z");
    await runtime.tick();
    const written = readdirSync(reports);
    expect(written).toEqual(["usage-2026-09-synthetic-installation-1.jws"]);
    const token = readFileSync(join(reports, written[0] ?? ""), "utf8").trim();
    const read = await readUsageReport(token, vectorKey().publicJwk);
    if (!read.ok) throw new Error(read.code);
    expect(read.kid).toBe("synthetic-usage-key-1");
    expect(read.claims).toMatchObject({
      iss: "synthetic-installation-1",
      aud: "org-synthetic",
      counts: { total: 2, by_mode: { ENFORCEMENT: 2, SHADOW: 0 } },
      delegated: 1,
      chain: { stream: EVIDENCE_STREAM, first_seq: 1, last_seq: 3 },
    });
    // What the executor counted live is what the chain recounts offline.
    expect(verifyUsage(lines, claimedUsage(read.claims), september).ok).toBe(true);
    expect(security()).toContainEqual(
      expect.objectContaining({ event: "EDGE_USAGE_REPORTED", destination: "file", total: 2 }),
    );
    runtime.stop();
    runtime.stop();
  });

  it("does not count a decision whose line could not be written", () => {
    const { runtime } = harness(
      {},
      {
        write: () => {
          throw new Error("disk full");
        },
      },
    );
    expect(() => runtime.record(decision())).toThrow("disk full");
    expect(runtime.usage.governed()).toBe(0);
  });

  it("sends the report to Decionis and reads the entitlement there, through the guarded fetch", async () => {
    const now = Date.parse("2026-10-01T00:30:00.000Z");
    const entitlement = await signedEntitlement(
      entitlementClaims(now, { edge: false, included_actions_per_month: 0 }),
    );
    const requests: string[] = [];
    const fetch = vi.fn(async (url: string, init?: RequestInit) => {
      requests.push(`${init?.method ?? "GET"} ${url}`);
      if (url.endsWith("/v1/edge/entitlement"))
        return new Response(JSON.stringify({ entitlement }));
      if (url.endsWith("/.well-known/decionis-policy-bundle-jwks.json"))
        return new Response(jwks());
      if (url.endsWith("/v1/edge/usage-reports")) return new Response("{}", { status: 201 });
      return new Response("", { status: 404 });
    });
    const { runtime, clock, security } = harness(
      {
        EXECUTOR_EDGE_BUNDLE_SOURCE: undefined,
        EXECUTOR_EDGE_BUNDLE_FILE: undefined,
        DECIONIS_API_URL: "https://api.decionis.example",
        EXECUTOR_EDGE_USAGE_SIGNING_KEY: vectorKeyPem(),
      },
      { fetch: fetch as unknown as typeof globalThis.fetch },
    );
    runtime.record(decision());
    clock.now = now;
    await runtime.tick();
    expect(requests).toContain("POST https://api.decionis.example/v1/edge/usage-reports");
    expect(requests).toContain("GET https://api.decionis.example/v1/edge/entitlement");
    const warnings = security()
      .filter((event) => event["event"] === "EDGE_LICENCE_WARNING")
      .map((event) => event["code"]);
    expect(warnings).toEqual(["EDGE_NOT_ENTITLED"]);
    expect(runtime.licence.warnings).toEqual(["EDGE_NOT_ENTITLED"]);
    runtime.stop();
  });
});

describe("EdgeRuntime licence warnings", () => {
  it("warns on a missing entitlement and a missing usage key, and clears what is put right", async () => {
    const { runtime, directory, security, clock } = harness();
    await runtime.start();
    expect(runtime.licence.warnings).toEqual(["ENTITLEMENT_MISSING", "USAGE_REPORT_KEY_MISSING"]);
    runtime.stop();
    const entitlementFile = join(directory, "entitlement.jws");
    const jwksFile = join(directory, "jwks.json");
    writeFileSync(entitlementFile, await signedEntitlement(entitlementClaims(clock.now)));
    writeFileSync(jwksFile, jwks());
    const placed = harness({
      EXECUTOR_EDGE_ENTITLEMENT_FILE: entitlementFile,
      EXECUTOR_EDGE_JWKS_FILE: jwksFile,
    });
    await placed.runtime.tick();
    expect(placed.runtime.licence.warnings).toEqual(["USAGE_REPORT_KEY_MISSING"]);
    writeFileSync(
      entitlementFile,
      await signedEntitlement(entitlementClaims(clock.now, { exp: Math.floor(clock.now / 1000) })),
    );
    await placed.runtime.tick();
    expect(
      placed.security().filter((event) => String(event["event"]).startsWith("EDGE_LICENCE")),
    ).toEqual([
      expect.objectContaining({ event: "EDGE_LICENCE_WARNING", code: "USAGE_REPORT_KEY_MISSING" }),
      expect.objectContaining({ event: "EDGE_LICENCE_WARNING", code: "ENTITLEMENT_EXPIRED" }),
    ]);
    writeFileSync(entitlementFile, await signedEntitlement(entitlementClaims(clock.now)));
    await placed.runtime.tick();
    expect(placed.security().at(-1)).toMatchObject({
      event: "EDGE_LICENCE_CLEARED",
      code: "ENTITLEMENT_EXPIRED",
    });
    expect(security().some((event) => event["event"] === "EDGE_BUNDLE_LOADED")).toBe(true);
    placed.runtime.stop();
  });
});

describe("EdgeRuntime over its allowance", () => {
  it("warns once this month's governed actions pass what the plan includes", async () => {
    const { directory, clock } = harness();
    const entitlementFile = join(directory, "entitlement.jws");
    const jwksFile = join(directory, "jwks.json");
    writeFileSync(
      entitlementFile,
      await signedEntitlement(entitlementClaims(clock.now, { included_actions_per_month: 1 })),
    );
    writeFileSync(jwksFile, jwks());
    const { runtime } = harness({
      EXECUTOR_EDGE_ENTITLEMENT_FILE: entitlementFile,
      EXECUTOR_EDGE_JWKS_FILE: jwksFile,
    });
    runtime.record(decision());
    runtime.record(decision({ verdict: "ESCALATE", delegated: true }));
    await runtime.tick();
    expect(runtime.licence.warnings).toEqual(["USAGE_REPORT_KEY_MISSING"]);
    runtime.record(decision());
    await runtime.tick();
    expect(runtime.licence.warnings).toEqual([
      "INCLUDED_ACTIONS_EXCEEDED",
      "USAGE_REPORT_KEY_MISSING",
    ]);
    runtime.stop();
  });
});

describe("EdgeRuntime replay store", () => {
  function pg(options: { fail?: boolean } = {}) {
    const ended = vi.fn();
    const queries: string[] = [];
    const load: LoadPg = async () => ({
      Pool: class implements PgPool {
        public async query(text: string): Promise<{ rowCount: number | null }> {
          queries.push(text);
          if (options.fail === true) throw new Error("connection refused");
          return { rowCount: 1 };
        }
        public on(): void {}
        public async end(): Promise<void> {
          ended();
        }
      },
    });
    return { load, ended, queries };
  }

  const postgres = {
    EXECUTOR_EDGE_SINGLE_REPLICA: undefined,
    EXECUTOR_EDGE_REPLAY_STORE: "postgres",
    EXECUTOR_EDGE_REPLAY_DATABASE_URL: "postgres://executor@db.invalid/edge",
  };

  it("uses the shared store, probes it before the first bundle, and cleans and closes it", async () => {
    const driver = pg();
    const { runtime } = harness(postgres, { loadPg: driver.load });
    await runtime.start();
    expect(driver.queries[0]).toBe(
      "SELECT namespace, intent_id, expires_at FROM agentsafe_edge_replay LIMIT 0",
    );
    expect(driver.queries).toContain("DELETE FROM agentsafe_edge_replay WHERE expires_at <= $1");
    await expect(runtime.replay.claim("intent-1", new Date(Date.now() + 60_000))).resolves.toBe(
      true,
    );
    runtime.stop();
    await new Promise((resolve) => setImmediate(resolve));
    expect(driver.ended).toHaveBeenCalledTimes(1);
  });

  it("refuses to start when the shared store cannot be reached or its driver is missing", async () => {
    const unreachable = harness(postgres, { loadPg: pg({ fail: true }).load });
    await expect(unreachable.runtime.start()).rejects.toThrow(
      "CONFIG_INVALID: EXECUTOR_EDGE_REPLAY_DATABASE_URL (REPLAY_STORE_UNAVAILABLE)",
    );
    const missing = harness(postgres, {
      loadPg: async () => {
        throw new Error("REPLAY_DRIVER_MISSING");
      },
    });
    await expect(missing.runtime.start()).rejects.toThrow(
      "CONFIG_INVALID: EXECUTOR_EDGE_REPLAY_DATABASE_URL (REPLAY_DRIVER_MISSING)",
    );
    missing.runtime.stop();
  });

  it("says when lapsed claims could not be removed, and goes on", async () => {
    const driver = pg();
    const { runtime, security } = harness(postgres, { loadPg: driver.load });
    await runtime.start();
    const failing = harness(postgres, { loadPg: pg({ fail: true }).load });
    await failing.runtime.tick();
    expect(failing.security().at(-1)).toMatchObject({ event: "EDGE_REPLAY_CLEANUP_FAILED" });
    expect(security().some((event) => event["event"] === "EDGE_REPLAY_CLEANUP_FAILED")).toBe(false);
    runtime.stop();
    failing.runtime.stop();
  });
});

describe("EdgeRuntime usage key", () => {
  it("refuses to start on a usage key that is not an Ed25519 private key", () => {
    const ec = generateKeyPairSync("ec", { namedCurve: "P-256" })
      .privateKey.export({ format: "pem", type: "pkcs8" })
      .toString();
    for (const key of ["not a key", ec]) {
      expect(() =>
        harness({ EXECUTOR_EDGE_USAGE_SIGNING_KEY: key, EXECUTOR_EDGE_USAGE_REPORT_DIR: "/tmp/u" }),
      ).toThrow("CONFIG_INVALID: EXECUTOR_EDGE_USAGE_SIGNING_KEY (not an Ed25519 key)");
    }
  });
});
