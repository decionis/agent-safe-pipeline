import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LOCAL_AUTHORITY_API_KEY, LocalAuthority } from "@decionis/agent-safe-pipeline/testing";
import { demoPolicy } from "../../src/gateway/DemoAuthority.js";
import {
  HOSTED_BOUNDARY_TEST_VERSION,
  HOSTED_TEST_ENVIRONMENT,
  hostedConfig,
  HostedTestError,
  runHostedBoundaryTest,
  type HostedBoundaryTestReport,
} from "../../src/gateway/HostedBoundaryTest.js";
import { closedPort } from "../support/Environment.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";
const LOOPBACK = "http://127.0.0.1";

describe("the hosted boundary test", () => {
  const authority = new LocalAuthority({ policy: demoPolicy });
  let report: HostedBoundaryTestReport;
  const byId = (id: string) => {
    const result = report.cases.find((candidate) => candidate.id === id);
    if (result === undefined) throw new Error(`no case ${id}`);
    return result;
  };

  beforeAll(async () => {
    await authority.start();
    report = await runHostedBoundaryTest({
      version: "9.9.9-test",
      credentials: {
        apiKey: LOCAL_AUTHORITY_API_KEY,
        tenantId: TENANT_ID,
        endpoint: null,
        provisional: true,
      },
      env: {
        DECIONIS_API_URL: authority.baseUrl,
        DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
        DECIONIS_TIMEOUT_MS: "5000",
        // Nothing of the operator's gateway is read: not the upstream, not the mode.
        AGENTSAFE_UPSTREAM: "http://must-not-be-read.example",
        AGENTSAFE_MODE: "enforcement",
      },
      surface: "homebrew",
      observationTimeoutMs: 5_000,
    });
  }, 30_000);

  afterAll(async () => {
    await authority.stop();
  });

  it("sends the cases directly and through a shadow gateway that Decionis decides for, and leaves the records", () => {
    expect(report.version).toBe(HOSTED_BOUNDARY_TEST_VERSION);
    expect(report.runtime).toBe("9.9.9-test");
    expect(report.target).toBe("synthetic loopback");
    expect(report.authority).toEqual({
      kind: "decionis",
      endpoint: authority.baseUrl,
      tenant: TENANT_ID,
      provisional: true,
      mode: "SHADOW",
    });
    // The outage case belongs to the local test; every other case is here.
    expect(report.cases.map((result) => result.id)).toEqual([
      "read",
      "routine-payment",
      "large-payment",
      "approval-payment",
      "destructive-delete",
      "forged-approval",
      "unreadable-body",
    ]);
    for (const result of report.cases) {
      expect(result.direct.reached, result.id).toBe(true);
    }
    // A read passes through unasked; a body the policy cannot read is still
    // an intent, and is held, because a policy cannot allow what it cannot see.
    expect(byId("read").decionis).toMatchObject({ consequential: false, state: null, status: 200 });
    expect(byId("unreadable-body").decionis).toMatchObject({
      consequential: true,
      state: "SHADOW",
      verdict: "ESCALATE",
    });
    // Every consequential request was forwarded unchanged and decided on.
    expect(byId("routine-payment").decionis).toMatchObject({
      consequential: true,
      state: "SHADOW",
      status: 201,
      verdict: "ALLOW",
    });
    expect(byId("large-payment").decionis.verdict).toBe("BLOCK");
    expect(byId("approval-payment").decionis.verdict).toBe("ESCALATE");
    expect(byId("destructive-delete").decionis.verdict).toBe("ESCALATE");
    expect(byId("forged-approval").decionis.verdict).toBe("BLOCK");
    expect(byId("forged-approval").direct.forgedHeadersReached).toBe(true);
    for (const id of ["routine-payment", "large-payment", "approval-payment", "forged-approval"]) {
      expect(byId(id).decionis.decision_id, id).toEqual(expect.any(String));
      expect(byId(id).decionis.dossier_id, id).toEqual(expect.any(String));
    }
    expect(report.decided).toEqual({
      consequential: 6,
      would: { ALLOW: 1, ESCALATE: 3, BLOCK: 2, NONE: 0 },
    });
    expect(report.dossiers).toHaveLength(6);
    expect(new Set(report.dossiers).size).toBe(6);
    expect(report.verdict).toBe("DECIONIS_DECIDED");
    // The first record, fetched with the run's own key and shown by its proof.
    expect(report.signedUnavailable).toBeNull();
    expect(report.signed?.dossierId).toBe(report.dossiers[0]);
    expect(report.signed?.keyId).toEqual(expect.any(String));
    expect(report.signed?.bytes).toBeGreaterThan(0);
    // Every hosted call named the test, not a gateway in service, and the surface.
    const agents = new Set(
      authority.requests
        .filter((request) => request.path.startsWith("/v1/authority/"))
        .map((request) => request.headers["user-agent"]),
    );
    expect(agents.size).toBe(1);
    expect([...agents][0]).toContain("example=agentsafe-test@9.9.9-test");
    expect([...agents][0]).toContain("surface=homebrew");
    expect(
      authority.requests.find((request) => request.path.startsWith("/v1/protocol/dossiers/"))
        ?.headers["user-agent"],
    ).toContain("example=agentsafe-test@9.9.9-test");
    // The lane reported its own adoption: connected to Decionis, in shadow, intercepting.
    expect(report.milestones).toEqual([
      "gateway_started",
      "shadow_enabled",
      "decionis_connected",
      "first_interception",
    ]);
  });

  it("reads the login and the DECIONIS_* variables, and nothing else", () => {
    expect(HOSTED_TEST_ENVIRONMENT).toEqual([
      "DECIONIS_API_KEY",
      "DECIONIS_API_KEY_FILE",
      "DECIONIS_API_URL",
      "DECIONIS_TENANT_ID",
      "DECIONIS_TIMEOUT_MS",
      "DECIONIS_ALLOW_INSECURE_LOOPBACK",
      "NODE_ENV",
    ]);
    const version = "9.9.9-test";
    const target = `${LOOPBACK}:1`;
    // No login and no key: refused by name, with the two commands that give one.
    expect(() => hostedConfig({ credentials: null, env: {}, version }, target)).toThrow(
      HostedTestError,
    );
    try {
      hostedConfig({ credentials: null, env: {}, version }, target);
    } catch (error) {
      expect((error as HostedTestError).code).toBe("NO_LOGIN");
      expect((error as HostedTestError).detail).toContain("agentsafe login --provision");
    }
    // A key in the environment wins over the login, as it does for proxy.
    const login = {
      apiKey: "synthetic-login-key-aaaaaaaa",
      tenantId: TENANT_ID,
      endpoint: null,
    };
    const fromLogin = hostedConfig({ credentials: login, env: {}, version }, target);
    expect(fromLogin.env["DECIONIS_API_KEY"]).toBe("synthetic-login-key-aaaaaaaa");
    expect(fromLogin.config.authority).toMatchObject({
      kind: "DECIONIS",
      mode: "SHADOW",
      tenantId: TENANT_ID,
      provisional: false,
    });
    const fromEnv = hostedConfig(
      {
        credentials: login,
        env: {
          DECIONIS_API_KEY: "synthetic-environment-key-aaaa",
          DECIONIS_TENANT_ID: TENANT_ID,
          AGENTSAFE_UPSTREAM: "http://must-not-be-read.example",
        },
        version,
      },
      target,
    );
    expect(fromEnv.env).toEqual({
      DECIONIS_API_KEY: "synthetic-environment-key-aaaa",
      DECIONIS_TENANT_ID: TENANT_ID,
    });
    expect(fromEnv.config.upstream.url).toBe(target);
    // A login with no organization is a configuration the loader refuses, by name.
    expect(() =>
      hostedConfig({ credentials: { ...login, tenantId: null }, env: {}, version }, target),
    ).toThrow(/CONFIG_INVALID: CONFIG_MISSING: DECIONIS_TENANT_ID/);
  });

  it("says when Decionis could not be reached, and leaves no record behind", async () => {
    const port = await closedPort();
    const unreachable = await runHostedBoundaryTest({
      version: "9.9.9-test",
      credentials: { apiKey: LOCAL_AUTHORITY_API_KEY, tenantId: TENANT_ID, endpoint: null },
      env: {
        DECIONIS_API_URL: `${LOOPBACK}:${String(port)}`,
        DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
        DECIONIS_TIMEOUT_MS: "300",
      },
      surface: null,
      observationTimeoutMs: 2_000,
    });
    expect(unreachable.verdict).toBe("AUTHORITY_UNREACHABLE");
    expect(unreachable.decided).toEqual({
      consequential: 6,
      would: { ALLOW: 0, ESCALATE: 0, BLOCK: 0, NONE: 6 },
    });
    expect(unreachable.dossiers).toEqual([]);
    expect(unreachable.signed).toBeNull();
    expect(unreachable.signedUnavailable).toBeNull();
    // Every request still reached the target: shadow forwards, whatever the authority did.
    for (const result of unreachable.cases) {
      expect(result.direct.reached, result.id).toBe(true);
      expect(result.decionis.state, result.id).toBe(
        result.decionis.consequential ? "SHADOW" : null,
      );
    }
  }, 30_000);
});
