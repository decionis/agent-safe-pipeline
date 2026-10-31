import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  ACCEPTANCE_REPORT_TYPE,
  ACCEPTANCE_REPORT_VERSION,
  ACCEPTANCE_SCOPE,
  STATED_NOT_RUN,
  acceptanceSigningKey,
  acceptanceVerdict,
  canonicalDigest,
  currency,
  judgeOutage,
  judgePermitted,
  judgeProhibited,
  readAcceptanceReport,
  reportDigest,
  signAcceptanceReport,
  zoneFailures,
  type AcceptanceReport,
  type GovernedOutcome,
  type OutageCase,
  type PermittedCase,
  type ProhibitedCase,
} from "../../src/acceptance/AcceptanceReport.js";

const AT = "2026-10-31T12:00:00.000Z";

function pem(): string {
  return generateKeyPairSync("ed25519")
    .privateKey.export({ format: "pem", type: "pkcs8" })
    .toString();
}

const allowed: GovernedOutcome = {
  upstream_status: 200,
  state: "ALLOW",
  verdict: "ALLOW",
  execution: "FORWARDED",
  intent_id: "intent-1",
  decision_id: "decision-1",
  dossier_id: "dossier-1",
  reason_codes: [],
};

const blocked: GovernedOutcome = {
  ...allowed,
  upstream_status: null,
  state: "BLOCK",
  verdict: "BLOCK",
  execution: "NOT_FORWARDED",
};

const unchanged = {
  outcome: "UNCHANGED" as const,
  version_before: "v1",
  version_after: "v1",
  read_before_at: AT,
  read_after_at: AT,
};

const noZone: AcceptanceReport["zone"] = {
  origins: [],
  providers: [],
  mcp: [],
  credentials: [],
  metadata: null,
};

function permitted(overrides: Partial<PermittedCase> = {}): PermittedCase {
  return {
    name: "update-customer",
    method: "PATCH",
    path: "/customers/1",
    action: "customers.update",
    observed_by: "GATEWAY",
    ...allowed,
    effect: { confirmation: "CONFIRMED", reason_codes: [] },
    lines: [
      {
        stream: "agent-safe.gateway-events/1",
        seq: 3,
        hash: `sha256:${"a".repeat(64)}`,
        event: "EFFECT_OBSERVED",
      },
    ],
    passed: true,
    failure: null,
    ...overrides,
  };
}

function prohibited(overrides: Partial<ProhibitedCase> = {}): ProhibitedCase {
  return {
    name: "block-customer",
    method: "PATCH",
    path: "/customers/canary",
    action: "customers.update",
    canary: "customer canary-1, a test record",
    observed_by: "GATEWAY",
    shadow: { verdict: "BLOCK", reason_codes: [], decision_id: "d-0", dossier_id: null },
    sent: true,
    ...blocked,
    observation: unchanged,
    lines: [],
    passed: true,
    failure: null,
    ...overrides,
  };
}

function outage(overrides: Partial<OutageCase> = {}): OutageCase {
  return {
    name: "update-customer",
    method: "PATCH",
    path: "/customers/1",
    action: "customers.update",
    observed_by: "GATEWAY",
    skipped: null,
    status: 503,
    execution: "NOT_FORWARDED",
    reason_codes: ["AUTHORITY_UNAVAILABLE"],
    upstream_writes: 0,
    passed: true,
    failure: null,
    ...overrides,
  };
}

function report(overrides: Partial<AcceptanceReport> = {}): AcceptanceReport {
  const document = { fingerprint: "agent-safe.deployment-fingerprint/1", routes: [] };
  const cases = {
    permitted: [permitted()],
    prohibited: [prohibited()],
    outage: [outage()],
    zone: noZone,
  };
  return {
    report: ACCEPTANCE_REPORT_VERSION,
    run_id: "0123456789abcdef0123456789abcdef",
    boundary_id: "bd_example",
    issued_at: AT,
    expires_at: "2026-12-31T00:00:00.000Z",
    plan_digest: `sha256:${"b".repeat(64)}`,
    fingerprint: { digest: canonicalDigest(document), document },
    coverage: { governed: [], ungoverned: [], refused: [], reads: "PASSTHROUGH" },
    ...cases,
    stated: STATED_NOT_RUN.map((item) => ({ ...item })),
    ...acceptanceVerdict(cases),
    scope: ACCEPTANCE_SCOPE,
    ...overrides,
  };
}

describe("judgePermitted", () => {
  it("passes an allowed write the upstream accepted, confirmed or not read", () => {
    expect(judgePermitted(allowed, { confirmation: "CONFIRMED" })).toEqual({
      passed: true,
      failure: null,
    });
    expect(judgePermitted(allowed, { confirmation: "PENDING" })).toEqual({
      passed: true,
      failure: null,
    });
    expect(judgePermitted(allowed, null)).toEqual({ passed: true, failure: null });
    expect(judgePermitted({ ...allowed, upstream_status: 299 }, null).passed).toBe(true);
  });

  it("fails a write the policy refused or never decided", () => {
    expect(judgePermitted(blocked, null)).toEqual({ passed: false, failure: "NOT_ALLOWED" });
    expect(judgePermitted({ ...allowed, verdict: null }, null)).toEqual({
      passed: false,
      failure: "NOT_DECIDED",
    });
  });

  it("fails an allowed write that was not forwarded, or that the upstream refused", () => {
    expect(judgePermitted({ ...allowed, execution: "FAILED" }, null)).toEqual({
      passed: false,
      failure: "NOT_FORWARDED",
    });
    for (const status of [null, 199, 300, 409]) {
      expect(judgePermitted({ ...allowed, upstream_status: status }, null)).toEqual({
        passed: false,
        failure: "UPSTREAM_REFUSED",
      });
    }
  });

  it("fails a write read back as something other than what it asked", () => {
    expect(judgePermitted(allowed, { confirmation: "UNKNOWN" })).toEqual({
      passed: false,
      failure: "EFFECT_MISMATCH",
    });
  });
});

describe("judgeProhibited", () => {
  const input = { shadow: "BLOCK" as const, sent: true, outcome: blocked, observation: unchanged };

  it("passes a write refused in shadow and in enforcement, its target unchanged", () => {
    expect(judgeProhibited(input)).toEqual({ passed: true, failure: null });
    expect(
      judgeProhibited({
        ...input,
        shadow: "ESCALATE",
        outcome: { ...blocked, verdict: "ESCALATE", execution: "HELD" },
      }),
    ).toEqual({ passed: true, failure: null });
  });

  it("says why every other run fails, in the order the case runs", () => {
    expect(judgeProhibited({ ...input, shadow: null })).toEqual({
      passed: false,
      failure: "SHADOW_UNDECIDED",
    });
    expect(judgeProhibited({ ...input, shadow: "ALLOW" })).toEqual({
      passed: false,
      failure: "SHADOW_ALLOWED",
    });
    expect(judgeProhibited({ ...input, sent: false })).toEqual({
      passed: false,
      failure: "NOT_SENT",
    });
    expect(judgeProhibited({ ...input, outcome: { ...blocked, execution: "FORWARDED" } })).toEqual({
      passed: false,
      failure: "FORWARDED",
    });
    expect(judgeProhibited({ ...input, outcome: { ...blocked, verdict: "ALLOW" } })).toEqual({
      passed: false,
      failure: "FORWARDED",
    });
    expect(judgeProhibited({ ...input, observation: null })).toEqual({
      passed: false,
      failure: "TARGET_NOT_OBSERVED",
    });
    expect(
      judgeProhibited({ ...input, observation: { ...unchanged, outcome: "CHANGED" } }),
    ).toEqual({ passed: false, failure: "TARGET_CHANGED" });
    expect(
      judgeProhibited({ ...input, observation: { ...unchanged, outcome: "UNREADABLE" } }),
    ).toEqual({ passed: false, failure: "TARGET_UNREADABLE" });
  });
});

describe("judgeOutage", () => {
  it("passes only a 503 that forwarded nothing", () => {
    expect(judgeOutage({ status: 503, execution: "NOT_FORWARDED", upstreamWrites: 0 })).toEqual({
      passed: true,
      failure: null,
    });
    expect(judgeOutage({ status: 503, execution: "NOT_FORWARDED", upstreamWrites: 1 })).toEqual({
      passed: false,
      failure: "UPSTREAM_WRITTEN",
    });
    expect(judgeOutage({ status: 200, execution: "NOT_FORWARDED", upstreamWrites: 0 })).toEqual({
      passed: false,
      failure: "NOT_FAIL_CLOSED",
    });
    expect(
      judgeOutage({ status: 503, execution: "FORWARDED_UNGOVERNED", upstreamWrites: 0 }),
    ).toEqual({ passed: false, failure: "NOT_FAIL_CLOSED" });
  });
});

describe("zoneFailures and acceptanceVerdict", () => {
  const origin = {
    name: "erp",
    address: "erp.internal:443",
    direct: { status: null, detail: "TIMED_OUT" },
    control: { status: 200, detail: "ANSWERED" },
    verdict: "CONTAINED" as const,
    at: AT,
  };
  const provider = {
    name: "payments",
    unattested: { status: 409, detail: "ANSWERED", reason_code: "SIGNATURE_INVALID_OR_INCOMPLETE" },
    signed: null,
    verdict: "REFUSED" as const,
    at: AT,
  };

  it("fails an origin that is not contained, a provider that did not refuse, and a reachable metadata endpoint", () => {
    expect(zoneFailures({ ...noZone, origins: [origin], providers: [provider] })).toEqual([]);
    expect(
      zoneFailures({
        ...noZone,
        origins: [
          { ...origin, verdict: "REACHABLE" },
          { ...origin, name: "crm", verdict: "INCONCLUSIVE" },
        ],
        providers: [{ ...provider, verdict: "ACCEPTED" }],
        metadata: {
          address: "169.254.169.254:80",
          status: 200,
          detail: "ANSWERED",
          verdict: "REACHABLE",
          at: AT,
        },
      }),
    ).toEqual([
      { case: "origin", name: "erp", code: "REACHABLE" },
      { case: "origin", name: "crm", code: "INCONCLUSIVE" },
      { case: "provider", name: "payments", code: "ACCEPTED" },
      { case: "metadata", name: "metadata", code: "REACHABLE" },
    ]);
  });

  it("lists credentials, MCP servers and an unanswered metadata endpoint without judging them", () => {
    expect(
      zoneFailures({
        ...noZone,
        mcp: [
          {
            name: "tools",
            address: "tools:443",
            verdict: "REACHABLE",
            detail: "CONNECTED",
            at: AT,
          },
        ],
        credentials: [
          { source: "environment", name: "OPENAI_API_KEY", kind: "secret-like", own: false },
        ],
        metadata: {
          address: "169.254.169.254:80",
          status: null,
          detail: "TIMED_OUT",
          verdict: "CONTAINED",
          at: AT,
        },
      }),
    ).toEqual([]);
  });

  it("accepts only when every case that ran passed", () => {
    expect(
      acceptanceVerdict({
        permitted: [permitted()],
        prohibited: [prohibited()],
        outage: [outage()],
        zone: noZone,
      }),
    ).toEqual({ verdict: "ACCEPTED", failures: [] });
    expect(
      acceptanceVerdict({
        permitted: [permitted({ passed: false, failure: "NOT_SENT" })],
        prohibited: [prohibited({ passed: false, failure: null })],
        outage: [outage({ passed: false, failure: "UPSTREAM_WRITTEN" })],
        zone: { ...noZone, origins: [{ ...origin, verdict: "REACHABLE" }] },
      }),
    ).toEqual({
      verdict: "NOT_ACCEPTED",
      failures: [
        { case: "permitted", name: "update-customer", code: "NOT_SENT" },
        { case: "prohibited", name: "block-customer", code: "FAILED" },
        { case: "outage", name: "update-customer", code: "UPSTREAM_WRITTEN" },
        { case: "origin", name: "erp", code: "REACHABLE" },
      ],
    });
  });
});

describe("signing and reading a report", () => {
  it("signs with the key's thumbprint as kid, and reads back what it signed", async () => {
    const key = acceptanceSigningKey(pem());
    expect(key.kid).toMatch(/^[\w-]{43}$/);
    expect(acceptanceSigningKey(pem(), "acceptance-2026").kid).toBe("acceptance-2026");
    const signed = report();
    const token = await signAcceptanceReport(signed, key);
    const header = JSON.parse(Buffer.from(token.split(".")[0]!, "base64url").toString()) as Record<
      string,
      unknown
    >;
    expect(header).toEqual({ alg: "EdDSA", typ: ACCEPTANCE_REPORT_TYPE, kid: key.kid });
    expect(await readAcceptanceReport(token, key.publicJwk)).toEqual({
      ok: true,
      kid: key.kid,
      report: signed,
    });
    expect(reportDigest(token)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("refuses a key that is not Ed25519", () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 })
      .privateKey.export({ format: "pem", type: "pkcs8" })
      .toString();
    expect(() => acceptanceSigningKey(rsa)).toThrow("ACCEPTANCE_KEY_NOT_ED25519");
  });

  it("refuses another key's signature, a malformed token and a wrong header", async () => {
    const key = acceptanceSigningKey(pem());
    const token = await signAcceptanceReport(report(), key);
    expect(await readAcceptanceReport(token, acceptanceSigningKey(pem()).publicJwk)).toEqual({
      ok: false,
      code: "ACCEPTANCE_REPORT_SIGNATURE_INVALID",
    });
    expect(await readAcceptanceReport("not-a-token", key.publicJwk)).toEqual({
      ok: false,
      code: "ACCEPTANCE_REPORT_MALFORMED",
    });
    const { CompactSign } = await import("jose");
    for (const header of [
      { alg: "EdDSA", typ: "JWT", kid: key.kid },
      { alg: "EdDSA", typ: ACCEPTANCE_REPORT_TYPE },
    ]) {
      const other = await new CompactSign(new TextEncoder().encode(JSON.stringify(report())))
        .setProtectedHeader(header)
        .sign(key.privateKey);
      expect(await readAcceptanceReport(other, key.publicJwk)).toEqual({
        ok: false,
        code: "ACCEPTANCE_REPORT_MALFORMED",
      });
    }
  });

  it("refuses a signed payload that is not a report, or whose parts disagree", async () => {
    const key = acceptanceSigningKey(pem());
    const { CompactSign } = await import("jose");
    const sign = async (payload: string): Promise<string> =>
      await new CompactSign(new TextEncoder().encode(payload))
        .setProtectedHeader({ alg: "EdDSA", typ: ACCEPTANCE_REPORT_TYPE, kid: key.kid })
        .sign(key.privateKey);
    expect(await readAcceptanceReport(await sign("{"), key.publicJwk)).toEqual({
      ok: false,
      code: "ACCEPTANCE_REPORT_MALFORMED",
    });
    expect(
      await readAcceptanceReport(await sign(JSON.stringify({ report: "x" })), key.publicJwk),
    ).toEqual({
      ok: false,
      code: "ACCEPTANCE_REPORT_MALFORMED",
    });
    const forged = report();
    const moved = {
      ...forged,
      fingerprint: { ...forged.fingerprint, digest: `sha256:${"c".repeat(64)}` },
    };
    expect(await readAcceptanceReport(await sign(JSON.stringify(moved)), key.publicJwk)).toEqual({
      ok: false,
      code: "ACCEPTANCE_REPORT_INCONSISTENT",
    });
    const claimed = {
      ...report({ permitted: [permitted({ passed: false, failure: "NOT_SENT" })] }),
      verdict: "ACCEPTED",
      failures: [],
    };
    expect(await readAcceptanceReport(await sign(JSON.stringify(claimed)), key.publicJwk)).toEqual({
      ok: false,
      code: "ACCEPTANCE_REPORT_INCONSISTENT",
    });
  });
});

describe("currency", () => {
  const changed = (): readonly string[] => ["routes"];

  it("is current while the date holds and the fingerprint is the one tested", () => {
    const signed = report();
    expect(currency(signed, signed.fingerprint, Date.parse(AT), changed)).toEqual({
      state: "CURRENT",
    });
  });

  it("expires on its date, whatever the fingerprint", () => {
    const signed = report();
    expect(currency(signed, signed.fingerprint, Date.parse(signed.expires_at), changed)).toEqual({
      state: "EXPIRED",
      expired_at: signed.expires_at,
    });
  });

  it("is stale, with the fields that differ, once the deployment is another", () => {
    const signed = report();
    expect(
      currency(
        signed,
        { digest: `sha256:${"d".repeat(64)}`, document: {} },
        Date.parse(AT),
        changed,
      ),
    ).toEqual({ state: "STALE", changed: ["routes"] });
  });
});

describe("what a signed report may hold", () => {
  it("reads back every method, confirmation, observation, route kind and read policy it names", async () => {
    const key = acceptanceSigningKey(pem());
    const methods = ["POST", "PUT", "PATCH", "DELETE"] as const;
    const confirmations = ["CONFIRMED", "UNKNOWN", "PENDING"] as const;
    const outcomes = ["UNCHANGED", "CHANGED", "UNREADABLE"] as const;
    for (const reads of ["PASSTHROUGH", "CHECK", "REFUSE_UNKNOWN"] as const) {
      const cases = {
        permitted: methods.map((method, index) =>
          permitted({
            name: `write-${index}`,
            method,
            effect: { confirmation: confirmations[index % 3]!, reason_codes: ["EFFECT_NOT_READ"] },
            passed: confirmations[index % 3] !== "UNKNOWN",
            failure: confirmations[index % 3] === "UNKNOWN" ? "EFFECT_MISMATCH" : null,
          }),
        ),
        prohibited: outcomes.map((outcome, index) =>
          prohibited({
            name: `refused-${index}`,
            observation: { ...unchanged, outcome },
            passed: outcome === "UNCHANGED",
            failure: outcome === "UNCHANGED" ? null : "TARGET_CHANGED",
          }),
        ),
        outage: [outage()],
        zone: noZone,
      };
      const signed = report({
        ...cases,
        ...acceptanceVerdict(cases),
        coverage: {
          governed: [
            { methods: ["POST", "PUT"], path: "/x", action: "x.write", target_read: false },
          ],
          ungoverned: (["SHADOW", "FAIL_OPEN", "PASSTHROUGH"] as const).map((kind) => ({
            methods: ["POST"],
            path: `/${kind}`,
            action: null,
            kind,
          })),
          refused: [],
          reads,
        },
      });
      const read = await readAcceptanceReport(
        await signAcceptanceReport(signed, key),
        key.publicJwk,
      );
      expect(read).toEqual({ ok: true, kid: key.kid, report: signed });
    }
  });

  it("names its key by the key's RFC 7638 thumbprint", async () => {
    const key = acceptanceSigningKey(pem());
    const { calculateJwkThumbprint } = await import("jose");
    expect(key.kid).toBe(await calculateJwkThumbprint(key.publicJwk, "sha256"));
  });

  it("refuses a report whose header names another algorithm, before any key is tried", async () => {
    const key = acceptanceSigningKey(pem());
    const token = await signAcceptanceReport(report(), key);
    const [, payload, signature] = token.split(".");
    const header = Buffer.from(
      JSON.stringify({ alg: "ES256", typ: ACCEPTANCE_REPORT_TYPE, kid: key.kid }),
    ).toString("base64url");
    expect(await readAcceptanceReport(`${header}.${payload}.${signature}`, key.publicJwk)).toEqual({
      ok: false,
      code: "ACCEPTANCE_REPORT_MALFORMED",
    });
  });
});

describe("the contract's names", () => {
  it("are the ones a verifier in another language reads", () => {
    expect(ACCEPTANCE_REPORT_VERSION).toBe("agent-safe.acceptance/1");
    expect(ACCEPTANCE_REPORT_TYPE).toBe("agent-safe-acceptance+jwt");
    expect(ACCEPTANCE_SCOPE).toBe(
      "This report establishes the named writes, targets, origins and window, under the fingerprint it carries, and nothing else. It does not carry over to other adapters, routes or environments.",
    );
  });

  it("refuses a digest with anything before or after it", async () => {
    const key = acceptanceSigningKey(pem());
    const hex = "b".repeat(64);
    for (const digest of [`sha256:${hex}0`, `xsha256:${hex}`]) {
      const token = await signAcceptanceReport(report({ plan_digest: digest }), key);
      expect(await readAcceptanceReport(token, key.publicJwk)).toEqual({
        ok: false,
        code: "ACCEPTANCE_REPORT_MALFORMED",
      });
    }
  });
});
