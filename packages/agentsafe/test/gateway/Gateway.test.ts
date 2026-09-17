import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  LOCAL_AUTHORITY_API_KEY,
  LocalAuthority,
  LocalPresence,
} from "@decionis/agent-safe-pipeline/testing";
import { demoPolicy } from "../../src/gateway/DemoAuthority.js";
import { Gateway, GATEWAY_PREFIX } from "../../src/gateway/Gateway.js";
import type { InterceptedRequest } from "../../src/gateway/InterceptedRequest.js";
import { verifyAuditChain } from "../../src/verify/VerifyAuditChain.js";
import { closedPort } from "../support/Environment.js";
import {
  collectedIo,
  testConfig,
  UpstreamDouble,
  type CollectedIo,
  LOOPBACK_ORIGIN,
} from "../support/GatewayHarness.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000009";

function request(
  method: string,
  path: string,
  body: unknown = undefined,
  headers: Record<string, string> = {},
  search = "",
): InterceptedRequest {
  const bytes = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body), "utf8");
  return {
    method,
    path,
    search,
    headers: {
      host: "gateway.example",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...headers,
    },
    body: bytes,
    remoteAddress: "127.0.0.1",
    encrypted: false,
  };
}

const json = (body: Buffer): Record<string, unknown> =>
  JSON.parse(body.toString("utf8")) as Record<string, unknown>;
const reports = (io: CollectedIo): Record<string, unknown>[] =>
  io.out
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((line) => line["event"] === "INTERCEPTED");
const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 30));

describe("the gateway in enforcement with the demo authority", () => {
  const upstream = new UpstreamDouble();
  let gateway: Gateway;
  let io: CollectedIo;

  beforeAll(async () => {
    await upstream.start();
    io = collectedIo();
    gateway = await Gateway.create(testConfig(upstream.baseUrl), {
      env: {},
      io,
      version: "0.0.0-test",
    });
  });
  afterAll(async () => {
    await gateway.close();
    await upstream.stop();
  });

  it("forwards an ALLOW exactly once, with the bytes the intent bound, the client's headers, and the evidence headers", async () => {
    const answer = await gateway.govern(
      request(
        "POST",
        "/payments",
        { amount: 50 },
        {
          authorization: "Bearer synthetic-client",
          "idempotency-key": "pay-1",
          "x-correlation-id": "run-1",
          connection: "keep-alive, x-hop",
          "x-hop": "dropped",
        },
      ),
      "http.post",
    );
    expect(answer.status).toBe(201);
    const headers = Object.fromEntries(answer.headers);
    expect(headers["agentsafe-decision"]).toBe("ALLOW");
    expect(headers["agentsafe-execution"]).toBe("FORWARDED");
    expect(headers["agentsafe-dossier-id"]).toMatch(/^synthetic-dossier-/);
    expect(headers["x-upstream"]).toBe("double");
    expect(answer.headers.filter(([name]) => name === "set-cookie")).toHaveLength(2);
    expect(answer.headers.filter(([name]) => name === "agentsafe-decision")).toEqual([
      ["agentsafe-decision", "ALLOW"],
    ]);
    expect(headers["connection"]).toBeUndefined();
    const seen = upstream.seen.at(-1);
    expect(seen?.method).toBe("POST");
    expect(seen?.url).toBe("/payments");
    expect(seen?.body).toBe('{"amount":50}');
    expect(seen?.headers["authorization"]).toBe("Bearer synthetic-client");
    expect(seen?.headers["idempotency-key"]).toBe("pay-1");
    expect(seen?.headers["x-agent-safe-dossier-id"]).toMatch(/^synthetic-dossier-/);
    expect(seen?.headers["x-agent-safe-intent-hash"]).toMatch(/^sha256:/);
    expect(seen?.headers["x-forwarded-for"]).toBe("127.0.0.1");
    expect(seen?.headers["x-forwarded-host"]).toBe("gateway.example");
    expect(seen?.headers["accept-encoding"]).toBe("identity");
    expect(seen?.headers["x-hop"]).toBeUndefined();
    expect(seen?.headers["host"]).not.toBe("gateway.example");
    const report = reports(io).at(-1);
    expect(report).toMatchObject({
      state: "ALLOW",
      verdict: "ALLOW",
      execution: "FORWARDED",
      upstream_status: 201,
      finalization: "RECORDED",
      action: "http.post",
      authority: "local/demo",
      reason_codes: ["POLICY_AUTONOMOUS_LIMIT"],
    });
    expect(gateway.status().counts).toMatchObject({ allows: 1, interceptions: 1 });
  });

  it("holds an ESCALATE without forwarding, and reports the hold as resumable only with Presence", async () => {
    const before = upstream.seen.length;
    const answer = await gateway.govern(request("POST", "/payments", { amount: 500 }), "http.post");
    expect(answer.status).toBe(202);
    const body = json(answer.body);
    expect(body).toMatchObject({
      state: "ESCALATE",
      verdict: "ESCALATE",
      execution: "HELD",
      reason_codes: ["HUMAN_APPROVAL_REQUIRED"],
      escalation: null,
    });
    expect(String(body["resume"])).toBe(
      `${GATEWAY_PREFIX}/v1/escalations/${String(body["intent_id"])}`,
    );
    expect(upstream.seen.length).toBe(before);
    const held = gateway.escalation(String(body["intent_id"]));
    expect(held).toMatchObject({ execution: "HELD", resumable: false });
    const resumed = await gateway.resume(String(body["intent_id"]));
    expect(resumed.status).toBe(409);
    expect(json(resumed.body)["reason_codes"]).toEqual([
      "ESCALATION_NOT_RESUMABLE",
      "PRESENCE_NOT_CONFIGURED",
    ]);
    expect(upstream.seen.length).toBe(before);
    expect(reports(io).at(-1)).toMatchObject({ state: "ESCALATE", execution: "HELD" });
  });

  it("refuses a BLOCK without forwarding and names the dossier", async () => {
    const before = upstream.seen.length;
    const answer = await gateway.govern(
      request("POST", "/payments", { amount: 5000 }),
      "http.post",
    );
    expect(answer.status).toBe(403);
    expect(json(answer.body)).toMatchObject({
      state: "BLOCK",
      verdict: "BLOCK",
      execution: "NOT_FORWARDED",
      reason_codes: ["POLICY_HARD_LIMIT_EXCEEDED"],
    });
    expect(String(json(answer.body)["dossier_id"])).toMatch(/^synthetic-dossier-/);
    expect(Object.fromEntries(answer.headers)["agentsafe-state"]).toBe("BLOCK");
    expect(upstream.seen.length).toBe(before);
    expect(reports(io).at(-1)).toMatchObject({ state: "BLOCK", execution: "NOT_FORWARDED" });
  });

  it("relays the upstream's own refusal as a failed execution, finalized", async () => {
    const answer = await gateway.govern(request("POST", "/refuse", { amount: 1 }), "http.post");
    expect(answer.status).toBe(422);
    expect(Object.fromEntries(answer.headers)["agentsafe-execution"]).toBe("FAILED");
    expect(json(answer.body)["ok"]).toBe(false);
    expect(reports(io).at(-1)).toMatchObject({
      state: "EXECUTION_FAILED",
      execution: "FAILED",
      upstream_status: 422,
      reason_codes: ["UPSTREAM_STATUS_422"],
      finalization: "RECORDED",
    });
  });

  it("relays a server error as an indeterminate execution, finalized as such", async () => {
    const answer = await gateway.govern(request("POST", "/fail", { amount: 1 }), "http.post");
    expect(answer.status).toBe(500);
    expect(Object.fromEntries(answer.headers)["agentsafe-execution"]).toBe("INDETERMINATE");
    expect(reports(io).at(-1)).toMatchObject({
      state: "EXECUTION_INDETERMINATE",
      execution: "INDETERMINATE",
      upstream_status: 500,
      reason_codes: ["PROVIDER_OUTCOME_UNKNOWN", "UPSTREAM_ERROR"],
    });
    expect(gateway.status().counts["indeterminate"]).toBe(1);
  });

  it("passes a safe method through unchanged and counts it", async () => {
    const answer = await gateway.passthrough(request("GET", "/health", undefined, {}, "?x=1&x=2"));
    expect(answer.status).toBe(200);
    expect(upstream.seen.at(-1)?.url).toBe("/health?x=1&x=2");
    expect(Object.fromEntries(answer.headers)["agentsafe-decision"]).toBeUndefined();
    expect(gateway.metricsText()).toContain('agentsafe_requests_total{kind="passthrough"} 1');
  });

  it("escalates a body it cannot read and a DELETE, under the demo policy", async () => {
    const unreadable: InterceptedRequest = {
      ...request("POST", "/payments"),
      body: Buffer.from("{not json", "utf8"),
      headers: { "content-type": "application/json" },
    };
    expect(json((await gateway.govern(unreadable, "http.post")).body)["verdict"]).toBe("ESCALATE");
    expect(
      json((await gateway.govern(request("DELETE", "/orders/7"), "http.delete")).body)["verdict"],
    ).toBe("ESCALATE");
  });

  it("refuses an intent it cannot bound before asking anyone", async () => {
    const long = request("POST", `/${"a".repeat(600)}`, { amount: 1 });
    const answer = await gateway.govern(long, "http.post");
    expect(answer.status).toBe(400);
    expect(json(answer.body)["reason_codes"]).toEqual(["TARGET_TOO_LONG"]);
  });

  it("renders metrics with the gateway families and reports status counts", () => {
    const text = gateway.metricsText();
    for (const family of [
      "agentsafe_requests_total",
      "agentsafe_interceptions_total",
      "agentsafe_decisions_total",
      "agentsafe_allows_total",
      "agentsafe_blocks_total",
      "agentsafe_escalations_total",
      "agentsafe_authority_latency_ms_sum",
      "agentsafe_forward_latency_ms_count",
      "agentsafe_execution_indeterminate_total",
      "agentsafe_escalations_held",
    ]) {
      expect(text).toContain(family);
    }
    const status = gateway.status();
    expect(status).toMatchObject({
      status: "ready",
      mode: "ENFORCEMENT",
      authority: "local/demo",
      failure_policy: "FAIL_CLOSED",
      routes: 0,
    });
    expect(status.held).toBeGreaterThanOrEqual(3);
    expect(gateway.readiness()).toEqual({
      ready: true,
      body: { ready: true, mode: "ENFORCEMENT", authority: "local/demo" },
    });
    expect(gateway.authorityLabel).toContain("local/demo");
    expect(gateway.evidenceLabel).toBe("terminal");
  });

  it("prints the banner and the stop line", () => {
    gateway.started("http://127.0.0.1:1");
    gateway.stopped("SIGTERM");
    const events = io.out.map((line) => (JSON.parse(line) as { event: string }).event);
    expect(events).toContain("GATEWAY_STARTED");
    expect(events.at(-1)).toBe("GATEWAY_STOPPED");
  });
});

describe("the gateway's evidence", () => {
  const upstream = new UpstreamDouble();
  const directory = mkdtempSync(join(tmpdir(), "agentsafe-gateway-"));
  afterAll(async () => {
    await upstream.stop();
    rmSync(directory, { recursive: true, force: true });
  });

  it("writes chained lines that verify offline, to the journal directory and not the terminal", async () => {
    await upstream.start();
    const io = collectedIo();
    const config = testConfig(upstream.baseUrl, {
      flags: { json: false },
      file: { version: 1, evidence: { journalDir: join(directory, "evidence") } },
    });
    const gateway = await Gateway.create(config, { env: {}, io });
    gateway.started("http://127.0.0.1:1");
    await gateway.govern(request("POST", "/payments", { amount: 10 }), "http.post");
    await gateway.govern(request("POST", "/payments", { amount: 50_000 }), "http.post");
    await gateway.close();
    const lines = readFileSync(join(directory, "evidence", "evidence.jsonl"), "utf8")
      .trim()
      .split("\n");
    const report = verifyAuditChain(lines);
    expect(report.ok).toBe(true);
    expect(lines.some((line) => line.includes('"event":"GATEWAY_STARTED"'))).toBe(true);
    expect(lines.some((line) => line.includes('"event":"EXECUTION_COMPLETED"'))).toBe(true);
    expect(lines.some((line) => line.includes('"event":"EXECUTION_BLOCKED"'))).toBe(true);
    expect(io.out.some((line) => line.startsWith("{"))).toBe(false);
    expect(io.out.join("\n")).toContain("ALLOW");
    expect(gateway.evidenceLabel).toContain("evidence.jsonl");
  });

  it("names the terminal only when verbose, and says when nothing is written", async () => {
    const quiet = await Gateway.create(testConfig(upstream.baseUrl, { flags: { json: false } }), {
      env: {},
      io: collectedIo(),
    });
    expect(quiet.evidenceLabel).toContain("not written");
    await quiet.close();
    const verbose = await Gateway.create(
      testConfig(upstream.baseUrl, { flags: { json: false, verbose: true } }),
      { env: {}, io: collectedIo() },
    );
    expect(verbose.evidenceLabel).toBe("terminal");
    await verbose.close();
  });
});

describe("the gateway in shadow", () => {
  const upstream = new UpstreamDouble();
  afterAll(() => upstream.stop());

  it("forwards unchanged, and reports what would have been decided as an observation", async () => {
    await upstream.start();
    const io = collectedIo();
    const gateway = await Gateway.create(
      testConfig(upstream.baseUrl, {
        flags: { mode: "shadow" },
        file: { version: 1, gateway: { upstreamTimeoutMs: 300 } },
      }),
      { env: {}, io },
    );
    const answer = await gateway.govern(
      request("POST", "/payments", { amount: 5000 }),
      "http.post",
    );
    expect(answer.status).toBe(201);
    expect(Object.fromEntries(answer.headers)).toMatchObject({
      "agentsafe-mode": "SHADOW",
      "agentsafe-execution": "PASSTHROUGH",
    });
    expect(upstream.seen.at(-1)?.body).toBe('{"amount":5000}');
    await settle();
    expect(reports(io).at(-1)).toMatchObject({
      state: "SHADOW",
      verdict: "BLOCK",
      execution: "PASSTHROUGH",
      upstream_status: 201,
      reason_codes: ["POLICY_HARD_LIMIT_EXCEEDED"],
    });
    expect(gateway.metricsText()).toContain('agentsafe_shadow_decisions_total{verdict="BLOCK"} 1');
    const failed = await gateway.govern(request("POST", "/hang", { amount: 1 }), "http.post");
    expect(failed.status).toBe(502);
    expect(json(failed.body)["reason_codes"]).toEqual(["UPSTREAM_UNREACHABLE"]);
    await gateway.close();
  }, 20_000);
});

describe("the gateway when the authority cannot be reached", () => {
  const upstream = new UpstreamDouble();
  afterAll(() => upstream.stop());

  async function unreachable(
    failurePolicy: string,
  ): Promise<{ gateway: Gateway; io: CollectedIo }> {
    const port = await closedPort();
    const env = {
      DECIONIS_API_KEY: "synthetic-authority-key",
      DECIONIS_API_URL: `${LOOPBACK_ORIGIN}:${port}`,
      DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
      DECIONIS_TENANT_ID: TENANT_ID,
      DECIONIS_TIMEOUT_MS: "500",
    };
    const io = collectedIo();
    const gateway = await Gateway.create(
      testConfig(upstream.baseUrl, { env, flags: { mode: "enforcement", failurePolicy } }),
      { env, io },
    );
    return { gateway, io };
  }

  it("fails closed as AUTHORITY_UNAVAILABLE, which is not a BLOCK", async () => {
    await upstream.start();
    const { gateway, io } = await unreachable("failClosed");
    const before = upstream.seen.length;
    const answer = await gateway.govern(request("POST", "/payments", { amount: 1 }), "http.post");
    expect(answer.status).toBe(503);
    expect(Object.fromEntries(answer.headers)["retry-after"]).toBe("5");
    expect(json(answer.body)).toMatchObject({
      state: "AUTHORITY_UNAVAILABLE",
      verdict: null,
      execution: "NOT_FORWARDED",
      reason_codes: ["AUTHORITY_UNAVAILABLE"],
    });
    expect(upstream.seen.length).toBe(before);
    expect(reports(io).at(-1)).toMatchObject({ state: "AUTHORITY_UNAVAILABLE", verdict: null });
    expect(gateway.metricsText()).toContain(
      'agentsafe_authority_errors_total{code="AUTHORITY_UNAVAILABLE"} 1',
    );
    expect(gateway.authorityLabel).toContain("decionis http://127.0.0.1:");
    await gateway.close();
  });

  it("forwards ungoverned only under an explicit fail-open policy, and says so on every surface", async () => {
    const { gateway, io } = await unreachable("failOpen");
    const answer = await gateway.govern(request("POST", "/payments", { amount: 1 }), "http.post");
    expect(answer.status).toBe(201);
    expect(Object.fromEntries(answer.headers)).toMatchObject({
      "agentsafe-state": "AUTHORITY_UNAVAILABLE",
      "agentsafe-execution": "FORWARDED_UNGOVERNED",
    });
    expect(reports(io).at(-1)).toMatchObject({
      state: "AUTHORITY_UNAVAILABLE",
      execution: "FORWARDED_UNGOVERNED",
      upstream_status: 201,
    });
    expect(io.out.some((line) => line.includes('"event":"EXECUTION_UNGOVERNED"'))).toBe(true);
    expect(gateway.metricsText()).toContain("agentsafe_ungoverned_forwards_total 1");
    await gateway.close();
  });
});

describe("the gateway with a managed escalation", () => {
  const upstream = new UpstreamDouble();
  const presence = new LocalPresence({ pendingLookups: 1, roles: { "synthetic-approver": "CRO" } });
  const authority = new LocalAuthority({ presence, policy: demoPolicy });
  afterAll(async () => {
    await authority.stop();
    await presence.stop();
    await upstream.stop();
  });

  it("resumes a held intent through the authority and executes once on the fresh grant", async () => {
    await upstream.start();
    await presence.start();
    await authority.start();
    const env = {
      DECIONIS_API_KEY: LOCAL_AUTHORITY_API_KEY,
      DECIONIS_API_URL: authority.baseUrl,
      DECIONIS_ALLOW_INSECURE_LOOPBACK: "true",
      DECIONIS_TENANT_ID: TENANT_ID,
      AGENTSAFE_PRESENCE_MANAGED: "true",
      PRESENCE_APPROVER_ID: "synthetic-approver",
      PRESENCE_APPROVER_ROLE: "CRO",
    };
    const io = collectedIo();
    const gateway = await Gateway.create(
      testConfig(upstream.baseUrl, { env, flags: { mode: "enforcement" } }),
      { env, io },
    );
    expect(gateway.config.escalation.mode).toBe("MANAGED");
    const held = await gateway.govern(
      request("POST", "/payments", { amount: 500 }, { "idempotency-key": "pay-managed" }),
      "http.post",
    );
    expect(held.status).toBe(202);
    const body = json(held.body);
    expect(body["escalation"]).toMatchObject({ mode: "MANAGED" });
    const intentId = String(body["intent_id"]);
    expect(gateway.escalation(intentId)).toMatchObject({ resumable: true });
    const before = upstream.seen.length;
    // The first lookup finds the person still deciding; the hold stays a hold.
    const pending = await gateway.resume(intentId);
    expect(pending.status).toBe(202);
    expect(json(pending.body)).toMatchObject({ execution: "HELD", state: "ESCALATE" });
    expect(upstream.seen.length).toBe(before);
    let resumed = pending;
    for (let attempt = 0; attempt < 5 && resumed.status === 202; attempt += 1) {
      await settle();
      resumed = await gateway.resume(intentId);
    }
    expect(resumed.status).toBe(201);
    expect(Object.fromEntries(resumed.headers)["agentsafe-execution"]).toBe("FORWARDED");
    expect(upstream.seen.length).toBe(before + 1);
    expect(upstream.seen.at(-1)?.body).toBe('{"amount":500}');
    expect(upstream.seen.at(-1)?.headers["idempotency-key"]).toBe("pay-managed");
    expect(gateway.escalation(intentId)).toBeNull();
    expect((await gateway.resume(intentId)).status).toBe(404);
    expect(reports(io).at(-1)).toMatchObject({
      state: "ALLOW",
      execution: "FORWARDED",
      reason_codes: ["PRESENCE_RECEIPT_VERIFIED"],
    });
    await gateway.close();
  }, 30_000);
});

describe("the forwarded bytes are the bytes the intent bound", () => {
  it("refuses before dispatch when the held request no longer matches the captured intent", async () => {
    const upstream = new UpstreamDouble();
    await upstream.start();
    const io = collectedIo();
    const gateway = await Gateway.create(testConfig(upstream.baseUrl), { env: {}, io });
    // Reach into the holder the way a mutation between authorization and
    // execution would: the intent said one body, the bytes are another.
    const holder = (
      gateway as unknown as {
        holder: {
          hold: (id: string, r: InterceptedRequest, h: Record<string, string>) => void;
          get: (id: string) => { request: InterceptedRequest } | undefined;
        };
      }
    ).holder;
    const original = holder.hold.bind(holder);
    holder.hold = (id, r, h) =>
      original(id, { ...r, body: Buffer.from('{"amount":999999}', "utf8") }, h);
    const answer = await gateway.govern(request("POST", "/payments", { amount: 10 }), "http.post");
    expect(answer.status).toBe(502);
    expect(json(answer.body)).toMatchObject({
      state: "EXECUTION_FAILED",
      execution: "NOT_FORWARDED",
      reason_codes: ["HANDLER_FAILED_BEFORE_DISPATCH"],
    });
    expect(upstream.seen).toHaveLength(0);
    expect(createHash("sha256").update('{"amount":10}').digest("hex")).not.toBe(
      createHash("sha256").update('{"amount":999999}').digest("hex"),
    );
    await gateway.close();
    await upstream.stop();
  });
});
