import { afterEach, describe, expect, it, vi } from "vitest";
import type { ChainFields } from "../../src/audit/HashChain.js";
import { ACCEPTANCE_PLAN_VERSION, writeBody } from "../../src/acceptance/AcceptancePlan.js";
import {
  ACCEPTANCE_SCOPE,
  canonicalDigest,
  type AcceptanceReport,
} from "../../src/acceptance/AcceptanceReport.js";
import {
  AcceptanceRuns,
  CLOSE_WAIT_MS,
  RUN_TTL_MS,
  type AcceptanceHost,
  type ShadowOutcome,
} from "../../src/acceptance/AcceptanceRun.js";
import type { InterceptionReport } from "../../src/gateway/GatewayReport.js";
import type { ZoneFindings } from "../../src/acceptance/ZoneProbes.js";

const AT = Date.parse("2026-10-31T12:00:00.000Z");
const RUN = "r".repeat(43);
const document = { fingerprint: "agent-safe.deployment-fingerprint/1" };
const noZone: ZoneFindings = {
  origins: [],
  providers: [],
  mcp: [],
  credentials: [],
  metadata: null,
};

const plan = {
  version: ACCEPTANCE_PLAN_VERSION,
  gateway: "https://gateway.example",
  expires_at: "2026-12-31T00:00:00Z",
  permitted: [
    { name: "update", method: "PATCH", path: "/customers/1?expand=x", body: { blocked: " " } },
  ],
  prohibited: [
    {
      name: "block",
      method: "PATCH",
      path: "/customers/9",
      body: { blocked: "All" },
      canary: "customer 9",
    },
  ],
};

interface Fake {
  readonly host: AcceptanceHost;
  readonly lines: ChainFields[];
  readonly signed: AcceptanceReport[];
  now: number;
}

function fake(overrides: Partial<AcceptanceHost> = {}): Fake {
  const state = { lines: [] as ChainFields[], signed: [] as AcceptanceReport[], now: AT };
  const host: AcceptanceHost = {
    boundaryId: "bd_test",
    fingerprint: {
      digest: canonicalDigest(document),
      document,
    } as unknown as AcceptanceHost["fingerprint"],
    failurePolicy: "FAIL_CLOSED",
    coverage: { governed: [], ungoverned: [], refused: [], reads: "PASSTHROUGH" },
    route: () => ({ enforced: true, action: "customers.update", targetRead: true }),
    decide: () =>
      Promise.resolve({
        verdict: "BLOCK",
        reason_codes: ["LIMIT"],
        decision_id: "d-shadow",
        dossier_id: "x",
      }),
    outage: () =>
      Promise.resolve({
        status: 503,
        execution: "NOT_FORWARDED",
        reason_codes: ["AUTHORITY_UNAVAILABLE"],
        upstreamWrites: 0,
      }),
    settled: () => Promise.resolve(),
    link: (fields) => {
      state.lines.push(fields);
      return {
        stream: "s",
        seq: state.lines.length,
        hash: `sha256:${"a".repeat(64)}`,
        event: String(fields["event"]),
      };
    },
    sign: (report) => {
      state.signed.push(report);
      return Promise.resolve(`signed.${state.signed.length}`);
    },
    clock: () => state.now,
    ...overrides,
  };
  return Object.assign(state, { host });
}

function request(write: { method: string; path: string; body?: unknown }) {
  const at = write.path.indexOf("?");
  return {
    method: write.method.toLowerCase(),
    path: at === -1 ? write.path : write.path.slice(0, at),
    search: at === -1 ? "" : write.path.slice(at),
    body: writeBody(write as never),
  };
}

function interception(
  intentId: string,
  overrides: Partial<InterceptionReport> = {},
): InterceptionReport {
  return {
    event: "INTERCEPTED",
    at: new Date(AT).toISOString(),
    method: "PATCH",
    path: "/customers/1",
    action: "customers.update",
    state: "ALLOW",
    verdict: "ALLOW",
    reason_codes: [],
    execution: "FORWARDED",
    mode: "ENFORCEMENT",
    authority: "decionis",
    intent_id: intentId,
    intent_hash: "h",
    decision_id: "d-1",
    dossier_id: "dossier-1",
    upstream_status: 204,
    finalization: "COMMITTED",
    latency_ms: 1,
    authority_ms: 1,
    ...overrides,
  };
}

function opened(runs: AcceptanceRuns): string {
  const answer = runs.open(plan);
  expect(answer.status).toBe(201);
  return answer.body["run_id"] as string;
}

afterEach(() => {
  vi.useRealTimers();
});

describe("opening a run", () => {
  it("checks the plan against the gateway's routes and chains the opening", () => {
    const state = fake();
    const runs = new AcceptanceRuns(state.host, () => RUN);
    const answer = runs.open(plan);
    expect(answer).toMatchObject({
      status: 201,
      body: {
        run_id: RUN,
        expires_at: new Date(AT + RUN_TTL_MS).toISOString(),
        fingerprint: state.host.fingerprint.digest,
        writes: [
          { name: "update", kind: "permitted", action: "customers.update" },
          { name: "block", kind: "prohibited", action: "customers.update" },
        ],
      },
    });
    expect(answer.body["plan_digest"]).toMatch(/^sha256:/);
    expect(state.lines[0]).toMatchObject({
      event: "ACCEPTANCE_RUN_OPENED",
      fingerprint: state.host.fingerprint.digest,
    });
    expect(state.lines[0]?.["run_id"]).toMatch(/^[0-9a-f]{32}$/);
    expect(JSON.stringify(state.lines)).not.toContain(RUN);
  });

  it("refuses a plan that does not parse", () => {
    const runs = new AcceptanceRuns(fake().host);
    expect(runs.open({ ...plan, version: "other" })).toMatchObject({
      status: 400,
      body: { code: "ACCEPTANCE_PLAN_INVALID" },
    });
  });

  it("refuses a write the gateway does not decide in enforcement, and a prohibited one it cannot read", () => {
    expect(
      new AcceptanceRuns(
        fake({ route: () => ({ enforced: false, action: null, targetRead: false }) }).host,
      ).open(plan),
    ).toEqual({ status: 422, body: { code: "ACCEPTANCE_WRITE_NOT_ENFORCED", detail: "update" } });
    expect(
      new AcceptanceRuns(
        fake({ route: () => ({ enforced: true, action: "a", targetRead: false }) }).host,
      ).open(plan),
    ).toEqual({ status: 422, body: { code: "ACCEPTANCE_WRITE_NOT_OBSERVABLE", detail: "block" } });
  });

  it("keeps one run open at a time, until it closes or its time is up", () => {
    const state = fake();
    const runs = new AcceptanceRuns(state.host);
    opened(runs);
    expect(runs.open(plan)).toEqual({ status: 409, body: { code: "ACCEPTANCE_RUN_OPEN" } });
    state.now += RUN_TTL_MS - 1;
    expect(runs.open(plan).status).toBe(409);
    state.now += 1;
    expect(runs.open(plan).status).toBe(201);
  });
});

describe("deciding a prohibited write in shadow", () => {
  it("decides a prohibited write the run names, once, and chains it", async () => {
    const decide = vi.fn<(write: unknown) => Promise<ShadowOutcome>>(() =>
      Promise.resolve({
        verdict: "ESCALATE",
        reason_codes: ["REVIEW"],
        decision_id: "d-s",
        dossier_id: null,
      }),
    );
    const state = fake({ decide });
    const runs = new AcceptanceRuns(state.host, () => RUN);
    opened(runs);
    expect(await runs.decide(RUN, "block")).toEqual({
      status: 200,
      body: {
        write: "block",
        verdict: "ESCALATE",
        reason_codes: ["REVIEW"],
        decision_id: "d-s",
        dossier_id: null,
      },
    });
    expect(decide).toHaveBeenCalledWith(plan.prohibited[0]);
    expect(state.lines.at(-1)).toMatchObject({
      event: "ACCEPTANCE_SHADOW_DECIDED",
      write: "block",
      verdict: "ESCALATE",
      decision_id: "d-s",
    });
    expect(await runs.decide(RUN, "block")).toEqual({
      status: 409,
      body: { code: "ACCEPTANCE_WRITE_DECIDED" },
    });
  });

  it("decides nothing else: another run, a permitted write, or a name the plan lacks", async () => {
    const runs = new AcceptanceRuns(fake().host, () => RUN);
    expect(await runs.decide(RUN, "block")).toEqual({
      status: 404,
      body: { code: "ACCEPTANCE_RUN_UNKNOWN" },
    });
    opened(runs);
    expect((await runs.decide("x".repeat(43), "block")).status).toBe(404);
    expect(await runs.decide(RUN, "update")).toEqual({
      status: 404,
      body: { code: "ACCEPTANCE_WRITE_UNKNOWN" },
    });
    expect((await runs.decide(RUN, "missing")).status).toBe(404);
  });
});

describe("admitting a request the run sends", () => {
  it("passes a request with no run header untouched", () => {
    expect(new AcceptanceRuns(fake().host).admit(undefined, request(plan.permitted[0]!))).toEqual({
      kind: "NONE",
    });
  });

  it("tracks a write sent exactly as the plan names it, once", () => {
    const runs = new AcceptanceRuns(fake().host, () => RUN);
    opened(runs);
    expect(runs.admit(`${RUN}:update`, request(plan.permitted[0]!))).toEqual({
      kind: "TRACK",
      name: "update",
    });
    expect(runs.admit(`${RUN}:update`, request(plan.permitted[0]!))).toEqual({
      kind: "REFUSE",
      code: "ACCEPTANCE_WRITE_REPEATED",
    });
  });

  it("refuses an unknown run, a malformed header, and a name the plan lacks", () => {
    const runs = new AcceptanceRuns(fake().host, () => RUN);
    const sent = request(plan.permitted[0]!);
    expect(runs.admit(`${RUN}:update`, sent)).toEqual({
      kind: "REFUSE",
      code: "ACCEPTANCE_RUN_UNKNOWN",
    });
    opened(runs);
    expect(runs.admit(RUN, sent)).toEqual({ kind: "REFUSE", code: "ACCEPTANCE_RUN_UNKNOWN" });
    expect(runs.admit(`other:update`, sent)).toEqual({
      kind: "REFUSE",
      code: "ACCEPTANCE_RUN_UNKNOWN",
    });
    expect(runs.admit(`${RUN}:missing`, sent)).toEqual({
      kind: "REFUSE",
      code: "ACCEPTANCE_WRITE_UNKNOWN",
    });
  });

  it("refuses a write sent other than as named: method, path, query or body", () => {
    const runs = new AcceptanceRuns(fake().host, () => RUN);
    opened(runs);
    const sent = request(plan.permitted[0]!);
    for (const other of [
      { ...sent, method: "PUT" },
      { ...sent, path: "/customers/2" },
      { ...sent, search: "" },
      { ...sent, body: Buffer.from("{}") },
    ]) {
      expect(runs.admit(`${RUN}:update`, other)).toEqual({
        kind: "REFUSE",
        code: "ACCEPTANCE_WRITE_DIFFERS",
      });
    }
  });

  it("sends a prohibited write only after a shadow BLOCK or ESCALATE", async () => {
    for (const verdict of ["ALLOW", null] as const) {
      const runs = new AcceptanceRuns(
        fake({
          decide: () =>
            Promise.resolve({ verdict, reason_codes: [], decision_id: null, dossier_id: null }),
        }).host,
        () => RUN,
      );
      opened(runs);
      const sent = request(plan.prohibited[0]!);
      expect(runs.admit(`${RUN}:block`, sent)).toEqual({
        kind: "REFUSE",
        code: "ACCEPTANCE_SHADOW_REFUSAL_REQUIRED",
      });
      await runs.decide(RUN, "block");
      expect(runs.admit(`${RUN}:block`, sent)).toEqual({
        kind: "REFUSE",
        code: "ACCEPTANCE_SHADOW_REFUSAL_REQUIRED",
      });
    }
    const runs = new AcceptanceRuns(fake().host, () => RUN);
    opened(runs);
    await runs.decide(RUN, "block");
    expect(runs.admit(`${RUN}:block`, request(plan.prohibited[0]!))).toEqual({
      kind: "TRACK",
      name: "block",
    });
  });

  it("admits nothing once the run is closing", async () => {
    let release = (): void => undefined;
    const settled = new Promise<void>((resolve) => {
      release = resolve;
    });
    const runs = new AcceptanceRuns(fake({ settled: () => settled }).host, () => RUN);
    opened(runs);
    const closing = runs.close(RUN, noZone);
    expect(runs.admit(`${RUN}:update`, request(plan.permitted[0]!))).toEqual({
      kind: "REFUSE",
      code: "ACCEPTANCE_RUN_UNKNOWN",
    });
    expect(await runs.close(RUN, noZone)).toEqual({
      status: 404,
      body: { code: "ACCEPTANCE_RUN_UNKNOWN" },
    });
    release();
    expect((await closing).status).toBe(200);
  });
});

describe("closing a run", () => {
  async function ran(state: Fake): Promise<{ runs: AcceptanceRuns; report: AcceptanceReport }> {
    const runs = new AcceptanceRuns(state.host, () => RUN);
    opened(runs);
    await runs.decide(RUN, "block");
    runs.admit(`${RUN}:update`, request(plan.permitted[0]!));
    runs.captured("update", "intent-update");
    runs.intercepted(
      interception("intent-update", { effect: { confirmation: "CONFIRMED", reason_codes: [] } }),
    );
    runs.linked(
      { event: "EFFECT_OBSERVED", intent_id: "intent-update" },
      {
        stream: "g",
        seq: 7,
        hash: `sha256:${"b".repeat(64)}`,
        event: "EFFECT_OBSERVED",
      },
    );
    runs.admit(`${RUN}:block`, request(plan.prohibited[0]!));
    runs.captured("block", "intent-block");
    runs.intercepted(
      interception("intent-block", {
        state: "BLOCK",
        verdict: "BLOCK",
        execution: "NOT_FORWARDED",
        upstream_status: null,
        reason_codes: ["LIMIT"],
      }),
    );
    runs.linked(
      {
        event: "REFUSAL_OBSERVATION",
        intent_id: "intent-block",
        outcome: "UNCHANGED",
        version_before: "v7",
        version_after: "v7",
        read_before_at: "2026-10-31T12:00:00.000Z",
        read_after_at: "2026-10-31T12:00:01.000Z",
      },
      { stream: "g", seq: 8, hash: `sha256:${"c".repeat(64)}`, event: "REFUSAL_OBSERVATION" },
    );
    const answer = await runs.close(RUN, noZone);
    expect(answer).toEqual({ status: 200, body: { report: "signed.1", verdict: "ACCEPTED" } });
    return { runs, report: state.signed[0]! };
  }

  it("assembles what the gateway observed of each write, signs it, and chains its digest", async () => {
    const state = fake();
    const { report } = await ran(state);
    expect(report.permitted[0]).toMatchObject({
      name: "update",
      path: "/customers/1?expand=x",
      action: "customers.update",
      observed_by: "GATEWAY",
      verdict: "ALLOW",
      execution: "FORWARDED",
      upstream_status: 204,
      intent_id: "intent-update",
      effect: { confirmation: "CONFIRMED", reason_codes: [] },
      lines: [{ seq: 7, event: "EFFECT_OBSERVED" }],
      passed: true,
      failure: null,
    });
    expect(report.prohibited[0]).toMatchObject({
      name: "block",
      canary: "customer 9",
      shadow: {
        verdict: "BLOCK",
        reason_codes: ["LIMIT"],
        decision_id: "d-shadow",
        dossier_id: "x",
      },
      sent: true,
      verdict: "BLOCK",
      execution: "NOT_FORWARDED",
      observation: {
        outcome: "UNCHANGED",
        version_before: "v7",
        version_after: "v7",
        read_before_at: "2026-10-31T12:00:00.000Z",
        read_after_at: "2026-10-31T12:00:01.000Z",
      },
      lines: [{ seq: 8, event: "REFUSAL_OBSERVATION" }],
      passed: true,
    });
    expect(
      report.outage.map((item) => [item.name, item.status, item.execution, item.passed]),
    ).toEqual([
      ["update", 503, "NOT_FORWARDED", true],
      ["block", 503, "NOT_FORWARDED", true],
    ]);
    expect(report).toMatchObject({
      boundary_id: "bd_test",
      issued_at: new Date(AT).toISOString(),
      expires_at: "2026-12-31T00:00:00Z",
      fingerprint: { digest: state.host.fingerprint.digest, document },
      verdict: "ACCEPTED",
      failures: [],
      scope: ACCEPTANCE_SCOPE,
    });
    expect(report.stated.map((item) => item.case)).toContain("grants_after_issuance");
    expect(report.run_id).toBe(state.lines[0]?.["run_id"]);
    expect(report.run_id).not.toBe(RUN);
    expect(state.lines.at(-1)).toEqual({
      event: "ACCEPTANCE_SIGNED",
      run_id: report.run_id,
      report_digest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/) as string,
      verdict: "ACCEPTED",
    });
  });

  it("discards the run once closed", async () => {
    const { runs } = await ran(fake());
    expect(await runs.decide(RUN, "block")).toEqual({
      status: 404,
      body: { code: "ACCEPTANCE_RUN_UNKNOWN" },
    });
    expect(runs.open(plan).status).toBe(201);
  });

  it("refuses zone findings that are not findings, and leaves the run open", async () => {
    const runs = new AcceptanceRuns(fake().host, () => RUN);
    opened(runs);
    expect(await runs.close(RUN, { origins: "none" })).toEqual({
      status: 400,
      body: { code: "ACCEPTANCE_ZONE_FINDINGS_INVALID" },
    });
    expect((await runs.close(RUN, noZone)).status).toBe(200);
  });

  it("fails the writes it never sent, and says so", async () => {
    const state = fake();
    const runs = new AcceptanceRuns(state.host, () => RUN);
    opened(runs);
    expect((await runs.close(RUN, noZone)).body["verdict"]).toBe("NOT_ACCEPTED");
    expect(state.signed[0]?.failures).toEqual([
      { case: "permitted", name: "update", code: "NOT_SENT" },
      { case: "prohibited", name: "block", code: "SHADOW_UNDECIDED" },
    ]);
    expect(state.signed[0]?.permitted[0]).toMatchObject({
      execution: null,
      intent_id: null,
      lines: [],
    });
    expect(state.signed[0]?.prohibited[0]).toMatchObject({
      sent: false,
      shadow: { verdict: null, reason_codes: [], decision_id: null, dossier_id: null },
    });
  });

  it("takes the gateway's answer for a write refused before it was captured", async () => {
    const state = fake();
    const runs = new AcceptanceRuns(state.host, () => RUN);
    opened(runs);
    runs.admit(`${RUN}:update`, request(plan.permitted[0]!));
    runs.answered("update", "ERROR", "NOT_FORWARDED");
    runs.answered("missing", "ERROR", "NOT_FORWARDED");
    await runs.close(RUN, noZone);
    expect(state.signed[0]?.permitted[0]).toMatchObject({
      state: "ERROR",
      execution: "NOT_FORWARDED",
      verdict: null,
      passed: false,
      failure: "NOT_DECIDED",
    });
  });

  it("ignores what concerns no tracked write", async () => {
    const state = fake();
    const runs = new AcceptanceRuns(state.host, () => RUN);
    runs.captured("update", "intent-x");
    opened(runs);
    runs.captured("update", "intent-x");
    runs.intercepted(interception("intent-other"));
    runs.intercepted(interception("intent-x"));
    runs.linked(
      { event: "EFFECT_OBSERVED" },
      { stream: "g", seq: 1, hash: `sha256:${"d".repeat(64)}`, event: "E" },
    );
    runs.linked(
      { event: "EFFECT_OBSERVED", intent_id: 7 },
      { stream: "g", seq: 2, hash: `sha256:${"d".repeat(64)}`, event: "E" },
    );
    await runs.close(RUN, noZone);
    expect(state.signed[0]?.permitted[0]).toMatchObject({ execution: null, lines: [] });
  });

  it("keeps at most sixteen lines a write", async () => {
    const state = fake();
    const runs = new AcceptanceRuns(state.host, () => RUN);
    opened(runs);
    runs.admit(`${RUN}:update`, request(plan.permitted[0]!));
    runs.captured("update", "intent-update");
    for (let seq = 1; seq <= 20; seq += 1) {
      runs.linked(
        { event: "E", intent_id: "intent-update" },
        { stream: "g", seq, hash: `sha256:${"e".repeat(64)}`, event: "E" },
      );
    }
    runs.intercepted(interception("intent-update"));
    await runs.close(RUN, noZone);
    expect(state.signed[0]?.permitted[0]?.lines.map((line) => line.seq)).toEqual(
      Array.from({ length: 16 }, (_, index) => index + 1),
    );
  });

  it("waits a bounded time for a report that never comes", async () => {
    vi.useFakeTimers();
    const state = fake();
    const runs = new AcceptanceRuns(state.host, () => RUN);
    opened(runs);
    runs.admit(`${RUN}:update`, request(plan.permitted[0]!));
    runs.captured("update", "intent-update");
    let done = false;
    const closing = runs.close(RUN, noZone).then((answer) => {
      done = true;
      return answer;
    });
    await vi.advanceTimersByTimeAsync(CLOSE_WAIT_MS - 1);
    expect(done).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect((await closing).status).toBe(200);
  });

  it("does not run the outage case on a gateway that fails open", async () => {
    const outage = vi.fn();
    const state = fake({ failurePolicy: "FAIL_OPEN", outage });
    const runs = new AcceptanceRuns(state.host, () => RUN);
    opened(runs);
    await runs.close(RUN, noZone);
    expect(outage).not.toHaveBeenCalled();
    expect(state.signed[0]?.outage[0]).toEqual({
      name: "update",
      method: "PATCH",
      path: "/customers/1?expand=x",
      action: "customers.update",
      observed_by: "GATEWAY",
      skipped: "FAIL_OPEN",
      status: null,
      execution: null,
      reason_codes: [],
      upstream_writes: 0,
      passed: true,
      failure: null,
    });
  });

  it("fails an outage case that wrote upstream", async () => {
    const state = fake({
      outage: () =>
        Promise.resolve({
          status: 503,
          execution: "NOT_FORWARDED",
          reason_codes: [],
          upstreamWrites: 2,
        }),
    });
    const runs = new AcceptanceRuns(state.host, () => RUN);
    opened(runs);
    await runs.close(RUN, noZone);
    expect(state.signed[0]?.outage[0]).toMatchObject({
      upstream_writes: 2,
      passed: false,
      failure: "UPSTREAM_WRITTEN",
    });
  });

  it("refuses to close another run, and discards an open run once its time is up", async () => {
    const state = fake();
    const runs = new AcceptanceRuns(state.host, () => RUN);
    opened(runs);
    expect((await runs.close("y".repeat(43), noZone)).status).toBe(404);
    state.now += RUN_TTL_MS;
    expect((await runs.close(RUN, noZone)).status).toBe(404);
  });
});

describe("a write's target", () => {
  it("is compared as the listener parses it, percent-encoding included", () => {
    const encoded = {
      ...plan,
      permitted: [{ name: "spaced", method: "POST", path: "/notes/ä?q=ü" }],
      prohibited: [],
    };
    const runs = new AcceptanceRuns(fake().host, () => RUN);
    expect(runs.open(encoded).status).toBe(201);
    expect(
      runs.admit(`${RUN}:spaced`, {
        method: "POST",
        path: "/notes/%C3%A4",
        search: "?q=%C3%BC",
        body: Buffer.alloc(0),
      }),
    ).toEqual({ kind: "TRACK", name: "spaced" });
  });
});

describe("what the run keeps, and for how long", () => {
  it("stays open for fifteen minutes", () => {
    const state = fake();
    const runs = new AcceptanceRuns(state.host, () => RUN);
    opened(runs);
    state.now += 900_000 - 1;
    expect(runs.open(plan).status).toBe(409);
  });

  it("answers a refusal with its code alone when there is nothing more to say", async () => {
    expect(await new AcceptanceRuns(fake().host).decide(RUN, "block")).toStrictEqual({
      status: 404,
      body: { code: "ACCEPTANCE_RUN_UNKNOWN" },
    });
  });

  it("forgets a run's intents once it closes or its time is up", async () => {
    for (const end of ["close", "expire"] as const) {
      const state = fake();
      const runs = new AcceptanceRuns(state.host, () => RUN);
      opened(runs);
      runs.admit(`${RUN}:update`, request(plan.permitted[0]!));
      runs.captured("update", "intent-old");
      runs.intercepted(interception("intent-old"));
      if (end === "close") await runs.close(RUN, noZone);
      else state.now += RUN_TTL_MS;
      opened(runs);
      runs.admit(`${RUN}:update`, request(plan.permitted[0]!));
      runs.intercepted(interception("intent-old"));
      runs.answered("update", "ERROR", "NOT_FORWARDED");
      await runs.close(RUN, noZone);
      expect(state.signed.at(-1)?.permitted[0]).toMatchObject({ verdict: null, intent_id: null });
    }
  });

  it("refuses a header that is the run's id with no write named", () => {
    const runs = new AcceptanceRuns(fake().host, () => RUN);
    opened(runs);
    expect(runs.admit(`${RUN}x`, request(plan.permitted[0]!))).toEqual({
      kind: "REFUSE",
      code: "ACCEPTANCE_RUN_UNKNOWN",
    });
  });

  it("sends a prohibited write after a shadow ESCALATE", async () => {
    const runs = new AcceptanceRuns(
      fake({
        decide: () =>
          Promise.resolve({
            verdict: "ESCALATE",
            reason_codes: [],
            decision_id: null,
            dossier_id: null,
          }),
      }).host,
      () => RUN,
    );
    opened(runs);
    await runs.decide(RUN, "block");
    expect(runs.admit(`${RUN}:block`, request(plan.prohibited[0]!))).toEqual({
      kind: "TRACK",
      name: "block",
    });
  });

  it("takes an answer or a capture with no run open as nothing", () => {
    const runs = new AcceptanceRuns(fake().host, () => RUN);
    expect(() => {
      runs.answered("update", "ERROR", "NOT_FORWARDED");
      runs.captured("update", "intent-x");
      runs.intercepted(interception("intent-x"));
      runs.linked(
        { event: "EFFECT_OBSERVED", intent_id: "intent-x" },
        { stream: "g", seq: 1, hash: `sha256:${"a".repeat(64)}`, event: "EFFECT_OBSERVED" },
      );
    }).not.toThrow();
  });

  it("waits for the report of a write it captured, even once the gateway has answered", async () => {
    vi.useFakeTimers();
    const runs = new AcceptanceRuns(fake().host, () => RUN);
    opened(runs);
    runs.admit(`${RUN}:update`, request(plan.permitted[0]!));
    runs.captured("update", "intent-update");
    runs.answered("update", "ALLOW", "FORWARDED");
    let done = false;
    const closing = runs.close(RUN, noZone).then(() => {
      done = true;
    });
    await vi.advanceTimersByTimeAsync(CLOSE_WAIT_MS - 1);
    expect(done).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await closing;
  });

  it("reads a target observation only from a refusal observation, and a missing field as null", async () => {
    const state = fake();
    const runs = new AcceptanceRuns(state.host, () => RUN);
    opened(runs);
    await runs.decide(RUN, "block");
    runs.admit(`${RUN}:block`, request(plan.prohibited[0]!));
    runs.captured("block", "intent-block");
    runs.intercepted(
      interception("intent-block", { state: "ESCALATE", verdict: "ESCALATE", execution: "HELD" }),
    );
    runs.linked(
      { event: "ESCALATION_HELD", intent_id: "intent-block", outcome: "UNCHANGED" },
      { stream: "g", seq: 1, hash: `sha256:${"f".repeat(64)}`, event: "ESCALATION_HELD" },
    );
    await runs.close(RUN, noZone);
    expect(state.signed[0]?.prohibited[0]).toMatchObject({
      observation: null,
      passed: false,
      failure: "TARGET_NOT_OBSERVED",
    });

    opened(runs);
    await runs.decide(RUN, "block");
    runs.admit(`${RUN}:block`, request(plan.prohibited[0]!));
    runs.captured("block", "intent-two");
    runs.intercepted(interception("intent-two", { verdict: "BLOCK", execution: "NOT_FORWARDED" }));
    runs.linked(
      {
        event: "REFUSAL_OBSERVATION",
        intent_id: "intent-two",
        outcome: "UNREADABLE",
        version_before: "v1",
      },
      { stream: "g", seq: 2, hash: `sha256:${"f".repeat(64)}`, event: "REFUSAL_OBSERVATION" },
    );
    await runs.close(RUN, noZone);
    expect(state.signed[1]?.prohibited[0]?.observation).toStrictEqual({
      outcome: "UNREADABLE",
      version_before: "v1",
      version_after: null,
      read_before_at: null,
      read_after_at: null,
    });
  });

  it("signs no report a verifier would refuse", async () => {
    const state = fake({ boundaryId: "" });
    const runs = new AcceptanceRuns(state.host, () => RUN);
    opened(runs);
    expect(await runs.close(RUN, noZone)).toEqual({
      status: 500,
      body: { code: "ACCEPTANCE_REPORT_INVALID" },
    });
    expect(state.signed).toEqual([]);
    expect(state.lines.map((line) => line["event"])).not.toContain("ACCEPTANCE_SIGNED");
  });

  it("carries every reason the gateway gave, and fails a refused write it never sent", async () => {
    const state = fake();
    const runs = new AcceptanceRuns(state.host, () => RUN);
    opened(runs);
    await runs.decide(RUN, "block");
    runs.admit(`${RUN}:update`, request(plan.permitted[0]!));
    runs.captured("update", "intent-update");
    runs.intercepted(
      interception("intent-update", {
        reason_codes: ["WITHIN_LIMIT"],
        effect: { confirmation: "PENDING", reason_codes: ["EFFECT_NOT_READ"] },
      }),
    );
    await runs.close(RUN, noZone);
    const signed = state.signed[0]!;
    expect(signed.permitted[0]).toMatchObject({
      reason_codes: ["WITHIN_LIMIT"],
      effect: { confirmation: "PENDING", reason_codes: ["EFFECT_NOT_READ"] },
    });
    expect(signed.prohibited[0]).toMatchObject({
      shadow: { verdict: "BLOCK" },
      sent: false,
      reason_codes: [],
      passed: false,
      failure: "NOT_SENT",
    });
    expect(signed.outage[0]?.reason_codes).toEqual(["AUTHORITY_UNAVAILABLE"]);
  });
});

describe("a run closing past its time", () => {
  it("stays the open run until its close finishes, then frees the gateway for the next", async () => {
    let release = (): void => undefined;
    const settled = new Promise<void>((resolve) => {
      release = resolve;
    });
    const state = fake({ settled: () => settled });
    const runs = new AcceptanceRuns(state.host, () => RUN);
    opened(runs);
    const closing = runs.close(RUN, noZone);
    state.now += RUN_TTL_MS;
    expect(runs.open(plan)).toEqual({ status: 409, body: { code: "ACCEPTANCE_RUN_OPEN" } });
    release();
    expect((await closing).status).toBe(200);
    expect(runs.open(plan).status).toBe(201);
  });
});
