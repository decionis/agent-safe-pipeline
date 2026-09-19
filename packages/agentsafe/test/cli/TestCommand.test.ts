import { describe, expect, it } from "vitest";
import { CONTAINMENT_STREAM } from "../../src/containment/ContainmentProbe.js";
import { renderTestReport, runTest, type TestReport } from "../../src/cli/TestCommand.js";
import type {
  BoundaryCaseResult,
  BoundaryTestReport,
  PassOutcome,
} from "../../src/gateway/BoundaryTest.js";
import { fakeProcess } from "../support/GatewayHarness.js";

const ESC = String.fromCharCode(27);

const reached = (status: number, extra: Partial<PassOutcome> = {}): PassOutcome => ({
  reached: true,
  forwarded: 1,
  status,
  state: null,
  verdict: null,
  execution: null,
  dossier: false,
  forgedHeadersReached: false,
  ...extra,
});

const stopped = (status: number, extra: Partial<PassOutcome> = {}): PassOutcome => ({
  reached: false,
  forwarded: 0,
  status,
  state: "BLOCK",
  verdict: "BLOCK",
  execution: "NOT_FORWARDED",
  dossier: false,
  forgedHeadersReached: false,
  ...extra,
});

const result = (
  id: string,
  adversarial: boolean,
  enforcement: PassOutcome,
  extra: Partial<BoundaryCaseResult> = {},
): BoundaryCaseResult => ({
  id,
  title: `Case ${id}`,
  adversarial,
  request: { method: "POST", path: "/payments", body: "{}", outage: false },
  direct: reached(201),
  shadow: reached(201, { state: "SHADOW", verdict: adversarial ? "BLOCK" : "ALLOW" }),
  enforcement,
  failOpen: null,
  ...extra,
});

const tested = { milestone: "boundary_tested", at: "2026-01-01T00:00:00.000Z" } as const;

const holding: BoundaryTestReport = {
  version: "agent-safe.boundary-test/1",
  at: "2026-01-01T00:00:00.000Z",
  runtime: "1.2.3",
  authority: "local/demo",
  target: "synthetic loopback",
  cases: [
    result("read", false, reached(200), {
      request: { method: "GET", path: "/accounts/42", body: null, outage: false },
      shadow: reached(200),
    }),
    result(
      "routine",
      false,
      reached(201, { state: "ALLOW", verdict: "ALLOW", execution: "FORWARDED", dossier: true }),
    ),
    result("large", true, stopped(403), { direct: reached(201, { forgedHeadersReached: true }) }),
    result(
      "held",
      true,
      stopped(202, { state: "ESCALATE", verdict: "ESCALATE", execution: "HELD" }),
      { shadow: reached(201, { state: "SHADOW", verdict: "ESCALATE" }) },
    ),
    result("outage", true, stopped(503, { state: "AUTHORITY_UNAVAILABLE", verdict: null }), {
      request: { method: "POST", path: "/payments", body: "{}", outage: true },
      shadow: reached(201, { state: "SHADOW", verdict: null }),
      failOpen: reached(201, {
        state: "AUTHORITY_UNAVAILABLE",
        execution: "FORWARDED_UNGOVERNED",
      }),
    }),
  ],
  exposure: { adversarial: 3, direct: 3, shadow: 3, enforcement: 0 },
  workFlowed: true,
  evidence: { lines: 12, verified: true },
  verdict: "BOUNDARY_HOLDS",
};

const run = (report: BoundaryTestReport) => () => Promise.resolve(report);

describe("agentsafe test", () => {
  it("prints the report, exits 0 when the boundary holds, and says what comes next", async () => {
    const io = fakeProcess();
    const report = await runTest(io, [], { run: run(holding) });
    expect(report?.exit).toBe(0);
    expect(io.exits).toEqual([0]);
    const text = io.out.join("");
    expect(text).toContain("AgentSafe 1.2.3 boundary test");
    expect(text).toContain("nothing real is called");
    expect(text).toContain("reached 200 (not consequential)");
    expect(text).toContain("ALLOW: forwarded once, 201, dossier");
    expect(text).toContain("reached 201, forged headers accepted");
    expect(text).toContain("BLOCK 403, NOT FORWARDED");
    expect(text).toContain("ESCALATE 202, HELD");
    expect(text).toContain("would decide nothing (authority unreachable)");
    expect(text).toContain("AUTHORITY UNAVAILABLE 503, NOT FORWARDED");
    expect(text).toContain(
      "with failurePolicy failOpen (explicit): reached 201, marked FORWARDED (fail-open, ungoverned)",
    );
    expect(text).toContain(
      "3 of 3 adversarial actions reached the target directly, 3 of 3 in shadow, 0 of 3 under enforcement",
    );
    expect(text).toContain("routine actions went through under enforcement, once each");
    expect(text).toContain("12 chained lines, verified");
    expect(text).toContain("Verdict     BOUNDARY HOLDS\n");
    expect(text).toContain("Next: agentsafe proxy --upstream <your service> --mode shadow");
    // The sentence the table demonstrates, and the step of the path the run is.
    expect(text).toContain("Caller      the same on every row, and never the reason");
    expect(text.trimEnd().endsWith("✓ boundary tested")).toBe(true);
    expect(text).not.toContain(ESC);
    expect(text).not.toContain("Target      Case");
  });

  it("prints one JSON line when asked, with the exit status inside it", async () => {
    const io = fakeProcess();
    await runTest(io, ["--json"], { run: run(holding) });
    expect(io.out).toHaveLength(1);
    const parsed = JSON.parse(io.out[0] ?? "") as TestReport;
    expect(parsed.version).toBe("agent-safe.boundary-test/1");
    expect(parsed.verdict).toBe("BOUNDARY_HOLDS");
    expect(parsed.containment).toBeNull();
    expect(parsed.exit).toBe(0);
    expect(parsed.cases).toHaveLength(5);
    expect(parsed.activation).toEqual({ milestone: "boundary_tested", at: holding.at });
    expect(io.out[0]?.endsWith("\n")).toBe(true);
    expect(io.out[0]?.slice(0, -1)).not.toContain("\n");
  });

  it("dials each named target, and a target that answers is exit 1 even when the boundary holds", async () => {
    const dialed: string[] = [];
    const io = fakeProcess();
    const report = await runTest(
      io,
      ["ledger=ledger.example:443", "vault=vault.example:8200", "--json"],
      {
        run: run(holding),
        timeoutMs: 50,
        dial: (host, port) => {
          dialed.push(`${host}:${String(port)}`);
          return Promise.resolve(
            host === "ledger.example" ? { state: "CONNECTED" } : { state: "TIMED_OUT" },
          );
        },
      },
    );
    expect(dialed).toEqual(["ledger.example:443", "vault.example:8200"]);
    expect(
      report?.containment?.findings.map((finding) => [finding.target, finding.verdict]),
    ).toEqual([
      ["ledger", "REACHABLE"],
      ["vault", "CONTAINED"],
    ]);
    expect(report?.containment?.findings[0]?.stream).toBe(CONTAINMENT_STREAM);
    expect(report?.exit).toBe(1);
    expect(io.exits).toEqual([1]);
    const human = fakeProcess();
    await runTest(human, ["ledger=ledger.example:443"], {
      run: run(holding),
      timeoutMs: 50,
      dial: () => Promise.resolve({ state: "REFUSED" }),
    });
    const text = human.out.join("");
    expect(text).toContain(
      "Target      ledger ledger.example:443: REACHABLE without the gateway; an agent here can go around it",
    );
    expect(text).toContain("Verdict     BOUNDARY HOLDS, BUT A TARGET ANSWERS DIRECTLY");
    expect(text).toContain("Put the gateway where the agent must pass through it");
  });

  it("calls a broken boundary what it is, exits 1, and asks for the JSON", async () => {
    const broken: BoundaryTestReport = {
      ...holding,
      cases: [
        result(
          "through",
          true,
          reached(201, { state: "ALLOW", verdict: "ALLOW", execution: "FORWARDED" }),
        ),
        result("twice", false, reached(201, { forwarded: 2, state: "ALLOW", verdict: "ALLOW" })),
      ],
      exposure: { adversarial: 1, direct: 1, shadow: 1, enforcement: 1 },
      workFlowed: false,
      evidence: { lines: 3, verified: false },
      verdict: "BOUNDARY_BROKEN",
    };
    const io = fakeProcess();
    const report = await runTest(io, [], { run: run(broken) });
    expect(report?.exit).toBe(1);
    expect(io.exits).toEqual([1]);
    const text = io.out.join("");
    expect(text).toContain("ALLOW: forwarded 2x, 201");
    expect(text).toContain("a routine action did not go through under enforcement");
    expect(text).toContain("3 chained lines, NOT verified");
    expect(text).toContain("BOUNDARY BROKEN: something adversarial got through under enforcement");
    expect(text).toContain("This is a defect in the runtime, not in your service");
  });

  it("colors the terminal rendering when the process has color", () => {
    const colored = renderTestReport(
      { ...holding, containment: null, exit: 0, activation: tested },
      { color: true },
    );
    expect(colored).toContain(`${ESC}[32m`);
    expect(colored).toContain(`${ESC}[33m`);
    expect(colored).toContain(`${ESC}[2m`);
    const through = renderTestReport(
      {
        ...holding,
        cases: [result("through", true, reached(201, { state: "ALLOW", verdict: "ALLOW" }))],
        exposure: { adversarial: 1, direct: 1, shadow: 1, enforcement: 1 },
        verdict: "BOUNDARY_BROKEN",
        containment: null,
        exit: 1,
        activation: tested,
      },
      { color: true },
    );
    expect(through).toContain(`${ESC}[31m`);
    const failed = renderTestReport(
      {
        ...holding,
        cases: [
          result(
            "silent",
            true,
            stopped(null as unknown as number, { status: null, execution: null }),
            {
              failOpen: reached(201, { execution: null }),
            },
          ),
        ],
        containment: null,
        exit: 0,
        activation: tested,
      },
      { color: true },
    );
    expect(failed).toContain("BLOCK no answer");
    expect(failed).toContain("marked nothing");
  });

  it("explains a run the synthetic authority refused, and exits 2", async () => {
    const refused = (): Promise<BoundaryTestReport> =>
      Promise.reject(new Error("LOCAL_DOUBLE_FORBIDDEN"));
    const human = fakeProcess();
    expect(await runTest(human, [], { run: refused })).toBeNull();
    expect(human.err.join("")).toContain("AgentSafe did not run the boundary test.");
    expect(human.err.join("")).toContain(
      "LOCAL_DOUBLE_FORBIDDEN: the synthetic authority is refused where NODE_ENV=production",
    );
    expect(human.out).toEqual([]);
    expect(human.exits).toEqual([2]);
    const json = fakeProcess();
    await runTest(json, ["--json"], { run: () => Promise.reject(new Error("PORT_EXHAUSTED")) });
    expect(json.err).toEqual([
      `${JSON.stringify({ event: "TEST_REFUSED", reason: "PORT_EXHAUSTED" })}\n`,
    ]);
    expect(json.exits).toEqual([2]);
    const bare = fakeProcess();
    await runTest(bare, [], { run: () => Promise.reject("boom") });
    expect(bare.err.join("")).toContain("TEST_FAILED");
  });

  it("refuses an unknown option or a malformed target with exit 2 and runs nothing", async () => {
    let ran = 0;
    const count = (): Promise<BoundaryTestReport> => {
      ran += 1;
      return Promise.resolve(holding);
    };
    const option = fakeProcess();
    expect(await runTest(option, ["--bogus"], { run: count })).toBeNull();
    expect(option.err).toEqual(["UNKNOWN_OPTION: bogus\n"]);
    expect(option.exits).toEqual([2]);
    const target = fakeProcess();
    expect(await runTest(target, ["ledger=nowhere"], { run: count })).toBeNull();
    expect(target.err).toEqual(["CONTAINMENT_TARGET_INVALID: ledger=nowhere\n"]);
    expect(target.exits).toEqual([2]);
    expect(ran).toBe(0);
  });
});
