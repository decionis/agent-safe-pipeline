import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { HaltSwitch, type HaltSwitchOptions } from "../../src/incident/HaltSwitch.js";
import { collectedEvents } from "../support/Environment.js";

const root = mkdtempSync(join(tmpdir(), "agentsafe-halt-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

interface Built {
  readonly halt: HaltSwitch;
  readonly lines: string[];
  tick(ms: number): void;
}

function build(options: Partial<HaltSwitchOptions> = {}): Built {
  let now = Date.parse("2026-09-15T10:00:00.000Z");
  const lines: string[] = [];
  const halt = new HaltSwitch({
    events: collectedEvents(lines),
    clock: () => new Date(now),
    ...options,
  });
  return {
    halt,
    lines,
    tick: (ms) => {
      now += ms;
    },
  };
}

const events = (lines: string[]): Record<string, unknown>[] =>
  lines.map((line) => JSON.parse(line) as Record<string, unknown>);

describe("HaltSwitch", () => {
  it("starts open, halts once with a reason, and says so", () => {
    const { halt, lines } = build();
    expect(halt.halted).toBe(false);
    expect(halt.current).toEqual({ halted: false, trigger: null, reason: null, since: null });
    const state = halt.halt("OPERATOR", "treasury asked us to stop");
    expect(state).toEqual({
      halted: true,
      trigger: "OPERATOR",
      reason: "treasury asked us to stop",
      since: "2026-09-15T10:00:00.000Z",
    });
    expect(halt.halted).toBe(true);
    // A second halt does not overwrite the first: the reason people act on is
    // the one that stopped it.
    expect(halt.halt("POSTURE_DRIFT", "check PROXY_ENV").trigger).toBe("OPERATOR");
    expect(events(lines)).toEqual([
      expect.objectContaining({
        event: "HALTED",
        trigger: "OPERATOR",
        reason: "treasury asked us to stop",
      }),
    ]);
    expect(build().halt.halt("OPERATOR", "x".repeat(400)).reason).toHaveLength(200);
  });

  it("resumes only with a reason, and refuses while the cause still stands", () => {
    const { halt, lines } = build({ posture: { degraded: true } });
    expect(halt.resume("nothing to resume")).toEqual({ resumed: false, code: "NOT_HALTED" });
    halt.halt("POSTURE_DRIFT", "check PROXY_ENV");
    expect(halt.resume("the proxy is gone")).toEqual({
      resumed: false,
      code: "HALT_CAUSE_PERSISTS",
    });
    expect(halt.halted).toBe(true);
    const recovered = build();
    recovered.halt.halt("AUTH_FAILURE_SPIKE", "50 in 60s");
    expect(recovered.halt.resume("the agent's token was rotated")).toEqual({
      resumed: true,
      code: null,
    });
    expect(recovered.halt.halted).toBe(false);
    expect(events(recovered.lines).at(-1)).toMatchObject({
      event: "RESUMED",
      trigger: "AUTH_FAILURE_SPIKE",
      reason: "the agent's token was rotated",
    });
    expect(events(lines).filter((event) => event["event"] === "RESUMED")).toEqual([]);
  });

  it("halts on a spike of refusals at the door and of refused outbound requests", () => {
    const { halt, lines } = build({
      authFailures: { count: 3, windowSeconds: 60 },
      egressRefusals: { count: 2, windowSeconds: 60 },
    });
    halt.recordAuthFailure();
    halt.recordAuthFailure();
    expect(halt.halted).toBe(false);
    // `3/60` reads as three in a minute, so the third refusal stops it.
    halt.recordAuthFailure();
    expect(halt.current).toMatchObject({ trigger: "AUTH_FAILURE_SPIKE", reason: "3 in 60s" });
    // Already halted: nothing else is counted, and nothing else is said.
    halt.recordEgressRefusal();
    halt.recordEgressRefusal();
    halt.recordEgressRefusal();
    expect(events(lines)).toHaveLength(1);
    const egress = build({ egressRefusals: { count: 2, windowSeconds: 60 } });
    egress.halt.recordEgressRefusal();
    egress.tick(60_001);
    // The window moved on, so the earlier refusal no longer counts toward it.
    egress.halt.recordEgressRefusal();
    expect(egress.halt.halted).toBe(false);
    egress.halt.recordEgressRefusal();
    expect(egress.halt.current).toMatchObject({ trigger: "EGRESS_REFUSAL_SPIKE" });
  });

  it("never halts on a spike it was not configured to watch", () => {
    const { halt } = build();
    for (let attempt = 0; attempt < 500; attempt += 1) {
      halt.recordAuthFailure();
      halt.recordEgressRefusal();
    }
    expect(halt.halted).toBe(false);
  });

  it("starts halted when the halt file is there, and cannot resume until it is gone", () => {
    const file = join(root, "halted");
    writeFileSync(file, "stopped by the on-call operator\n");
    const { halt, lines } = build({ haltFile: file });
    expect(halt.assertAtStartup()).toMatchObject({ halted: true, trigger: "HALT_FILE" });
    expect(halt.resume("I would like it back")).toEqual({
      resumed: false,
      code: "HALT_CAUSE_PERSISTS",
    });
    rmSync(file);
    expect(halt.resume("the file is gone").resumed).toBe(true);
    expect(events(lines).map((event) => event["event"])).toEqual(["HALTED", "RESUMED"]);
    const open = build({ haltFile: join(root, "never-written") });
    expect(open.halt.assertAtStartup().halted).toBe(false);
    expect(build().halt.assertAtStartup().halted).toBe(false);
  });

  it("halts while running when the halt file appears, and stops watching when told", async () => {
    const file = join(root, "appears");
    const { halt, lines } = build({ haltFile: file, pollSeconds: 1 });
    const stop = halt.start();
    halt.start();
    expect(halt.halted).toBe(false);
    writeFileSync(file, "stop\n");
    await new Promise((resolve) => setTimeout(resolve, 60));
    halt.check();
    expect(halt.current).toMatchObject({ halted: true, trigger: "HALT_FILE" });
    halt.check();
    expect(events(lines)).toHaveLength(1);
    stop();
    stop();
    rmSync(file);
    // A directory in place of a file is not a halt file.
    const notAFile = build({ haltFile: root });
    expect(notAFile.halt.assertAtStartup().halted).toBe(false);
  });

  it("reads the file through whatever the process was given, so a test needs no filesystem", () => {
    let present = true;
    const { halt } = build({ haltFile: "/var/run/agent-safe/halt", fileExists: () => present });
    expect(halt.assertAtStartup().halted).toBe(true);
    expect(halt.resume("try").code).toBe("HALT_CAUSE_PERSISTS");
    present = false;
    expect(halt.resume("the flag was removed").resumed).toBe(true);
    const watching = build({ haltFile: "/var/run/agent-safe/halt", fileExists: () => present });
    const stop = watching.halt.start();
    present = true;
    watching.halt.check();
    expect(watching.halt.halted).toBe(true);
    stop();
  });
});
