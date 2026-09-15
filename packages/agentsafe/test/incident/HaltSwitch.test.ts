import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FSWatcher } from "node:fs";
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

/** A watcher a test owns: it emits when the test says so, and closes once. */
function fakeWatcher(listeners: Record<string, () => void>): FSWatcher {
  return {
    on: (event: string, listener: () => void) => {
      listeners[event] = listener;
      return undefined as unknown as FSWatcher;
    },
    close: () => undefined,
  } as unknown as FSWatcher;
}

/** Waits for the switch to notice something by itself, rather than being told. */
async function waitFor(condition: () => boolean, withinMs = 2_000): Promise<void> {
  const deadline = Date.now() + withinMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("the switch never noticed");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

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

  it("follows the halt file's own directory, and not the file", () => {
    const watched: string[] = [];
    const listeners: Record<string, () => void> = {};
    const present = { value: false };
    const { halt } = build({
      haltFile: "/var/run/agent-safe/halt/halted",
      fileExists: () => present.value,
      watchDirectory: (path, onChange) => {
        watched.push(path);
        listeners["change"] = onChange;
        return fakeWatcher(listeners);
      },
    });
    const stop = halt.start();
    expect(halt.following).toBe(true);
    // A file's own inode cannot be watched across the symlink swap a secret
    // or ConfigMap mount performs, so the directory is what is followed.
    expect(watched).toEqual(["/var/run/agent-safe/halt"]);
    present.value = true;
    listeners["change"]?.();
    expect(halt.current).toMatchObject({ halted: true, trigger: "HALT_FILE" });
    stop();
  });

  it("survives a watcher that errors, and one that cannot be created at all", async () => {
    const listeners: Record<string, () => void> = {};
    const present = { value: false };
    const erroring = build({
      haltFile: "/var/run/agent-safe/halt/halted",
      fileExists: () => present.value,
      pollSeconds: 0.02,
      watchDirectory: (_path, onChange) => {
        listeners["change"] = onChange;
        return fakeWatcher(listeners);
      },
    });
    const stopErroring = erroring.halt.start();
    // The error listener is registered under that name, so an `EPERM` from
    // the mount reaches something rather than becoming an unhandled event.
    expect(Object.keys(listeners).sort()).toEqual(["change", "error"]);
    // An error from the watcher is not a crash and not a halt: the poll is
    // still the thing that has to work.
    listeners["error"]?.();
    expect(erroring.halt.halted).toBe(false);
    present.value = true;
    await waitFor(() => erroring.halt.halted);
    stopErroring();

    const unwatchable = { value: false };
    const refused = build({
      haltFile: "/var/run/agent-safe/halt/halted",
      fileExists: () => unwatchable.value,
      pollSeconds: 0.02,
      watchDirectory: () => {
        throw new Error("ENOSPC");
      },
    });
    const stopRefused = refused.halt.start();
    unwatchable.value = true;
    await waitFor(() => refused.halt.halted);
    stopRefused();
  });

  it("follows nothing when there is no file to follow", () => {
    const asked: string[] = [];
    const { halt } = build({
      fileExists: (path) => {
        asked.push(path);
        return true;
      },
      watchDirectory: () => {
        throw new Error("should not be watched");
      },
    });
    // No halt file means no watcher, no poll, and the file check never asked
    // about a path that does not exist.
    const stop = halt.start();
    expect(halt.following).toBe(false);
    expect(halt.halted).toBe(false);
    expect(halt.assertAtStartup().halted).toBe(false);
    halt.check();
    expect(asked).toEqual([]);
    stop();
  });

  it("waits the interval it was given, and five seconds when it was given none", async () => {
    const present = { value: true };
    const { halt } = build({
      haltFile: "/var/run/agent-safe/halt/halted",
      fileExists: () => present.value,
      watchDirectory: (_path, onChange) => fakeWatcher({ change: onChange }),
    });
    const stop = halt.start();
    // The default is five seconds, so nothing has happened yet a moment in.
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(halt.halted).toBe(false);
    stop();
  });

  it("follows a real directory when it was given no substitute for one", () => {
    // No injected watcher: this is the default follower, on a real
    // directory. Whether the platform then delivers an event within a test's
    // patience is the platform's business, and the poll is what the stop
    // actually depends on, so this asserts only that the switch is following
    // and that letting go of it is clean.
    const directory = mkdtempSync(join(root, "watched-"));
    const { halt } = build({ haltFile: join(directory, "halted"), pollSeconds: 600 });
    const stop = halt.start();
    expect(halt.following).toBe(true);
    expect(halt.halted).toBe(false);
    stop();
    expect(halt.following).toBe(false);
    rmSync(directory, { recursive: true, force: true });
  });

  it("checks the file only while it is open, and refuses a path that is not a file", async () => {
    const { halt } = build({ haltFile: join(root, "never-created") });
    // The real check, with no injected filesystem: a path that does not
    // exist is not a halt file, and neither is a directory.
    expect(halt.assertAtStartup().halted).toBe(false);
    expect(build({ haltFile: root }).halt.assertAtStartup().halted).toBe(false);
    const file = join(root, "real");
    writeFileSync(file, "stop\n");
    expect(build({ haltFile: file }).halt.assertAtStartup().halted).toBe(true);
    // A path whose parent is a regular file cannot be stated at all, and is
    // not a halt file either: the look must answer rather than throw, because
    // it also runs inside the poll's own callback.
    const throughAFile = join(file, "halted");
    expect(build({ haltFile: throughAFile }).halt.assertAtStartup().halted).toBe(false);
    const following = build({ haltFile: throughAFile, pollSeconds: 0.02 });
    const stop = following.halt.start();
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(following.halt.halted).toBe(false);
    stop();
    rmSync(file);
  });

  it("checks once per look, and a look with the file gone changes nothing", () => {
    const present = { value: false };
    const { halt, lines } = build({
      haltFile: "/var/run/agent-safe/halt/halted",
      fileExists: () => present.value,
    });
    halt.check();
    halt.check();
    expect(halt.halted).toBe(false);
    expect(events(lines)).toHaveLength(0);
    present.value = true;
    halt.check();
    halt.check();
    expect(events(lines)).toHaveLength(1);
  });

  it("notices the file on its own, without anyone calling the check", async () => {
    // The watcher is the fast path; the poll is the one that has to work. So
    // this waits for the interval rather than calling `check()`, which is
    // what a mount reporting no events looks like.
    const file = join(root, "polled");
    const { halt, lines } = build({
      haltFile: "/var/run/agent-safe/halt",
      fileExists: () => existsSync(file),
      pollSeconds: 0.02,
    });
    const stop = halt.start();
    expect(halt.halted).toBe(false);
    writeFileSync(file, "stop\n");
    await waitFor(() => halt.halted);
    expect(halt.current.trigger).toBe("HALT_FILE");
    expect(events(lines)).toHaveLength(1);
    stop();
    rmSync(file);
  });

  it("stops following the file when told, and does not follow it twice", async () => {
    const present = { value: false };
    const { halt } = build({
      haltFile: "/var/run/agent-safe/halt",
      fileExists: () => present.value,
      pollSeconds: 0.02,
    });
    // Two starts leave one follower: the second replaces the first rather
    // than adding to it, so stopping once stops everything.
    halt.start();
    const stop = halt.start();
    expect(halt.following).toBe(true);
    stop();
    expect(halt.following).toBe(false);
    present.value = true;
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(halt.halted).toBe(false);
    // And after a stop, starting again follows it as before.
    const again = halt.start();
    await waitFor(() => halt.halted);
    again();
  });

  it("follows the file even where the directory cannot be watched at all", async () => {
    const present = { value: false };
    const { halt } = build({
      // A directory that does not exist: `fs.watch` throws, and the poll is
      // what keeps the stop reachable.
      haltFile: join(root, "no-such-directory", "halted"),
      fileExists: () => present.value,
      pollSeconds: 0.02,
    });
    const stop = halt.start();
    present.value = true;
    await waitFor(() => halt.halted);
    expect(halt.current.trigger).toBe("HALT_FILE");
    stop();
  });

  it("holds nothing open: a switch with no file to follow starts and stops cleanly", () => {
    const { halt } = build();
    const stop = halt.start();
    expect(halt.halted).toBe(false);
    stop();
    stop();
    halt.stop();
    expect(halt.halted).toBe(false);
  });

  it("counts each kind of refusal in its own window", () => {
    const { halt } = build({
      authFailures: { count: 2, windowSeconds: 60 },
      egressRefusals: { count: 2, windowSeconds: 60 },
    });
    // One of each is not two of either: the windows must not share a key.
    halt.recordAuthFailure();
    halt.recordEgressRefusal();
    expect(halt.halted).toBe(false);
    halt.recordAuthFailure();
    expect(halt.current).toMatchObject({ halted: true, trigger: "AUTH_FAILURE_SPIKE" });
  });

  it("bounds the words an operator gives it, on the way in and on the way out", () => {
    const { halt, lines } = build();
    halt.halt("OPERATOR", "h".repeat(400));
    expect(halt.current.reason?.length).toBe(200);
    const resumed = build();
    resumed.halt.halt("OPERATOR", "stopping");
    resumed.halt.resume("r".repeat(400));
    const event = events(resumed.lines).at(-1);
    expect(event).toMatchObject({ event: "RESUMED", trigger: "OPERATOR" });
    expect(String(event?.["reason"]).length).toBe(200);
    expect(events(lines)[0]).toMatchObject({ event: "HALTED", reason: "h".repeat(200) });
  });

  it("names the trigger it is resuming from, whichever one halted it", () => {
    for (const trigger of ["HALT_FILE", "CLOCK_SKEW", "EFFECT_MISMATCH"] as const) {
      const { halt, lines } = build();
      halt.halt(trigger, "a cause");
      expect(halt.resume("the cause is gone").resumed).toBe(true);
      expect(events(lines).at(-1)).toMatchObject({ event: "RESUMED", trigger });
    }
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
