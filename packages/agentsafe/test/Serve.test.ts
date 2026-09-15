import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import { SECURITY_STREAM } from "../src/incident/SecurityEvents.js";
import { nodeProcess, serve, type ServeProcess } from "../src/Serve.js";
import {
  CALLER_TOKEN,
  LOOPBACK_ORIGIN,
  closedPort,
  offlineEnvironment,
} from "./support/Environment.js";
import { TestCertificateAuthority } from "./support/TestCertificateAuthority.js";

interface Recorded {
  readonly io: ServeProcess;
  readonly stdout: string[];
  readonly stderr: string[];
  readonly exits: number[];
  readonly signals: Map<string, () => void>;
  readonly exited: Promise<number>;
  readonly locks: number[];
}

function recorded(env: Record<string, string>): Recorded {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const exits: number[] = [];
  const signals = new Map<string, () => void>();
  const locks: number[] = [];
  let resolveExit: (code: number) => void = () => undefined;
  const exited = new Promise<number>((resolve) => {
    resolveExit = resolve;
  });
  const io: ServeProcess = {
    env,
    stdout: (line) => {
      stdout.push(line);
    },
    stderr: (line) => {
      stderr.push(line);
    },
    exit: (code) => {
      exits.push(code);
      resolveExit(code);
    },
    onSignal: (signal, handler) => {
      signals.set(signal, handler);
    },
    lockFetch: () => {
      locks.push(stdout.length + stderr.length);
    },
  };
  return { io, stdout, stderr, exits, signals, exited, locks };
}

const parsed = (line: string | undefined): Record<string, unknown> =>
  JSON.parse(line ?? "{}") as Record<string, unknown>;

describe("serve", () => {
  it("refuses to start on invalid configuration, naming the variable and never the value", async () => {
    const env = offlineEnvironment();
    delete env["DECIONIS_API_URL"];
    const run = recorded(env);
    await serve(undefined, run.io);
    expect(run.exits).toEqual([1]);
    expect(run.stdout).toEqual([]);
    expect(run.stderr).toHaveLength(1);
    const refusal = parsed(run.stderr[0]);
    expect(refusal["event"]).toBe("REFUSED_TO_START");
    expect(String(refusal["reason"])).toContain("DECIONIS_API_URL");
    expect(run.stderr[0]).not.toContain(CALLER_TOKEN);
  });

  it("refuses to start under enforced posture on a host that does not hold it, before any secret is read", async () => {
    const env = offlineEnvironment();
    delete env["EXECUTOR_POSTURE"];
    const run = recorded(env);
    await serve(undefined, run.io);
    expect(run.exits).toEqual([1]);
    const refusal = parsed(run.stderr.at(-1));
    expect(refusal["event"]).toBe("REFUSED_TO_START");
    expect(String(refusal["reason"])).toMatch(/^POSTURE_[A-Z_]+/);
    expect(run.stderr.join("\n")).not.toContain(CALLER_TOKEN);
  });

  it("verifies posture, opens the secrets, listens, reports, and exits cleanly on a signal", async () => {
    const port = await closedPort();
    const run = recorded({ ...offlineEnvironment(), PORT: String(port) });
    await serve(undefined, run.io);
    expect(run.exits).toEqual([]);
    const events = run.stdout.map((line) => parsed(line)["event"]);
    expect(events).toEqual(["POSTURE_VERIFIED", "LISTENING"]);
    expect(parsed(run.stdout[0])).toMatchObject({ mode: "DEVELOPMENT" });
    expect(parsed(run.stdout[1])).toEqual({
      event: "LISTENING",
      mode: "ENFORCEMENT",
      tls: false,
      address: "127.0.0.1",
      port,
      actions: ["forward_request"],
    });
    // The global fetch was sealed before any line was written or any secret read.
    expect(run.locks).toEqual([0]);
    expect(run.stderr.map((line) => parsed(line)["event"])).toContain("POSTURE_VERIFIED");
    const health = await fetch(`${LOOPBACK_ORIGIN}:${port}/health`);
    expect(health.status).toBe(200);
    expect([...run.signals.keys()]).toEqual(["SIGTERM", "SIGINT", "SIGHUP"]);
    run.signals.get("SIGHUP")?.();
    run.signals.get("SIGTERM")?.();
    expect(await run.exited).toBe(0);
    await expect(fetch(`${LOOPBACK_ORIGIN}:${port}/health`)).rejects.toThrow();
  });
});

describe("serve with a journal and TLS material", () => {
  const directory = mkdtempSync(join(tmpdir(), "agentsafe-serve-"));
  afterAll(() => rmSync(directory, { recursive: true, force: true }));

  it("listens over TLS, persists the chain heads on shutdown, and resumes them on the next start", async () => {
    const ca = new TestCertificateAuthority("Synthetic Serve CA");
    const issued = ca.issueServer(["localhost"], ["127.0.0.1"]);
    mkdirSync(join(directory, "tls"));
    writeFileSync(join(directory, "tls", "tls.crt"), issued.cert);
    writeFileSync(join(directory, "tls", "tls.key"), issued.key);
    const env = offlineEnvironment();
    delete env["EXECUTOR_ALLOW_PLAINTEXT_LISTENER"];
    Object.assign(env, {
      PORT: String(await closedPort()),
      EXECUTOR_TLS_CERT_FILE: join(directory, "tls", "tls.crt"),
      EXECUTOR_TLS_KEY_FILE: join(directory, "tls", "tls.key"),
      EXECUTOR_JOURNAL_DIR: join(directory, "journal"),
    });
    const first = recorded(env);
    await serve(undefined, first.io);
    expect(first.exits).toEqual([]);
    expect(parsed(first.stdout[1])).toMatchObject({ event: "LISTENING", tls: true });
    first.signals.get("SIGTERM")?.();
    expect(await first.exited).toBe(0);
    expect(existsSync(join(directory, "journal", "chain", "agent-safe.security_1.json"))).toBe(
      true,
    );
    const checkpoints = first.stderr.filter((line) => line.includes('"CHAIN_CHECKPOINT"'));
    expect(checkpoints.length).toBeGreaterThanOrEqual(2);
    const second = recorded(env);
    await serve(undefined, second.io);
    expect(second.exits).toEqual([]);
    const resumed = second.stderr
      .map((line) => parsed(line))
      .find((line) => line["event"] === "CHAIN_RESUMED");
    expect(resumed).toMatchObject({ chain: SECURITY_STREAM });
    expect(Number(resumed?.["head"])).toBeGreaterThan(0);
    expect(
      second.stderr.every((line) => Number(parsed(line)["seq"]) > Number(resumed?.["head"])),
    ).toBe(true);
    second.signals.get("SIGTERM")?.();
    expect(await second.exited).toBe(0);
  });

  it("refuses to start when the journal directory cannot be made, after the posture is verified", async () => {
    writeFileSync(join(directory, "occupied"), "a file, not a directory");
    const unusable = join(directory, "occupied", "journal");
    const run = recorded({ ...offlineEnvironment(), EXECUTOR_JOURNAL_DIR: unusable });
    await serve(undefined, run.io);
    expect(run.exits).toEqual([1]);
    expect(parsed(run.stderr.at(-1))).toEqual({
      event: "REFUSED_TO_START",
      reason: "JOURNAL_UNAVAILABLE: EXECUTOR_JOURNAL_DIR",
    });
    // The posture ran first and said so, and no secret was opened after it.
    expect(run.stderr.map((line) => parsed(line)["event"])).toContain("POSTURE_VERIFIED");
    // A host that does not hold its posture is refused for that, not for the
    // directory: the check is named, the journal is not reached.
    const enforced = recorded({
      ...offlineEnvironment(),
      EXECUTOR_POSTURE: undefined,
      EXECUTOR_JOURNAL_DIR: unusable,
    } as unknown as Record<string, string>);
    delete (enforced.io.env as Record<string, string | undefined>)["EXECUTOR_POSTURE"];
    await serve(undefined, enforced.io);
    expect(enforced.exits).toEqual([1]);
    const refusal = parsed(enforced.stderr.at(-1));
    expect(String(refusal["reason"])).toMatch(/^POSTURE_[A-Z_]+/);
    expect(enforced.stderr.join("\n")).not.toContain("JOURNAL_UNAVAILABLE");
  });
});

describe("nodeProcess", () => {
  it("binds the real process: its environment, its streams, its signals", () => {
    const io = nodeProcess();
    expect(io.env).toBe(process.env);
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    io.stdout("out");
    io.stderr("err");
    expect(stdout).toHaveBeenCalledWith("out\n");
    expect(stderr).toHaveBeenCalledWith("err\n");
    stdout.mockRestore();
    stderr.mockRestore();
    const handler = (): void => undefined;
    io.onSignal("SIGINT", handler);
    expect(process.listeners("SIGINT")).toContain(handler);
    process.off("SIGINT", handler);
  });
});
