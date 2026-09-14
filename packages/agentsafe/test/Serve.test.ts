import { describe, expect, it, vi } from "vitest";
import { nodeProcess, serve, type ServeProcess } from "../src/Serve.js";
import {
  CALLER_TOKEN,
  LOOPBACK_ORIGIN,
  closedPort,
  offlineEnvironment,
} from "./support/Environment.js";

interface Recorded {
  readonly io: ServeProcess;
  readonly stdout: string[];
  readonly stderr: string[];
  readonly exits: number[];
  readonly signals: Map<string, () => void>;
  readonly exited: Promise<number>;
}

function recorded(env: Record<string, string>): Recorded {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const exits: number[] = [];
  const signals = new Map<string, () => void>();
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
  };
  return { io, stdout, stderr, exits, signals, exited };
}

describe("serve", () => {
  it("refuses to start on invalid configuration, naming the variable and never the value", async () => {
    const env = offlineEnvironment();
    delete env["DECIONIS_API_URL"];
    const run = recorded(env);
    await serve(undefined, run.io);
    expect(run.exits).toEqual([1]);
    expect(run.stdout).toEqual([]);
    expect(run.stderr).toHaveLength(1);
    const refusal = JSON.parse(run.stderr[0] ?? "{}") as Record<string, unknown>;
    expect(refusal["event"]).toBe("REFUSED_TO_START");
    expect(String(refusal["reason"])).toContain("DECIONIS_API_URL");
    expect(run.stderr[0]).not.toContain(CALLER_TOKEN);
  });

  it("listens on the configured address, reports it, and exits cleanly on a signal", async () => {
    const port = await closedPort();
    const run = recorded({ ...offlineEnvironment(), PORT: String(port) });
    await serve(undefined, run.io);
    expect(run.stderr).toEqual([]);
    const listening = JSON.parse(run.stdout[0] ?? "{}") as Record<string, unknown>;
    expect(listening).toEqual({
      event: "LISTENING",
      mode: "ENFORCEMENT",
      address: "127.0.0.1",
      port,
      actions: ["forward_request"],
    });
    const health = await fetch(`${LOOPBACK_ORIGIN}:${port}/health`);
    expect(health.status).toBe(200);
    expect([...run.signals.keys()]).toEqual(["SIGTERM", "SIGINT"]);
    run.signals.get("SIGTERM")?.();
    expect(await run.exited).toBe(0);
    await expect(fetch(`${LOOPBACK_ORIGIN}:${port}/health`)).rejects.toThrow();
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
