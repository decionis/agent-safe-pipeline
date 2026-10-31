import { once } from "node:events";
import { createServer, type Server } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { runIntercept } from "../../src/cli/Intercept.js";
import { startOnFreePorts } from "./Environment.js";
import { fakeProcess, type FakeProcess } from "./GatewayHarness.js";

describe("startOnFreePorts", () => {
  /** Listeners standing in for a test in another worker that binds a port first. */
  const thieves: Server[] = [];
  const started: FakeProcess[] = [];

  afterEach(async () => {
    for (const io of started.splice(0)) {
      if (io.exits.length === 0) io.signals.get("SIGTERM")?.();
      for (let wait = 0; wait < 40 && io.exits.length === 0; wait += 1) {
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }
    for (const thief of thieves.splice(0)) {
      await new Promise((resolve) => thief.close(resolve));
    }
  });

  const steal = async (port: number): Promise<void> => {
    const thief = createServer();
    thief.listen(port, "127.0.0.1");
    await once(thief, "listening");
    thieves.push(thief);
  };

  const intercept = async (
    http: number,
    https: number,
    argv: readonly string[] = [],
  ): Promise<FakeProcess> => {
    const io = fakeProcess({ env: { NODE_ENV: "production" } });
    started.push(io);
    await runIntercept(io, ["--http-port", String(http), "--https-port", String(https), ...argv]);
    return io;
  };

  it("hands one start ports that differ from each other", async () => {
    for (let pick = 0; pick < 50; pick += 1) {
      const { ports } = await startOnFreePorts(["a", "b", "c"], async () => ({ exits: [] }));
      expect(new Set([ports.a, ports.b, ports.c]).size).toBe(3);
    }
  });

  it("starts again on new ports when one is taken between the pick and the bind", async () => {
    const tried: { http: number; https: number }[] = [];
    const { ports, started: io } = await startOnFreePorts(
      ["http", "https"],
      async ({ http, https }) => {
        tried.push({ http, https });
        // Another worker binds the port first, on the first try only.
        if (tried.length === 1) await steal(https);
        return intercept(http, https);
      },
    );
    expect(tried).toHaveLength(2);
    expect(ports).toEqual(tried[1]);
    expect(ports.https).not.toBe(tried[0]?.https);
    expect(io.exits).toEqual([]);
    expect(JSON.parse(io.out[0] ?? "{}")).toMatchObject({ event: "INTERCEPT_STARTED" });
  });

  it("returns a refusal that is not about a port as it was, without trying again", async () => {
    let tries = 0;
    const { started: io } = await startOnFreePorts(["http", "https"], async ({ http, https }) => {
      tries += 1;
      return intercept(http, https, ["--unlisted", "maybe"]);
    });
    expect(tries).toBe(1);
    expect(io.exits).toEqual([2]);
    expect(JSON.parse(io.err.join(""))).toEqual({
      event: "REFUSED_TO_START",
      reason: "CONFIG_INVALID: unlisted (passthrough or refuse)",
    });
  });

  it("tries a bounded number of times, and then returns the refusal for the test to assert", async () => {
    let tries = 0;
    const { started: io } = await startOnFreePorts(["http", "https"], async ({ http, https }) => {
      tries += 1;
      await steal(http);
      return intercept(http, https);
    });
    expect(tries).toBe(5);
    expect(io.exits).toEqual([1]);
    expect(JSON.parse(io.err.join("")).reason).toMatch(/^EADDRINUSE: 127\.0\.0\.1:/);
  });

  it("starts again after a throw while a port is taken, and rethrows any other", async () => {
    let tries = 0;
    const { started } = await startOnFreePorts(["port"], async ({ port }) => {
      tries += 1;
      if (tries === 1) {
        await steal(port);
        throw new Error("listen EADDRINUSE");
      }
      return { exits: [] };
    });
    expect(tries).toBe(2);
    expect(started.exits).toEqual([]);
    await expect(
      startOnFreePorts(["port"], async () => {
        throw new Error("JOURNAL_UNAVAILABLE");
      }),
    ).rejects.toThrow("JOURNAL_UNAVAILABLE");
  });
});
