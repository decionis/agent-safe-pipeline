import { createServer, type Server } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  CONTAINMENT_STREAM,
  parseTarget,
  probeContainment,
  verdictFor,
  type ContainmentTarget,
} from "../../src/containment/ContainmentProbe.js";
import { dial, dialOutcomeFor } from "../../src/egress/TcpProbe.js";

const LOOPBACK = "127.0.0.1";
const clock = (): Date => new Date("2026-09-15T10:00:00.000Z");

describe("verdictFor", () => {
  it("treats an answer as a hole and only a silent drop as containment", () => {
    expect(verdictFor({ state: "CONNECTED" })).toEqual({
      verdict: "REACHABLE",
      detail: "CONNECTED",
    });
    // An RST is an answer: a packet reached a host willing to reply, which is
    // what a policy that is not being enforced looks like.
    expect(verdictFor({ state: "REFUSED" })).toEqual({
      verdict: "REACHABLE",
      detail: "REFUSED_NOT_DROPPED",
    });
    expect(verdictFor({ state: "TIMED_OUT" })).toEqual({
      verdict: "CONTAINED",
      detail: "TIMED_OUT",
    });
    expect(verdictFor({ state: "UNREACHABLE", code: "EHOSTUNREACH" })).toEqual({
      verdict: "CONTAINED",
      detail: "EHOSTUNREACH",
    });
    expect(verdictFor({ state: "UNRESOLVED", code: "ENOTFOUND" })).toEqual({
      verdict: "INCONCLUSIVE",
      detail: "ENOTFOUND",
    });
    expect(verdictFor({ state: "OTHER", code: "ECONNRESET" })).toEqual({
      verdict: "INCONCLUSIVE",
      detail: "ECONNRESET",
    });
  });
});

describe("dialOutcomeFor", () => {
  it("maps each kernel code to the outcome the probe reads", () => {
    expect(dialOutcomeFor("ECONNREFUSED")).toEqual({ state: "REFUSED" });
    expect(dialOutcomeFor("ETIMEDOUT")).toEqual({ state: "TIMED_OUT" });
    for (const code of ["EHOSTUNREACH", "ENETUNREACH", "ENETDOWN", "EHOSTDOWN"]) {
      expect(dialOutcomeFor(code)).toEqual({ state: "UNREACHABLE", code });
    }
    for (const code of ["ENOTFOUND", "EAI_AGAIN", "EAI_NONAME"]) {
      expect(dialOutcomeFor(code)).toEqual({ state: "UNRESOLVED", code });
    }
    expect(dialOutcomeFor("EPERM")).toEqual({ state: "OTHER", code: "EPERM" });
    expect(dialOutcomeFor("UNKNOWN")).toEqual({ state: "OTHER", code: "UNKNOWN" });
  });
});

describe("parseTarget", () => {
  it("reads a named or bare address, and refuses one it cannot spell", () => {
    expect(parseTarget("core=core.bank.example:443")).toEqual({
      name: "core",
      host: "core.bank.example",
      port: 443,
    });
    expect(parseTarget("core.bank.example:443")).toEqual({
      name: "core.bank.example:443",
      host: "core.bank.example",
      port: 443,
    });
    // A one-character name puts the separator where a port number could be.
    expect(parseTarget("a=core.example:443")).toEqual({
      name: "a",
      host: "core.example",
      port: 443,
    });
    // Both ends of the port range are addresses, not errors.
    expect(parseTarget("host:1").port).toBe(1);
    expect(parseTarget("host:65535").port).toBe(65_535);
    // A probe of the wrong address that times out reads exactly like
    // containment, so a target that will not parse is refused outright.
    for (const bad of [
      "core.bank.example",
      ":443",
      "core=:443",
      "host:0",
      "host:65536",
      "host:x",
    ]) {
      expect(() => parseTarget(bad)).toThrow(/CONTAINMENT_TARGET_INVALID/);
    }
  });
});

describe("probeContainment", () => {
  it("names every target, counts the ones that answered, and claims nothing else", async () => {
    const targets: ContainmentTarget[] = [
      { name: "core", host: "core.bank.example", port: 443 },
      { name: "hub", host: "hub.bank.example", port: 443 },
    ];
    const report = await probeContainment({
      targets,
      clock,
      dial: async (host) =>
        host === "core.bank.example" ? { state: "CONNECTED" } : { state: "TIMED_OUT" },
    });
    expect(report.reachable).toBe(1);
    expect(report.noneReachable).toBe(false);
    expect(report.findings.map((finding) => finding.verdict)).toEqual(["REACHABLE", "CONTAINED"]);
    expect(report.findings[0]).toEqual({
      stream: CONTAINMENT_STREAM,
      event: "CONTAINMENT_PROBED",
      target: "core",
      address: "core.bank.example:443",
      verdict: "REACHABLE",
      detail: "CONNECTED",
      at: "2026-09-15T10:00:00.000Z",
    });
  });

  it("reports nothing reachable when every target stayed silent", async () => {
    const report = await probeContainment({
      targets: [{ name: "core", host: "core.bank.example", port: 443 }],
      clock,
      dial: async () => ({ state: "TIMED_OUT" }),
    });
    expect(report.reachable).toBe(0);
    expect(report.noneReachable).toBe(true);
  });

  it("probes one at a time, in the order given, and passes the timeout down", async () => {
    const seen: string[] = [];
    const report = await probeContainment({
      targets: [
        { name: "a", host: "a.example", port: 1 },
        { name: "b", host: "b.example", port: 2 },
        { name: "c", host: "c.example", port: 3 },
      ],
      clock,
      timeoutMs: 250,
      dial: async (host, port, timeoutMs) => {
        seen.push(`${host}:${String(port)}/${String(timeoutMs)}`);
        return { state: "TIMED_OUT" };
      },
    });
    expect(seen).toEqual(["a.example:1/250", "b.example:2/250", "c.example:3/250"]);
    expect(report.findings).toHaveLength(3);
  });

  it("defaults the timeout and the clock, and carries no target of its own", async () => {
    let observed = 0;
    const report = await probeContainment({
      targets: [{ name: "core", host: "core.bank.example", port: 443 }],
      dial: async (_host, _port, timeoutMs) => {
        observed = timeoutMs;
        return { state: "TIMED_OUT" };
      },
    });
    expect(observed).toBe(5_000);
    expect(Date.parse(report.findings[0]!.at)).not.toBeNaN();
    expect(
      await probeContainment({ targets: [], dial: async () => ({ state: "TIMED_OUT" }), clock }),
    ).toEqual({ findings: [], reachable: 0, noneReachable: true });
  });

  it("holds no path, parameter or body, only a host and a port", async () => {
    const report = await probeContainment({
      targets: [{ name: "core", host: "core.bank.example", port: 443 }],
      clock,
      dial: async () => ({ state: "CONNECTED" }),
    });
    // The address is a host and a port, never a URL: the only slash anywhere
    // in a finding is the one in the envelope's own version.
    expect(report.findings[0]!.address).toBe("core.bank.example:443");
    expect(report.findings[0]!.address).not.toMatch(/\//);
    const slashes = [...JSON.stringify(report).matchAll(/\//g)];
    expect(slashes).toHaveLength(1);
    expect(Object.keys(report.findings[0]!).sort()).toEqual([
      "address",
      "at",
      "detail",
      "event",
      "stream",
      "target",
      "verdict",
    ]);
  });
});

describe("dial against a real socket", () => {
  let server: Server;
  let open = 0;

  beforeAll(async () => {
    server = createServer((socket) => socket.end());
    await new Promise<void>((resolve) => server.listen(0, LOOPBACK, resolve));
    open = (server.address() as { port: number }).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("connects to a listening port and is refused by a closed one", async () => {
    expect(await dial(LOOPBACK, open, 2_000)).toEqual({ state: "CONNECTED" });
    // A port nothing listens on answers with an RST on loopback, which the
    // probe reports as reachable: the path was never the thing missing.
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, LOOPBACK, resolve));
    const port = (closed.address() as { port: number }).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    expect(await dial(LOOPBACK, port, 2_000)).toEqual({ state: "REFUSED" });
    expect(verdictFor(await dial(LOOPBACK, open, 2_000)).verdict).toBe("REACHABLE");
  });

  it("reports an address that does not resolve without throwing", async () => {
    const outcome = await dial("containment-probe-no-such-host.invalid", 443, 2_000);
    expect(["UNRESOLVED", "TIMED_OUT", "OTHER"]).toContain(outcome.state);
  });
});
