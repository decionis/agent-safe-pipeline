import { describe, expect, it } from "vitest";
import { runStatus } from "../../src/cli/Status.js";
import { fakeProcess } from "../support/GatewayHarness.js";

const status = {
  status: "ready",
  version: "0.1.0",
  mode: "ENFORCEMENT",
  authority: "local/demo",
  failure_policy: "FAIL_CLOSED",
  upstream: "http://localhost:3000",
  routes: 2,
  held: 1,
  counts: { governed: 3, allows: 2 },
  evidence: { seq: 9, hash: "sha256:0" },
};

describe("agentsafe status", () => {
  it("asks the running gateway and prints what it says", async () => {
    const urls: string[] = [];
    const io = fakeProcess({
      fetch: (async (input: string | URL | Request) => {
        urls.push(String(input));
        return new Response(JSON.stringify(status), { status: 200 });
      }) as typeof fetch,
    });
    await runStatus(io, ["--upstream", "http://localhost:3000", "--port", "8090"]);
    expect(urls).toEqual(["http://127.0.0.1:8090/_agentsafe/status"]);
    expect(io.exits).toEqual([0]);
    const text = io.out.join("");
    expect(text).toContain("Mode          ENFORCEMENT");
    expect(text).toContain("Counts        governed=3 allows=2");
    expect(text).toContain("Held          1");
    const json = fakeProcess({
      fetch: (async () => new Response(JSON.stringify(status))) as typeof fetch,
    });
    await runStatus(json, ["--upstream", "http://localhost:3000", "--json"]);
    expect(JSON.parse(json.out.join(""))).toEqual(status);
    const wide = fakeProcess({
      fetch: (async () =>
        new Response(
          JSON.stringify({ ...status, counts: {}, failure_policy: "FAIL_OPEN" }),
        )) as typeof fetch,
    });
    await runStatus(wide, ["--upstream", "http://localhost:3000", "--listen", "0.0.0.0:8091"]);
    expect(wide.out.join("")).toContain("Gateway       http://127.0.0.1:8091");
    expect(wide.out.join("")).toContain("none yet");
    expect(wide.out.join("")).toContain("fail-open");
    expect(wide.out.join("")).toContain("Surface       not named; set AGENTSAFE_SURFACE");
    expect(wide.out.join("")).not.toContain("Shadow report");
  });

  it("prints the shadow report of a gateway in shadow, ending with the switch", async () => {
    const shadow = {
      ...status,
      mode: "SHADOW",
      surface: "homebrew",
      shadow: {
        since: "2026-09-19T10:00:00.000Z",
        until: "2026-09-19T12:00:00.000Z",
        observed: 184,
        would: { ALLOW: 171, ESCALATE: 9, BLOCK: 4, NONE: 0 },
        by_action: {
          "http.post": { ALLOW: 150, ESCALATE: 7, BLOCK: 3, NONE: 0 },
          "payments.refund": { ALLOW: 21, ESCALATE: 2, BLOCK: 1, NONE: 0 },
        },
      },
    };
    const io = fakeProcess({
      env: { AGENTSAFE_MODE: "shadow" },
      fetch: (async () => new Response(JSON.stringify(shadow))) as typeof fetch,
    });
    await runStatus(io, ["--upstream", "http://localhost:3000"]);
    const text = io.out.join("");
    expect(text).toContain("Surface       homebrew");
    expect(text).toContain("Shadow report");
    expect(text).toContain("Observed     184 consequential actions, every one forwarded unchanged");
    expect(text).toContain("Would hold   9");
    expect(text).toContain("By action    http.post          160");
    expect(text).toContain("payments.refund     24");
    expect(text).toContain(
      "Enforcement would have held 9 and refused 4 of 184; 171 would have gone through as they did.",
    );
    // The mode came from the environment, so the switch is the variable.
    expect(text).toContain("Turn it on   set `AGENTSAFE_MODE=enforcement` and restart");
  });

  it("says when nothing answers, and when the configuration cannot say where to ask", async () => {
    const down = fakeProcess({
      fetch: (async () =>
        Promise.reject(
          Object.assign(new Error("fetch failed"), { cause: { code: "ECONNREFUSED" } }),
        )) as typeof fetch,
    });
    await runStatus(down, ["--upstream", "http://localhost:3000"]);
    expect(down.exits).toEqual([1]);
    expect(down.err.join("")).toContain(
      "No gateway answered at http://127.0.0.1:8080/_agentsafe/status (ECONNREFUSED)",
    );
    const refused = fakeProcess({
      fetch: (async () => new Response("nope", { status: 503 })) as typeof fetch,
    });
    await runStatus(refused, ["--upstream", "http://localhost:3000"]);
    expect(refused.err.join("")).toContain("STATUS_503");
    const unconfigured = fakeProcess();
    await runStatus(unconfigured, []);
    expect(unconfigured.exits).toEqual([1]);
    expect(unconfigured.err.join("")).toContain("cannot resolve where the gateway listens");
    const bad = fakeProcess();
    await runStatus(bad, ["--what"]);
    expect(bad.exits).toEqual([2]);
  });
});
