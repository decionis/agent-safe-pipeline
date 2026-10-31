import { describe, expect, it } from "vitest";
import type { ApiProfile } from "@decionis/agent-safe-pipeline";
import { coverageOf } from "../../src/acceptance/Coverage.js";
import {
  AUTHORITY_UNREACHABLE,
  OUTAGE_VERSION,
  recordingUpstream,
  statingAnswer,
} from "../../src/acceptance/OutageDoubles.js";
import { RouteTable } from "../../src/gateway/RouteTable.js";
import { testConfig } from "../support/GatewayHarness.js";

const UPSTREAM = "http://127.0.0.1:1";

function covered(
  file: Record<string, unknown>,
  env: Record<string, string> = {},
): ReturnType<typeof coverageOf> {
  const config = testConfig(UPSTREAM, {
    env: { AGENTSAFE_MODE: "enforcement", ...env },
    file: { version: 1, ...file },
  });
  return coverageOf(RouteTable.of(config), config);
}

describe("coverageOf", () => {
  it("lists every governed route of an enforcing, fail-closed gateway, and says which read their target", () => {
    const coverage = covered({
      interception: {
        profile: "businesscentral/api/v2",
        routes: [{ path: "/payments/**", action: "payment.create", methods: ["POST"] }],
      },
    });
    expect(coverage.governed[0]).toEqual({
      methods: ["POST"],
      path: "/payments/**",
      action: "payment.create",
      target_read: false,
    });
    const customers = coverage.governed.find((route) => route.action === "customer.update");
    expect(customers).toEqual({
      methods: ["PATCH"],
      path: "/companies({companyId})/customers({customerId})",
      action: "customer.update",
      target_read: true,
    });
    // A write of the profile that names no read, and one of another action on the same method.
    expect(coverage.governed.find((route) => route.action === "vendor.update")?.target_read).toBe(
      false,
    );
    expect(coverage.governed.filter((route) => route.target_read)).toHaveLength(1);
    // Anything unmatched is governed by its method's derived action, and reads nothing.
    expect(coverage.governed.at(-1)).toMatchObject({ path: "/**", target_read: false });
    expect(coverage.ungoverned).toEqual([]);
    expect(coverage.refused).toEqual([]);
    expect(coverage.reads).toBe("PASSTHROUGH");
  });

  it("lists an unmatched path that passes through as not governed", () => {
    expect(covered({ interception: { unmatched: "passthrough" } }).ungoverned).toEqual([
      {
        methods: ["POST", "PUT", "PATCH", "DELETE"],
        path: "/**",
        action: null,
        kind: "PASSTHROUGH",
      },
    ]);
  });

  it("lists every route of a gateway in shadow, or failing open, as not governed", () => {
    const routes = {
      routes: [{ path: "/payments/**", action: "payment.create", methods: ["POST"] }],
    };
    const shadow = covered({ interception: routes }, { AGENTSAFE_MODE: "shadow" });
    expect(shadow.governed).toEqual([]);
    expect(shadow.ungoverned[0]).toEqual({
      methods: ["POST"],
      path: "/payments/**",
      action: "payment.create",
      kind: "SHADOW",
    });
    const open = covered({ interception: routes }, { AGENTSAFE_FAILURE_POLICY: "fail-open" });
    expect(open.governed).toEqual([]);
    expect(open.ungoverned[0]).toEqual({
      methods: ["POST"],
      path: "/payments/**",
      action: "payment.create",
      kind: "FAIL_OPEN",
    });
    expect(new Set(open.ungoverned.map((route) => route.kind))).toEqual(new Set(["FAIL_OPEN"]));
  });

  it("lists what the gateway refuses outright, and how it treats reads", () => {
    const coverage = covered({
      interception: { profile: "businesscentral/api/v2", privacy: "facts" },
    });
    expect(coverage.refused).toEqual([
      { methods: ["POST", "PUT", "PATCH", "DELETE"], path: "/**", action: null },
    ]);
  });
});

describe("the outage case's doubles", () => {
  const profile = (preconditions: readonly ({ version: string; state?: string } | undefined)[]) =>
    ({
      definition: {
        operations: preconditions.map((precondition, index) => ({
          id: `operation${index}`,
          ...(precondition === undefined ? {} : { precondition: { read: "x", ...precondition } }),
        })),
      },
    }) as unknown as ApiProfile;

  it("states nothing for a gateway without a profile", () => {
    expect(statingAnswer(null)).toEqual({ headers: {}, body: undefined });
  });

  it("states a version, and a state, wherever a precondition looks for one", () => {
    expect(
      statingAnswer(
        profile([
          undefined,
          { version: "/headers/etag" },
          { version: "/body/@odata.etag", state: "/body/blocked" },
          { version: "/body/meta/version", state: "/body/meta/a~1b~0c" },
        ]),
      ),
    ).toEqual({
      headers: { etag: OUTAGE_VERSION },
      body: {
        "@odata.etag": OUTAGE_VERSION,
        blocked: OUTAGE_VERSION,
        meta: { version: OUTAGE_VERSION, "a/b~c": OUTAGE_VERSION },
      },
    });
  });

  it("states the whole body when a precondition reads the body itself, and an object over it after", () => {
    expect(statingAnswer(profile([{ version: "/body" }])).body).toBe(OUTAGE_VERSION);
    expect(statingAnswer(profile([{ version: "/body" }, { version: "/body/v" }])).body).toEqual({
      v: OUTAGE_VERSION,
    });
    expect(statingAnswer(profile([{ version: "/body/a" }, { version: "/body/a/b" }])).body).toEqual(
      { a: { b: OUTAGE_VERSION } },
    );
  });

  it("answers reads with the stating answer, and counts and refuses everything else", async () => {
    const upstream = recordingUpstream(
      profile([{ version: "/body/v", state: "/headers/x-state" }]),
    );
    const read = await upstream.fetch("http://upstream.example/a", { method: "GET" });
    expect(read.status).toBe(200);
    expect(read.headers.get("content-type")).toBe("application/json");
    expect(read.headers.get("x-state")).toBe(OUTAGE_VERSION);
    expect(await read.json()).toEqual({ v: OUTAGE_VERSION });
    expect((await upstream.fetch("http://upstream.example/a", { method: "head" })).status).toBe(
      200,
    );
    expect((await upstream.fetch("http://upstream.example/a")).status).toBe(200);
    expect(upstream.writes()).toBe(0);
    expect((await upstream.fetch("http://upstream.example/a", { method: "PATCH" })).status).toBe(
      502,
    );
    expect((await upstream.fetch("http://upstream.example/a", { method: "post" })).status).toBe(
      502,
    );
    expect(upstream.writes()).toBe(2);
    expect(await (await recordingUpstream(null).fetch("http://upstream.example/a")).text()).toBe(
      "",
    );
  });

  it("never reaches the authority", async () => {
    await expect(AUTHORITY_UNREACHABLE("http://authority.example/v1")).rejects.toThrow(
      "AUTHORITY_UNREACHABLE",
    );
  });
});
