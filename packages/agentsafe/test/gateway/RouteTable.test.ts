import { describe, expect, it } from "vitest";
import { derivedAction, RouteTable } from "../../src/gateway/RouteTable.js";

const routes = [
  { path: "/payments", action: "payment.create", methods: ["POST"] as const },
  { path: "/payments/*/refunds", action: "refund.create", methods: ["POST"] as const },
  { path: "/orders/:id", action: "order.change", methods: ["PUT", "PATCH", "DELETE"] as const },
  {
    path: "/admin/**",
    action: "admin.write",
    methods: ["POST", "PUT", "PATCH", "DELETE"] as const,
  },
];

describe("the route table", () => {
  const table = new RouteTable(routes, "GOVERN");

  it("never governs a safe method", () => {
    for (const method of ["GET", "HEAD", "OPTIONS", "get"]) {
      expect(table.plan(method, "/payments")).toEqual({
        kind: "PASSTHROUGH",
        reason: "SAFE_METHOD",
      });
    }
  });

  it("never classifies an unsupported state-changing method as safe", () => {
    for (const method of ["MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "PROPPATCH", "TRACE"]) {
      expect(table.plan(method, "/payments")).toEqual({
        kind: "REFUSE",
        code: "HTTP_METHOD_UNSUPPORTED",
      });
    }
  });

  it("matches exact paths, one segment, a named segment, and a subtree, first match first", () => {
    expect(table.plan("POST", "/payments")).toMatchObject({
      kind: "GOVERN",
      action: "payment.create",
    });
    expect(table.plan("post", "/payments/")).toMatchObject({
      kind: "GOVERN",
      action: "payment.create",
    });
    expect(table.plan("POST", "/payments/p1/refunds")).toMatchObject({
      kind: "GOVERN",
      action: "refund.create",
    });
    expect(table.plan("POST", "/payments/p1/x/refunds")).toMatchObject({
      kind: "GOVERN",
      action: "http.post",
      route: null,
    });
    expect(table.plan("PATCH", "/orders/42")).toMatchObject({
      kind: "GOVERN",
      action: "order.change",
    });
    expect(table.plan("PATCH", "/orders/42/lines")).toMatchObject({
      kind: "GOVERN",
      action: "http.patch",
    });
    expect(table.plan("DELETE", "/admin")).toMatchObject({ kind: "GOVERN", action: "admin.write" });
    expect(table.plan("PUT", "/admin/users/7/roles")).toMatchObject({
      kind: "GOVERN",
      action: "admin.write",
    });
    expect(table.plan("POST", "/payment")).toMatchObject({ kind: "GOVERN", action: "http.post" });
  });

  it("governs by method: a route names the methods it covers and nothing else", () => {
    expect(table.plan("PUT", "/payments")).toMatchObject({
      kind: "GOVERN",
      action: "http.put",
      route: null,
    });
    expect(table.plan("POST", "/orders/42")).toMatchObject({
      kind: "GOVERN",
      action: "http.post",
      route: null,
    });
  });

  it("passes an unmatched unsafe request through only when told to", () => {
    const narrow = new RouteTable(routes, "PASSTHROUGH");
    expect(narrow.plan("POST", "/elsewhere")).toEqual({ kind: "PASSTHROUGH", reason: "UNMATCHED" });
    expect(narrow.plan("POST", "/payments")).toMatchObject({
      kind: "GOVERN",
      action: "payment.create",
    });
  });

  it("cannot hide a governed route behind percent-encoded path characters", () => {
    const narrow = new RouteTable(routes, "PASSTHROUGH");
    expect(narrow.plan("POST", "/%70ayments")).toMatchObject({
      kind: "GOVERN",
      action: "payment.create",
    });
    expect(narrow.plan("POST", "/%61dmin/users")).toMatchObject({
      kind: "GOVERN",
      action: "admin.write",
    });
  });

  it.each([
    "/admin%2fusers",
    "/admin%5cusers",
    "/%2561dmin",
    "/admin;ignored/users",
    "/admin/%00",
    "/admin/%zz",
  ])("refuses ambiguous path interpretation: %s", (path) => {
    expect(new RouteTable(routes, "PASSTHROUGH").plan("POST", path)).toEqual({
      kind: "REFUSE",
      code: "HTTP_PATH_AMBIGUOUS",
    });
  });

  it("passes everything through when interception is off", () => {
    const off = new RouteTable(routes, "GOVERN", false);
    expect(off.plan("POST", "/payments")).toEqual({ kind: "PASSTHROUGH", reason: "DISABLED" });
  });

  it("keeps decoded Unicode paths usable and refuses ambiguous configured patterns", () => {
    const unicode = new RouteTable(
      [{ path: "/café/:id", action: "cafe.write", methods: ["POST"] }],
      "PASSTHROUGH",
    );
    expect(unicode.plan("POST", "/caf%C3%A9/receipt%20id")).toMatchObject({
      kind: "GOVERN",
      action: "cafe.write",
    });
    for (const path of ["/admin/%2a", "/admin;ignored", "/admin/../payments"]) {
      expect(
        () => new RouteTable([{ path, action: "admin.write", methods: ["POST"] }], "GOVERN"),
      ).toThrow("ROUTE_PATH_AMBIGUOUS");
    }
  });

  it("lists every action it can produce, derived names included, once each", () => {
    expect(new RouteTable([], "GOVERN").actions()).toEqual([
      "http.post",
      "http.put",
      "http.patch",
      "http.delete",
    ]);
    const named = table.actions();
    expect(named.slice(0, 4)).toEqual(["http.post", "http.put", "http.patch", "http.delete"]);
    expect(named.slice(4)).toEqual([
      "payment.create",
      "refund.create",
      "order.change",
      "admin.write",
    ]);
    expect(new RouteTable([...routes, routes[0]!], "GOVERN").actions()).toHaveLength(8);
    expect(derivedAction("DELETE")).toBe("http.delete");
  });
});
