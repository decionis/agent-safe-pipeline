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

  it("passes everything through when interception is off", () => {
    const off = new RouteTable(routes, "GOVERN", false);
    expect(off.plan("POST", "/payments")).toEqual({ kind: "PASSTHROUGH", reason: "DISABLED" });
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
