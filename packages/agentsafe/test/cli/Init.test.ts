import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import {
  actionNameFrom,
  routesFromOpenApi,
  runInit,
  upstreamFromPackage,
} from "../../src/cli/Init.js";
import { GatewayConfigLoader } from "../../src/gateway/GatewayConfig.js";
import { fakeProcess } from "../support/GatewayHarness.js";

const openapi = `
openapi: 3.0.0
paths:
  /payments:
    post:
      operationId: createPayment
    get: {}
  /orders/{id}:
    delete:
      operationId: cancel order!
    put: {}
    patch: null
  not-a-path:
    post: {}
`;

describe("agentsafe init", () => {
  it("writes the smallest working file, looking at package.json for the port and OpenAPI for the routes", () => {
    const io = fakeProcess({
      files: {
        "/work/package.json": JSON.stringify({ scripts: { dev: "node server.js --port 3999" } }),
        "/work/openapi.yaml": openapi,
      },
    });
    const report = runInit(io, ["--port", "8099"]);
    expect(report).toMatchObject({
      path: "/work/agentsafe.yaml",
      upstream: "http://localhost:3999",
      source: "package.json",
      openapi: "openapi.yaml",
    });
    expect(report?.routes).toEqual([
      { path: "/payments", action: "create.payment", methods: ["POST"] },
      { path: "/orders/*", action: "orders.update", methods: ["PUT"] },
      { path: "/orders/*", action: "cancel.order", methods: ["DELETE"] },
    ]);
    const text = io.stored.get("/work/agentsafe.yaml")?.text ?? "";
    const config = GatewayConfigLoader.load({
      env: {},
      file: parse(text) as unknown,
      version: "0",
    });
    expect(config.listen).toEqual({ host: "127.0.0.1", port: 8099 });
    expect(config.upstream.url).toBe("http://localhost:3999");
    expect(config.interception.routes).toHaveLength(3);
    expect(io.out.join("")).toContain("Routes       3 from openapi.yaml");
    expect(io.exits).toEqual([]);
  });

  it("defaults the upstream, takes flags first, and refuses to overwrite without --force", () => {
    const io = fakeProcess();
    expect(runInit(io, [])).toMatchObject({
      upstream: "http://localhost:3000",
      source: "default",
      routes: [],
      openapi: null,
    });
    expect(io.out.join("")).toContain("none named");
    expect(runInit(io, [])).toBeNull();
    expect(io.exits).toEqual([1]);
    expect(io.err.join("")).toContain("--force");
    expect(
      runInit(io, [
        "--force",
        "--upstream",
        "https://api.example",
        "--mode",
        "shadow",
        "--config",
        "/work/custom.yaml",
      ]),
    ).toMatchObject({ path: "/work/custom.yaml", upstream: "https://api.example", source: "flag" });
    expect(io.stored.get("/work/custom.yaml")?.text).toContain("mode: shadow");
    const bad = fakeProcess();
    expect(runInit(bad, ["--nope"])).toBeNull();
    expect(bad.exits).toEqual([2]);
  });

  it("derives action names from operation ids or the path and method", () => {
    expect(actionNameFrom("createPayment", "/payments", "POST")).toBe("create.payment");
    expect(actionNameFrom("Cancel Order!!", "/orders/{id}", "DELETE")).toBe("cancel.order");
    expect(actionNameFrom("123", "/orders/{id}", "DELETE")).toBe("orders.delete");
    expect(actionNameFrom(undefined, "/api/v1/Orders/{id}/lines", "PATCH")).toBe("lines.update");
    expect(actionNameFrom(undefined, "/{id}", "POST")).toBe("http.create");
    expect(actionNameFrom(undefined, "/9lives", "PUT")).toBe("http.update");
  });

  it("reads hints defensively", () => {
    expect(routesFromOpenApi("not: [yaml")).toEqual([]);
    expect(routesFromOpenApi("paths: 3")).toEqual([]);
    expect(routesFromOpenApi("openapi: 3.0.0")).toEqual([]);
    expect(routesFromOpenApi("paths:\n  /a:\n    post: {}\n")).toEqual([
      { path: "/a", action: "a.create", methods: ["POST"] },
    ]);
    expect(upstreamFromPackage(null)).toBeNull();
    expect(upstreamFromPackage("{oops")).toBeNull();
    expect(upstreamFromPackage(JSON.stringify({ scripts: "none" }))).toBeNull();
    expect(upstreamFromPackage(JSON.stringify({ scripts: { start: "PORT=4000 node ." } }))).toBe(
      "http://localhost:4000",
    );
    expect(upstreamFromPackage(JSON.stringify({ scripts: { serve: "vite -p 5173" } }))).toBe(
      "http://localhost:5173",
    );
    expect(upstreamFromPackage(JSON.stringify({ scripts: { test: "vitest" } }))).toBeNull();
    const io = fakeProcess({ files: { "/work/openapi.json": "x".repeat(5 * 1024 * 1024) } });
    expect(runInit(io, [])?.openapi).toBeNull();
  });
});
