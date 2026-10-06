import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";

// Exercise the dependency actually reached by the MCP example, without
// starting its server. GHSA-jqcg-44mw-7w3h lets an untrusted IPv4 client
// supply its own apparent address through an IPv6 trust-subnet configuration.
const exampleRequire = createRequire(
  new URL("../../examples/mcp-tool-gate/package.json", import.meta.url),
);
const sdkRequire = createRequire(exampleRequire.resolve("@modelcontextprotocol/sdk/server/mcp.js"));
const expressRequire = createRequire(sdkRequire.resolve("express"));
const proxyAddress = expressRequire("proxy-addr");

const request = (remoteAddress, forwardedFor) => ({
  socket: { remoteAddress },
  headers: { "x-forwarded-for": forwardedFor },
});

test("IPv6 trust subnets cannot make an untrusted IPv4 client its own proxy", () => {
  for (const subnet of ["::ffff:10.0.0.0/8", "::/1"]) {
    const trust = proxyAddress.compile(subnet);
    const incoming = request("203.0.113.9", "10.0.0.7");
    assert.equal(proxyAddress(incoming, trust), "203.0.113.9", subnet);
    assert.deepEqual(proxyAddress.all(incoming, trust), ["203.0.113.9"], subnet);
  }
});

test("correct IPv4 and IPv4-mapped trust ranges still recognize the proxy", () => {
  for (const subnet of ["10.0.0.0/8", "::ffff:10.0.0.0/104"]) {
    const trust = proxyAddress.compile(subnet);
    for (const remote of ["10.0.0.8", "::ffff:10.0.0.8"]) {
      assert.equal(proxyAddress(request(remote, "198.51.100.12"), trust), "198.51.100.12");
    }
    assert.equal(proxyAddress(request("203.0.113.9", "10.0.0.7"), trust), "203.0.113.9");
  }
});

test("native IPv6 proxies retain their configured trust", () => {
  assert.equal(
    proxyAddress(request("2001:db8::10", "198.51.100.12"), proxyAddress.compile("2001:db8::/32")),
    "198.51.100.12",
  );
});
