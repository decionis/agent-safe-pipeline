import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  assertAllowedDiscoveryUrl,
  probeAllowedDiscoveryUrl,
} from "../../scripts/DiscoveryUrlPolicy.mjs";

function response(status, location) {
  return {
    status,
    headers: new globalThis.Headers(location === undefined ? {} : { location }),
    body: null,
  };
}

describe("DiscoveryUrlPolicy", () => {
  it("accepts the canonical HTTPS GitHub origin", () => {
    assert.equal(
      assertAllowedDiscoveryUrl("https://github.com/decionis/agent-safe-pipeline").hostname,
      "github.com",
    );
  });

  it("rejects unsafe schemes, credentials, ports, and hosts", () => {
    const unsafeUrls = [
      "http://github.com/decionis/agent-safe-pipeline",
      "https://user:password@github.com/decionis/agent-safe-pipeline",
      "https://github.com:444/decionis/agent-safe-pipeline",
      "https://github.com.example/",
      "https://127.0.0.1/",
    ];

    for (const url of unsafeUrls) {
      assert.throws(() => assertAllowedDiscoveryUrl(url), /DISCOVERY_URL_/);
    }
  });

  it("permits only non-mutating probe methods", async () => {
    await assert.rejects(
      probeAllowedDiscoveryUrl("https://github.com/decionis/project", "POST"),
      /DISCOVERY_URL_METHOD_FORBIDDEN/,
    );
  });

  it("validates every redirect destination before requesting it", async () => {
    const requested = [];
    const fetchImpl = async (url) => {
      requested.push(url.href);
      return response(302, "http://127.0.0.1/internal");
    };

    await assert.rejects(
      probeAllowedDiscoveryUrl("https://github.com/decionis/agent-safe-pipeline", "HEAD", {
        fetchImpl,
      }),
      /DISCOVERY_URL_MUST_USE_HTTPS/,
    );
    assert.deepEqual(requested, ["https://github.com/decionis/agent-safe-pipeline"]);
  });

  it("follows a bounded same-origin redirect", async () => {
    const requested = [];
    const fetchImpl = async (url) => {
      requested.push(url.href);
      return requested.length === 1 ? response(301, "/security") : response(200);
    };

    const status = await probeAllowedDiscoveryUrl("https://github.com/decionis/project", "HEAD", {
      fetchImpl,
    });
    assert.equal(status, 200);
    assert.deepEqual(requested, [
      "https://github.com/decionis/project",
      "https://github.com/security",
    ]);
  });
});
