import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import { packageVersion, userAgent } from "../../src/http/ClientIdentification.js";

const manifest = createRequire(import.meta.url)("../../package.json") as { version: string };

describe("client identification", () => {
  it("names this package and the version its manifest declares", () => {
    expect(packageVersion()).toBe(manifest.version);
    expect(userAgent()).toBe(`agent-safe-pipeline/${manifest.version}`);
    expect(userAgent({})).toBe(`agent-safe-pipeline/${manifest.version}`);
  });

  it("adds the source as a comment, in a fixed order, with only what a header can carry", () => {
    const product = `agent-safe-pipeline/${manifest.version}`;
    expect(userAgent({ repo: "decionis/agent-safe-pipeline", example: "basic-agent" })).toBe(
      `${product} (repo=decionis/agent-safe-pipeline; example=basic-agent)`,
    );
    expect(userAgent({ example: "mcp-tool-gate" })).toBe(`${product} (example=mcp-tool-gate)`);
    expect(userAgent({ repo: "owner/fork_1.0" })).toBe(`${product} (repo=owner/fork_1.0)`);
    expect(
      userAgent({
        repo: "decionis/agent-safe-pipeline",
        example: "basic-agent",
        surface: "github",
      }),
    ).toBe(`${product} (repo=decionis/agent-safe-pipeline; example=basic-agent; surface=github)`);
    expect(userAgent({ surface: "git hub" })).toBe(product);

    // A value the header could not carry verbatim is left out, never escaped or truncated.
    for (const bad of ["a b", "x)\r\nauthorization: y", "(", "é", "", "a".repeat(121)]) {
      expect(userAgent({ repo: bad, example: "basic-agent" }), JSON.stringify(bad)).toBe(
        `${product} (example=basic-agent)`,
      );
    }
    expect(userAgent({ repo: "a b", example: "c d" })).toBe(product);
  });
});
