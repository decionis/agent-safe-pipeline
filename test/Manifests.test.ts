import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { COMMERCEGATE_TOOL_NAMES } from "../src/Tools.js";
import { MCP_SERVER_VERSION } from "../src/Version.js";

async function text(relativePath: string): Promise<string> {
  return readFile(new URL(`../${relativePath}`, import.meta.url), "utf8");
}

describe("CommerceGate distribution metadata", () => {
  it("keeps the stable npm package, MCP identity, binary, and registry manifest aligned", async () => {
    const packageJson = JSON.parse(await text("package.json"));
    const server = JSON.parse(await text("server.json"));

    expect(packageJson).toMatchObject({
      name: "@decionis/commerce",
      version: "0.1.1",
      mcpName: "com.decionis/commerce-gate",
      author: "Decionis",
      bin: { "commercegate-mcp": "dist/Index.js" },
      scripts: { mcp: "node --import tsx src/Index.ts" },
      license: "Apache-2.0",
    });
    expect(packageJson.version).toBe(MCP_SERVER_VERSION);
    expect(server).toMatchObject({
      name: packageJson.mcpName,
      title: "Decionis CommerceGate MCP",
      version: packageJson.version,
      packages: [
        {
          registryType: "npm",
          identifier: packageJson.name,
          version: packageJson.version,
          runtimeHint: "npx",
          transport: { type: "stdio" },
        },
      ],
    });
    expect(server.packages).toHaveLength(1);
    expect(server._meta).toBeUndefined();
    expect(packageJson.repository).toBeUndefined();
    expect(server.repository).toBeUndefined();
    expect(server.remotes).toBeUndefined();
  });

  it("marks only the API key as secret in package-level registry metadata", async () => {
    const server = JSON.parse(await text("server.json"));
    const variables = server.packages[0].environmentVariables;

    expect(variables).toEqual([
      expect.objectContaining({ name: "DECIONIS_API_KEY", isRequired: false, isSecret: true }),
      expect.objectContaining({ name: "DECIONIS_ORG_ID", isRequired: false, isSecret: false }),
      expect.objectContaining({ name: "DECIONIS_API_BASE", isRequired: false, isSecret: false }),
    ]);
  });

  it("documents the SHADOW-only, no-marketplace-write boundary in every entry point", async () => {
    const readme = await text("README.md");
    const smithery = await text("smithery.yaml");
    const server = await text("server.json");

    expect(readme).toContain("hard-locked to `SHADOW`");
    expect(readme).toContain(
      "exposes no order, price, refund, fulfillment, or inventory mutation tool",
    );
    expect(readme).toContain("APPROVE` is evidence, not user consent");
    expect(readme).toContain("npx -y @decionis/commerce@0.1.1");
    expect(readme).toContain("https://www.npmjs.com/package/@decionis/commerce");
    expect(readme).toContain("## Support and license");
    expect(readme).not.toContain("local-source-only");
    expect(smithery).toContain("fail closed");
    expect(smithery).toContain('command: "npx"');
    expect(smithery).toContain('args: ["-y", "@decionis/commerce@0.1.1"]');
    expect(smithery).not.toContain('command: "pnpm"');
    expect(server).toContain("Shadow Mode");
    for (const toolName of COMMERCEGATE_TOOL_NAMES) expect(readme).toContain(toolName);
  });

  it("ships the full Apache license text", async () => {
    const license = await text("LICENSE");
    expect(license).toContain("Apache License");
    expect(license).toContain("Version 2.0, January 2004");
    expect(license).toContain("END OF TERMS AND CONDITIONS");
  });
});
