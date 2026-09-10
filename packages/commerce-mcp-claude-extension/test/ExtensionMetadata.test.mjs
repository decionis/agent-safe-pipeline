import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { URL } from "node:url";

import {
  BUNDLE_FILES,
  MCPB_VERSION,
  PACKED_PACKAGE,
  TOOL_NAMES,
  VENDORED_RUNTIME_PACKAGE,
} from "../scripts/BundleContract.mjs";

const directory = new URL("../", import.meta.url);
const commerceDirectory = new URL("../commerce-mcp/", directory);
const read = (base, path) => readFile(new URL(path, base), "utf8");
const json = async (base, path) => JSON.parse(await read(base, path));

test("keeps the MIT extension separate from the Apache-2.0 runtime", async () => {
  const [extensionPackage, commercePackage, extensionLicense, commerceLicense, notices] =
    await Promise.all([
      json(directory, "package.json"),
      json(commerceDirectory, "package.json"),
      read(directory, "LICENSE"),
      read(commerceDirectory, "LICENSE"),
      read(directory, "THIRD_PARTY_NOTICES.md"),
    ]);

  assert.equal(extensionPackage.license, "MIT");
  assert.equal(
    extensionPackage.devDependencies["@decionis/commerce"],
    `workspace:${commercePackage.version}`,
  );
  assert.equal(extensionPackage.devDependencies["@anthropic-ai/mcpb"], MCPB_VERSION);
  assert.equal(extensionPackage.version, commercePackage.version);
  assert.equal(PACKED_PACKAGE.version, extensionPackage.version);
  assert.equal(VENDORED_RUNTIME_PACKAGE.version, commercePackage.version);
  assert.equal(VENDORED_RUNTIME_PACKAGE.license, commercePackage.license);
  assert.equal(JSON.stringify(PACKED_PACKAGE).includes("workspace:"), false);
  assert.equal(commercePackage.name, "@decionis/commerce");
  assert.equal(commercePackage.license, "Apache-2.0");
  assert.match(extensionLicense, /^MIT License$/m);
  assert.match(extensionLicense, /Copyright \(c\) 2026 Decionis, Inc\./);
  assert.equal(commerceLicense.includes("Apache License"), true);
  assert.match(notices, /runtime remains licensed under Apache License 2\.0/);
  assert.match(notices, /it is not relicensed under MIT/);
});

test("points discovery and privacy metadata at the canonical AgentSafe source", async () => {
  const manifest = await json(directory, "manifest.json");
  assert.equal(manifest.author.url, "https://github.com/decionis");
  assert.equal(manifest.repository.url, "https://github.com/decionis/agent-safe-pipeline.git");
  assert.deepEqual(manifest.privacy_policies, [
    "https://decionis.com/privacy",
    "https://github.com/decionis/agent-safe-pipeline/blob/master/packages/commerce-mcp-claude-extension/README.md#privacy-policy",
  ]);
});

test("uses the canonical copy and extension-subtree URLs", async () => {
  const [manifest, directoryListing, readme] = await Promise.all([
    json(directory, "manifest.json"),
    json(commerceDirectory, "directory-listing.json"),
    read(directory, "README.md"),
  ]);

  for (const field of [
    "name",
    "display_name",
    "description",
    "long_description",
    "user_config",
    "tools",
    "keywords",
    "compatibility",
  ]) {
    assert.deepEqual(manifest[field], directoryListing[field]);
  }
  assert.ok(
    readme.startsWith(`# Decionis CommerceGate for Claude Desktop\n\n${manifest.description}\n`),
  );
  const directoryCopy = readme
    .slice(readme.indexOf("## Directory description"))
    .split("<!-- markdownlint-disable MD034 -->")[1]
    ?.split("<!-- markdownlint-enable MD034 -->")[0]
    ?.trim();
  assert.equal(directoryCopy, manifest.long_description);
  assert.equal(manifest.author.url, "https://github.com/decionis");
  assert.equal(manifest.repository.url, "https://github.com/decionis/agent-safe-pipeline.git");
  assert.deepEqual(manifest.privacy_policies, [
    "https://decionis.com/privacy",
    "https://github.com/decionis/agent-safe-pipeline/blob/master/packages/commerce-mcp-claude-extension/README.md#privacy-policy",
  ]);
  assert.equal(manifest.license, "MIT");
  assert.equal(manifest.server.entry_point, "dist/Index.js");
  assert.deepEqual(manifest.tools.map(({ name }) => name).sort(), [...TOOL_NAMES].sort());
});

test("pins the MCPB tool and the mixed-license bundle allowlist", () => {
  assert.equal(MCPB_VERSION, "2.1.2");
  assert.deepEqual(BUNDLE_FILES, [
    "LICENSE",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "dist/Index.js",
    "icon.png",
    "manifest.json",
    "package.json",
    "vendor/commerce-mcp/Index.js",
    "vendor/commerce-mcp/LICENSE",
    "vendor/commerce-mcp/NOTICE",
    "vendor/commerce-mcp/package.json",
  ]);
});
