import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalizeZipArchive, readZipEntries } from "../scripts/CanonicalizeZip.mjs";
import {
  packArchive,
  packBundle,
  unpackBundle,
  validateManifest,
} from "../scripts/McpbArchive.mjs";

const FILES = [
  { name: "server/index.js", payload: Buffer.from("console.log('ok');\n") },
  { name: "manifest.json", payload: Buffer.from("{}\n") },
  { name: "icon.png", payload: Buffer.alloc(0) },
];

function manifest(overrides = {}) {
  return {
    manifest_version: "0.3",
    name: "example-extension",
    version: "1.2.3",
    description: "An example.",
    author: { name: "Example" },
    icon: "icon.png",
    server: {
      type: "node",
      entry_point: "server/index.js",
      mcp_config: { command: "node", args: ["${__dirname}/server/index.js"], env: {} },
    },
    ...overrides,
  };
}

const BUNDLE = ["manifest.json", "icon.png", "server/index.js"];

test("packs deterministically whatever the input order", () => {
  const first = packArchive(FILES);
  assert.deepEqual(packArchive([...FILES].reverse()), first);
  assert.deepEqual(
    readZipEntries(first).map(({ name }) => name),
    ["icon.png", "manifest.json", "server/index.js"],
  );
});

test("packs in the canonical form CanonicalizeZip.mjs defines", () => {
  const archive = packArchive(FILES);
  assert.deepEqual(canonicalizeZipArchive(Buffer.from(archive)), archive);
});

test("round-trips every payload, including an empty one", () => {
  const entries = readZipEntries(packArchive(FILES));
  for (const file of FILES) {
    assert.deepEqual(entries.find(({ name }) => name === file.name).payload, file.payload);
  }
});

test("refuses to pack a name that escapes the bundle", () => {
  assert.throws(() => packArchive([{ name: "../outside.js", payload: Buffer.from("x") }]));
  assert.throws(() => packArchive([{ name: "/absolute.js", payload: Buffer.from("x") }]));
});

test("packs a directory and unpacks the same files", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "mcpb-archive-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const source = path.join(directory, "source");
  const target = path.join(directory, "target");
  for (const { name, payload } of FILES) {
    const file = path.join(source, ...name.split("/"));
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, payload);
  }
  const bundlePath = path.join(directory, "bundle.mcpb");
  const archive = await packBundle(source, BUNDLE, bundlePath);
  assert.deepEqual(await readFile(bundlePath), archive);
  assert.deepEqual((await unpackBundle(bundlePath, target)).sort(), [...BUNDLE].sort());
  for (const { name, payload } of FILES) {
    assert.deepEqual(await readFile(path.join(target, ...name.split("/"))), payload);
  }
});

test("accepts a complete MCPB 0.3 manifest", () => {
  validateManifest(
    manifest({
      tools: [{ name: "lookup", description: "Looks up." }],
      user_config: {
        api_key: { type: "string", title: "Key", description: "The key.", sensitive: true },
      },
      compatibility: { platforms: ["darwin", "win32"], runtimes: { node: ">=20" } },
      privacy_policies: ["https://example.com/privacy"],
    }),
    BUNDLE,
  );
});

test("refuses manifests outside MCPB 0.3", () => {
  const refusals = [
    [manifest({ manifest_version: "0.2" }), /manifest_version/u],
    [manifest({ unknown_field: true }), /unknown_field/u],
    [manifest({ name: "Not Lower" }), /name/u],
    [manifest({ version: "1.2" }), /version/u],
    [manifest({ author: {} }), /author\.name/u],
    [manifest({ icon: "missing.png" }), /icon/u],
    [manifest({ icon: "../icon.png" }), /icon/u],
    [manifest({ server: { ...manifest().server, type: "ruby" } }), /server\.type/u],
    [
      manifest({ server: { ...manifest().server, entry_point: "server/other.js" } }),
      /entry_point/u,
    ],
    [
      manifest({ server: { ...manifest().server, mcp_config: { command: "node", args: [1] } } }),
      /args/u,
    ],
    [
      manifest({ user_config: { x: { type: "secret", title: "X", description: "X." } } }),
      /user_config/u,
    ],
    [manifest({ compatibility: { platforms: ["beos"] } }), /platforms/u],
  ];
  for (const [candidate, message] of refusals) {
    assert.throws(() => validateManifest(candidate, BUNDLE), message);
  }
});
