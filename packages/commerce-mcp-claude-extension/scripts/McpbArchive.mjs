import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { deflateRawSync } from "node:zlib";
import { crc32, readZipEntries, REPRODUCIBLE_DOS_DATE } from "./CanonicalizeZip.mjs";

// Packs, unpacks and validates a Claude Desktop extension bundle (MCPB: a ZIP
// archive with manifest.json at its root) with Node's own zlib, so the bundle
// is built without a packaging CLI and its dependency tree. The archive is
// deterministic by construction: entries in byte order of their names, one
// fixed timestamp, UTF-8 names, no extra fields, comments or attributes. That
// is the canonical form CanonicalizeZip.mjs defines, so canonicalizing an
// archive built here changes nothing. Unpacking reads through the same checks
// CanonicalizeZip.mjs applies to every archive.

const UTF8_NAMES = 0x0800;
const VERSION = 20;
const DEFLATE = 8;

function localHeader(entry) {
  const header = Buffer.alloc(30);
  header.writeUInt32LE(0x04034b50, 0);
  header.writeUInt16LE(VERSION, 4);
  header.writeUInt16LE(UTF8_NAMES, 6);
  header.writeUInt16LE(DEFLATE, 8);
  header.writeUInt16LE(0, 10);
  header.writeUInt16LE(REPRODUCIBLE_DOS_DATE, 12);
  header.writeUInt32LE(entry.crc, 14);
  header.writeUInt32LE(entry.compressed.length, 18);
  header.writeUInt32LE(entry.payload.length, 22);
  header.writeUInt16LE(entry.nameBytes.length, 26);
  header.writeUInt16LE(0, 28);
  return header;
}

function centralHeader(entry, localOffset) {
  const header = Buffer.alloc(46);
  header.writeUInt32LE(0x02014b50, 0);
  header.writeUInt16LE(VERSION, 4);
  header.writeUInt16LE(VERSION, 6);
  header.writeUInt16LE(UTF8_NAMES, 8);
  header.writeUInt16LE(DEFLATE, 10);
  header.writeUInt16LE(0, 12);
  header.writeUInt16LE(REPRODUCIBLE_DOS_DATE, 14);
  header.writeUInt32LE(entry.crc, 16);
  header.writeUInt32LE(entry.compressed.length, 20);
  header.writeUInt32LE(entry.payload.length, 24);
  header.writeUInt16LE(entry.nameBytes.length, 28);
  header.writeUInt32LE(localOffset, 42);
  return header;
}

/** A deterministic ZIP of `files` ({name, payload}), entries in byte order of their names. */
export function packArchive(files) {
  const entries = files
    .map(({ name, payload }) => {
      assert.ok(Buffer.isBuffer(payload), `${name} must be a Buffer.`);
      return {
        nameBytes: Buffer.from(name, "utf8"),
        payload,
        crc: crc32(payload),
        compressed: deflateRawSync(payload, { level: 9 }),
      };
    })
    .sort((left, right) => Buffer.compare(left.nameBytes, right.nameBytes));
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const entry of entries) {
    const local = Buffer.concat([localHeader(entry), entry.nameBytes, entry.compressed]);
    centrals.push(Buffer.concat([centralHeader(entry, offset), entry.nameBytes]));
    locals.push(local);
    offset += local.length;
  }
  const central = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(offset, 16);
  const archive = Buffer.concat([...locals, central, end]);
  // Read it back through every check an unpack applies, so nothing is written
  // that this module would refuse to read.
  readZipEntries(archive);
  return archive;
}

/** Packs `relativePaths` (forward slashes) from `directory` into a bundle at `bundlePath`. */
export async function packBundle(directory, relativePaths, bundlePath) {
  const files = [];
  for (const name of relativePaths) {
    files.push({ name, payload: await readFile(path.join(directory, ...name.split("/"))) });
  }
  const archive = packArchive(files);
  await writeFile(bundlePath, archive);
  return archive;
}

/** Unpacks a bundle into `directory`, through CanonicalizeZip.mjs's name and payload checks. */
export async function unpackBundle(bundlePath, directory) {
  const entries = readZipEntries(await readFile(bundlePath));
  const root = path.resolve(directory);
  for (const { name, payload } of entries) {
    const target = path.resolve(root, ...name.split("/"));
    assert.ok(target.startsWith(`${root}${path.sep}`), `${name} escapes the unpack directory.`);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, payload);
  }
  return entries.map(({ name }) => name);
}

const MANIFEST_KEYS = new Set([
  "manifest_version",
  "name",
  "display_name",
  "version",
  "description",
  "long_description",
  "author",
  "repository",
  "homepage",
  "documentation",
  "support",
  "icon",
  "screenshots",
  "server",
  "tools",
  "tools_generated",
  "prompts",
  "prompts_generated",
  "keywords",
  "license",
  "privacy_policies",
  "compatibility",
  "user_config",
]);
const SERVER_TYPES = new Set(["node", "python", "binary", "uv"]);
const PLATFORMS = new Set(["darwin", "win32", "linux"]);
const USER_CONFIG_TYPES = new Set(["string", "number", "boolean", "directory", "file"]);
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u;

function text(value, label) {
  assert.ok(typeof value === "string" && value.trim() !== "", `manifest ${label} must be text.`);
}

function optionalText(object, key, label = key) {
  if (object[key] !== undefined) text(object[key], label);
}

function bundlePath(value, label, files) {
  text(value, label);
  assert.ok(
    !value.startsWith("/") && !value.split("/").includes(".."),
    `${label} must be relative.`,
  );
  assert.ok(files.has(value), `${label} names ${value}, which the bundle does not contain.`);
}

/**
 * Checks a manifest against the MCPB 0.3 fields this bundle can use: the
 * required ones are present and typed, every path it names is in the bundle,
 * and no field outside the format is present.
 */
export function validateManifest(manifest, bundleFiles) {
  const files = new Set(bundleFiles);
  assert.ok(
    manifest && typeof manifest === "object" && !Array.isArray(manifest),
    "manifest must be an object.",
  );
  for (const key of Object.keys(manifest)) {
    assert.ok(MANIFEST_KEYS.has(key), `manifest field ${key} is not part of MCPB 0.3.`);
  }
  assert.equal(manifest.manifest_version, "0.3", "manifest_version must be 0.3.");
  text(manifest.name, "name");
  assert.match(
    manifest.name,
    /^[a-z0-9][a-z0-9-]*$/u,
    "manifest name must be lower-case and hyphenated.",
  );
  text(manifest.version, "version");
  assert.match(manifest.version, SEMVER, "manifest version must be semantic.");
  text(manifest.description, "description");
  for (const key of [
    "display_name",
    "long_description",
    "homepage",
    "documentation",
    "support",
    "license",
  ]) {
    optionalText(manifest, key);
  }
  assert.ok(
    manifest.author && typeof manifest.author === "object",
    "manifest author must be an object.",
  );
  text(manifest.author.name, "author.name");
  optionalText(manifest.author, "email", "author.email");
  optionalText(manifest.author, "url", "author.url");
  if (manifest.repository !== undefined) {
    text(manifest.repository.type, "repository.type");
    text(manifest.repository.url, "repository.url");
  }
  if (manifest.icon !== undefined) bundlePath(manifest.icon, "icon", files);

  const server = manifest.server;
  assert.ok(server && typeof server === "object", "manifest server must be an object.");
  assert.ok(
    SERVER_TYPES.has(server.type),
    `server.type ${server.type} is not an MCPB server type.`,
  );
  bundlePath(server.entry_point, "server.entry_point", files);
  const config = server.mcp_config;
  assert.ok(config && typeof config === "object", "server.mcp_config must be an object.");
  text(config.command, "server.mcp_config.command");
  assert.ok(
    Array.isArray(config.args) && config.args.every((argument) => typeof argument === "string"),
    "server.mcp_config.args must be a list of strings.",
  );
  if (config.env !== undefined) {
    for (const [name, value] of Object.entries(config.env)) {
      assert.equal(typeof value, "string", `server.mcp_config.env.${name} must be text.`);
    }
  }

  for (const key of ["tools", "prompts"]) {
    if (manifest[key] === undefined) continue;
    assert.ok(Array.isArray(manifest[key]), `manifest ${key} must be a list.`);
    for (const item of manifest[key]) {
      text(item.name, `${key}[].name`);
      optionalText(item, "description", `${key}[].description`);
    }
  }
  for (const key of ["keywords", "privacy_policies", "screenshots"]) {
    if (manifest[key] === undefined) continue;
    assert.ok(Array.isArray(manifest[key]), `manifest ${key} must be a list.`);
    manifest[key].forEach((item) => text(item, `${key}[]`));
  }
  if (manifest.user_config !== undefined) {
    for (const [name, option] of Object.entries(manifest.user_config)) {
      assert.ok(
        USER_CONFIG_TYPES.has(option.type),
        `user_config.${name}.type is not an MCPB type.`,
      );
      text(option.title, `user_config.${name}.title`);
      text(option.description, `user_config.${name}.description`);
      for (const flag of ["required", "sensitive", "multiple"]) {
        if (option[flag] !== undefined) {
          assert.equal(
            typeof option[flag],
            "boolean",
            `user_config.${name}.${flag} must be true or false.`,
          );
        }
      }
    }
  }
  if (manifest.compatibility !== undefined) {
    const { platforms, runtimes, claude_desktop: claudeDesktop } = manifest.compatibility;
    if (claudeDesktop !== undefined) text(claudeDesktop, "compatibility.claude_desktop");
    if (platforms !== undefined) {
      assert.ok(Array.isArray(platforms), "compatibility.platforms must be a list.");
      for (const platform of platforms) {
        assert.ok(PLATFORMS.has(platform), `compatibility.platforms has unknown ${platform}.`);
      }
    }
    if (runtimes !== undefined) {
      for (const [runtime, range] of Object.entries(runtimes))
        text(range, `compatibility.runtimes.${runtime}`);
    }
  }
}
