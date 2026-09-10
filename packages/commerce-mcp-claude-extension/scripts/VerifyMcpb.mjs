import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  BUNDLE_FILES,
  MCPB_VERSION,
  PACKED_PACKAGE,
  TOOL_NAMES,
  VENDORED_RUNTIME_PACKAGE,
} from "./BundleContract.mjs";
import { canonicalizeZipFile } from "./CanonicalizeZip.mjs";

const packageDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const commercePackageDirectory = path.resolve(packageDirectory, "../commerce-mcp");
const repositoryDirectory = path.resolve(packageDirectory, "../..");
const maximumOutputBytes = 1024 * 1024;
const smokeTimeoutMilliseconds = 10_000;
const reproducibleTimestamp = new Date("2000-01-01T00:00:00.000Z");

const sourceFiles = new Map([
  ["LICENSE", path.join(packageDirectory, "LICENSE")],
  ["README.md", path.join(packageDirectory, "README.md")],
  ["THIRD_PARTY_NOTICES.md", path.join(packageDirectory, "THIRD_PARTY_NOTICES.md")],
  ["dist/Index.js", path.join(packageDirectory, "dist", "Index.js")],
  ["icon.png", path.join(packageDirectory, "icon.png")],
  ["manifest.json", path.join(packageDirectory, "manifest.json")],
  ["vendor/commerce-mcp/Index.js", path.join(commercePackageDirectory, "dist", "Index.js")],
  ["vendor/commerce-mcp/LICENSE", path.join(commercePackageDirectory, "LICENSE")],
  ["vendor/commerce-mcp/NOTICE", path.join(repositoryDirectory, "NOTICE")],
]);

function requestedOutputPath(arguments_) {
  if (arguments_.length === 0) return undefined;
  assert.deepEqual(
    arguments_.slice(0, 1),
    ["--output"],
    "The only supported argument is --output <bundle.mcpb>.",
  );
  assert.equal(arguments_.length, 2, "--output requires exactly one path.");
  assert.ok(arguments_[1].endsWith(".mcpb"), "The output path must end in .mcpb.");
  return path.resolve(packageDirectory, arguments_[1]);
}

function safeEnvironment() {
  const allowedNames = new Set([
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "NODE_NO_WARNINGS",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "WINDIR",
  ]);

  return Object.fromEntries(
    Object.entries(process.env).filter(
      ([name, value]) => value !== undefined && allowedNames.has(name.toUpperCase()),
    ),
  );
}

function runCli(cliPath, arguments_, options = {}) {
  try {
    return execFileSync(process.execPath, [cliPath, ...arguments_], {
      cwd: packageDirectory,
      encoding: "utf8",
      env: safeEnvironment(),
      maxBuffer: maximumOutputBytes,
      ...options,
    });
  } catch (error) {
    const exitCode = typeof error?.status === "number" ? error.status : "unknown";
    throw new Error(`MCPB CLI failed with exit code ${exitCode}.`, { cause: error });
  }
}

async function inventory(directory, prefix = "") {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries.sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
  )) {
    const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
    const absolutePath = path.join(directory, entry.name);
    assert.ok(!entry.isSymbolicLink(), `${relativePath} must not be a symbolic link.`);
    if (entry.isDirectory()) {
      files.push(...(await inventory(absolutePath, relativePath)));
    } else {
      assert.ok(entry.isFile(), `${relativePath} must be a regular file.`);
      files.push(relativePath);
    }
  }

  return files;
}

async function normalizeTimestamps(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) await normalizeTimestamps(absolutePath);
    await utimes(absolutePath, reproducibleTimestamp, reproducibleTimestamp);
  }
  await utimes(directory, reproducibleTimestamp, reproducibleTimestamp);
}

async function stageBundle(stagingDirectory) {
  assert.deepEqual(
    [...sourceFiles.keys(), "package.json", "vendor/commerce-mcp/package.json"].sort(),
    BUNDLE_FILES,
    "Source map must exactly match the reviewed bundle allowlist.",
  );

  for (const [relativePath, sourcePath] of sourceFiles) {
    const sourceStat = await lstat(sourcePath);
    assert.ok(sourceStat.isFile(), `${relativePath} must come from a regular source file.`);
    assert.ok(!sourceStat.isSymbolicLink(), `${relativePath} source must not be a symlink.`);
    const destinationPath = path.join(stagingDirectory, ...relativePath.split("/"));
    await mkdir(path.dirname(destinationPath), { recursive: true });
    await copyFile(sourcePath, destinationPath);
  }
  await writeFile(
    path.join(stagingDirectory, "package.json"),
    `${JSON.stringify(PACKED_PACKAGE, null, 2)}\n`,
  );
  await writeFile(
    path.join(stagingDirectory, "vendor", "commerce-mcp", "package.json"),
    `${JSON.stringify(VENDORED_RUNTIME_PACKAGE, null, 2)}\n`,
  );

  assert.deepEqual(
    await inventory(stagingDirectory),
    BUNDLE_FILES,
    "MCPB staging must contain only the reviewed mixed-license files.",
  );
  await normalizeTimestamps(stagingDirectory);
}

function parseResponses(stdout) {
  const lines = stdout
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);

  return new Map(
    lines.map((line) => {
      const response = JSON.parse(line);
      return [response.id, response];
    }),
  );
}

async function verifyMetadata() {
  const [manifest, extensionPackage, commercePackage, directoryListing, readme] = await Promise.all(
    [
      readFile(path.join(packageDirectory, "manifest.json"), "utf8").then(JSON.parse),
      readFile(path.join(packageDirectory, "package.json"), "utf8").then(JSON.parse),
      readFile(path.join(commercePackageDirectory, "package.json"), "utf8").then(JSON.parse),
      readFile(path.join(commercePackageDirectory, "directory-listing.json"), "utf8").then(
        JSON.parse,
      ),
      readFile(path.join(packageDirectory, "README.md"), "utf8"),
    ],
  );
  assert.equal(extensionPackage.license, "MIT", "Extension wrapper must remain MIT.");
  assert.equal(commercePackage.license, "Apache-2.0", "Commerce runtime must remain Apache-2.0.");
  assert.equal(
    extensionPackage.devDependencies?.["@decionis/commerce"],
    `workspace:${commercePackage.version}`,
    "Extension must pin the workspace CommerceGate runtime version.",
  );
  assert.equal(
    extensionPackage.version,
    commercePackage.version,
    "Extension package and runtime versions must match.",
  );
  assert.equal(
    manifest.version,
    commercePackage.version,
    "Extension and runtime versions must match.",
  );
  assert.equal(manifest.license, "MIT", "MCPB manifest must describe the MIT wrapper.");
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
    assert.deepEqual(manifest[field], directoryListing[field], `Canonical ${field} drifted.`);
  }
  assert.equal(PACKED_PACKAGE.version, manifest.version, "Packed wrapper version drifted.");
  assert.equal(
    VENDORED_RUNTIME_PACKAGE.version,
    commercePackage.version,
    "Vendored runtime metadata version drifted.",
  );
  assert.equal(
    VENDORED_RUNTIME_PACKAGE.license,
    commercePackage.license,
    "Vendored runtime metadata license drifted.",
  );
  assert.ok(
    readme.startsWith(`# Decionis CommerceGate for Claude Desktop\n\n${manifest.description}\n`),
    "README short description drifted from the canonical copy.",
  );
  const directoryCopy = readme
    .slice(readme.indexOf("## Directory description"))
    .split("<!-- markdownlint-disable MD034 -->")[1]
    ?.split("<!-- markdownlint-enable MD034 -->")[0]
    ?.trim();
  assert.equal(directoryCopy, manifest.long_description, "README directory copy drifted.");
  assert.equal(manifest.server?.entry_point, "dist/Index.js", "MCPB must start the MIT loader.");
}

async function verifyMcpb() {
  const outputPath = requestedOutputPath(process.argv.slice(2));
  const configuredCli = process.env.MCPB_CLI_PATH;
  assert.ok(configuredCli, "MCPB_CLI_PATH must point to @anthropic-ai/mcpb 2.1.2 cli.js.");
  const cliPath = path.resolve(configuredCli);
  const cliStat = await lstat(cliPath);
  assert.ok(cliStat.isFile(), "Configured MCPB CLI must be a regular JavaScript file.");
  assert.ok(!cliStat.isSymbolicLink(), "Configured MCPB CLI must not be a symbolic link.");
  assert.equal(runCli(cliPath, ["--version"]).trim(), MCPB_VERSION, "Unexpected MCPB CLI version.");
  await verifyMetadata();

  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), "commercegate-claude-mcpb-"));
  try {
    const stagingDirectory = path.join(temporaryDirectory, "staging");
    const bundlePath = path.join(temporaryDirectory, "decionis-commercegate.mcpb");
    const repeatedBundlePath = path.join(temporaryDirectory, "decionis-commercegate-repeat.mcpb");
    const unpackedDirectory = path.join(temporaryDirectory, "unpacked");
    await mkdir(stagingDirectory);
    await stageBundle(stagingDirectory);

    runCli(cliPath, ["validate", path.join(stagingDirectory, "manifest.json")]);
    runCli(cliPath, ["pack", stagingDirectory, bundlePath]);
    runCli(cliPath, ["pack", stagingDirectory, repeatedBundlePath]);
    await canonicalizeZipFile(bundlePath);
    await canonicalizeZipFile(repeatedBundlePath);
    const bundle = await readFile(bundlePath);
    assert.deepEqual(
      await readFile(repeatedBundlePath),
      bundle,
      "Repeated MCPB packs must be byte-for-byte identical.",
    );
    runCli(cliPath, ["unpack", bundlePath, unpackedDirectory]);

    assert.deepEqual(
      await inventory(unpackedDirectory),
      BUNDLE_FILES,
      "Unpacked MCPB must contain only the reviewed mixed-license files.",
    );
    for (const relativePath of BUNDLE_FILES) {
      const staged = await readFile(path.join(stagingDirectory, ...relativePath.split("/")));
      const unpacked = await readFile(path.join(unpackedDirectory, ...relativePath.split("/")));
      assert.deepEqual(unpacked, staged, `Unpacked ${relativePath} drifted from staging.`);
    }
    const packedPackage = JSON.parse(
      await readFile(path.join(unpackedDirectory, "package.json"), "utf8"),
    );
    const vendoredRuntimePackage = JSON.parse(
      await readFile(
        path.join(unpackedDirectory, "vendor", "commerce-mcp", "package.json"),
        "utf8",
      ),
    );
    assert.equal(packedPackage.version, PACKED_PACKAGE.version);
    assert.deepEqual(vendoredRuntimePackage, VENDORED_RUNTIME_PACKAGE);
    assert.equal(
      JSON.stringify(packedPackage).includes("workspace:"),
      false,
      "Packed package metadata must not expose an unresolved workspace dependency.",
    );

    const requests = [
      {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-11-25", capabilities: {} },
      },
      { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "commercegate_describe_capabilities", arguments: {} },
      },
    ];
    const smoke = spawnSync(process.execPath, [path.join(unpackedDirectory, "dist", "Index.js")], {
      cwd: unpackedDirectory,
      encoding: "utf8",
      env: safeEnvironment(),
      input: `${requests.map((request) => JSON.stringify(request)).join("\n")}\n`,
      maxBuffer: maximumOutputBytes,
      timeout: smokeTimeoutMilliseconds,
    });

    assert.equal(smoke.error, undefined, "Unpacked MCPB failed to start over STDIO.");
    assert.equal(smoke.status, 0, "Unpacked MCPB exited with a failure status.");
    assert.equal(smoke.signal, null, "Unpacked MCPB was terminated by a signal.");
    assert.equal(smoke.stderr, "", "Unpacked MCPB wrote unexpected startup diagnostics.");

    const responses = parseResponses(smoke.stdout);
    assert.equal(responses.size, requests.length, "Unpacked MCPB returned incomplete responses.");
    assert.equal(
      responses.get(1)?.result?.serverInfo?.version,
      VENDORED_RUNTIME_PACKAGE.version,
      "Unpacked MCPB reported a different runtime version.",
    );
    assert.deepEqual(
      responses.get(2)?.result?.tools?.map((tool) => tool.name),
      TOOL_NAMES,
      "Unpacked MCPB tool catalog drifted from the seven public tools.",
    );
    const guarantees = responses.get(3)?.result?.structuredContent?.guarantees;
    assert.equal(guarantees?.marketplace_writes, false, "No-marketplace-write guarantee drifted.");
    assert.equal(guarantees?.erp_writes, false, "No-ERP-write guarantee drifted.");

    if (outputPath) {
      await mkdir(path.dirname(outputPath), { recursive: true });
      await copyFile(bundlePath, outputPath);
    }
    const sha256 = createHash("sha256").update(bundle).digest("hex");
    process.stdout.write(
      `Verified CommerceGate Claude MCPB with mcpb ${MCPB_VERSION}: deterministic mixed-license bundle ${sha256} and seven-tool JSON-RPC smoke passed${outputPath ? `; wrote ${outputPath}` : ""}.\n`,
    );
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
}

await verifyMcpb();
