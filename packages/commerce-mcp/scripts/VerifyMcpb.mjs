import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { lstat, mkdir, mkdtemp, readFile, readdir, rm, copyFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const mcpbVersion = "2.1.2";
const maximumOutputBytes = 1024 * 1024;
const smokeTimeoutMilliseconds = 10_000;
const stagedFiles = [
  "LICENSE",
  "README.md",
  "dist/Index.js",
  "icon.png",
  "manifest.json",
  "package.json",
];
const expectedToolNames = [
  "commercegate_describe_capabilities",
  "commercegate_validate_erp_transaction",
  "commercegate_evaluate_action",
  "commercegate_get_dossier",
  "commercegate_get_proof_packet",
  "commercegate_list_shadow_reports",
  "commercegate_summarize_shadow_reports",
];

function sortedFiles(files) {
  return [...files].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
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

function run(command, args, options = {}) {
  try {
    return execFileSync(command, args, {
      cwd: packageDirectory,
      encoding: "utf8",
      env: safeEnvironment(),
      maxBuffer: maximumOutputBytes,
      ...options,
    });
  } catch (error) {
    const exitCode = typeof error?.status === "number" ? error.status : "unknown";
    throw new Error(`${command} failed with exit code ${exitCode}.`, { cause: error });
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

async function copyReviewerFiles(stagingDirectory) {
  for (const relativePath of stagedFiles) {
    const sourcePath = path.join(packageDirectory, ...relativePath.split("/"));
    const sourceStat = await lstat(sourcePath);
    assert.ok(sourceStat.isFile(), `${relativePath} must be a regular source file.`);
    assert.ok(!sourceStat.isSymbolicLink(), `${relativePath} must not be a source symlink.`);

    const destinationPath = path.join(stagingDirectory, ...relativePath.split("/"));
    await mkdir(path.dirname(destinationPath), { recursive: true });
    await copyFile(sourcePath, destinationPath);
  }

  assert.deepEqual(
    await inventory(stagingDirectory),
    sortedFiles(stagedFiles),
    "MCPB staging must contain only the approved runtime and reviewer files.",
  );
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

async function verifyMcpb() {
  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), "commercegate-mcpb-"));
  const configuredMcpbCli = process.env.MCPB_CLI_PATH;
  const mcpbCommand = configuredMcpbCli
    ? process.execPath
    : process.platform === "win32"
      ? "mcpb.cmd"
      : "mcpb";
  const mcpbPrefix = configuredMcpbCli ? [path.resolve(configuredMcpbCli)] : [];

  try {
    const stagingDirectory = path.join(temporaryDirectory, "staging");
    const bundlePath = path.join(temporaryDirectory, "decionis-commercegate.mcpb");
    const unpackedDirectory = path.join(temporaryDirectory, "unpacked");
    await mkdir(stagingDirectory);
    await copyReviewerFiles(stagingDirectory);

    const manifest = JSON.parse(
      await readFile(path.join(stagingDirectory, "manifest.json"), "utf8"),
    );
    const packageManifest = JSON.parse(
      await readFile(path.join(stagingDirectory, "package.json"), "utf8"),
    );
    assert.equal(manifest.version, packageManifest.version, "MCPB and npm versions must match.");
    assert.equal(
      manifest.server?.entry_point,
      "dist/Index.js",
      "MCPB entry point must be the reviewed bundled server.",
    );

    if (configuredMcpbCli) {
      const cliStat = await lstat(mcpbPrefix[0]);
      assert.ok(cliStat.isFile(), "Configured MCPB CLI must be a regular file.");
      assert.ok(!cliStat.isSymbolicLink(), "Configured MCPB CLI must not be a symbolic link.");
    }
    assert.equal(
      run(mcpbCommand, [...mcpbPrefix, "--version"]).trim(),
      mcpbVersion,
      "Unexpected MCPB CLI version.",
    );
    run(mcpbCommand, [...mcpbPrefix, "validate", path.join(stagingDirectory, "manifest.json")]);
    run(mcpbCommand, [...mcpbPrefix, "pack", stagingDirectory, bundlePath]);
    run(mcpbCommand, [...mcpbPrefix, "unpack", bundlePath, unpackedDirectory]);

    assert.deepEqual(
      await inventory(unpackedDirectory),
      sortedFiles(stagedFiles),
      "Unpacked MCPB must contain only the approved runtime and reviewer files.",
    );
    for (const relativePath of stagedFiles) {
      const staged = await readFile(path.join(stagingDirectory, ...relativePath.split("/")));
      const unpacked = await readFile(path.join(unpackedDirectory, ...relativePath.split("/")));
      assert.deepEqual(unpacked, staged, `Unpacked ${relativePath} drifted from staging.`);
    }

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
    const entryPoint = path.join(unpackedDirectory, "dist", "Index.js");
    const smoke = spawnSync(process.execPath, [entryPoint], {
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
      manifest.version,
      "Unpacked MCPB reported a different implementation version.",
    );
    assert.deepEqual(
      responses.get(2)?.result?.tools?.map((tool) => tool.name),
      expectedToolNames,
      "Unpacked MCPB tool catalog drifted from the seven public tools.",
    );
    const guarantees = responses.get(3)?.result?.structuredContent?.guarantees;
    assert.equal(
      guarantees?.marketplace_writes,
      false,
      "Unpacked MCPB capability response lost its no-marketplace-write guarantee.",
    );
    assert.equal(
      guarantees?.erp_writes,
      false,
      "Unpacked MCPB capability response lost its no-ERP-write guarantee.",
    );

    process.stdout.write(
      `Verified CommerceGate MCPB ${manifest.version} with mcpb ${mcpbVersion}: clean bundle and JSON-RPC smoke test passed.\n`,
    );
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
}

await verifyMcpb();
