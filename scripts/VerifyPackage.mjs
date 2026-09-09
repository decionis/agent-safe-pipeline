import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { access, lstat, mkdtemp, mkdir, readFile, readdir, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const binName = "commercegate-mcp";
const maximumOutputBytes = 1024 * 1024;
const smokeTimeoutMilliseconds = 10_000;
const credentialSentinel = "commercegate-release-smoke-secret";
const organizationSentinel = "00000000-0000-4000-8000-000000000001";

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
      maxBuffer: maximumOutputBytes,
      ...options,
    });
  } catch (error) {
    const exitCode = typeof error?.status === "number" ? error.status : "unknown";
    throw new Error(`${command} failed with exit code ${exitCode}.`, { cause: error });
  }
}

function requiredString(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string.`);
  assert.notEqual(value.trim(), "", `${label} must not be empty.`);
  return value;
}

function parsedResponses(stdout) {
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

async function verifyPackage() {
  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), "commercegate-mcp-package-"));

  try {
    const sourcePackage = JSON.parse(
      await readFile(path.join(packageDirectory, "package.json"), "utf8"),
    );
    const sourceManifest = JSON.parse(
      await readFile(path.join(packageDirectory, "server.json"), "utf8"),
    );
    const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
    const npmEnvironment = {
      ...safeEnvironment(),
      NPM_CONFIG_AUDIT: "false",
      NPM_CONFIG_CACHE: path.join(temporaryDirectory, "npm-cache"),
      NPM_CONFIG_FUND: "false",
      NPM_CONFIG_LOGLEVEL: "error",
      NPM_CONFIG_UPDATE_NOTIFIER: "false",
      NPM_CONFIG_USERCONFIG: path.join(temporaryDirectory, "empty-npmrc"),
    };
    run(npmCommand, ["pack", "--pack-destination", temporaryDirectory], {
      env: npmEnvironment,
    });
    const archives = (await readdir(temporaryDirectory, { withFileTypes: true }))
      .filter((entry) => entry.isFile() && entry.name.endsWith(".tgz"))
      .map((entry) => entry.name);
    assert.equal(archives.length, 1, "npm pack must produce exactly one tarball.");
    const archiveName = requiredString(archives[0], "npm pack filename");

    const archivePath = path.join(temporaryDirectory, archiveName);
    const extractionDirectory = path.join(temporaryDirectory, "unpacked");
    await mkdir(extractionDirectory);
    run("tar", ["-xzf", archivePath, "-C", extractionDirectory], {
      env: safeEnvironment(),
    });

    const packedRoot = await realpath(path.join(extractionDirectory, "package"));
    const packedPackage = JSON.parse(await readFile(path.join(packedRoot, "package.json"), "utf8"));
    const expectedName = requiredString(sourcePackage.name, "source package name");
    const expectedVersion = requiredString(sourcePackage.version, "source package version");
    const expectedMcpName = requiredString(sourcePackage.mcpName, "source package mcpName");

    assert.equal(packedPackage.name, expectedName, "Packed package name drifted.");
    assert.equal(packedPackage.version, expectedVersion, "Packed package version drifted.");
    assert.equal(packedPackage.mcpName, expectedMcpName, "Packed package mcpName drifted.");
    assert.equal(expectedMcpName, sourceManifest.name, "Package mcpName must match server.json.");
    assert.equal(
      expectedVersion,
      sourceManifest.version,
      "Package version must match server.json.",
    );

    const binRelativePath = requiredString(
      packedPackage.bin?.[binName],
      `packed package bin.${binName}`,
    );
    const packedBin = path.resolve(packedRoot, binRelativePath);
    const binStat = await lstat(packedBin);
    assert.ok(binStat.isFile(), `Packed ${binName} must be a regular file, not a symlink.`);
    const packedBinRealPath = await realpath(packedBin);
    const binPathFromRoot = path.relative(packedRoot, packedBinRealPath);
    assert.ok(
      binPathFromRoot !== "" &&
        binPathFromRoot !== ".." &&
        !binPathFromRoot.startsWith(`..${path.sep}`) &&
        !path.isAbsolute(binPathFromRoot),
      `Packed ${binName} path must stay inside the package.`,
    );
    await assert.doesNotReject(
      access(packedBinRealPath, fsConstants.X_OK),
      `Packed ${binName} must be executable.`,
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
    const executable = process.platform === "win32" ? process.execPath : packedBinRealPath;
    const executableArgs = process.platform === "win32" ? [packedBinRealPath] : [];
    const smoke = spawnSync(executable, executableArgs, {
      cwd: packedRoot,
      encoding: "utf8",
      env: {
        ...safeEnvironment(),
        DECIONIS_API_BASE: "http://127.0.0.1:9",
        DECIONIS_API_KEY: credentialSentinel,
        DECIONIS_ORG_ID: organizationSentinel,
      },
      input: `${requests.map((request) => JSON.stringify(request)).join("\n")}\n`,
      maxBuffer: maximumOutputBytes,
      timeout: smokeTimeoutMilliseconds,
    });
    const combinedOutput = `${smoke.stdout ?? ""}\n${smoke.stderr ?? ""}`;

    assert.equal(smoke.error, undefined, `Packed ${binName} failed to start over STDIO.`);
    assert.equal(smoke.status, 0, `Packed ${binName} exited with a failure status.`);
    assert.equal(smoke.signal, null, `Packed ${binName} was terminated by a signal.`);
    assert.equal(smoke.stderr, "", `Packed ${binName} wrote unexpected startup diagnostics.`);
    assert.ok(!combinedOutput.includes(credentialSentinel), "Packed MCP exposed an API key value.");
    assert.ok(
      !combinedOutput.includes(organizationSentinel),
      "Packed MCP exposed an organization identifier.",
    );

    const responses = parsedResponses(smoke.stdout);
    assert.equal(
      responses.size,
      requests.length,
      "Packed MCP returned an incomplete response set.",
    );
    assert.equal(
      responses.get(1)?.result?.serverInfo?.version,
      expectedVersion,
      "Packed MCP reported a different implementation version.",
    );
    assert.ok(
      responses
        .get(2)
        ?.result?.tools?.some((tool) => tool.name === "commercegate_describe_capabilities"),
      "Packed MCP tool catalog is missing commercegate_describe_capabilities.",
    );
    assert.equal(
      responses.get(3)?.result?.structuredContent?.guarantees?.credential_values_are_never_returned,
      true,
      "Packed MCP capability response did not preserve the credential-redaction guarantee.",
    );

    process.stdout.write(
      `Verified packed MCP package ${expectedName}@${expectedVersion}: ${binName} is executable and credential-safe over STDIO.\n`,
    );
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
}

await verifyPackage();
