import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { basename } from "node:path";
import { pathToFileURL } from "node:url";

const maxTarballBytes = 10 * 1024 * 1024;
const maxChecksumBytes = 100 * 1024;
const maxArchiveEntries = 1_000;
const maxCommandOutputBytes = 2 * 1024 * 1024;

export function checksumFor(checksums, filename) {
  const matches = [];
  for (const line of checksums.split(/\r?\n/)) {
    if (line.length === 0) continue;
    const match = /^([0-9a-f]{64}) [ *](.+)$/i.exec(line);
    if (match === null) throw new Error("BOOTSTRAP_CHECKSUMS_INVALID");
    if (match[2] === filename) matches.push(match[1].toLowerCase());
  }
  if (matches.length !== 1) throw new Error("BOOTSTRAP_CHECKSUM_ENTRY_INVALID");
  return matches[0];
}

export function validateArchiveEntries(entries) {
  const names = entries.split(/\r?\n/).filter(Boolean);
  if (names.length === 0 || names.length > maxArchiveEntries) {
    throw new Error("BOOTSTRAP_ARCHIVE_ENTRY_COUNT_INVALID");
  }

  const unique = new Set();
  for (const name of names) {
    const segments = name.split("/");
    if (
      name.length > 500 ||
      name.includes("\\") ||
      segments[0] !== "package" ||
      segments.some((segment) => segment === "" || segment === "." || segment === "..")
    ) {
      throw new Error("BOOTSTRAP_ARCHIVE_PATH_INVALID");
    }
    if (unique.has(name)) throw new Error("BOOTSTRAP_ARCHIVE_DUPLICATE_ENTRY");
    unique.add(name);

    const allowed =
      name === "package/package.json" ||
      name === "package/README.md" ||
      name === "package/LICENSE" ||
      name === "package/NOTICE" ||
      name.startsWith("package/dist/");
    if (!allowed) throw new Error("BOOTSTRAP_ARCHIVE_CONTENT_INVALID");
  }

  for (const required of [
    "package/package.json",
    "package/README.md",
    "package/LICENSE",
    "package/NOTICE",
    "package/dist/Index.js",
    "package/dist/Index.d.ts",
  ]) {
    if (!unique.has(required)) throw new Error("BOOTSTRAP_ARCHIVE_REQUIRED_FILE_MISSING");
  }
}

export function validatePackageManifest(manifest, expectedName, expectedVersion) {
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error("BOOTSTRAP_PACKAGE_MANIFEST_INVALID");
  }
  const expectedFiles = ["LICENSE", "NOTICE", "README.md", "dist"];
  const actualFiles = Array.isArray(manifest.files) ? [...manifest.files].sort() : [];
  if (
    manifest.name !== expectedName ||
    manifest.version !== expectedVersion ||
    manifest.private === true ||
    manifest.publishConfig?.access !== "public" ||
    manifest.publishConfig?.provenance !== true ||
    manifest.repository?.url !== "git+https://github.com/decionis/agent-safe-pipeline.git" ||
    JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)
  ) {
    throw new Error("BOOTSTRAP_PACKAGE_MANIFEST_MISMATCH");
  }
}

function runTar(arguments_) {
  const result = spawnSync("tar", arguments_, {
    encoding: "utf8",
    maxBuffer: maxCommandOutputBytes,
  });
  if (result.status !== 0 || result.signal !== null || result.error !== undefined) {
    throw new Error("BOOTSTRAP_ARCHIVE_INVALID");
  }
  return result.stdout;
}

export async function verifyBootstrapTarball({
  tarballPath,
  checksumsPath,
  expectedName,
  expectedVersion,
  expectedSha256,
}) {
  if (!/^[0-9a-f]{64}$/.test(expectedSha256)) {
    throw new Error("BOOTSTRAP_EXPECTED_DIGEST_INVALID");
  }
  const [tarballMetadata, checksumMetadata] = await Promise.all([
    stat(tarballPath),
    stat(checksumsPath),
  ]);
  if (!tarballMetadata.isFile() || tarballMetadata.size > maxTarballBytes) {
    throw new Error("BOOTSTRAP_TARBALL_SIZE_INVALID");
  }
  if (!checksumMetadata.isFile() || checksumMetadata.size > maxChecksumBytes) {
    throw new Error("BOOTSTRAP_CHECKSUMS_SIZE_INVALID");
  }

  const [tarball, checksums] = await Promise.all([
    readFile(tarballPath),
    readFile(checksumsPath, "utf8"),
  ]);
  const actualSha256 = createHash("sha256").update(tarball).digest("hex");
  if (
    actualSha256 !== expectedSha256 ||
    checksumFor(checksums, basename(tarballPath)) !== expectedSha256
  ) {
    throw new Error("BOOTSTRAP_TARBALL_DIGEST_MISMATCH");
  }

  validateArchiveEntries(runTar(["-tzf", tarballPath]));
  let manifest;
  try {
    manifest = JSON.parse(runTar(["-xOzf", tarballPath, "package/package.json"]));
  } catch {
    throw new Error("BOOTSTRAP_PACKAGE_MANIFEST_INVALID");
  }
  validatePackageManifest(manifest, expectedName, expectedVersion);
  return Object.freeze({ sha256: actualSha256, name: expectedName, version: expectedVersion });
}

async function main() {
  const [tarballPath, checksumsPath, expectedName, expectedVersion, expectedSha256] =
    process.argv.slice(2);
  if (!tarballPath || !checksumsPath || !expectedName || !expectedVersion || !expectedSha256) {
    throw new Error(
      "Usage: VerifyBootstrapTarball.mjs <tarball> <checksums> <name> <version> <sha256>",
    );
  }
  const verified = await verifyBootstrapTarball({
    tarballPath,
    checksumsPath,
    expectedName,
    expectedVersion,
    expectedSha256,
  });
  process.stdout.write(`Verified ${verified.name}@${verified.version} (${verified.sha256}).\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(
      (error instanceof Error ? error.message : "BOOTSTRAP_VERIFY_FAILED") + "\n",
    );
    process.exitCode = 1;
  });
}
