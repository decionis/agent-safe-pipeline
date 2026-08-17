import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import { basename } from "node:path";
import { pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";

const maxArchiveBytes = 50 * 1024 * 1024;
const tarBlockBytes = 512;
const maxMembers = 10_000;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function readString(buffer, start, length) {
  const end = buffer.indexOf(0, start);
  const boundedEnd = end === -1 || end > start + length ? start + length : end;
  return buffer.subarray(start, boundedEnd).toString("utf8");
}

function parseOctal(buffer, start, length) {
  const value = readString(buffer, start, length).trim();
  if (!/^[0-7]*$/.test(value)) throw new Error("PACKAGE_TAR_SIZE_INVALID");
  return value === "" ? 0 : Number.parseInt(value, 8);
}

export function listTarMembers(tar) {
  const members = [];
  let offset = 0;
  while (offset + tarBlockBytes <= tar.length) {
    const header = tar.subarray(offset, offset + tarBlockBytes);
    if (header.every((byte) => byte === 0)) break;
    if (members.length >= maxMembers) throw new Error("PACKAGE_TAR_MEMBER_LIMIT_EXCEEDED");

    const name = readString(header, 0, 100);
    const prefix = readString(header, 345, 155);
    const size = parseOctal(header, 124, 12);
    const type = readString(header, 156, 1) || "0";
    if (name === "") throw new Error("PACKAGE_TAR_MEMBER_NAME_MISSING");
    if (!Number.isSafeInteger(size) || size < 0) throw new Error("PACKAGE_TAR_SIZE_INVALID");

    members.push({ name: prefix === "" ? name : `${prefix}/${name}`, size, type });
    offset += tarBlockBytes + Math.ceil(size / tarBlockBytes) * tarBlockBytes;
    if (offset > tar.length) throw new Error("PACKAGE_TAR_TRUNCATED");
  }
  if (members.length === 0) throw new Error("PACKAGE_TAR_EMPTY");
  return members;
}

export async function inspectPackageArchive(path) {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size === 0 || metadata.size > maxArchiveBytes) {
    throw new Error("PACKAGE_ARCHIVE_SIZE_INVALID");
  }
  const gzip = await readFile(path);
  const tar = gunzipSync(gzip, { maxOutputLength: maxArchiveBytes });
  const members = listTarMembers(tar);
  return Object.freeze({
    filename: basename(path),
    size_bytes: gzip.length,
    gzip_sha256: sha256(gzip),
    tar_sha256: sha256(tar),
    member_count: members.length,
    member_manifest_sha256: sha256(JSON.stringify(members)),
  });
}

export async function comparePackageBuilds(firstPath, secondPath, reportPath) {
  const [first, second] = await Promise.all([
    inspectPackageArchive(firstPath),
    inspectPackageArchive(secondPath),
  ]);
  const report = {
    schema_version: 1,
    package: first.filename,
    identical: first.size_bytes === second.size_bytes && first.gzip_sha256 === second.gzip_sha256,
    archive_payload_identical: first.tar_sha256 === second.tar_sha256,
    member_manifest_identical:
      first.member_count === second.member_count &&
      first.member_manifest_sha256 === second.member_manifest_sha256,
    first,
    second,
  };
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, { flag: "wx" });
  if (!report.identical || !report.archive_payload_identical || !report.member_manifest_identical) {
    throw new Error("PACKAGE_BUILD_NOT_REPRODUCIBLE");
  }
  return Object.freeze(report);
}

async function main() {
  const [firstPath, secondPath, reportPath] = process.argv.slice(2);
  if (!firstPath || !secondPath || !reportPath) {
    throw new Error("Usage: ComparePackageBuilds.mjs <first.tgz> <second.tgz> <report.json>");
  }
  const report = await comparePackageBuilds(firstPath, secondPath, reportPath);
  process.stdout.write(
    `Reproducible package verified: ${report.package} sha256:${report.first.gzip_sha256}\n`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : "PACKAGE_COMPARE_FAILED"}\n`);
    process.exitCode = 1;
  });
}
