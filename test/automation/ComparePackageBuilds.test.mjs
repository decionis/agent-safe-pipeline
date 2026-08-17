import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { gzipSync } from "node:zlib";
import { comparePackageBuilds, listTarMembers } from "../../scripts/ComparePackageBuilds.mjs";

function tarWith(name, contents) {
  const payload = Buffer.from(contents);
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, "utf8");
  header.write(`${payload.length.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
  header.write("0", 156, 1, "ascii");
  return Buffer.concat([
    header,
    payload,
    Buffer.alloc(Math.ceil(payload.length / 512) * 512 - payload.length),
    Buffer.alloc(1024),
  ]);
}

describe("ComparePackageBuilds", () => {
  it("accepts byte-identical gzip and tar payloads", async () => {
    const directory = await mkdtemp(join(tmpdir(), "agent-safe-reproducible-"));
    const archive = gzipSync(tarWith("package/index.js", "export {};\n"));
    const first = join(directory, "first.tgz");
    const second = join(directory, "second.tgz");
    const reportPath = join(directory, "report.json");
    await Promise.all([writeFile(first, archive), writeFile(second, archive)]);

    const report = await comparePackageBuilds(first, second, reportPath);

    assert.equal(report.identical, true);
    assert.equal(report.archive_payload_identical, true);
    assert.equal(report.member_manifest_identical, true);
    assert.equal(JSON.parse(await readFile(reportPath, "utf8")).first.member_count, 1);
  });

  it("reports and rejects content drift", async () => {
    const directory = await mkdtemp(join(tmpdir(), "agent-safe-reproducible-"));
    const first = join(directory, "package.tgz");
    const second = join(directory, "package-copy.tgz");
    const reportPath = join(directory, "report.json");
    await Promise.all([
      writeFile(first, gzipSync(tarWith("package/index.js", "first\n"))),
      writeFile(second, gzipSync(tarWith("package/index.js", "second\n"))),
    ]);

    await assert.rejects(
      comparePackageBuilds(first, second, reportPath),
      /PACKAGE_BUILD_NOT_REPRODUCIBLE/,
    );
    const report = JSON.parse(await readFile(reportPath, "utf8"));
    assert.equal(report.identical, false);
    assert.equal(report.archive_payload_identical, false);
  });

  it("rejects truncated member data", () => {
    const tar = tarWith("package/index.js", "content").subarray(0, 512);
    assert.throws(() => listTarMembers(tar), /PACKAGE_TAR_TRUNCATED/);
  });
});
