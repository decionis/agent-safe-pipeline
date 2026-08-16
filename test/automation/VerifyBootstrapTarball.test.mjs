import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  checksumFor,
  validateArchiveEntries,
  validatePackageManifest,
} from "../../scripts/VerifyBootstrapTarball.mjs";

const requiredEntries = [
  "package/package.json",
  "package/README.md",
  "package/LICENSE",
  "package/NOTICE",
  "package/dist/Index.js",
  "package/dist/Index.d.ts",
].join("\n");

const packageManifest = {
  name: "@decionis/agent-safe-pipeline",
  version: "0.1.2",
  files: ["dist", "README.md", "LICENSE", "NOTICE"],
  repository: { url: "git+https://github.com/decionis/agent-safe-pipeline.git" },
  publishConfig: { access: "public", provenance: true },
};

describe("VerifyBootstrapTarball", () => {
  it("accepts the exact package surface and manifest", () => {
    assert.doesNotThrow(() => validateArchiveEntries(requiredEntries));
    assert.doesNotThrow(() =>
      validatePackageManifest(packageManifest, "@decionis/agent-safe-pipeline", "0.1.2"),
    );
  });

  it("rejects traversal, duplicate, and unexpected archive entries", () => {
    for (const entry of [
      "package/../outside",
      "package/dist/Index.js\\extra",
      "other/package.json",
      "package/private.pem",
    ]) {
      assert.throws(() => validateArchiveEntries(requiredEntries + "\n" + entry), /BOOTSTRAP_/);
    }
    assert.throws(
      () => validateArchiveEntries(requiredEntries + "\npackage/dist/Index.js"),
      /BOOTSTRAP_ARCHIVE_DUPLICATE_ENTRY/,
    );
  });

  it("rejects a missing required package file", () => {
    assert.throws(
      () => validateArchiveEntries(requiredEntries.replace("package/NOTICE\n", "")),
      /BOOTSTRAP_ARCHIVE_REQUIRED_FILE_MISSING/,
    );
  });

  it("rejects publication metadata drift", () => {
    for (const changed of [
      { ...packageManifest, version: "0.1.3" },
      { ...packageManifest, private: true },
      { ...packageManifest, files: ["dist", "README.md", "LICENSE", "NOTICE", "extra"] },
      { ...packageManifest, publishConfig: { access: "restricted", provenance: true } },
      { ...packageManifest, repository: { url: "https://example.invalid/project" } },
    ]) {
      assert.throws(
        () => validatePackageManifest(changed, "@decionis/agent-safe-pipeline", "0.1.2"),
        /BOOTSTRAP_PACKAGE_MANIFEST_MISMATCH/,
      );
    }
  });

  it("requires exactly one valid checksum entry", () => {
    const digest = "a".repeat(64);
    assert.equal(checksumFor(`${digest}  package.tgz\n`, "package.tgz"), digest);
    assert.throws(() => checksumFor(`${digest}  other.tgz\n`, "package.tgz"), /CHECKSUM_ENTRY/);
    assert.throws(
      () => checksumFor(`${digest}  package.tgz\n${digest}  package.tgz\n`, "package.tgz"),
      /CHECKSUM_ENTRY/,
    );
    assert.throws(() => checksumFor("not-a-checksum\n", "package.tgz"), /CHECKSUMS_INVALID/);
  });
});
