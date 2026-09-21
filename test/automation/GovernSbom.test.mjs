import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { writeZip } from "../../scripts/ArchiveExecutable.mjs";
import {
  BUILD_COMMAND,
  executableOf,
  parseModules,
  readBuildInfo,
  renderSbom,
} from "../../scripts/GovernSbom.mjs";
import { archiveName, TARGETS } from "../../scripts/RenderGovernRelease.mjs";

const MAIN = "github.com/decionis/agent-safe-pipeline/govern/v2";
const JCS_SUM = "h1:Qjzg8EOkrOTuWP7DqQ1FbYtcpEbeTzUoTN9bptp8FOU=";

/** A varint as Go encodes lengths. */
function uvarint(value) {
  const bytes = [];
  let rest = value;
  while (rest >= 0x80) {
    bytes.push((rest % 0x80) | 0x80);
    rest = Math.floor(rest / 0x80);
  }
  bytes.push(rest);
  return Buffer.from(bytes);
}

/**
 * Bytes shaped like a Go executable's build information: the linker's
 * 32-byte header (magic, pointer size, the flag for inline strings), then the
 * toolchain version and the module record, each behind its length, the
 * record wrapped in the toolchain's own start and end markers, and some bytes
 * on either side standing in for the rest of the file.
 */
function executableWith({ goVersion = "go1.26.4", record }) {
  const header = Buffer.alloc(32);
  Buffer.from("\xff Go buildinf:", "latin1").copy(header);
  header[14] = 8;
  header[15] = 0x2;
  const start = Buffer.from("3077af0c9274080241e1c107e6d618e6", "hex");
  const end = Buffer.from("f932433186182072008242104116d8f2", "hex");
  const modules = Buffer.concat([start, Buffer.from(record, "utf8"), end]);
  return Buffer.concat([
    Buffer.from("MZ not really a program, but bytes before the record\0"),
    header,
    uvarint(Buffer.byteLength(goVersion)),
    Buffer.from(goVersion),
    uvarint(modules.length),
    modules,
    Buffer.from("\0and bytes after it"),
  ]);
}

const recordFor = (target, { deps, cgo = "0", trimpath = "true", main = MAIN } = {}) => {
  const [os, arch] = target.split("-");
  const lines = [
    `path\t${MAIN}/cmd/govern`,
    `mod\t${main}\t(devel)\t`,
    ...(deps ?? [`dep\tgithub.com/gowebpki/jcs\tv1.0.1\t${JCS_SUM}`]),
    "build\t-buildmode=exe",
    "build\t-compiler=gc",
    `build\t-trimpath=${trimpath}`,
    "build\tDefaultGODEBUG=asynctimerchan=1,winsymlink=0",
    `build\tCGO_ENABLED=${cgo}`,
    `build\tGOARCH=${arch === "x64" ? "amd64" : "arm64"}`,
    `build\tGOOS=${os}`,
    arch === "x64" ? "build\tGOAMD64=v1" : "build\tGOARM64=v8.0",
  ];
  return `${lines.join("\n")}\n`;
};

const archiveFor = (target, options = {}) => {
  const executable = executableWith({ ...options, record: recordFor(target, options) });
  return {
    name: archiveName("2.0.0", target),
    version: "2.0.0",
    target,
    sha256: createHash("sha256").update(executable).digest("hex"),
    executable,
  };
};

const allArchives = (options) => TARGETS.map((target) => archiveFor(target, options));

/**
 * Govern's SBOM is read from the shipped executables: the modules a Go
 * binary records in itself, the toolchain, the build settings. These gates
 * hold the reader to Go's format, the SBOM to the release's rules (no
 * timestamp, a serial number from the bytes, every archive's checksum), and
 * the refusals to what they refuse: an archive built for another target,
 * with another build, or from other modules.
 */
describe("govern's SBOM", () => {
  it("reads the build information Go writes into an executable", () => {
    const info = readBuildInfo(executableWith({ record: recordFor("linux-x64") }));
    assert.equal(info.goVersion, "go1.26.4");
    assert.equal(info.modules.path, `${MAIN}/cmd/govern`);
    assert.deepEqual(info.modules.main, { path: MAIN, version: "(devel)", sum: "" });
    assert.deepEqual(info.modules.deps, [
      { path: "github.com/gowebpki/jcs", version: "v1.0.1", sum: JCS_SUM },
    ]);
    assert.equal(info.modules.settings.get("GOOS"), "linux");
    assert.equal(info.modules.settings.get("DefaultGODEBUG"), "asynctimerchan=1,winsymlink=0");
    assert.throws(() => readBuildInfo(Buffer.from("no record here")), /no Go build information/);
    const old = executableWith({ record: recordFor("linux-x64") });
    old[old.indexOf(Buffer.from("\xff Go buildinf:", "latin1")) + 15] = 0;
    assert.throws(() => readBuildInfo(old), /predates Go 1\.18/);
  });

  it("parses a replacement, refuses a line it does not know, and needs a main module", () => {
    const record = parseModules(
      [
        "path\tx/cmd",
        "mod\tx\t(devel)\t",
        "dep\texample.com/a\tv1.0.0\th1:AAAA",
        "dep\texample.com/b\tv1.0.0\th1:BBBB",
        "=>\texample.com/b-fork\tv1.0.1\th1:CCCC",
        "build\t-ldflags=-X main.v=1=2",
        "",
      ].join("\n"),
    );
    assert.deepEqual(record.deps[1], {
      path: "example.com/b-fork",
      version: "v1.0.1",
      sum: "h1:CCCC",
      replaces: "example.com/b@v1.0.0",
    });
    assert.equal(record.settings.get("-ldflags"), "-X main.v=1=2");
    assert.throws(() => parseModules("=>\tx\tv1\th1:A\n"), /no module before it/);
    assert.throws(() => parseModules("mod\tx\t(devel)\t\nfoo\tbar\n"), /unknown line/);
    assert.throws(() => parseModules("build\tnovalue\n"), /without a value/);
    assert.throws(() => parseModules("path\tx\n"), /names no main module/);
  });

  describe("read from the archives the release ships", () => {
    let work;
    before(() => {
      work = mkdtempSync(join(tmpdir(), "govern-sbom-"));
    });
    after(() => {
      rmSync(work, { recursive: true, force: true });
    });

    it("takes the executable out of the tarball and out of the zip alike", () => {
      const executable = executableWith({ record: recordFor("windows-x64") });
      const staging = join(work, "staging");
      mkdirSync(join(staging, "govern-2.0.0-windows-x64"), { recursive: true });
      writeFileSync(join(staging, "govern-2.0.0-windows-x64", "govern.exe"), executable);
      writeFileSync(join(staging, "govern-2.0.0-windows-x64", "LICENSE"), "license\n");
      const zip = join(work, "govern-2.0.0-windows-x64.zip");
      writeZip(zip, staging, "govern-2.0.0-windows-x64");
      const fromZip = executableOf(zip);
      assert.equal(fromZip.target, "windows-x64");
      assert.equal(fromZip.version, "2.0.0");
      assert.equal(fromZip.name, "govern-2.0.0-windows-x64.zip");
      assert.ok(fromZip.executable.equals(executable));
      assert.equal(fromZip.sha256, createHash("sha256").update(readFileSync(zip)).digest("hex"));
      // The zip is one the platform's own tools read: the same bytes come back.
      const unzip = spawnSync("unzip", ["-p", zip, "govern-2.0.0-windows-x64/govern.exe"]);
      if (unzip.status === 0) assert.ok(unzip.stdout.equals(executable));

      const linux = executableWith({ record: recordFor("linux-x64") });
      mkdirSync(join(staging, "govern-2.0.0-linux-x64"));
      writeFileSync(join(staging, "govern-2.0.0-linux-x64", "govern"), linux);
      const tarball = join(work, "govern-2.0.0-linux-x64.tar.gz");
      execFileSync("tar", ["-czf", tarball, "-C", staging, "govern-2.0.0-linux-x64"]);
      const fromTar = executableOf(tarball);
      assert.equal(fromTar.target, "linux-x64");
      assert.ok(fromTar.executable.equals(linux));
      assert.throws(
        () => executableOf(join(work, "govern-2.0.0-plan9-x64.tar.gz")),
        /not a govern archive/,
      );
    });

    it("renders one document from the five, deterministic and complete, and the release's assertion accepts it", () => {
      const archives = allArchives();
      const sbom = renderSbom({ version: "2.0.0", tag: "v0.4.0", archives, toolVersion: "0.3.3" });
      assert.equal(sbom.bomFormat, "CycloneDX");
      assert.equal(sbom.specVersion, "1.5");
      assert.equal(sbom.metadata.timestamp, undefined);
      assert.match(
        sbom.serialNumber,
        /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );
      const root = sbom.metadata.component;
      assert.equal(root.name, "govern");
      assert.equal(root.version, "2.0.0");
      assert.equal(root.type, "application");
      assert.equal(root.purl, `pkg:golang/${MAIN}@v2.0.0`);
      assert.deepEqual(root.licenses, [{ license: { id: "Apache-2.0" } }]);
      const property = (name) => root.properties.find((entry) => entry.name === name)?.value;
      assert.equal(property("decionis:go:module"), MAIN);
      assert.equal(property("decionis:go:version"), "go1.26.4");
      assert.equal(property("decionis:go:build"), BUILD_COMMAND);
      assert.equal(property("decionis:go:build:CGO_ENABLED"), "0");
      assert.equal(property("decionis:go:build:-trimpath"), "true");
      // What names a target is no property of the release: it differs per archive.
      assert.equal(property("decionis:go:build:GOOS"), undefined);
      assert.equal(property("decionis:go:build:GOAMD64"), undefined);
      // Every archive is a distribution of the root, with its checksum.
      const distributions = root.externalReferences.filter((ref) => ref.type === "distribution");
      assert.deepEqual(
        distributions.map((ref) => ref.url),
        [...archives]
          .sort((a, b) => (a.name < b.name ? -1 : 1))
          .map(
            (archive) =>
              `https://github.com/decionis/agent-safe-pipeline/releases/download/v0.4.0/${archive.name}`,
          ),
      );
      for (const ref of distributions) {
        const archive = archives.find((each) => ref.url.endsWith(`/${each.name}`));
        assert.deepEqual(ref.hashes, [{ alg: "SHA-256", content: archive.sha256 }]);
      }
      // The linked module carries go.sum's checksum, as a hash and as the sum.
      const jcs = sbom.components.find((component) => component.name === "github.com/gowebpki/jcs");
      assert.equal(jcs.purl, "pkg:golang/github.com/gowebpki/jcs@v1.0.1");
      assert.deepEqual(jcs.hashes, [
        {
          alg: "SHA-256",
          content: Buffer.from(JCS_SUM.slice(3), "base64").toString("hex"),
        },
      ]);
      assert.deepEqual(jcs.properties, [{ name: "decionis:go:sum", value: JCS_SUM }]);
      assert.deepEqual(jcs.externalReferences, [
        { type: "vcs", url: "https://github.com/gowebpki/jcs" },
      ]);
      const std = sbom.components.find((component) => component.name === "std");
      assert.equal(std.version, "go1.26.4");
      assert.deepEqual(sbom.dependencies[0], {
        ref: root["bom-ref"],
        dependsOn: [jcs["bom-ref"], std["bom-ref"]],
      });
      // The same bytes give the same document, in any order.
      const again = renderSbom({
        version: "2.0.0",
        tag: "v0.4.0",
        archives: [...archives].reverse(),
        toolVersion: "0.3.3",
      });
      assert.deepEqual(again, sbom);
      const other = renderSbom({
        version: "2.0.0",
        tag: "v0.4.0",
        archives: allArchives({ goVersion: "go1.26.5" }),
        toolVersion: "0.3.3",
      });
      assert.notEqual(other.serialNumber, sbom.serialNumber);
      const path = join(work, "govern-2.0.0.cdx.json");
      writeFileSync(path, `${JSON.stringify(sbom, null, 2)}\n`);
      const asserted = spawnSync(
        "node",
        [
          new URL("../../scripts/AssertReleaseSbom.mjs", import.meta.url).pathname,
          path,
          "govern",
          "2.0.0",
          "2",
        ],
        { encoding: "utf8" },
      );
      assert.equal(asserted.status, 0, asserted.stderr);
    });

    it("refuses archives that do not describe one release", () => {
      const render = (archives) =>
        renderSbom({ version: "2.0.0", tag: "v0.4.0", archives, toolVersion: "0.3.3" });
      assert.throws(() => render(allArchives().slice(1)), /not every target/);
      assert.throws(
        () =>
          render([...allArchives().slice(1), { ...archiveFor("darwin-arm64"), version: "2.0.1" }]),
        /is not version 2\.0\.0/,
      );
      const crossed = allArchives();
      crossed[0] = { ...crossed[0], executable: crossed[1].executable };
      assert.throws(() => render(crossed), /was built for/);
      assert.throws(
        () => render([...allArchives().slice(1), archiveFor("darwin-arm64", { cgo: "1" })]),
        /CGO_ENABLED=1, not 0/,
      );
      assert.throws(
        () =>
          render([...allArchives().slice(1), archiveFor("darwin-arm64", { trimpath: "false" })]),
        /-trimpath=false, not true/,
      );
      assert.throws(
        () =>
          render([
            ...allArchives().slice(1),
            archiveFor("darwin-arm64", {
              deps: ["dep\tgithub.com/gowebpki/jcs\tv1.0.2\th1:other="],
            }),
          ]),
        /links different modules/,
      );
      assert.throws(
        () =>
          render([
            ...allArchives().slice(1),
            archiveFor("darwin-arm64", { main: "example.com/fork" }),
          ]),
        /was built from example\.com\/fork/,
      );
      assert.throws(
        () =>
          renderSbom({
            version: "two",
            tag: "v0.4.0",
            archives: allArchives(),
            toolVersion: "0.3.3",
          }),
        /not a version/,
      );
      assert.throws(
        () =>
          renderSbom({
            version: "2.0.0",
            tag: "0.4.0",
            archives: allArchives(),
            toolVersion: "0.3.3",
          }),
        /not a release tag/,
      );
    });
  });
});
