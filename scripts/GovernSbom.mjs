/**
 * The CycloneDX SBOM of a govern release, read from the binaries the release
 * ships. A Go executable carries its own build information: the main module,
 * every module linked into it with the version and the checksum `go.sum`
 * pins, the toolchain, and the settings the build ran under. This reads that
 * record out of each archive's executable, holds the five to one account of
 * the modules and the toolchain, checks each was built for the target its
 * archive names with the flags the release promises, and writes the SBOM the
 * release attests beside the archives: the module list as the bytes state
 * it, not as a manifest beside the source would.
 *
 *   node scripts/GovernSbom.mjs --version <v> --tag <release tag> --out <out.cdx.json> --archive <path>...
 *
 * The serial number is the RFC 4122 v5 UUID of the archives' checksums, so
 * the same bytes give the same document; there is no timestamp.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { inflateRawSync } from "node:zlib";
import { RELEASE_BASE, TARGETS } from "./RenderGovernRelease.mjs";

const root = resolve(fileURLToPath(new URL("../", import.meta.url)));

/** The build every govern archive is held to; the SBOM states it, and the workflow runs it. */
export const BUILD_COMMAND = 'CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w"';

const REPOSITORY = "https://github.com/decionis/agent-safe-pipeline";
const MAIN_MODULE = "github.com/decionis/agent-safe-pipeline/govern/v2";
const VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[\w.-]+)?$/;
const TAG = /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[\w.-]+)?$/;

/** The Go toolchain writes this ahead of the build information in every executable. */
const MAGIC = Buffer.from("\xff Go buildinf:", "latin1");
const FLAG_INLINE_STRINGS = 0x2;

function readUvarint(bytes, at) {
  let value = 0;
  let shift = 0;
  let index = at;
  for (;;) {
    if (index >= bytes.length) throw new Error("the build information ends inside a length");
    const byte = bytes[index];
    index += 1;
    value += (byte & 0x7f) * 2 ** shift;
    if (byte < 0x80) return { value, next: index };
    shift += 7;
    if (shift > 56) throw new Error("the build information holds a length too long to be one");
  }
}

function readString(bytes, at) {
  const { value: length, next } = readUvarint(bytes, at);
  if (next + length > bytes.length) throw new Error("the build information ends inside a string");
  return { value: bytes.subarray(next, next + length).toString("utf8"), next: next + length };
}

/**
 * The build information a Go executable carries, as `go version -m` prints
 * it: the toolchain's version and the module record. The record starts at a
 * fixed header the linker writes; since Go 1.18 both strings follow it
 * inline, each behind its length, and the module record is wrapped in a
 * marker line at either end, which is dropped here as the toolchain drops it.
 */
export function readBuildInfo(bytes) {
  const at = bytes.indexOf(MAGIC);
  if (at === -1) throw new Error("no Go build information in the executable");
  const flags = bytes[at + 15];
  if ((flags & FLAG_INLINE_STRINGS) === 0) {
    throw new Error("the executable's build information predates Go 1.18");
  }
  const version = readString(bytes, at + 32);
  let modules = readString(bytes, version.next).value;
  if (modules.length >= 33 && modules[modules.length - 17] === "\n") {
    modules = modules.slice(16, -16);
  }
  return { goVersion: version.value, modules: parseModules(modules) };
}

/**
 * The module record's lines: `path`, the main module (`mod`), each linked
 * module (`dep`), a replacement (`=>`) for the module on the line before it,
 * and the build settings (`build`).
 */
export function parseModules(text) {
  const record = { path: "", main: null, deps: [], settings: new Map() };
  for (const line of text.split("\n")) {
    if (line === "") continue;
    const [kind, ...fields] = line.split("\t");
    switch (kind) {
      case "path":
        record.path = fields[0];
        break;
      case "mod":
        record.main = { path: fields[0], version: fields[1], sum: fields[2] ?? "" };
        break;
      case "dep":
        record.deps.push({ path: fields[0], version: fields[1], sum: fields[2] ?? "" });
        break;
      case "=>": {
        const replaced = record.deps.at(-1);
        if (replaced === undefined) throw new Error("a replacement with no module before it");
        replaced.replaces = `${replaced.path}@${replaced.version}`;
        replaced.path = fields[0];
        replaced.version = fields[1];
        replaced.sum = fields[2] ?? "";
        break;
      }
      case "build": {
        const setting = fields.join("\t");
        const equals = setting.indexOf("=");
        if (equals === -1) throw new Error(`a build setting without a value: ${setting}`);
        record.settings.set(setting.slice(0, equals), setting.slice(equals + 1));
        break;
      }
      default:
        throw new Error(`an unknown line in the build information: ${line}`);
    }
  }
  if (record.main === null) throw new Error("the build information names no main module");
  return record;
}

/** The one file at `name` in a zip: the central directory names it, the local header precedes its bytes. */
function fileFromZip(bytes, name) {
  const end = bytes.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (end === -1) throw new Error("not a zip: no end of central directory");
  const entries = bytes.readUInt16LE(end + 10);
  let at = bytes.readUInt32LE(end + 16);
  for (let entry = 0; entry < entries; entry += 1) {
    if (bytes.readUInt32LE(at) !== 0x02014b50)
      throw new Error("not a zip: a central directory entry is missing");
    const method = bytes.readUInt16LE(at + 10);
    const compressedSize = bytes.readUInt32LE(at + 20);
    const size = bytes.readUInt32LE(at + 24);
    const nameLength = bytes.readUInt16LE(at + 28);
    const extraLength = bytes.readUInt16LE(at + 30);
    const commentLength = bytes.readUInt16LE(at + 32);
    const offset = bytes.readUInt32LE(at + 42);
    const entryName = bytes.subarray(at + 46, at + 46 + nameLength).toString("utf8");
    at += 46 + nameLength + extraLength + commentLength;
    if (entryName !== name) continue;
    if (bytes.readUInt32LE(offset) !== 0x04034b50)
      throw new Error("not a zip: a local header is missing");
    const start = offset + 30 + bytes.readUInt16LE(offset + 26) + bytes.readUInt16LE(offset + 28);
    const data = bytes.subarray(start, start + compressedSize);
    if (method === 0) return data;
    if (method === 8) {
      const inflated = inflateRawSync(data);
      if (inflated.length !== size) throw new Error(`${name} inflates to the wrong size`);
      return inflated;
    }
    throw new Error(`${name} is compressed with method ${method}`);
  }
  throw new Error(`the zip holds no ${name}`);
}

/**
 * The executable inside a release archive, by the layout the archive script
 * writes: one directory named as the archive, the executable in it.
 */
export function executableOf(archivePath) {
  const file = basename(archivePath);
  const match = /^(govern-(.+?)-((?:darwin|linux|windows)-(?:x64|arm64)))\.(tar\.gz|zip)$/.exec(
    file,
  );
  if (match === null) throw new Error(`not a govern archive: ${file}`);
  const [, directory, version, target, extension] = match;
  const bytes = readFileSync(archivePath);
  const executable =
    extension === "zip"
      ? fileFromZip(bytes, `${directory}/govern.exe`)
      : execFileSync(
          "tar",
          ["--extract", "--gzip", "--to-stdout", "--file", archivePath, `${directory}/govern`],
          { maxBuffer: 256 * 1024 * 1024 },
        );
  return {
    name: file,
    version,
    target,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    executable,
  };
}

const GOOS = { darwin: "darwin", linux: "linux", windows: "windows" };
const GOARCH = { x64: "amd64", arm64: "arm64" };
/** The build settings that name the target rather than the build; the rest must agree across archives. */
const TARGET_SETTINGS = new Set(["GOOS", "GOARCH", "GOAMD64", "GOARM64", "GOARM", "GO386"]);

function uuidV5(name) {
  const urlNamespace = Buffer.from("6ba7b8119dad11d180b400c04fd430c8", "hex");
  const bytes = createHash("sha1").update(urlNamespace).update(name).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

const purlOf = (path, version) => `pkg:golang/${path}@${version}`;

function componentOf(dep) {
  const [host] = dep.path.split("/");
  const references = host.includes(".") ? [{ type: "vcs", url: `https://${dep.path}` }] : [];
  const hashes = dep.sum.startsWith("h1:")
    ? [{ alg: "SHA-256", content: Buffer.from(dep.sum.slice(3), "base64").toString("hex") }]
    : [];
  return {
    "bom-ref": purlOf(dep.path, dep.version),
    type: "library",
    name: dep.path,
    version: dep.version,
    scope: "required",
    purl: purlOf(dep.path, dep.version),
    properties: [
      ...(dep.sum === "" ? [] : [{ name: "decionis:go:sum", value: dep.sum }]),
      ...(dep.replaces === undefined
        ? []
        : [{ name: "decionis:go:replaces", value: dep.replaces }]),
    ],
    externalReferences: references,
    ...(hashes.length === 0 ? {} : { hashes }),
  };
}

/**
 * The SBOM of one govern version from its archives' executables. Every
 * executable must carry the same main module, the same linked modules and
 * the same toolchain; each must name its archive's target and the release's
 * build in its settings.
 */
export function renderSbom({ version, tag, archives, base = RELEASE_BASE, toolVersion }) {
  if (!VERSION.test(version)) throw new Error(`not a version: ${version}`);
  if (!TAG.test(tag)) throw new Error(`not a release tag: ${tag}`);
  const targets = archives.map((archive) => archive.target).sort();
  if (targets.join(" ") !== [...TARGETS].sort().join(" ")) {
    throw new Error(`the archives cover ${targets.join(", ")}, not every target`);
  }
  const accounts = archives.map((archive) => {
    if (archive.version !== version) throw new Error(`${archive.name} is not version ${version}`);
    const info = readBuildInfo(archive.executable);
    const { main, deps, settings } = info.modules;
    if (main.path !== MAIN_MODULE) throw new Error(`${archive.name} was built from ${main.path}`);
    const [os, arch] = archive.target.split("-");
    if (settings.get("GOOS") !== GOOS[os] || settings.get("GOARCH") !== GOARCH[arch]) {
      throw new Error(
        `${archive.name} was built for ${settings.get("GOOS")}/${settings.get("GOARCH")}`,
      );
    }
    // The toolchain records neither -ldflags nor -buildvcs under -trimpath;
    // the two settings it does record are held to the release's build.
    for (const [key, value] of [
      ["CGO_ENABLED", "0"],
      ["-trimpath", "true"],
    ]) {
      if (settings.get(key) !== value) {
        throw new Error(
          `${archive.name} was built with ${key}=${settings.get(key) ?? "unset"}, not ${value}`,
        );
      }
    }
    const modules = deps
      .map(
        (dep) =>
          `${dep.path}@${dep.version} ${dep.sum}${dep.replaces === undefined ? "" : ` replaces ${dep.replaces}`}`,
      )
      .sort()
      .join("\n");
    return { archive, info, account: `${info.goVersion}\n${main.path}\n${modules}` };
  });
  for (const { archive, account } of accounts.slice(1)) {
    if (account !== accounts[0].account) {
      throw new Error(`${archive.name} links different modules from ${accounts[0].archive.name}`);
    }
  }
  const { info } = accounts[0];
  const settings = [...info.modules.settings]
    .filter(([key]) => !TARGET_SETTINGS.has(key))
    .filter(([key, value]) =>
      accounts.every((each) => each.info.modules.settings.get(key) === value),
    )
    .sort(([a], [b]) => (a < b ? -1 : 1));
  const components = info.modules.deps
    .map(componentOf)
    .sort((a, b) => (a["bom-ref"] < b["bom-ref"] ? -1 : 1));
  const standardLibrary = {
    "bom-ref": purlOf("std", info.goVersion),
    type: "library",
    name: "std",
    version: info.goVersion,
    scope: "required",
    description: "The Go standard library the toolchain linked into the executable.",
    purl: purlOf("std", info.goVersion),
    externalReferences: [{ type: "vcs", url: "https://go.googlesource.com/go" }],
  };
  const rootRef = purlOf(MAIN_MODULE, `v${version}`);
  const sorted = [...archives].sort((a, b) => (a.name < b.name ? -1 : 1));
  const checksums = sorted.map((archive) => `${archive.sha256}  ${archive.name}`).join("\n");
  const serial = uuidV5(
    `${REPOSITORY}/sbom/govern@${version}/sha256:${createHash("sha256").update(checksums).digest("hex")}`,
  );
  return {
    $schema: "http://cyclonedx.org/schema/bom-1.5.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${serial}`,
    version: 1,
    metadata: {
      lifecycles: [{ phase: "build" }],
      tools: [{ vendor: "decionis", name: "GovernSbom.mjs", version: toolVersion }],
      component: {
        "bom-ref": rootRef,
        type: "application",
        name: "govern",
        version,
        description:
          "The Decionis workflow gate: one verdict before a workflow step runs, with a signed Decision Dossier of it.",
        scope: "required",
        purl: rootRef,
        licenses: [{ license: { id: "Apache-2.0" } }],
        properties: [
          { name: "decionis:go:module", value: MAIN_MODULE },
          { name: "decionis:go:version", value: info.goVersion },
          { name: "decionis:go:build", value: BUILD_COMMAND },
          ...settings.map(([key, value]) => ({ name: `decionis:go:build:${key}`, value })),
        ],
        externalReferences: [
          { type: "vcs", url: REPOSITORY },
          { type: "documentation", url: `${REPOSITORY}/blob/master/docs/govern.md` },
          ...sorted.map((archive) => ({
            type: "distribution",
            url: `${base}/${tag}/${archive.name}`,
            hashes: [{ alg: "SHA-256", content: archive.sha256 }],
          })),
        ],
      },
    },
    components: [...components, standardLibrary],
    dependencies: [
      {
        ref: rootRef,
        dependsOn: [
          ...components.map((component) => component["bom-ref"]),
          standardLibrary["bom-ref"],
        ],
      },
      ...components.map((component) => ({ ref: component["bom-ref"], dependsOn: [] })),
      { ref: standardLibrary["bom-ref"], dependsOn: [] },
    ],
  };
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  const options = { archive: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index].replace(/^--/, "");
    const value = argv[index + 1];
    if (!["version", "tag", "out", "base", "archive"].includes(flag) || value === undefined) {
      throw new Error(
        "Usage: GovernSbom.mjs --version <v> --tag <release tag> --out <out.cdx.json> --archive <path>...",
      );
    }
    if (flag === "archive") options.archive.push(value);
    else options[flag] = value;
    index += 1;
  }
  if (options.version === undefined || options.tag === undefined || options.out === undefined) {
    throw new Error("--version, --tag and --out are required");
  }
  const sbom = renderSbom({
    version: options.version,
    tag: options.tag,
    base: options.base,
    archives: options.archive.map(executableOf),
    toolVersion: JSON.parse(readFileSync(`${root}/package.json`, "utf8")).version,
  });
  writeFileSync(options.out, `${JSON.stringify(sbom, null, 2)}\n`);
  process.stdout.write(
    `Wrote the SBOM of govern ${options.version} from ${String(options.archive.length)} executables' build information: ${String(sbom.components.length)} components, ${sbom.serialNumber}.\n`,
  );
}
