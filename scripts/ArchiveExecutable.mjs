/**
 * Wraps a built executable as the release archive one target installs from:
 * `<name>-<version>-<os>-<arch>.tar.gz`, or `.zip` for Windows, holding one
 * directory with the executable, `LICENSE` and `NOTICE`, and, for the
 * runtime's launcher layout, the `node` and `agentsafe.cjs` beside it. It
 * prints the archive path and its SHA-256, which is what the installer and
 * the formula verify against. The name and version default to the runtime's;
 * govern's build names itself and reads its version from its own VERSION
 * file. The zip is written here, entry by entry, rather than by whatever
 * `zip` a runner has: a Windows runner's shell has none, and the entries'
 * dates and modes are fixed so the archive's bytes depend on its contents
 * and the runner's zlib, never on the minute it was wrapped.
 *
 *   node scripts/ArchiveExecutable.mjs --executable <path> --target <os>-<arch> --out <dir> [--name govern --version 2.0.0]
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { crc32, deflateRawSync } from "node:zlib";

/** The targets a release archives, and the archive each one takes. */
export const TARGETS = /^(?:(?:darwin|linux)-(?:x64|arm64)|windows-x64)$/;
export const extensionOf = (target) => (target.startsWith("windows-") ? "zip" : "tar.gz");

// Every entry carries the same date, 2000-01-01 00:00:00 in the zip's own
// DOS fields: the archive names a build, not the minute it was wrapped.
const DOS_DATE = ((2000 - 1980) << 9) | (1 << 5) | 1;
const DOS_TIME = 0;
const DEFLATE = 8;
const STORED = 0;
const MADE_BY_UNIX = 0x031e;
const NEEDS_2_0 = 20;

/**
 * Writes `<out>` as a zip of one directory under `root`: the directory entry,
 * then its files by name, deflated, each with a Unix mode so an extraction
 * on a Unix keeps the executable executable (Windows ignores them): 0755 for
 * `.exe` files and the directory, 0644 for the rest, whatever the runner's
 * file system reports. Local headers, a central directory and the end
 * record, as the format specifies; nothing here needs zip64, the archives
 * are megabytes.
 */
export function writeZip(out, root, directory) {
  const parts = [];
  const central = [];
  let offset = 0;
  const add = (name, data, mode, isDirectory) => {
    const nameBytes = Buffer.from(name, "utf8");
    const method = isDirectory ? STORED : DEFLATE;
    const compressed = isDirectory ? Buffer.alloc(0) : deflateRawSync(data, { level: 9 });
    const crc = isDirectory ? 0 : crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(NEEDS_2_0, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    const header = Buffer.alloc(46);
    header.writeUInt32LE(0x02014b50, 0);
    header.writeUInt16LE(MADE_BY_UNIX, 4);
    header.writeUInt16LE(NEEDS_2_0, 6);
    header.writeUInt16LE(0, 8);
    header.writeUInt16LE(method, 10);
    header.writeUInt16LE(DOS_TIME, 12);
    header.writeUInt16LE(DOS_DATE, 14);
    header.writeUInt32LE(crc, 16);
    header.writeUInt32LE(compressed.length, 20);
    header.writeUInt32LE(data.length, 24);
    header.writeUInt16LE(nameBytes.length, 28);
    header.writeUInt16LE(0, 30);
    header.writeUInt16LE(0, 32);
    header.writeUInt16LE(0, 34);
    header.writeUInt16LE(0, 36);
    // The Unix mode in the high half, the DOS directory bit in the low.
    const unixMode = (isDirectory ? 0o040000 : 0o100000) | (mode & 0o7777);
    header.writeUInt32LE(unixMode * 0x10000 + (isDirectory ? 0x10 : 0), 38);
    header.writeUInt32LE(offset, 42);
    parts.push(local, nameBytes, compressed);
    central.push(header, nameBytes);
    offset += local.length + nameBytes.length + compressed.length;
  };
  add(`${directory}/`, Buffer.alloc(0), 0o755, true);
  const files = readdirSync(join(root, directory)).sort();
  for (const file of files) {
    const mode = file.endsWith(".exe") ? 0o755 : 0o644;
    add(`${directory}/${file}`, readFileSync(join(root, directory, file)), mode, false);
  }
  const centralSize = central.reduce((sum, part) => sum + part.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(files.length + 1, 8);
  end.writeUInt16LE(files.length + 1, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  writeFileSync(out, Buffer.concat([...parts, ...central, end]));
}

const root = resolve(fileURLToPath(new URL("../", import.meta.url)));
const argument = (name) => {
  const index = process.argv.indexOf(name);
  const value = index === -1 ? undefined : process.argv[index + 1];
  if (value === undefined) throw new Error(`${name} is required`);
  return value;
};
const optional = (name) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
};

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  archive();
}

function archive() {
  const executable = resolve(argument("--executable"));
  const target = argument("--target");
  const out = resolve(argument("--out"));
  if (!TARGETS.test(target)) throw new Error(`unexpected target ${target}`);
  const windows = target.startsWith("windows-");

  const product = optional("--name") ?? "agentsafe";
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(product)) throw new Error(`unexpected name ${product}`);
  const version =
    optional("--version") ??
    JSON.parse(readFileSync(join(root, "packages/agentsafe/package.json"), "utf8")).version;
  if (!/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[\w.-]+)?$/.test(version))
    throw new Error(`not a version: ${version}`);
  const name = `${product}-${version}-${target}`;
  const archive = join(out, `${name}.${extensionOf(target)}`);
  // The launcher layout is the runtime's alone; govern is one static file.
  const launcher = product === "agentsafe" && existsSync(join(dirname(executable), "node"));
  mkdirSync(out, { recursive: true });
  const staging = mkdtempSync(join(tmpdir(), "agentsafe-archive-"));
  try {
    const directory = join(staging, name);
    mkdirSync(directory);
    copyFileSync(executable, join(directory, windows ? `${product}.exe` : product));
    // The launcher layout ships the Node release and the bundle with the launcher.
    if (launcher) {
      for (const entry of ["node", "agentsafe.cjs"]) {
        copyFileSync(join(dirname(executable), entry), join(directory, entry));
      }
    }
    copyFileSync(join(root, "LICENSE"), join(directory, "LICENSE"));
    copyFileSync(join(root, "NOTICE"), join(directory, "NOTICE"));
    // The executable keeps its mode; the archive's top-level directory is the
    // name, so an extraction is one directory and never a spray of files.
    if (windows) {
      writeZip(archive, staging, name);
    } else {
      const tar = spawnSync("tar", ["-czf", archive, "-C", staging, name], { stdio: "inherit" });
      if (tar.status !== 0) throw new Error(`tar exited with ${tar.status}`);
    }
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
  const sha256 = createHash("sha256").update(readFileSync(archive)).digest("hex");
  process.stdout.write(
    `${JSON.stringify({ archive, name: `${name}.${extensionOf(target)}`, product, version, target, layout: launcher ? "launcher" : product === "agentsafe" ? "sea" : "static", sha256 })}\n`,
  );
}
