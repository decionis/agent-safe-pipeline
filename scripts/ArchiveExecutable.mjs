/**
 * Wraps a built executable as the release archive one target installs from:
 * `agentsafe-<version>-<os>-<arch>.tar.gz` holding `agentsafe`, `LICENSE`
 * and `NOTICE`, and prints the archive path and its SHA-256, which is what
 * the installer and the formula verify against.
 *
 *   node scripts/ArchiveExecutable.mjs --executable <path> --target <os>-<arch> --out <dir>
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("../", import.meta.url)));
const argument = (name) => {
  const index = process.argv.indexOf(name);
  const value = index === -1 ? undefined : process.argv[index + 1];
  if (value === undefined) throw new Error(`${name} is required`);
  return value;
};
const executable = resolve(argument("--executable"));
const target = argument("--target");
const out = resolve(argument("--out"));
if (!/^(?:darwin|linux)-(?:x64|arm64)$/.test(target))
  throw new Error(`unexpected target ${target}`);

const version = JSON.parse(
  readFileSync(join(root, "packages/agentsafe/package.json"), "utf8"),
).version;
const name = `agentsafe-${version}-${target}`;
const archive = join(out, `${name}.tar.gz`);
mkdirSync(out, { recursive: true });
const staging = mkdtempSync(join(tmpdir(), "agentsafe-archive-"));
try {
  const directory = join(staging, name);
  mkdirSync(directory);
  copyFileSync(executable, join(directory, "agentsafe"));
  copyFileSync(join(root, "LICENSE"), join(directory, "LICENSE"));
  copyFileSync(join(root, "NOTICE"), join(directory, "NOTICE"));
  // The executable keeps its mode; the archive's top-level directory is the
  // name, so an extraction is one directory and never a spray of files.
  const tar = spawnSync("tar", ["-czf", archive, "-C", staging, name], { stdio: "inherit" });
  if (tar.status !== 0) throw new Error(`tar exited with ${tar.status}`);
} finally {
  rmSync(staging, { recursive: true, force: true });
}
const sha256 = createHash("sha256").update(readFileSync(archive)).digest("hex");
process.stdout.write(
  `${JSON.stringify({ archive, name: `${name}.tar.gz`, version, target, sha256 })}\n`,
);
