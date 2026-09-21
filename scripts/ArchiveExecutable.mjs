/**
 * Wraps a built executable as the release archive one target installs from:
 * `<name>-<version>-<os>-<arch>.tar.gz` holding one directory with the
 * executable, `LICENSE` and `NOTICE`, and, for the runtime's launcher
 * layout, the `node` and `agentsafe.cjs` beside it. It prints the archive
 * path and its SHA-256, which is what the installer and the formula verify
 * against. The name and version default to the runtime's; govern's build
 * names itself and reads its version from its own VERSION file.
 *
 *   node scripts/ArchiveExecutable.mjs --executable <path> --target <os>-<arch> --out <dir> [--name govern --version 2.0.0]
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

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
const executable = resolve(argument("--executable"));
const target = argument("--target");
const out = resolve(argument("--out"));
if (!/^(?:darwin|linux)-(?:x64|arm64)$/.test(target))
  throw new Error(`unexpected target ${target}`);

const product = optional("--name") ?? "agentsafe";
if (!/^[a-z][a-z0-9-]{0,31}$/.test(product)) throw new Error(`unexpected name ${product}`);
const version =
  optional("--version") ??
  JSON.parse(readFileSync(join(root, "packages/agentsafe/package.json"), "utf8")).version;
if (!/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[\w.-]+)?$/.test(version))
  throw new Error(`not a version: ${version}`);
const name = `${product}-${version}-${target}`;
const archive = join(out, `${name}.tar.gz`);
// The launcher layout is the runtime's alone; govern is one static file.
const launcher = product === "agentsafe" && existsSync(join(dirname(executable), "node"));
mkdirSync(out, { recursive: true });
const staging = mkdtempSync(join(tmpdir(), "agentsafe-archive-"));
try {
  const directory = join(staging, name);
  mkdirSync(directory);
  copyFileSync(executable, join(directory, product));
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
  const tar = spawnSync("tar", ["-czf", archive, "-C", staging, name], { stdio: "inherit" });
  if (tar.status !== 0) throw new Error(`tar exited with ${tar.status}`);
} finally {
  rmSync(staging, { recursive: true, force: true });
}
const sha256 = createHash("sha256").update(readFileSync(archive)).digest("hex");
process.stdout.write(
  `${JSON.stringify({ archive, name: `${name}.tar.gz`, product, version, target, layout: launcher ? "launcher" : product === "agentsafe" ? "sea" : "static", sha256 })}\n`,
);
