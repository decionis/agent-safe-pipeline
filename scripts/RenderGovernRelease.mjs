/**
 * Renders govern's release manifest, `govern/release.json`, from a release's
 * checksum file: the version the release shipped, the release tag its
 * archives live under, and each platform archive's SHA-256. The action reads
 * it to download the archive for the runner and refuse any other bytes, so
 * the action's commit names the binary it runs, the way an action pinned by
 * commit names its code. Nothing in it is typed by hand.
 *
 *   node scripts/RenderGovernRelease.mjs --version <v> --tag <release tag> --sums <SHA256SUMS> --out <govern/release.json>
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { parseSums, TARGETS } from "./RenderHomebrewFormula.mjs";

export const RELEASE_BASE = "https://github.com/decionis/agent-safe-pipeline/releases/download";
const VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[\w.-]+)?$/;
const TAG = /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[\w.-]+)?$/;

/**
 * The manifest for a govern version from the checksums of its four archives.
 * A missing archive is a refusal: a manifest that fetches on one platform and
 * builds on another would make the two paths' bytes a matter of luck.
 */
export function renderManifest(version, tag, sums, base = RELEASE_BASE) {
  if (!VERSION.test(version)) throw new Error(`not a version: ${version}`);
  if (!TAG.test(tag)) throw new Error(`not a release tag: ${tag}`);
  const sha256 = {};
  for (const target of TARGETS) {
    const name = `govern-${version}-${target}.tar.gz`;
    const sum = sums.get(name);
    if (sum === undefined) throw new Error(`SHA256SUMS does not list ${name}`);
    sha256[target] = sum;
  }
  return { version, tag, base, sha256 };
}

const argument = (name) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
};

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const version = argument("--version");
  const tag = argument("--tag");
  const sumsPath = argument("--sums");
  const out = argument("--out");
  if (version === undefined || tag === undefined || sumsPath === undefined || out === undefined) {
    throw new Error("--version, --tag, --sums and --out are required");
  }
  const manifest = renderManifest(
    version,
    tag,
    parseSums(readFileSync(sumsPath, "utf8")),
    argument("--base") ?? RELEASE_BASE,
  );
  writeFileSync(out, `${JSON.stringify(manifest, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({ out, version, tag })}\n`);
}
