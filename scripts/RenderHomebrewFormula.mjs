/**
 * Renders the Homebrew formula for one release from its checksum file.
 *
 *   node scripts/RenderHomebrewFormula.mjs --version <v> --sums <SHA256SUMS> --out <Formula/agentsafe.rb>
 *
 * The four archives the release built are looked up by name in SHA256SUMS,
 * which is the same file the installer verifies against, so the formula
 * pins exactly what the release published and nothing is typed by hand. A
 * missing archive is a refusal: a formula that installs on one platform and
 * fails on another is worse than none.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const TARGETS = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"];
export const RELEASE_BASE = "https://github.com/decionis/agent-safe-pipeline/releases/download";
const VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[\w.-]+)?$/;

/** The SHA-256 of each archive named in a SHA256SUMS file, by file name. */
export function parseSums(text) {
  const sums = new Map();
  for (const line of text.split("\n")) {
    const match = /^([0-9a-f]{64})\s+\*?(\S+)$/.exec(line.trim());
    if (match) sums.set(match[2], match[1]);
  }
  return sums;
}

/** The formula text for a version, from its template and its checksums. */
export function renderFormula(template, version, sums, base = RELEASE_BASE) {
  if (!VERSION.test(version)) throw new Error(`not a version: ${version}`);
  const values = { VERSION: version, BASE: base };
  for (const target of TARGETS) {
    const name = `agentsafe-${version}-${target}.tar.gz`;
    const sum = sums.get(name);
    if (sum === undefined) throw new Error(`SHA256SUMS does not list ${name}`);
    values[`SHA256_${target.toUpperCase().replace("-", "_")}`] = sum;
  }
  const rendered = template.replace(/\{\{([A-Z0-9_]+)\}\}/g, (whole, key) => {
    const value = values[key];
    if (value === undefined) throw new Error(`no value for ${whole}`);
    return value;
  });
  if (rendered.includes("{{")) throw new Error("unrendered placeholder");
  return rendered;
}

const argument = (name) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
};

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const version = argument("--version");
  const sumsPath = argument("--sums");
  const out = argument("--out");
  if (version === undefined || sumsPath === undefined || out === undefined) {
    throw new Error("--version, --sums and --out are required");
  }
  const template = readFileSync(
    new URL("../packaging/homebrew/agentsafe.rb.tmpl", import.meta.url),
    "utf8",
  );
  const base = argument("--base") ?? RELEASE_BASE;
  writeFileSync(
    out,
    renderFormula(template, version, parseSums(readFileSync(sumsPath, "utf8")), base),
  );
  process.stdout.write(`${JSON.stringify({ out, version })}\n`);
}
