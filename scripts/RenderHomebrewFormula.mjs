/**
 * Renders the Homebrew formula for one release from its checksum file.
 *
 *   node scripts/RenderHomebrewFormula.mjs --version <v> --tag <release tag> --sums <SHA256SUMS> --out <Formula/agentsafe.rb> [--product govern]
 *
 * The four archives the release built are looked up by name in SHA256SUMS,
 * which is the same file the installer verifies against, so the formula
 * pins exactly what the release published and nothing is typed by hand. A
 * missing archive is a refusal: a formula that installs on one platform and
 * fails on another is worse than none. The product is the runtime unless
 * named: govern's template and archives carry its name.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const TARGETS = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"];
/** The products a release ships as archives, each with a template of its name. */
export const PRODUCTS = ["agentsafe", "govern"];
export const RELEASE_BASE = "https://github.com/decionis/agent-safe-pipeline/releases/download";
const VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[\w.-]+)?$/;
/** A release tag: the repository's releases are tagged by the library's version, which the runtime's is not. */
const TAG = /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[\w.-]+)?$/;

/** The SHA-256 of each archive named in a SHA256SUMS file, by file name. */
export function parseSums(text) {
  const sums = new Map();
  for (const line of text.split("\n")) {
    const match = /^([0-9a-f]{64})\s+\*?(\S+)$/.exec(line.trim());
    if (match) sums.set(match[2], match[1]);
  }
  return sums;
}

/**
 * The formula text for a product version, from its template and its
 * checksums. The archives live under the release tagged `tag`, the
 * library's version, which is neither the runtime's nor govern's: the
 * formula's `version` is the product's and its URLs are the release's.
 */
export function renderFormula(
  template,
  version,
  tag,
  sums,
  base = RELEASE_BASE,
  product = "agentsafe",
) {
  if (!VERSION.test(version)) throw new Error(`not a version: ${version}`);
  if (!TAG.test(tag)) throw new Error(`not a release tag: ${tag}`);
  if (!PRODUCTS.includes(product)) throw new Error(`not a product: ${product}`);
  const values = { VERSION: version, TAG: tag, BASE: base };
  for (const target of TARGETS) {
    const name = `${product}-${version}-${target}.tar.gz`;
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
  const tag = argument("--tag");
  const sumsPath = argument("--sums");
  const out = argument("--out");
  if (version === undefined || tag === undefined || sumsPath === undefined || out === undefined) {
    throw new Error("--version, --tag, --sums and --out are required");
  }
  const product = argument("--product") ?? "agentsafe";
  if (!PRODUCTS.includes(product)) throw new Error(`not a product: ${product}`);
  const template = readFileSync(
    new URL(`../packaging/homebrew/${product}.rb.tmpl`, import.meta.url),
    "utf8",
  );
  const base = argument("--base") ?? RELEASE_BASE;
  writeFileSync(
    out,
    renderFormula(template, version, tag, parseSums(readFileSync(sumsPath, "utf8")), base, product),
  );
  process.stdout.write(`${JSON.stringify({ out, product, version, tag })}\n`);
}
