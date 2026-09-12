import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { describe, it } from "node:test";

/**
 * The "What each record establishes" table is a hand-written inventory of
 * the package's own vocabulary, published twice (root README and the npm
 * README). This gate keeps both copies equal, keeps every backticked token
 * real, and keeps every discovery surface from saying the one thing the
 * table exists to deny: that a dossier turns into a grant.
 */
const root = new URL("../../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");
const HEADING = "### What each record establishes";

async function sourceText(directory) {
  const entries = await readdir(new URL(`${directory}/`, root), { withFileTypes: true });
  const parts = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) parts.push(await sourceText(path));
    else if (entry.name.endsWith(".ts")) parts.push(await read(path));
  }
  return parts.join("\n");
}

function tableRows(markdown, file) {
  const start = markdown.indexOf(HEADING);
  assert.notEqual(start, -1, `${file} carries "${HEADING}"`);
  const section = markdown.slice(start).split(/\n## /)[0];
  const rows = section
    .split("\n")
    .filter(
      (line) =>
        line.startsWith("| ") && !line.startsWith("| Record or state") && !line.startsWith("| ---"),
    )
    .map((line) =>
      line
        .split("|")
        .slice(1, -1)
        .map((cell) => cell.trim()),
    );
  assert.equal(rows.length, 8, `${file} table has eight rows`);
  return rows;
}

const label = (cell) => cell.replace(/\[([^[\]]+)\]\([^()]+\)/g, "$1");
const tokens = (row) => [...row.join(" ").matchAll(/`([^`]+)`/g)].map((match) => match[1]);

describe("record vocabulary", () => {
  it("publishes the same table in the root README and the npm README", async () => {
    const rootRows = tableRows(await read("README.md"), "README.md");
    const packageRows = tableRows(
      await read("packages/pipeline/README.md"),
      "packages/pipeline/README.md",
    );
    assert.deepEqual(
      packageRows.map((row) => label(row[0])),
      rootRows.map((row) => label(row[0])),
    );
    rootRows.forEach((row, index) => {
      assert.deepEqual(new Set(tokens(packageRows[index])), new Set(tokens(row)), row[0]);
      assert.equal(label(packageRows[index][1]), label(row[1]), `${row[0]}: establishes`);
    });
  });

  it("names only tokens that exist in the package source", async () => {
    const source = await sourceText("packages/pipeline/src");
    for (const row of tableRows(await read("README.md"), "README.md")) {
      for (const token of tokens(row)) {
        assert.ok(
          source.includes(token),
          `${row[0]}: \`${token}\` is not in packages/pipeline/src`,
        );
      }
    }
  });

  it("never says that a dossier becomes a grant", async () => {
    const docs = (await readdir(new URL("docs/", root))).map((name) => `docs/${name}`);
    const surfaces = [
      "README.md",
      "packages/pipeline/README.md",
      "llms.txt",
      "llms-full.txt",
      ...docs,
    ];
    const conversion =
      /dossier[^.\n]{0,80} (?:convert(?:ed|s)?|turn(?:ed|s)?|becom(?:e|es|ing)) [^.\n]{0,40}grant|(?:convert|turn)(?:s|ed)? [^.\n]{0,40}dossier [^.\n]{0,40}into (?:a |an )?(?:grant|execution)/i;
    for (const surface of surfaces) {
      assert.doesNotMatch(await read(surface), conversion, surface);
    }
  });

  it("keeps the two owning documents reachable from llms.txt", async () => {
    const short = await read("llms.txt");
    for (const document of [
      "docs/decision-dossiers.md",
      "docs/execution-outcomes.md",
      "docs/audit-events.md",
    ]) {
      assert.ok(short.includes(`/blob/master/${document}`), `llms.txt links ${document}`);
    }
    assert.match(short, /Verdicts \(ALLOW \/ ESCALATE \/ BLOCK\)/);
  });

  it("says what shadow mode is not", async () => {
    const shadow = await read("docs/shadow-mode.md");
    assert.match(shadow, /not a dry run/);
    assert.match(shadow, /no real writes/);
  });

  it("pins one @decionis/verify version across the READMEs", async () => {
    const pins = new Set();
    for (const file of ["README.md", "dossiers/README.md"]) {
      const matches = [...(await read(file)).matchAll(/@decionis\/verify@(\d+\.\d+\.\d+)/g)];
      assert.ok(matches.length > 0, `${file} pins @decionis/verify`);
      for (const match of matches) pins.add(match[1]);
    }
    assert.equal(pins.size, 1, `one pinned version, found ${[...pins].join(", ")}`);
  });
});
