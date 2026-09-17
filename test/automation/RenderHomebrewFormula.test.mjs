import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { parseSums, renderFormula, TARGETS } from "../../scripts/RenderHomebrewFormula.mjs";

const template = await readFile(
  new URL("../../packaging/homebrew/agentsafe.rb.tmpl", import.meta.url),
  "utf8",
);
const sum = (character) => character.repeat(64);
const sums = new Map(
  TARGETS.map((target, index) => [`agentsafe-1.2.3-${target}.tar.gz`, sum("abcd"[index])]),
);

describe("the Homebrew formula renderer", () => {
  it("reads a SHA256SUMS file in either checksum spelling", () => {
    const parsed = parseSums(`${sum("1")}  a.tar.gz\n${sum("2")} *b.tar.gz\nnot a line\n`);
    assert.equal(parsed.get("a.tar.gz"), sum("1"));
    assert.equal(parsed.get("b.tar.gz"), sum("2"));
    assert.equal(parsed.size, 2);
  });

  it("pins every platform's archive to the checksum the release listed", () => {
    const formula = renderFormula(template, "1.2.3", sums);
    assert.match(formula, /^class Agentsafe < Formula$/m);
    assert.match(formula, /version "1\.2\.3"/);
    for (const [index, target] of TARGETS.entries()) {
      assert.ok(
        formula.includes(
          `https://github.com/decionis/agent-safe-pipeline/releases/download/v1.2.3/agentsafe-1.2.3-${target}.tar.gz`,
        ),
        target,
      );
      assert.ok(formula.includes(`sha256 "${sum("abcd"[index])}"`), target);
    }
    assert.doesNotMatch(formula, /\{\{/);
    assert.match(formula, /bin\.install "agentsafe"/);
    assert.match(formula, /agentsafe doctor --upstream http:\/\/127\.0\.0\.1:1 --no-network/);
    assert.match(
      renderFormula(template, "1.2.3", sums, "https://mirror.example/r"),
      /https:\/\/mirror\.example\/r\/v1\.2\.3\//,
    );
  });

  it("refuses a missing archive, a placeholder without a value, and a version that is not one", () => {
    const partial = new Map(sums);
    partial.delete("agentsafe-1.2.3-linux-arm64.tar.gz");
    assert.throws(
      () => renderFormula(template, "1.2.3", partial),
      /does not list agentsafe-1\.2\.3-linux-arm64/,
    );
    assert.throws(() => renderFormula("{{NOPE}}", "1.2.3", sums), /no value for \{\{NOPE\}\}/);
    assert.throws(() => renderFormula(template, "v1.2.3", sums), /not a version/);
  });
});
