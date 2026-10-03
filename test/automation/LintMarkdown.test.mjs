import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { fileURLToPath, URL } from "node:url";
import { describe, it } from "node:test";
import { isLinted, lintMarkdown } from "../../scripts/LintMarkdown.mjs";

const repository = fileURLToPath(new URL("../..", import.meta.url));
const script = join(repository, "scripts", "LintMarkdown.mjs");
const config = { MD013: false, MD024: { siblings_only: true } };

function withFile(content, test) {
  const directory = mkdtempSync(join(tmpdir(), "agent-safe-mdlint-"));
  const file = join(directory, "page.md");
  writeFileSync(file, content);
  try {
    test(file);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

describe("LintMarkdown", () => {
  it("lints tracked Markdown and skips generated, vendored and archived files", () => {
    assert.equal(isLinted("README.md"), true);
    assert.equal(isLinted("docs/install/macos.md"), true);
    assert.equal(isLinted("docs/notes.MD"), true);
    assert.equal(isLinted("README.txt"), false);
    assert.equal(isLinted("packages/agentsafe/node_modules/x/README.md"), false);
    assert.equal(isLinted("packages/pipeline/dist/README.md"), false);
    assert.equal(isLinted("coverage/index.md"), false);
    assert.equal(isLinted("brief.pipeline.md"), false);
    assert.equal(isLinted("brief.docker-ecosystem.md"), false);
    assert.equal(isLinted("docs/brief.pipeline.md"), true);
  });

  it("reports a finding with its file, line, rule and description", () => {
    withFile("# Title\n\n# Title again\n", (file) => {
      const findings = lintMarkdown([file], config);
      assert.equal(findings.length, 1);
      assert.match(findings[0], /page\.md:3 MD025\/single-title\/single-h1 /);
    });
  });

  it("applies the repository's rules: long lines are allowed, sibling headings must differ", () => {
    withFile(
      `# Title\n\n${"word ".repeat(80).trim()}\n\n## A\n\n### Same\n\n## B\n\n### Same\n`,
      (file) => {
        assert.deepEqual(lintMarkdown([file], config), []);
      },
    );
  });

  it("exits 1 on a finding and 0 on a clean file, as the hook and CI need", () => {
    withFile("#Title\n", (file) => {
      const failing = spawnSync(process.execPath, [script, file], {
        cwd: repository,
        encoding: "utf8",
      });
      assert.equal(failing.status, 1);
      assert.match(failing.stderr, /MD018/);
    });
    withFile("# Title\n", (file) => {
      const passing = spawnSync(process.execPath, [script, file], {
        cwd: repository,
        encoding: "utf8",
      });
      assert.equal(passing.status, 0, passing.stderr);
      assert.match(passing.stdout, /1 file\(s\), 0 finding\(s\)/);
    });
  });
});
