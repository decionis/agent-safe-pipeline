import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { fileURLToPath, URL } from "node:url";
import { describe, it } from "node:test";

const checker = fileURLToPath(new URL("../../scripts/CheckDco.mjs", import.meta.url));
let changeNumber = 0;

function git(directory, arguments_) {
  return execFileSync("git", arguments_, { cwd: directory, encoding: "utf8" }).trim();
}

function createRepository() {
  const directory = mkdtempSync(join(tmpdir(), "agent-safe-dco-"));
  git(directory, ["init", "--quiet", "--initial-branch=master"]);
  git(directory, ["config", "user.name", "Example Contributor"]);
  git(directory, ["config", "user.email", "contributor@example.invalid"]);
  writeFileSync(join(directory, "evidence.txt"), "base\n");
  git(directory, ["add", "evidence.txt"]);
  git(directory, ["commit", "--quiet", "-m", "Base commit"]);
  return directory;
}

function addCommit(directory, body) {
  changeNumber += 1;
  writeFileSync(join(directory, "evidence.txt"), `change-${changeNumber}\n`, { flag: "a" });
  git(directory, ["add", "evidence.txt"]);
  const arguments_ = ["commit", "--quiet", "-m", "Governance change"];
  if (body) arguments_.push("-m", body);
  git(directory, arguments_);
  return git(directory, ["rev-parse", "HEAD"]);
}

function signed() {
  return `Signed-off-by: Example Contributor <contributor@example.invalid>`;
}

/** A pull request branch off master, then master moves on in another file. */
function divergedRepository() {
  const directory = createRepository();
  const base = git(directory, ["rev-parse", "HEAD"]);
  git(directory, ["switch", "--quiet", "-c", "feature"]);
  addCommit(directory, signed());
  git(directory, ["switch", "--quiet", "master"]);
  writeFileSync(join(directory, "other.txt"), "master moved on\n");
  git(directory, ["add", "other.txt"]);
  git(directory, ["commit", "--quiet", "-m", "Master change", "-m", signed()]);
  git(directory, ["switch", "--quiet", "feature"]);
  return { directory, base };
}

function runChecker(directory, base, head, pullRequestAuthor) {
  const arguments_ = [checker, base, head];
  if (pullRequestAuthor) arguments_.push(pullRequestAuthor);
  return spawnSync(process.execPath, arguments_, {
    cwd: directory,
    encoding: "utf8",
  });
}

describe("CheckDco", () => {
  it("accepts an author-matching Signed-off-by trailer", () => {
    const directory = createRepository();
    try {
      const base = git(directory, ["rev-parse", "HEAD"]);
      const head = addCommit(
        directory,
        "Signed-off-by: Example Contributor <contributor@example.invalid>",
      );
      const result = runChecker(directory, base, head);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /verified for 1 commit/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("rejects a commit without a Signed-off-by trailer", () => {
    const directory = createRepository();
    try {
      const base = git(directory, ["rev-parse", "HEAD"]);
      const head = addCommit(directory);
      const result = runChecker(directory, base, head);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /DCO_AUTHOR_SIGNOFF_MISSING/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("rejects a trailer that belongs to a different identity", () => {
    const directory = createRepository();
    try {
      const base = git(directory, ["rev-parse", "HEAD"]);
      const head = addCommit(directory, "Signed-off-by: Other Person <other@example.invalid>");
      const result = runChecker(directory, base, head);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /missing: Signed-off-by: Example Contributor/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("exempts only the authenticated Dependabot identity on a Dependabot pull request", () => {
    const directory = createRepository();
    try {
      const base = git(directory, ["rev-parse", "HEAD"]);
      git(directory, ["config", "user.name", "dependabot[bot]"]);
      git(directory, ["config", "user.email", "49699333+dependabot[bot]@users.noreply.github.com"]);
      const head = addCommit(directory);
      assert.equal(runChecker(directory, base, head, "dependabot[bot]").status, 0);
      assert.equal(runChecker(directory, base, head, "someone-else").status, 1);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
  it("does not ask a clean merge, such as GitHub's Update branch, for a sign-off", () => {
    const { directory, base } = divergedRepository();
    try {
      git(directory, ["merge", "--quiet", "--no-edit", "--no-ff", "master"]);
      const head = git(directory, ["rev-parse", "HEAD"]);
      assert.equal(
        git(directory, ["show", "--no-patch", "--format=%B", head]).includes("Signed-off-by"),
        false,
      );
      const result = runChecker(directory, base, head);
      assert.equal(result.status, 0, result.stderr);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("asks a merge that resolved a conflict for its author's sign-off", () => {
    const directory = createRepository();
    try {
      const base = git(directory, ["rev-parse", "HEAD"]);
      git(directory, ["switch", "--quiet", "-c", "feature"]);
      addCommit(directory, signed());
      git(directory, ["switch", "--quiet", "master"]);
      writeFileSync(join(directory, "evidence.txt"), "master rewrote the line\n");
      git(directory, ["commit", "--quiet", "-am", "Master change", "-m", signed()]);
      git(directory, ["switch", "--quiet", "feature"]);
      spawnSync("git", ["merge", "--quiet", "master"], { cwd: directory, encoding: "utf8" });
      writeFileSync(join(directory, "evidence.txt"), "resolved by hand\n");
      git(directory, ["commit", "--quiet", "-am", "Merge master"]);
      const head = git(directory, ["rev-parse", "HEAD"]);
      const result = runChecker(directory, base, head);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /DCO_AUTHOR_SIGNOFF_MISSING/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("asks a merge that slipped in a change of its own for a sign-off", () => {
    const { directory, base } = divergedRepository();
    try {
      git(directory, ["merge", "--quiet", "--no-ff", "--no-commit", "master"]);
      writeFileSync(join(directory, "slipped.txt"), "not from either parent\n");
      git(directory, ["add", "slipped.txt"]);
      git(directory, ["commit", "--quiet", "-m", "Merge master"]);
      const head = git(directory, ["rev-parse", "HEAD"]);
      const result = runChecker(directory, base, head);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /DCO_AUTHOR_SIGNOFF_MISSING/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
