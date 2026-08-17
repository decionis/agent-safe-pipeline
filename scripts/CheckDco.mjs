import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const maxCommits = 500;
const maxCommandOutputBytes = 2 * 1024 * 1024;
const commitReference = /^[0-9a-f]{40}$/;
const dependabotIdentity = Object.freeze({
  name: "dependabot[bot]",
  email: "49699333+dependabot[bot]@users.noreply.github.com",
});

function runGit(arguments_) {
  const result = spawnSync("git", arguments_, {
    encoding: "utf8",
    maxBuffer: maxCommandOutputBytes,
  });
  if (result.status !== 0 || result.signal !== null || result.error !== undefined) {
    throw new Error("DCO_GIT_COMMAND_FAILED");
  }
  return result.stdout;
}

export function hasAuthorSignoff(message, authorName, authorEmail) {
  const normalizedName = authorName.trim();
  const normalizedEmail = authorEmail.trim().toLowerCase();
  const prefix = "signed-off-by:";
  for (const untrimmedLine of message.split("\n")) {
    const line = untrimmedLine.endsWith("\r") ? untrimmedLine.slice(0, -1) : untrimmedLine;
    if (!line.toLowerCase().startsWith(prefix)) continue;
    const value = line.slice(prefix.length).trim();
    const openingBracket = value.indexOf("<");
    if (
      openingBracket <= 0 ||
      openingBracket !== value.lastIndexOf("<") ||
      !value.endsWith(">") ||
      value.slice(openingBracket + 1, -1).includes(">")
    ) {
      continue;
    }
    const signedName = value.slice(0, openingBracket).trim();
    const signedEmail = value
      .slice(openingBracket + 1, -1)
      .trim()
      .toLowerCase();
    if (signedName === normalizedName && signedEmail === normalizedEmail) {
      return true;
    }
  }
  return false;
}

export function verifyCommitRange(baseCommit, headCommit, pullRequestAuthor = "") {
  if (!commitReference.test(baseCommit) || !commitReference.test(headCommit)) {
    throw new Error("DCO_COMMIT_REFERENCE_INVALID");
  }

  const commits = runGit([
    "rev-list",
    "--reverse",
    `--max-count=${maxCommits + 1}`,
    `${baseCommit}..${headCommit}`,
  ])
    .split(/\r?\n/)
    .filter(Boolean);
  if (commits.length === 0) throw new Error("DCO_COMMIT_RANGE_EMPTY");
  if (commits.length > maxCommits) throw new Error("DCO_COMMIT_RANGE_TOO_LARGE");

  const failures = [];
  for (const commit of commits) {
    const metadata = runGit(["show", "--no-patch", "--format=%H%x00%an%x00%ae%x00%B", commit]);
    const [hash, authorName, authorEmail, ...messageParts] = metadata.split("\0");
    if (!hash || !authorName || !authorEmail) throw new Error("DCO_COMMIT_METADATA_INVALID");
    const trustedDependabotCommit =
      pullRequestAuthor === dependabotIdentity.name &&
      authorName === dependabotIdentity.name &&
      authorEmail.toLowerCase() === dependabotIdentity.email;
    if (trustedDependabotCommit) continue;
    if (!hasAuthorSignoff(messageParts.join("\0"), authorName, authorEmail)) {
      failures.push({ hash, authorName, authorEmail });
    }
  }

  if (failures.length > 0) {
    for (const failure of failures) {
      process.stderr.write(
        `${failure.hash.slice(0, 12)} is missing: Signed-off-by: ${failure.authorName} <${failure.authorEmail}>\n`,
      );
    }
    throw new Error("DCO_AUTHOR_SIGNOFF_MISSING");
  }
  return Object.freeze({ commits: commits.length });
}

function main() {
  const [baseCommit, headCommit, pullRequestAuthor = ""] = process.argv.slice(2);
  if (!baseCommit || !headCommit) {
    throw new Error(
      "Usage: CheckDco.mjs <base-commit-sha> <head-commit-sha> [pull-request-author]",
    );
  }
  const verified = verifyCommitRange(baseCommit, headCommit, pullRequestAuthor);
  process.stdout.write(`DCO sign-off verified for ${verified.commits} commit(s).\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write((error instanceof Error ? error.message : "DCO_CHECK_FAILED") + "\n");
    process.exitCode = 1;
  }
}
