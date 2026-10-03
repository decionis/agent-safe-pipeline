import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { lint } from "markdownlint/sync";

// The repository's Markdown lint: the markdownlint library, the rules in
// .markdownlint.json, and the tracked files. Git decides which files exist,
// so what .gitignore keeps out of the repository is kept out of the lint, and
// nothing else needs to walk the tree. A wrapper CLI would add a globber and
// its dependencies for the same job.

/** Tracked Markdown that is not linted: generated or vendored output, and two archived briefs. */
const excluded = [
  /(^|\/)node_modules\//,
  /(^|\/)dist\//,
  /(^|\/)coverage\//,
  /^brief\.pipeline\.md$/,
  /^brief\.docker-ecosystem\.md$/,
];

export function isLinted(path) {
  return /\.md$/i.test(path) && !excluded.some((pattern) => pattern.test(path));
}

export function trackedMarkdown(cwd = process.cwd()) {
  return execFileSync("git", ["ls-files", "-z", "--", "*.md", "*.MD"], { cwd, encoding: "utf8" })
    .split("\0")
    .filter(Boolean)
    .filter(isLinted);
}

export function lintMarkdown(files, config) {
  const results = lint({ files, config });
  const findings = [];
  for (const file of files) {
    for (const issue of results[file] ?? []) {
      const column = issue.errorRange ? `:${issue.errorRange[0]}` : "";
      const detail = issue.errorDetail ? ` [${issue.errorDetail}]` : "";
      const context = issue.errorContext ? ` [Context: "${issue.errorContext}"]` : "";
      findings.push(
        `${file}:${issue.lineNumber}${column} ${issue.ruleNames.join("/")} ${issue.ruleDescription}${detail}${context}`,
      );
    }
  }
  return findings;
}

function main() {
  const config = JSON.parse(readFileSync(".markdownlint.json", "utf8"));
  const requested = process.argv.slice(2);
  const files = requested.length > 0 ? requested.filter(isLinted) : trackedMarkdown();
  const findings = lintMarkdown(files, config);
  for (const finding of findings) process.stderr.write(`${finding}\n`);
  process.stdout.write(`Markdown lint: ${files.length} file(s), ${findings.length} finding(s).\n`);
  if (findings.length > 0) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
