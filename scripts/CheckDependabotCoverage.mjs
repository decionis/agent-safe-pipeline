import { readFile, readdir } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { pathToFileURL } from "node:url";

const ignoredDirectories = new Set([".git", "coverage", "dist", "node_modules"]);
const maxDirectories = 10_000;

function unquote(value) {
  const trimmed = value.trim();
  if (
    trimmed.length >= 2 &&
    ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'")))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

export function parseDependabotUpdates(source) {
  const updates = [];
  let current = null;
  for (const line of source.split(/\r?\n/)) {
    const trimmed = line.trim();
    const ecosystemPrefix = "- package-ecosystem:";
    if (trimmed.startsWith(ecosystemPrefix)) {
      current = {
        ecosystem: unquote(trimmed.slice(ecosystemPrefix.length)),
        directory: null,
        interval: null,
      };
      updates.push(current);
      continue;
    }
    if (current === null) continue;
    const directoryPrefix = "directory:";
    if (trimmed.startsWith(directoryPrefix) && current.directory === null) {
      current.directory = unquote(trimmed.slice(directoryPrefix.length));
    }
    const intervalPrefix = "interval:";
    if (trimmed.startsWith(intervalPrefix) && current.interval === null) {
      current.interval = unquote(trimmed.slice(intervalPrefix.length));
    }
  }
  return updates;
}

export function parseWorkspacePatterns(source) {
  const patterns = [];
  for (const line of source.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith("- ")) patterns.push(unquote(trimmed.slice(2)));
  }
  if (patterns.length === 0) throw new Error("PNPM_WORKSPACE_PATTERNS_MISSING");
  return patterns;
}

function matchesWorkspacePattern(directory, pattern) {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", "[^/]*");
  return new RegExp(`^${escaped}$`).test(directory);
}

export function assertDependabotCoverage({
  configSource,
  packageDirectories,
  workspaceSource,
  workflowFiles,
}) {
  const updates = parseDependabotUpdates(configSource);
  for (const ecosystem of ["npm", "github-actions"]) {
    const matches = updates.filter((entry) => entry.ecosystem === ecosystem);
    if (matches.length !== 1)
      throw new Error(`DEPENDABOT_${ecosystem.toUpperCase()}_ENTRY_INVALID`);
    if (matches[0].directory !== "/" || matches[0].interval !== "weekly") {
      throw new Error(`DEPENDABOT_${ecosystem.toUpperCase()}_ROOT_WEEKLY_REQUIRED`);
    }
  }

  const patterns = parseWorkspacePatterns(workspaceSource);
  const uncovered = packageDirectories.filter(
    (directory) =>
      directory !== "." && !patterns.some((pattern) => matchesWorkspacePattern(directory, pattern)),
  );
  if (uncovered.length > 0)
    throw new Error(`PNPM_WORKSPACE_PACKAGE_UNCOVERED:${uncovered.join(",")}`);
  if (packageDirectories.length < 2) throw new Error("PNPM_WORKSPACE_PACKAGES_MISSING");
  if (workflowFiles.length === 0 || workflowFiles.some((file) => !/\.ya?ml$/.test(file))) {
    throw new Error("GITHUB_ACTIONS_WORKFLOWS_UNCOVERED");
  }
  return Object.freeze({
    packageDirectories: packageDirectories.length,
    workflowFiles: workflowFiles.length,
    workspacePatterns: patterns.length,
  });
}

async function findPackageDirectories(root) {
  const found = [];
  const pending = [root];
  let visited = 0;
  while (pending.length > 0) {
    const directory = pending.pop();
    if (directory === undefined) break;
    visited += 1;
    if (visited > maxDirectories) throw new Error("REPOSITORY_DIRECTORY_LIMIT_EXCEEDED");
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isFile() && entry.name === "package.json") {
        const path = relative(root, directory).split(sep).join("/");
        found.push(path === "" ? "." : path);
      } else if (entry.isDirectory() && !ignoredDirectories.has(entry.name)) {
        pending.push(join(directory, entry.name));
      }
    }
  }
  return found.sort();
}

async function main() {
  const root = new URL("../", import.meta.url);
  const [configSource, workspaceSource, packageDirectories, workflowEntries] = await Promise.all([
    readFile(new URL(".github/dependabot.yml", root), "utf8"),
    readFile(new URL("pnpm-workspace.yaml", root), "utf8"),
    findPackageDirectories(root.pathname),
    readdir(new URL(".github/workflows/", root), { withFileTypes: true }),
  ]);
  const result = assertDependabotCoverage({
    configSource,
    packageDirectories,
    workspaceSource,
    workflowFiles: workflowEntries.filter((entry) => entry.isFile()).map((entry) => entry.name),
  });
  process.stdout.write(
    `Dependabot covers ${result.packageDirectories} package manifests and ${result.workflowFiles} workflows.\n`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : "DEPENDABOT_CHECK_FAILED"}\n`);
    process.exitCode = 1;
  });
}
