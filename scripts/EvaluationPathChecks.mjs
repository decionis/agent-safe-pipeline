/**
 * Checks that keep EVALUATION-PATH.md true: every file it links exists, every
 * `pnpm` script it names exists, every package it names is a workspace
 * package or a published Decionis dependency it declares, and its prose
 * carries no version literal (the npm dist-tag and the release page are the
 * truth) and no performance figure (discovery rule 1.3).
 *
 * Pure functions over the document text and facts the caller supplies, so
 * the automation test can exercise them without a filesystem.
 */

const LINK = /\]\(([^)\s]+)\)/g;
const SCRIPT = /`pnpm ([a-z][a-z0-9:-]*)/g;
const PACKAGE = /`@decionis\/([a-z0-9-]+)`/g;
const VERSION_LITERAL = /\b\d+\.\d+\.\d+(?:-[0-9a-z.]+)?\b/;
const PERFORMANCE_FIGURE = /\b\d+(?:\.\d+)?\s*(?:ms|milliseconds|seconds|%|percent|req\/s|rps)\b/i;

export function linkedFiles(document) {
  return [...document.matchAll(LINK)]
    .map((match) => match[1])
    .filter((target) => !/^(?:https?:|mailto:|#)/.test(target))
    .map((target) => target.replace(/^\.\//, "").split("#")[0]);
}

/** pnpm's own commands are not root scripts. */
const PNPM_COMMANDS = new Set(["install", "add", "remove", "exec", "dlx", "run", "test", "build"]);

export function namedScripts(document) {
  return [...new Set([...document.matchAll(SCRIPT)].map((match) => match[1]))].filter(
    (name) => !name.startsWith("--") && !PNPM_COMMANDS.has(name),
  );
}

export function namedPackages(document) {
  return [...new Set([...document.matchAll(PACKAGE)].map((match) => `@decionis/${match[1]}`))];
}

/**
 * @param {object} facts
 * @param {string} facts.document
 * @param {(path: string) => boolean} facts.fileExists
 * @param {Record<string, string>} facts.rootScripts
 * @param {Set<string>} facts.workspacePackages non-private workspace package names
 * @param {Set<string>} facts.declaredDependencies published Decionis packages the workspace depends on
 * @returns {string[]} problems, empty when the document is consistent
 */
export function evaluationPathProblems({
  document,
  fileExists,
  rootScripts,
  workspacePackages,
  declaredDependencies,
}) {
  const problems = [];
  for (const file of linkedFiles(document)) {
    if (!fileExists(file)) problems.push(`links a file that does not exist: ${file}`);
  }
  for (const script of namedScripts(document)) {
    if (!(script in rootScripts))
      problems.push(`names a root script that does not exist: pnpm ${script}`);
  }
  for (const name of namedPackages(document)) {
    if (!workspacePackages.has(name) && !declaredDependencies.has(name)) {
      problems.push(
        `names a package that is neither in the workspace nor a declared dependency: ${name}`,
      );
    }
  }
  const prose = document.replace(/`[^`]*`/g, "").replace(/\([^()]*doi\.org[^()]*\)/g, "");
  const version = VERSION_LITERAL.exec(prose);
  if (version) problems.push(`carries a version literal in prose: ${version[0]}`);
  const figure = PERFORMANCE_FIGURE.exec(prose);
  if (figure) problems.push(`carries a performance figure: ${figure[0]}`);
  return problems;
}
