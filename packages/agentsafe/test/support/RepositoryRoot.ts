import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The repository root, found by walking up from this file rather than
 * assumed from the working directory. A test that reads a repository
 * artefact — a conformance vector, the mirrored profile — runs both from the
 * package and from a mutation sandbox nested inside it, and only a walk is
 * right in both places.
 */
export function repositoryRoot(): string {
  let directory = dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 12; depth += 1) {
    if (existsSync(join(directory, "pnpm-workspace.yaml"))) return directory;
    const parent = dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  throw new Error("REPOSITORY_ROOT_NOT_FOUND");
}

/** A path inside the repository, from its root. */
export function repositoryPath(...parts: readonly string[]): string {
  return resolve(repositoryRoot(), ...parts);
}
