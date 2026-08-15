import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const outputDirectory = resolve(process.argv[2] ?? "artifacts/dependency-licenses");
const lockfile = await readFile("pnpm-lock.yaml");
const lockfileSha256 = createHash("sha256").update(lockfile).digest("hex");

const collect = (arguments_) => {
  const result = spawnSync(pnpm, arguments_, { encoding: "utf8" });
  if (result.status !== 0) {
    process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }
  const raw = JSON.parse(result.stdout);
  const licenses = Object.fromEntries(
    Object.entries(raw)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([license, dependencies]) => [
        license,
        dependencies
          .map(({ name, versions }) => ({ name, versions: [...versions].sort() }))
          .sort((left, right) => left.name.localeCompare(right.name)),
      ]),
  );
  const componentCount = Object.values(licenses).reduce(
    (count, dependencies) =>
      count +
      dependencies.reduce(
        (dependencyCount, dependency) => dependencyCount + dependency.versions.length,
        0,
      ),
    0,
  );
  if (componentCount === 0) throw new Error("Dependency-license inventory is empty");
  return { componentCount, licenses };
};

const common = {
  schemaVersion: 1,
  source: {
    file: "pnpm-lock.yaml",
    sha256: lockfileSha256,
    installPolicy: "pnpm install --frozen-lockfile --ignore-scripts",
  },
  generatedFor: { os: process.platform, architecture: process.arch },
};
const workspace = {
  ...common,
  scope: "complete workspace dependency tree, including development dependencies",
  ...collect(["licenses", "list", "--json"]),
};
const production = {
  ...common,
  scope: "@decionis/agent-safe-pipeline production dependency tree",
  ...collect(["--filter", "@decionis/agent-safe-pipeline", "licenses", "list", "--prod", "--json"]),
};

await mkdir(outputDirectory, { recursive: true });
await Promise.all([
  writeFile(
    resolve(outputDirectory, "dependency-licenses-workspace.json"),
    `${JSON.stringify(workspace, null, 2)}\n`,
  ),
  writeFile(
    resolve(outputDirectory, "dependency-licenses-package-production.json"),
    `${JSON.stringify(production, null, 2)}\n`,
  ),
]);
process.stdout.write(
  `Generated ${workspace.componentCount} workspace and ${production.componentCount} production license records.\n`,
);
