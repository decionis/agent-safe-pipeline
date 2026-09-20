/**
 * A consumer of a packed tarball, assembled from pinned parts instead of
 * installed from the registry: the tarball's own files unpacked as the
 * package a consumer would import, and the package's dependencies linked
 * from the tree the repository's lockfile pins and `pnpm install
 * --frozen-lockfile` put in place. What the consumer then imports is exactly
 * what the tarball ships (its `files`, its `exports`, its manifest), against
 * the dependency versions the tests ran, and nothing is fetched to build it.
 *
 * Usage: ConsumerFromTarball.mjs <tarball.tgz> <workspace-package-dir> <consumer-dir> [extra-dependency...]
 *
 * Each extra dependency is one the consumer declares for itself; it is linked
 * from the same pinned tree, so a consumer that also imports `zod` gets the
 * `zod` the package was tested with. A dependency the tree links from another
 * workspace package comes from that package's source, as the tree has it.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const [tarball, packageDirArgument, consumerDirArgument, ...extras] = process.argv.slice(2);
if (!tarball || !packageDirArgument || !consumerDirArgument) {
  throw new Error(
    "Usage: ConsumerFromTarball.mjs <tarball.tgz> <workspace-package-dir> <consumer-dir> [extra-dependency...]",
  );
}
const packageDir = realpathSync(resolve(packageDirArgument));
const consumerDir = resolve(consumerDirArgument);
const manifest = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8"));
const name = manifest.name;

// The tarball, unpacked where a consumer's resolver looks for the package.
const installed = join(consumerDir, "node_modules", name);
rmSync(installed, { recursive: true, force: true });
mkdirSync(installed, { recursive: true });
execFileSync(
  "tar",
  [
    "--extract",
    "--gzip",
    "--strip-components=1",
    "--file",
    resolve(tarball),
    "--directory",
    installed,
  ],
  {
    stdio: "inherit",
  },
);
const shipped = JSON.parse(readFileSync(join(installed, "package.json"), "utf8"));
if (shipped.name !== name || shipped.version !== manifest.version) {
  throw new Error(
    `the tarball is ${shipped.name}@${shipped.version}, not ${name}@${manifest.version}`,
  );
}

// The dependencies the tarball declares, and the consumer's own, from the pinned tree.
const wanted = [...Object.keys(shipped.dependencies ?? {}), ...extras].sort();
let linked = 0;
for (const dependency of new Set(wanted)) {
  if (dependency === name) continue;
  const source = join(packageDir, "node_modules", dependency);
  if (!existsSync(source)) {
    throw new Error(
      `${dependency} is not installed beside ${name}; run pnpm install --frozen-lockfile`,
    );
  }
  const target = join(consumerDir, "node_modules", dependency);
  rmSync(target, { recursive: true, force: true });
  mkdirSync(dirname(target), { recursive: true });
  symlinkSync(realpathSync(source), target, "dir");
  linked += 1;
}
process.stdout.write(
  `Assembled a consumer of ${name}@${shipped.version} from its tarball at ${installed}, ${String(linked)} dependencies linked from the lockfile's tree.\n`,
);
