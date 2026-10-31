/**
 * Runs one shard of a package's mutation gate.
 *
 *   node scripts/MutationShard.mjs <package directory> <k>/<n> [--print]
 *
 * A package's `stryker.config.mjs` lists exactly the files its gate covers.
 * Shard k of n takes every n-th file of that list, starting at the k-th, so
 * the n shards of one package cover the list exactly once. A file added to
 * the list joins a shard without a change here, and each shard is held to the
 * package's own break threshold, so splitting the gate changes how long it
 * takes and nothing about what it requires. `--print` names the shard's files
 * and runs nothing.
 */
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const SHARD = /^([1-9]\d*)\/([1-9]\d*)$/;

/** The files shard `k/n` mutates, in the list's order. */
export function shardFiles(files, shard) {
  const match = SHARD.exec(shard);
  if (match === null) throw new Error(`MUTATION_SHARD_INVALID: ${shard}`);
  const index = Number(match[1]);
  const count = Number(match[2]);
  if (index > count) throw new Error(`MUTATION_SHARD_INVALID: ${shard}`);
  const selected = files.filter((_, position) => position % count === index - 1);
  // A shard with nothing to mutate would pass without testing anything.
  if (selected.length === 0) throw new Error(`MUTATION_SHARD_EMPTY: ${shard}`);
  return selected;
}

async function main() {
  const [directory, shard, flag] = process.argv.slice(2);
  if (
    directory === undefined ||
    shard === undefined ||
    (flag !== undefined && flag !== "--print")
  ) {
    throw new Error("usage: node scripts/MutationShard.mjs <package directory> <k>/<n> [--print]");
  }
  const packageDirectory = resolve(directory);
  const { default: config } = await import(
    pathToFileURL(resolve(packageDirectory, "stryker.config.mjs")).href
  );
  const files = shardFiles(config.mutate, shard);
  if (flag === "--print") {
    process.stdout.write(`${files.join("\n")}\n`);
    return;
  }
  // The package's own script, so a step it runs first (agentsafe builds the
  // pipeline) runs here too; pnpm appends the option to its last command.
  const run = spawnSync("pnpm", ["run", "test:mutation", "--mutate", files.join(",")], {
    cwd: packageDirectory,
    stdio: "inherit",
  });
  if (run.error !== undefined) throw run.error;
  process.exitCode = run.status ?? 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
