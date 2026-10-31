import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { parse } from "yaml";
import { shardFiles } from "../../scripts/MutationShard.mjs";

const files = ["a.ts", "b.ts", "c.ts", "d.ts", "e.ts", "f.ts", "g.ts"];

describe("MutationShard", () => {
  it("covers the list exactly once across a package's shards", () => {
    const shards = ["1/3", "2/3", "3/3"].map((shard) => shardFiles(files, shard));
    assert.deepEqual(shards, [
      ["a.ts", "d.ts", "g.ts"],
      ["b.ts", "e.ts"],
      ["c.ts", "f.ts"],
    ]);
    assert.deepEqual(shards.flat().sort(), files);
    assert.deepEqual(shardFiles(files, "1/1"), files);
  });

  it("refuses a malformed shard, one past the count, and one with nothing to mutate", () => {
    for (const shard of ["0/3", "4/3", "1", "1/0", "a/b", " 1/3", "1/3 ", "-1/3"]) {
      assert.throws(() => shardFiles(files, shard), /MUTATION_SHARD_INVALID/, shard);
    }
    assert.throws(() => shardFiles(["a.ts"], "2/2"), /MUTATION_SHARD_EMPTY/);
  });

  it("runs every shard the workflow names, and every package's shards cover its whole list", async () => {
    const workflow = parse(
      await readFile(new URL("../../.github/workflows/deploy.yml", import.meta.url), "utf8"),
    );
    const shards = workflow.jobs.mutation.strategy.matrix.include;
    for (const directory of ["packages/pipeline", "packages/agentsafe"]) {
      const { default: config } = await import(
        new URL(`../../${directory}/stryker.config.mjs`, import.meta.url).href
      );
      const named = shards.filter((entry) => entry.directory === directory);
      const counts = new Set(named.map((entry) => entry.shard.split("/")[1]));
      assert.equal(counts.size, 1, `${directory} names one shard count`);
      const covered = named.flatMap((entry) => shardFiles(config.mutate, entry.shard));
      assert.deepEqual(covered.sort(), [...config.mutate].sort(), directory);
    }
    // The required check keeps its name, and it fails unless every shard passed.
    const gate = workflow.jobs.assurance;
    assert.equal(gate.name, "Mutation assurance");
    assert.equal(gate.needs, "mutation");
    assert.equal(gate.if, "always()");
    assert.ok(gate.steps.some((step) => /test "\$RESULT" = success/.test(step.run ?? "")));
  });
});
