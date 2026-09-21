import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { parse } from "yaml";
import { renderManifest } from "../../scripts/RenderGovernRelease.mjs";
import { parseSums, TARGETS } from "../../scripts/RenderHomebrewFormula.mjs";

const read = (path) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");
const sum = (character) => character.repeat(64);

/**
 * The action runs the bytes its commit names: the release manifest beside it
 * pins each platform archive's SHA-256, the resolve step downloads and
 * verifies before it extracts, and only a version the manifest does not
 * name, or a runner without an archive, is built from the commit itself.
 */
describe("govern's release manifest", () => {
  it("is rendered from the four archives' checksums and refuses a missing one", () => {
    const sums = new Map(
      TARGETS.map((target, index) => [`govern-2.0.0-${target}.tar.gz`, sum("abcd"[index])]),
    );
    const manifest = renderManifest("2.0.0", "v0.4.0", sums);
    assert.equal(manifest.version, "2.0.0");
    assert.equal(manifest.tag, "v0.4.0");
    assert.equal(
      manifest.base,
      "https://github.com/decionis/agent-safe-pipeline/releases/download",
    );
    assert.deepEqual(Object.keys(manifest.sha256).sort(), [...TARGETS].sort());
    assert.equal(manifest.sha256["linux-x64"], sum("d"));
    sums.delete("govern-2.0.0-linux-arm64.tar.gz");
    assert.throws(
      () => renderManifest("2.0.0", "v0.4.0", sums),
      /does not list govern-2\.0\.0-linux-arm64/,
    );
    assert.throws(() => renderManifest("two", "v0.4.0", sums), /not a version/);
    assert.throws(() => renderManifest("2.0.0", "0.4.0", sums), /not a release tag/);
    assert.equal(parseSums(`${sum("1")}  govern-2.0.0-linux-x64.tar.gz\n`).size, 1);
  });

  it("is checked in beside the action, empty until a release names a version", async () => {
    const manifest = JSON.parse(await read("govern/release.json"));
    assert.deepEqual(Object.keys(manifest).sort(), ["base", "sha256", "tag", "version"]);
    assert.equal(
      manifest.base,
      "https://github.com/decionis/agent-safe-pipeline/releases/download",
    );
    const version = (await read("govern/VERSION")).trim();
    if (manifest.version === "") {
      assert.deepEqual(manifest.sha256, {});
    } else {
      // A pinned manifest names the source's version, or the action would
      // build from a commit whose bytes the manifest does not describe.
      assert.equal(manifest.version, version);
      assert.deepEqual(Object.keys(manifest.sha256).sort(), [...TARGETS].sort());
      for (const digest of Object.values(manifest.sha256)) assert.match(digest, /^[0-9a-f]{64}$/);
      assert.match(manifest.tag, /^v\d+\.\d+\.\d+/);
    }
  });
});

describe("govern's action", () => {
  it("downloads the pinned archive, verifies it before extracting, and builds only when there is none", async () => {
    const action = parse(await read("govern/action.yml"));
    assert.equal(action.runs.using, "composite");
    const names = action.runs.steps.map((step) => step.name);
    assert.deepEqual(names, [
      "Resolve the govern binary",
      "Set up Go",
      "Build govern",
      "Govern the step",
    ]);
    const resolve = action.runs.steps[0];
    assert.equal(resolve.id, "resolve");
    assert.match(resolve.run, /jq -r '\.version' release\.json/);
    assert.match(
      resolve.run,
      /curl --proto '=https' --tlsv1\.2 -fsSL --retry 3 -o "\$RUNNER_TEMP\/\$archive" "\$base\/\$tag\/\$archive"/,
    );
    assert.match(resolve.run, /sha256sum --check --strict/);
    assert.match(resolve.run, /shasum -a 256 --check --strict/);
    // Verification precedes extraction, and a build is the answer to no archive.
    assert.ok(resolve.run.indexOf("--check --strict") < resolve.run.indexOf("tar -xzf"));
    assert.match(resolve.run, /echo "source=build" >> "\$GITHUB_OUTPUT"/);
    assert.match(resolve.run, /echo "source=release" >> "\$GITHUB_OUTPUT"/);
    for (const name of ["Set up Go", "Build govern"]) {
      const step = action.runs.steps.find((candidate) => candidate.name === name);
      assert.equal(step.if, "steps.resolve.outputs.source == 'build'", name);
    }
    const build = action.runs.steps.find((step) => step.name === "Build govern");
    assert.match(build.run, /CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w"/);
    const setupGo = action.runs.steps.find((step) => step.name === "Set up Go");
    assert.match(setupGo.uses, /^actions\/setup-go@[0-9a-f]{40}$/);
    assert.equal(setupGo.with["go-version-file"], "${{ github.action_path }}/go.mod");
    const gate = action.runs.steps.find((step) => step.name === "Govern the step");
    assert.equal(gate.run, '"$RUNNER_TEMP/govern" run');
    assert.equal(gate.env.GOVERN_HOST, "github");
    // Every input reaches the binary as a variable, and the key only as one.
    for (const input of Object.keys(action.inputs)) {
      const expected = `\${{ inputs.${input} }}`;
      assert.ok(Object.values(gate.env).includes(expected), `input ${input} is not passed`);
    }
    assert.equal(gate.env.DECIONIS_API_KEY, "${{ inputs.api-key }}");
    // Every output the binary writes is declared, from the gate step.
    for (const [name, output] of Object.entries(action.outputs)) {
      assert.equal(output.value, `\${{ steps.gate.outputs.${name} }}`, name);
    }
  });
});
