import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { parse } from "yaml";
import { BUILD_COMMAND } from "../../scripts/GovernSbom.mjs";
import { archiveName, renderManifest, TARGETS } from "../../scripts/RenderGovernRelease.mjs";
import { parseSums, TARGETS as FORMULA_TARGETS } from "../../scripts/RenderHomebrewFormula.mjs";

const read = (path) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");
const sum = (character) => character.repeat(64);

/**
 * The action runs the bytes its commit names: the release manifest beside it
 * pins each platform archive's SHA-256, the resolve step downloads and
 * verifies before it extracts, and only a version the manifest does not
 * name, or a runner without an archive, is built from the commit itself.
 */
describe("govern's release manifest", () => {
  it("is rendered from the five archives' checksums and refuses a missing one", () => {
    // The formula's four tarballs, and the Windows zip the action alone installs.
    assert.deepEqual(TARGETS, [...FORMULA_TARGETS, "windows-x64"]);
    assert.equal(archiveName("2.0.0", "windows-x64"), "govern-2.0.0-windows-x64.zip");
    assert.equal(archiveName("2.0.0", "darwin-arm64"), "govern-2.0.0-darwin-arm64.tar.gz");
    const sums = new Map(
      TARGETS.map((target, index) => [archiveName("2.0.0", target), sum("abcde"[index])]),
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
    assert.equal(manifest.sha256["windows-x64"], sum("e"));
    sums.delete("govern-2.0.0-windows-x64.zip");
    assert.throws(
      () => renderManifest("2.0.0", "v0.4.0", sums),
      /does not list govern-2\.0\.0-windows-x64\.zip/,
    );
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
      // build from a commit whose bytes the manifest does not describe. It
      // pins every tarball; the Windows zip from the first release that
      // ships one, and the action builds on Windows until then.
      assert.equal(manifest.version, version);
      const pinned = Object.keys(manifest.sha256).sort();
      for (const target of FORMULA_TARGETS) assert.ok(pinned.includes(target), target);
      for (const target of pinned) assert.ok(TARGETS.includes(target), target);
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
    assert.ok(resolve.run.indexOf("--check --strict") < resolve.run.indexOf("tar.exe"));
    assert.match(resolve.run, /echo "source=build" >> "\$GITHUB_OUTPUT"/);
    assert.match(resolve.run, /echo "source=release" >> "\$GITHUB_OUTPUT"/);
    // Every runner the release archives for is mapped; Windows takes the zip
    // and runs govern.exe, which every later step is told the path of.
    for (const [runner, target] of [
      ["Linux/X64", "linux-x64"],
      ["Linux/ARM64", "linux-arm64"],
      ["macOS/ARM64", "darwin-arm64"],
      ["macOS/X64", "darwin-x64"],
      ["Windows/X64", "windows-x64"],
    ]) {
      assert.ok(resolve.run.includes(`${runner}) target=${target} ;;`), runner);
    }
    assert.match(resolve.run, /windows-\*\) archive="govern-\$version-\$target\.zip" ;;/);
    assert.match(
      resolve.run,
      /"\$\{SYSTEMROOT:-C:\/Windows\}\/System32\/tar\.exe" -xf "\$RUNNER_TEMP\/\$archive" -C "\$RUNNER_TEMP"/,
    );
    assert.match(
      resolve.run,
      /if \[ "\$RUNNER_OS" = Windows \]; then executable="\$RUNNER_TEMP\/govern\.exe"; fi/,
    );
    assert.match(resolve.run, /echo "executable=\$executable" >> "\$GITHUB_OUTPUT"/);
    for (const name of ["Set up Go", "Build govern"]) {
      const step = action.runs.steps.find((candidate) => candidate.name === name);
      assert.equal(step.if, "steps.resolve.outputs.source == 'build'", name);
    }
    const build = action.runs.steps.find((step) => step.name === "Build govern");
    assert.ok(build.run.startsWith(`${BUILD_COMMAND} -o "$GOVERN_EXECUTABLE" ./cmd/govern`));
    assert.equal(build.env.GOVERN_EXECUTABLE, "${{ steps.resolve.outputs.executable }}");
    const setupGo = action.runs.steps.find((step) => step.name === "Set up Go");
    assert.match(setupGo.uses, /^actions\/setup-go@[0-9a-f]{40}$/);
    assert.equal(setupGo.with["go-version-file"], "${{ github.action_path }}/go.mod");
    const gate = action.runs.steps.find((step) => step.name === "Govern the step");
    assert.equal(gate.run, '"$GOVERN_EXECUTABLE" run');
    assert.equal(gate.env.GOVERN_EXECUTABLE, "${{ steps.resolve.outputs.executable }}");
    assert.equal(gate.env.GOVERN_HOST, "github");
    // The shell is the runner's default until named: bash, or PowerShell on Windows.
    assert.equal(action.inputs.shell.default, "");
    assert.match(
      action.inputs.shell.description,
      /`pwsh`, `powershell` \(the default on Windows\) or `cmd`/,
    );
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
