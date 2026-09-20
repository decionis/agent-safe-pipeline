import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { parse } from "yaml";

const root = fileURLToPath(new URL("../../", import.meta.url));
/** A NuGet content hash: SHA-512, base64. */
const SHA512_BASE64 = /^[a-z0-9+/]{86}==$/i;
const read = (path) => readFile(join(root, path), "utf8");
const json = async (path) => JSON.parse(await read(path));
const run = (script, args, cwd = root) => {
  const result = spawnSync(process.execPath, [join(root, "scripts", script), ...args], {
    cwd,
    encoding: "utf8",
  });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
};

/**
 * Every package CI installs is the one the lockfile pins. The release SBOMs
 * are read from that tree, the tarball's consumers are assembled from it, the
 * publishing workflows use the npm their Node release ships, and the .NET
 * verifier restores in locked mode. These gates hold the workflows and the
 * two scripts to it, so an `npm install` cannot slip back in unnoticed as a
 * convenience.
 */
describe("the workflows", () => {
  it("fetch packages only through the lockfiles", async () => {
    const directory = join(root, ".github/workflows");
    const names = (await readdir(directory)).filter((name) => name.endsWith(".yml"));
    assert.ok(names.length >= 10);
    for (const name of names) {
      const workflow = parse(await read(`.github/workflows/${name}`));
      for (const [jobName, job] of Object.entries(workflow.jobs)) {
        for (const step of job.steps ?? []) {
          if (typeof step.run !== "string") continue;
          const commands = step.run
            .split("\n")
            .filter((line) => !/^\s*(?:#|echo\b)/.test(line))
            .join("\n");
          const where = `${name} › ${jobName} › ${step.name ?? step.run.slice(0, 40)}`;
          assert.doesNotMatch(commands, /\bnpm\s+(?:install|i|add|update|up|ci)\b/, where);
          assert.doesNotMatch(commands, /\bnpm\s+sbom\b/, where);
          for (const restore of commands.match(/\bdotnet\s+restore\b[^\n]*/g) ?? []) {
            assert.match(restore, /--locked-mode/, where);
          }
          for (const install of commands.match(/\bpnpm\s+install\b[^\n]*/g) ?? []) {
            assert.match(install, /--frozen-lockfile/, where);
          }
        }
      }
    }
  });

  it("read both release SBOMs from the lockfile's tree and assemble the tarball's consumer from it", async () => {
    const workflow = parse(await read(".github/workflows/deploy.yml"));
    const step = (name) => workflow.jobs.release.steps.find((entry) => entry.name === name);
    const pipeline = step("Build package, SBOM, and license inventories").run;
    assert.match(
      pipeline,
      /node scripts\/ReleaseSbom\.mjs packages\/pipeline "release\/\$RELEASE_STEM\.cdx\.json" library/,
    );
    assert.match(pipeline, /node scripts\/FinalizeReleaseSbom\.mjs/);
    assert.match(pipeline, /node scripts\/AssertReleaseSbom\.mjs/);
    assert.match(
      pipeline,
      /node scripts\/ConsumerFromTarball\.mjs \\\n\s+"release\/\$RELEASE_TARBALL" packages\/pipeline "\$RUNNER_TEMP\/consumer"/,
    );
    assert.match(pipeline, /typeof pkg\.SafeExecutor !== 'function'/);
    const runtime = step("Pack the runtime package and build its SBOM").run;
    assert.match(
      runtime,
      /node scripts\/ReleaseSbom\.mjs packages\/agentsafe \\\n\s+"release\/agentsafe-\$runtime_version\.cdx\.json" application \\\n\s+--packed "release\/\$PIPELINE_TARBALL"/,
    );
    // The packed runtime must declare a publishable range for the pipeline;
    // that check outlives the install it once preceded.
    assert.match(runtime, /case "\$pipeline_range" in workspace:\*\)/);
  });

  it("test the packed tarball from a consumer assembled without a package manager", async () => {
    const workflow = parse(await read(".github/workflows/test-packed-package.yml"));
    const steps = workflow.jobs["packed-package-matrix"].steps;
    const names = steps.map((step) => step.name);
    const assemble = steps.find(
      (step) => step.name === "Assemble a consumer of the tarball from the pinned tree",
    );
    assert.match(
      assemble.run,
      /node scripts\/ConsumerFromTarball\.mjs "\$TARBALL_PATH" packages\/pipeline \/tmp\/consumer zod @decionis\/presence-node/,
    );
    const held = steps.find(
      (step) => step.name === "Verify the consumer holds the tarball's files and nothing else",
    );
    assert.equal(
      held["working-directory"],
      "/tmp/consumer/node_modules/@decionis/agent-safe-pipeline",
    );
    assert.match(held.run, /tar --list --gzip --file "\$TARBALL_PATH"/);
    assert.match(held.run, /diff \/tmp\/shipped\.txt \/tmp\/held\.txt/);
    assert.ok(
      names.indexOf("Assemble a consumer of the tarball from the pinned tree") <
        names.indexOf("Verify the consumer holds the tarball's files and nothing else") &&
        names.indexOf("Verify the consumer holds the tarball's files and nothing else") <
          names.indexOf("Run consumer validation (ALLOW + BLOCK)"),
    );
    // The harness imports these two itself; they come from the same tree.
    const harness = await readdir(join(root, "tests/integration/contract"));
    const imports = new Set();
    for (const file of harness.filter((name) => name.endsWith(".mjs"))) {
      for (const match of (await read(`tests/integration/contract/${file}`)).matchAll(
        /from "((?:@[^/"]+\/)?[^./"][^/"]*)/g,
      )) {
        if (!match[1].startsWith("node:"))
          imports.add(
            match[1]
              .split("/")
              .slice(0, match[1].startsWith("@") ? 2 : 1)
              .join("/"),
          );
      }
    }
    imports.delete("@decionis/agent-safe-pipeline");
    assert.deepEqual([...imports].sort(), ["@decionis/presence-node", "zod"]);
  });

  it("publish with the npm a pinned Node release ships, verified rather than installed", async () => {
    for (const path of [
      ".github/workflows/deploy.yml",
      ".github/workflows/commerce-mcp-npm-publish.yml",
    ]) {
      const workflow = parse(await read(path));
      for (const job of Object.values(workflow.jobs)) {
        const verify = (job.steps ?? []).find(
          (step) => step.name === "Verify npm supports trusted publishing",
        );
        if (verify === undefined) continue;
        const setup = job.steps.find(
          (step) => step.uses?.startsWith("actions/setup-node@") && step.with?.["registry-url"],
        );
        assert.equal(setup.with["node-version"], "24.18.0", path);
        assert.match(verify.run, /major < 11 \|\| \(major === 11 && minor < 5\)/, path);
      }
    }
    const commerce = await read(".github/workflows/commerce-mcp-npm-publish.yml");
    assert.match(commerce, /name: Verify npm supports trusted publishing/);
    assert.doesNotMatch(commerce, /NPM_VERSION/);
  });

  it("restore the .NET verifier in locked mode against committed lock files", async () => {
    const workflow = parse(await read(".github/workflows/deploy.yml"));
    const dotnet = Object.values(workflow.jobs)
      .flatMap((job) => job.steps)
      .find(
        (step) =>
          step.name === "Format-check and test the .NET verifier against the profile's vectors",
      );
    assert.match(dotnet.run, /^dotnet restore --nologo --locked-mode$/m);
    assert.match(dotnet.run, /^dotnet format --verify-no-changes --no-restore$/m);
    assert.match(dotnet.run, /^dotnet test --nologo --no-restore$/m);
    for (const project of ["Decionis.VerifyingProvider", "Decionis.VerifyingProvider.Tests"]) {
      const csproj = await read(`verifiers/dotnet/${project}/${project}.csproj`);
      assert.match(
        csproj,
        /<RestorePackagesWithLockFile>true<\/RestorePackagesWithLockFile>/,
        project,
      );
      const lock = await json(`verifiers/dotnet/${project}/packages.lock.json`);
      assert.equal(lock.version, 1);
      const locked = lock.dependencies["net8.0"];
      for (const [, name, version] of csproj.matchAll(
        /<PackageReference Include="([^"]+)" Version="([^"]+)" \/>/g,
      )) {
        assert.equal(locked[name]?.type, "Direct", `${project}: ${name}`);
        assert.equal(locked[name].resolved, version, `${project}: ${name}`);
        assert.match(locked[name].contentHash, SHA512_BASE64, `${project}: ${name}`);
      }
      for (const [name, entry] of Object.entries(locked)) {
        if (entry.type !== "Project") {
          assert.match(entry.contentHash ?? "", SHA512_BASE64, `${project}: ${name}`);
        }
      }
    }
    assert.match(await read(".prettierignore"), /^verifiers\/dotnet\/\*\*\/packages\.lock\.json$/m);
  });
});

const lockfile = parse(await read("pnpm-lock.yaml"));

describe("ReleaseSbom.mjs", () => {
  const integrityOf = (name, version) => {
    const integrity = lockfile.packages[`${name}@${version}`].resolution.integrity;
    return Buffer.from(integrity.slice("sha512-".length), "base64").toString("hex");
  };

  it("writes the pipeline's SBOM from the lockfile's tree, every registry component with the lockfile's hash", async () => {
    const directory = await mkdtemp(join(tmpdir(), "release-sbom-"));
    try {
      const out = join(directory, "pipeline.cdx.json");
      const first = run("ReleaseSbom.mjs", ["packages/pipeline", out, "library"]);
      assert.equal(first.status, 0, first.output);
      const sbom = JSON.parse(await readFile(out, "utf8"));
      const manifest = await json("packages/pipeline/package.json");
      assert.equal(sbom.bomFormat, "CycloneDX");
      assert.equal(sbom.specVersion, "1.5");
      assert.equal(sbom.metadata.component.name, manifest.name);
      assert.equal(sbom.metadata.component.version, manifest.version);
      assert.equal(sbom.metadata.component.type, "library");
      assert.equal(
        sbom.metadata.component.purl,
        `pkg:npm/%40decionis/agent-safe-pipeline@${manifest.version}`,
      );
      assert.equal(sbom.metadata.timestamp, undefined);
      assert.equal(sbom.metadata.tools[0].name, "ReleaseSbom.mjs");
      const pinned = lockfile.importers["packages/pipeline"].dependencies;
      const byName = new Map(sbom.components.map((component) => [component.name, component]));
      for (const [name, { version }] of Object.entries(pinned)) {
        const component = byName.get(name);
        assert.ok(component, `${name} is a component`);
        assert.equal(component.version, version, `${name} is the lockfile's version`);
        assert.equal(
          component.purl,
          name.startsWith("@")
            ? `pkg:npm/%40${name.slice(1)}@${version}`
            : `pkg:npm/${name}@${version}`,
        );
        assert.deepEqual(component.hashes, [
          { alg: "SHA-512", content: integrityOf(name, version) },
        ]);
        assert.ok(
          component.externalReferences.some(
            (reference) =>
              reference.type === "distribution" &&
              reference.url.startsWith("https://registry.npmjs.org/"),
          ),
          `${name} names its tarball`,
        );
      }
      assert.ok(sbom.components.length >= 4);
      for (const component of sbom.components) {
        assert.equal(component.hashes?.length, 1, `${component.name} carries a hash`);
        assert.equal(component.scope, "required");
      }
      const rootGraph = sbom.dependencies.find(
        (entry) => entry.ref === `${manifest.name}@${manifest.version}`,
      );
      assert.deepEqual(
        rootGraph.dependsOn,
        Object.entries(pinned)
          .map(([name, { version }]) => `${name}@${version}`)
          .sort(),
      );
      assert.equal(sbom.dependencies.length, sbom.components.length + 1);
      // The same tree twice is the same document.
      const again = join(directory, "again.cdx.json");
      assert.equal(run("ReleaseSbom.mjs", ["packages/pipeline", again, "library"]).status, 0);
      assert.equal(await readFile(again, "utf8"), await readFile(out, "utf8"));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("gives a workspace package the hash of the tarball the release ships for it", async () => {
    const directory = await mkdtemp(join(tmpdir(), "release-sbom-"));
    try {
      const pipeline = await json("packages/pipeline/package.json");
      const runtime = await json("packages/agentsafe/package.json");
      mkdirSync(join(directory, "package"));
      writeFileSync(
        join(directory, "package", "package.json"),
        JSON.stringify({ name: pipeline.name, version: pipeline.version }),
      );
      const tarball = join(directory, "pipeline.tgz");
      assert.equal(
        spawnSync("tar", ["--create", "--gzip", "--file", tarball, "-C", directory, "package"])
          .status,
        0,
      );
      const out = join(directory, "runtime.cdx.json");
      const result = run("ReleaseSbom.mjs", [
        "packages/agentsafe",
        out,
        "application",
        "--packed",
        tarball,
      ]);
      assert.equal(result.status, 0, result.output);
      const sbom = JSON.parse(await readFile(out, "utf8"));
      assert.equal(sbom.metadata.component.type, "application");
      assert.equal(sbom.metadata.component.name, runtime.name);
      const component = sbom.components.find((entry) => entry.name === pipeline.name);
      assert.equal(component.version, pipeline.version);
      assert.deepEqual(component.hashes, [
        {
          alg: "SHA-512",
          content: createHash("sha512")
            .update(await readFile(tarball))
            .digest("hex"),
        },
      ]);
      assert.ok(
        component.externalReferences.some(
          (reference) =>
            reference.url ===
            `https://registry.npmjs.org/${pipeline.name}/-/agent-safe-pipeline-${pipeline.version}.tgz`,
        ),
      );
      for (const entry of sbom.components) assert.equal(entry.hashes?.length, 1, entry.name);
      // Without the tarball the component is still there, honestly without a hash.
      const bare = join(directory, "bare.cdx.json");
      assert.equal(run("ReleaseSbom.mjs", ["packages/agentsafe", bare, "application"]).status, 0);
      const bareComponent = JSON.parse(await readFile(bare, "utf8")).components.find(
        (entry) => entry.name === pipeline.name,
      );
      assert.equal(bareComponent.hashes, undefined);
      // A tarball for a package that is not in the tree is a mistake, not a component.
      writeFileSync(
        join(directory, "package", "package.json"),
        JSON.stringify({ name: "@decionis/other", version: "1.0.0" }),
      );
      const stray = join(directory, "stray.tgz");
      spawnSync("tar", ["--create", "--gzip", "--file", stray, "-C", directory, "package"]);
      const refused = run("ReleaseSbom.mjs", [
        "packages/agentsafe",
        join(directory, "x.cdx.json"),
        "application",
        "--packed",
        stray,
      ]);
      assert.notEqual(refused.status, 0);
      assert.match(refused.output, /@decionis\/other@1\.0\.0 was packed but is not in the tree/);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("refuses a bad invocation", () => {
    assert.notEqual(run("ReleaseSbom.mjs", ["packages/pipeline"]).status, 0);
    assert.notEqual(run("ReleaseSbom.mjs", ["packages/pipeline", "out.json", "tool"]).status, 0);
    assert.notEqual(
      run("ReleaseSbom.mjs", ["packages/pipeline", "out.json", "library", "--packed"]).status,
      0,
    );
  });
});

describe("ConsumerFromTarball.mjs", () => {
  /** A workspace package with one pinned dependency, and the tarball it packs to. */
  async function stage(directory) {
    const workspace = join(directory, "workspace");
    mkdirSync(join(workspace, "node_modules", ".pnpm", "dep@1.2.3", "node_modules", "dep"), {
      recursive: true,
    });
    writeFileSync(
      join(workspace, "node_modules", ".pnpm", "dep@1.2.3", "node_modules", "dep", "package.json"),
      JSON.stringify({ name: "dep", version: "1.2.3", type: "module", exports: "./index.js" }),
    );
    writeFileSync(
      join(workspace, "node_modules", ".pnpm", "dep@1.2.3", "node_modules", "dep", "index.js"),
      "export const dep = 'pinned';\n",
    );
    symlinkSync(
      join(".pnpm", "dep@1.2.3", "node_modules", "dep"),
      join(workspace, "node_modules", "dep"),
      "dir",
    );
    mkdirSync(join(workspace, "node_modules", "@scope", "extra"), { recursive: true });
    writeFileSync(
      join(workspace, "node_modules", "@scope", "extra", "package.json"),
      JSON.stringify({ name: "@scope/extra", version: "2.0.0" }),
    );
    const manifest = {
      name: "@scope/thing",
      version: "0.1.0",
      type: "module",
      exports: "./dist/index.js",
      dependencies: { dep: "^1.2.0" },
      devDependencies: { "left-out": "^9.0.0" },
    };
    writeFileSync(join(workspace, "package.json"), JSON.stringify(manifest));
    const packed = join(directory, "package");
    mkdirSync(join(packed, "dist"), { recursive: true });
    writeFileSync(join(packed, "package.json"), JSON.stringify(manifest));
    writeFileSync(
      join(packed, "dist", "index.js"),
      "import { dep } from 'dep';\nexport const thing = `thing over ${dep}`;\n",
    );
    const tarball = join(directory, "thing.tgz");
    assert.equal(
      spawnSync("tar", ["--create", "--gzip", "--file", tarball, "-C", directory, "package"])
        .status,
      0,
    );
    return { workspace, tarball };
  }

  it("unpacks the tarball as the package and links its dependencies from the pinned tree", async () => {
    const directory = await mkdtemp(join(tmpdir(), "consumer-"));
    try {
      const { workspace, tarball } = await stage(directory);
      const consumer = join(directory, "consumer");
      const result = run("ConsumerFromTarball.mjs", [tarball, workspace, consumer, "@scope/extra"]);
      assert.equal(result.status, 0, result.output);
      assert.match(
        result.output,
        /Assembled a consumer of @scope\/thing@0\.1\.0 .* 2 dependencies linked/,
      );
      const installed = join(consumer, "node_modules", "@scope", "thing");
      assert.ok(lstatSync(installed).isDirectory() && !lstatSync(installed).isSymbolicLink());
      assert.deepEqual((await readdir(installed)).sort(), ["dist", "package.json"]);
      const dep = join(consumer, "node_modules", "dep");
      assert.ok(lstatSync(dep).isSymbolicLink());
      assert.equal(realpathSync(dep), realpathSync(join(workspace, "node_modules", "dep")));
      assert.ok(lstatSync(join(consumer, "node_modules", "@scope", "extra")).isSymbolicLink());
      assert.ok(
        !existsSync(join(consumer, "node_modules", "left-out")),
        "devDependencies are not the consumer's",
      );
      assert.ok(!existsSync(join(consumer, "package-lock.json")));
      const imported = spawnSync(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          "const { thing } = await import('@scope/thing'); process.stdout.write(thing)",
        ],
        { cwd: consumer, encoding: "utf8" },
      );
      assert.equal(imported.status, 0, imported.stderr);
      assert.equal(imported.stdout, "thing over pinned");
      // Assembling again replaces what is there rather than layering on it.
      writeFileSync(join(installed, "stale.js"), "");
      assert.equal(run("ConsumerFromTarball.mjs", [tarball, workspace, consumer]).status, 0);
      assert.ok(!existsSync(join(installed, "stale.js")));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("refuses a dependency the pinned tree lacks and a tarball of another package", async () => {
    const directory = await mkdtemp(join(tmpdir(), "consumer-"));
    try {
      const { workspace, tarball } = await stage(directory);
      const missing = run("ConsumerFromTarball.mjs", [
        tarball,
        workspace,
        join(directory, "c1"),
        "absent",
      ]);
      assert.notEqual(missing.status, 0);
      assert.match(
        missing.output,
        /absent is not installed beside @scope\/thing; run pnpm install --frozen-lockfile/,
      );
      writeFileSync(
        join(workspace, "package.json"),
        JSON.stringify({ name: "@scope/thing", version: "0.2.0" }),
      );
      const drift = run("ConsumerFromTarball.mjs", [tarball, workspace, join(directory, "c2")]);
      assert.notEqual(drift.status, 0);
      assert.match(drift.output, /the tarball is @scope\/thing@0\.1\.0, not @scope\/thing@0\.2\.0/);
      assert.notEqual(run("ConsumerFromTarball.mjs", [tarball]).status, 0);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
