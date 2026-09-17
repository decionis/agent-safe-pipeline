import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { parse } from "yaml";

const read = (path) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");

/**
 * The distribution surfaces are one runtime wrapped four ways. These gates
 * hold each wrapper to what the install pages promise: the installer verifies
 * before it installs and touches nothing else, the packages place the same
 * executable under the same hardened unit, the image's default command is the
 * gateway and its executor is named explicitly, and the workflow builds and
 * smoke-tests every target before a release can carry it.
 */
describe("the installer", () => {
  it("is POSIX sh, fails closed on verification, and modifies nothing but the executable", async () => {
    const script = await read("packaging/install.sh");
    assert.equal(spawnSync("sh", ["-n", "-"], { input: script, encoding: "utf8" }).status, 0);
    assert.match(script, /^set -eu$/m);
    assert.match(script, /curl --proto '=https' --tlsv1\.2/);
    assert.match(script, /checksum mismatch .* refusing to install/);
    assert.match(script, /does not list .* refusing to install/);
    assert.match(script, /^REPO="decionis\/agent-safe-pipeline"$/m);
    assert.match(script, /https:\/\/github\.com\/\$REPO\/releases\/download/);
    assert.doesNotMatch(script, /\bsudo\b/);
    assert.doesNotMatch(script, /\.bashrc|\.zshrc|\.profile|systemctl|launchctl/);
    assert.match(script, /"\$target\/agentsafe" version/);
  });
});

describe("the Linux packages", () => {
  it("place the executable, the unit and the examples where a distribution expects them", async () => {
    const config = parse(await read("packaging/linux/nfpm.yaml"));
    assert.equal(config.name, "agentsafe");
    assert.equal(config.license, "Apache-2.0");
    const destinations = config.contents.map((entry) => entry.dst);
    assert.deepEqual(destinations, [
      "/usr/bin/agentsafe",
      "/usr/share/doc/agentsafe/LICENSE",
      "/usr/share/doc/agentsafe/NOTICE",
      "/usr/lib/systemd/system/agentsafe.service",
      "/etc/agentsafe/agentsafe.yaml.example",
      "/etc/agentsafe/environment.example",
      "/etc/agentsafe",
    ]);
    assert.match(
      await read("packaging/linux/nfpm.yaml"),
      /dst: \/usr\/bin\/agentsafe\n\s+file_info:\n\s+mode: 0755/,
    );
    for (const entry of config.contents) {
      if (entry.dst.endsWith(".example")) assert.equal(entry.type, "config|noreplace");
    }
  });

  it("run the gateway under a hardened unit whose key is a systemd credential", async () => {
    const unit = await read("packaging/linux/agentsafe.service");
    assert.match(
      unit,
      /^ExecStart=\/usr\/bin\/agentsafe run --config \/etc\/agentsafe\/agentsafe\.yaml$/m,
    );
    assert.match(unit, /^LoadCredential=decionis-api-key:\/etc\/agentsafe\/decionis-api-key$/m);
    assert.match(unit, /^Environment=DECIONIS_API_KEY_FILE=%d\/decionis-api-key$/m);
    assert.match(unit, /^Environment=NODE_ENV=production$/m);
    for (const key of [
      "DynamicUser=yes",
      "NoNewPrivileges=yes",
      "ProtectSystem=strict",
      "ProtectHome=yes",
      "CapabilityBoundingSet=",
      "KillSignal=SIGTERM",
    ]) {
      assert.ok(unit.includes(`\n${key}\n`), key);
    }
    assert.doesNotMatch(unit, /DECIONIS_API_KEY=/);
    const environment = await read("packaging/linux/environment.example");
    assert.doesNotMatch(environment, /^DECIONIS_API_KEY=/m);
    const example = parse(await read("packaging/linux/agentsafe.yaml.example"));
    assert.equal(example.version, 1);
    assert.equal(example.authority.mode, "shadow");
    assert.equal(example.authority.failurePolicy, "failClosed");
  });
});

describe("the image", () => {
  it("runs the gateway by default, the executor by name, and reads only what it is given", async () => {
    const dockerfile = await read("packages/agentsafe/Dockerfile");
    assert.match(dockerfile, /^ENTRYPOINT \["\/nodejs\/bin\/node", "--permission",/m);
    assert.match(dockerfile, /"\/app\/dist\/Cli\.js"\]$/m);
    assert.match(dockerfile, /^CMD \["proxy"\]$/m);
    assert.match(dockerfile, /--allow-fs-read=\/etc\/agentsafe/);
    assert.match(dockerfile, /--allow-fs-write=\/var\/lib\/agent-safe"/);
    assert.doesNotMatch(dockerfile, /--allow-fs-write=\/app|--allow-child-process|--allow-worker/);
    assert.match(dockerfile, /^ENV NODE_ENV=production$/m);
    assert.match(dockerfile, /^EXPOSE 8080 8443$/m);
    const kit = await read("deploy/kubernetes/TrustedExecutor.yaml");
    assert.match(kit, /args: \["serve"\]/);
  });
});

describe("the workflow", () => {
  it("builds, archives and smoke-tests the runtime on every target before a release", async () => {
    const workflow = parse(await read(".github/workflows/deploy.yml"));
    const distribution = workflow.jobs.distribution;
    const targets = distribution.strategy.matrix.include.map((entry) => entry.target).sort();
    assert.deepEqual(targets, ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"]);
    const steps = distribution.steps.map((step) => step.name);
    assert.ok(steps.includes("Build, archive and smoke-test the executable"));
    assert.ok(steps.includes("Build, install and smoke-test the Linux packages"));
    const build = distribution.steps.find(
      (step) => step.name === "Build, archive and smoke-test the executable",
    );
    assert.match(build.run, /scripts\/BuildExecutable\.mjs/);
    assert.match(build.run, /packaging\/smoke\/Smoke\.sh/);
    const packages = distribution.steps.find(
      (step) => step.name === "Build, install and smoke-test the Linux packages",
    );
    assert.match(packages.run, /sha256sum --check --strict/);
    assert.match(packages.run, /sudo dpkg -i/);
    assert.match(packages.run, /packaging\/smoke\/Smoke\.sh \/usr\/bin\/agentsafe/);
    assert.deepEqual(workflow.jobs.release.needs, ["verify", "assurance", "image", "distribution"]);
    const releaseSteps = workflow.jobs.release.steps.map((step) => step.name);
    for (const name of [
      "Download the runtime artifacts",
      "Pack the runtime package and build its SBOM",
      "Attest runtime provenance",
      "Build the runtime image",
      "Package the Helm chart",
      "Push the Helm chart",
      "Render the Homebrew formula",
      "Open the Homebrew formula for review",
    ]) {
      assert.ok(releaseSteps.includes(name), name);
    }
    const image = workflow.jobs.release.steps.find(
      (step) => step.name === "Build the runtime image",
    );
    assert.match(
      image.run,
      /--platform linux\/amd64,linux\/arm64 --sbom=true --provenance=mode=max/,
    );
    assert.match(image.run, /\$image:\$minor" -t "\$image:\$major" -t "\$image:latest"/);
    for (const step of [...distribution.steps, ...workflow.jobs.release.steps]) {
      if (step.uses !== undefined) assert.match(step.uses, /@[0-9a-f]{40}( #|$)/, step.uses);
    }
    const imageJob = workflow.jobs.image.steps.map((step) => step.name);
    assert.ok(imageJob.includes("Run the gateway in the image and watch it fail closed"));
  });

  it("keeps the smoke test runnable", async () => {
    const smoke = await read("packaging/smoke/Smoke.sh");
    assert.equal(spawnSync("bash", ["-n", "-"], { input: smoke, encoding: "utf8" }).status, 0);
    for (const expectation of [
      "agentsafe-decision: ALLOW",
      "agentsafe-execution: HELD",
      "agentsafe-state: BLOCK",
      "verify chain",
      "GATEWAY_STOPPED",
    ]) {
      assert.ok(smoke.includes(expectation), expectation);
    }
  });
});
