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
    // The release is tagged by the library's version, not the runtime's: the
    // archive is fetched from the release the listing says carries it, and
    // never from a tag guessed out of the runtime version.
    assert.match(script, /"\$BASE\/\$tag\/\$archive"/);
    assert.match(script, /"\$BASE\/\$tag\/SHA256SUMS"/);
    assert.doesNotMatch(script, /\$BASE\/v\$version/);
    assert.match(script, /AGENTSAFE_RELEASE_TAG/);
    assert.doesNotMatch(script, /\bsudo\b/);
    assert.doesNotMatch(script, /\.bashrc|\.zshrc|\.profile|systemctl|launchctl/);
    assert.match(script, /lib="\$prefix\/lib\/agentsafe\/\$version"/);
    assert.match(script, /ln -sf "\$lib\/agentsafe"/);
    assert.match(script, /"\$bin\/agentsafe" version/);
    assert.match(script, /AGENTSAFE_INSTALL_PREFIX/);
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
    assert.equal(config.contents[0].src, "./packaging/linux/build/agentsafe");
    assert.match(
      await read("packaging/linux/nfpm.yaml"),
      /dst: \/usr\/bin\/agentsafe\n\s+file_info:\n\s+mode: 0755/,
    );
    for (const entry of config.contents) {
      if (entry.dst.endsWith(".example")) assert.equal(entry.type, "config|noreplace");
    }
    // The service reads its configuration as a dynamic user, so the directory
    // is traversable by everyone; the secrets in it are root's 0600 files.
    assert.equal(config.contents.find((entry) => entry.dst === "/etc/agentsafe").type, "dir");
    assert.match(
      await read("packaging/linux/nfpm.yaml"),
      /dst: \/etc\/agentsafe\n\s+type: dir\n\s+file_info:\n\s+mode: 0755\n/,
    );
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
    assert.match(unit, /^Environment=AGENTSAFE_SURFACE=linux$/m);
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
    assert.match(dockerfile, /^ENV AGENTSAFE_SURFACE=docker$/m);
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
    // The .rpm is installed where .rpm files install, and the installer runs
    // against the build over a mirror it is told to trust, both on Linux only.
    const fedora = distribution.steps.find(
      (step) => step.name === "Install and check the .rpm on Fedora",
    );
    assert.equal(fedora.if, "runner.os == 'Linux'");
    assert.match(
      fedora.env.FEDORA_IMAGE,
      /^public\.ecr\.aws\/docker\/library\/fedora:\d+@sha256:[0-9a-f]{64}$/,
    );
    assert.match(fedora.run, /rpm -i \/release\/agentsafe-\*\.rpm/);
    assert.match(fedora.run, /rpm -ql agentsafe \| grep -qx \/usr\/bin\/agentsafe/);
    assert.match(fedora.run, /\[ "\$installed" -ef \/usr\/bin\/agentsafe \]/);
    assert.match(fedora.run, /agentsafe test --json/);
    assert.match(fedora.run, /rpm -e agentsafe/);
    const installer = distribution.steps.find(
      (step) => step.name === "Run the installer against this build over a local mirror",
    );
    assert.equal(installer.if, "runner.os == 'Linux'");
    assert.match(installer.run, /AGENTSAFE_RELEASE_BASE="https:\/\/127\.0\.0\.1:\$port\/download"/);
    assert.match(installer.run, /AGENTSAFE_RELEASE_CA="\$RUNNER_TEMP\/mirror\.crt"/);
    assert.match(installer.run, /sh packaging\/install\.sh/);
    assert.match(
      installer.run,
      /packaging\/smoke\/Smoke\.sh "\$prefix\/bin\/agentsafe" "\$version"/,
    );
    assert.match(installer.run, /grep -q "checksum mismatch"/);
    const build = distribution.steps.find(
      (step) => step.name === "Build, archive and smoke-test the executable",
    );
    assert.match(build.run, /scripts\/BuildExecutable\.mjs/);
    assert.match(build.run, /packaging\/smoke\/Smoke\.sh/);
    const packages = distribution.steps.find(
      (step) => step.name === "Build, install and smoke-test the Linux packages",
    );
    assert.match(
      packages.run,
      /echo "\$NFPM_SHA256 {2}\$RUNNER_TEMP\/nfpm\.tgz" \| sha256sum --check --strict/,
    );
    for (const entry of distribution.strategy.matrix.include) {
      if (entry.target.startsWith("linux-")) assert.match(entry.nfpm_sha256, /^[0-9a-f]{64}$/);
    }
    const pnpm = distribution.steps.find((step) => step.name === "Install pnpm");
    assert.equal(pnpm.with.standalone, false);
    assert.match(packages.run, /cp "\$extracted\/agentsafe" packaging\/linux\/build\/agentsafe/);
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
    // The interception init: built from the same file's `init` stage, pushed
    // under the same name with the `-init` suffix on every tag, its digest
    // recorded and attested beside the runtime's.
    assert.match(image.run, /--target init/);
    assert.match(
      image.run,
      /\$image:\$minor-init" -t "\$image:\$major-init" -t "\$image:latest-init"/,
    );
    assert.match(image.run, /init_digest=\$init_digest/);
    assert.match(image.run, /init_version=%s-init/);
    const attestInit = workflow.jobs.release.steps.find(
      (step) => step.name === "Attest the interception init image",
    );
    assert.equal(attestInit.with["subject-digest"], "${{ steps.image.outputs.init_digest }}");
    assert.equal(attestInit.with["push-to-registry"], true);
    const verifyImages = workflow.jobs.release.steps.find(
      (step) => step.name === "Verify the published image attestations",
    );
    assert.match(verifyImages.run, /gh attestation verify "oci:\/\/\$INIT_REFERENCE"/);
    const imageJobSteps = workflow.jobs.image.steps.map((step) => step.name);
    assert.ok(imageJobSteps.includes("Build the interception init image and run the redirect"));
    assert.ok(imageJobSteps.includes("Intercept a workload's connections transparently"));
    // The govern phase on a real kernel: the interceptor hardened as the
    // manifests run it, the workload as another user trusting the operator's
    // authority alone, the allowed payment reaching the provider and the
    // blocked one never.
    const govern = workflow.jobs.image.steps.find(
      (step) => step.name === "Govern a destination transparently",
    );
    assert.match(govern.run, /AGENTSAFE_INTERCEPT_GOVERN=provider\.example/);
    assert.match(
      govern.run,
      /AGENTSAFE_INTERCEPT_CA_CERT_FILE=\/var\/run\/agent-safe\/intercept\/ca\.crt/,
    );
    assert.match(
      govern.run,
      /AGENTSAFE_INTERCEPT_CA_KEY_FILE=\/var\/run\/agent-safe\/intercept\/ca\.key/,
    );
    assert.match(
      govern.run,
      /--read-only --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges/,
    );
    assert.match(govern.run, /--user 1000:1000/);
    assert.match(govern.run, /"amount":5000,"status":403,"decision":null,"state":"BLOCK"/);
    assert.match(govern.run, /if grep -q '5000' <<<"\$reached"; then/);
    assert.match(govern.run, /"governed":true/);
    assert.match(govern.run, /\\"governed\\":false/);
    for (const step of [...distribution.steps, ...workflow.jobs.release.steps]) {
      if (step.uses !== undefined) assert.match(step.uses, /@[0-9a-f]{40}( #|$)/, step.uses);
    }
    const imageJob = workflow.jobs.image.steps.map((step) => step.name);
    assert.ok(imageJob.includes("Run the gateway in the image and watch it fail closed"));
    const failClosed = workflow.jobs.image.steps.find(
      (step) => step.name === "Run the gateway in the image and watch it fail closed",
    );
    assert.match(failClosed.run, /AGENTSAFE_MODE=enforcement/);
    assert.match(failClosed.run, /test "\$status" = "503"/);
  });

  it("copies the attested manifest to Docker Hub by digest, after the release and only when enabled", async () => {
    const workflow = parse(await read(".github/workflows/deploy.yml"));
    const release = workflow.jobs.release;
    assert.equal(release.outputs.image_published, "${{ steps.image.outputs.published }}");
    assert.equal(release.outputs.runtime_version, "${{ steps.runtime.outputs.version }}");
    const notes = release.steps.find((step) => step.name === "Create verified GitHub release");
    assert.equal(notes.env.DOCKERHUB_PUBLISH_ENABLED, "${{ vars.DOCKERHUB_PUBLISH_ENABLED }}");
    assert.match(notes.run, /if \[\[ "\$DOCKERHUB_PUBLISH_ENABLED" == "true" \]\]; then/);
    assert.match(notes.run, /gh attestation verify oci:\/\/\$hub@\$IMAGE_DIGEST/);

    const hub = workflow.jobs.dockerhub;
    assert.deepEqual(hub.needs, ["release"]);
    assert.equal(
      hub.if,
      "needs.release.outputs.image_published == 'true' && vars.DOCKERHUB_PUBLISH_ENABLED == 'true'",
    );
    assert.equal(hub.uses, "./.github/workflows/dockerhub.yml");
    assert.equal(hub.with.version, "${{ needs.release.outputs.runtime_version }}");
    assert.deepEqual(Object.keys(hub.secrets).sort(), ["DOCKERHUB_TOKEN", "DOCKERHUB_USERNAME"]);
    assert.deepEqual(hub.permissions, {
      attestations: "write",
      contents: "read",
      "id-token": "write",
      packages: "read",
    });

    const publish = parse(await read(".github/workflows/dockerhub.yml"));
    assert.deepEqual(Object.keys(publish.on).sort(), ["workflow_call", "workflow_dispatch"]);
    assert.equal(publish.on.workflow_call.inputs.version.required, true);
    assert.equal(publish.on.workflow_dispatch.inputs.version.required, true);
    for (const secret of ["DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN"]) {
      assert.equal(publish.on.workflow_call.secrets[secret].required, true);
    }
    assert.deepEqual(publish.permissions, { contents: "read" });
    const job = publish.jobs.publish;
    assert.deepEqual(job.permissions, hub.permissions);
    const names = job.steps.map((step) => step.name);
    assert.deepEqual(names, [
      "Harden runner",
      "Check out repository",
      "Resolve the attested GHCR image",
      "Copy the manifest to Docker Hub",
      "Attest the Docker Hub image",
      "Attest the Docker Hub init image",
      "Verify the published image attestation",
      "Publish the repository overview",
    ]);
    const checkout = job.steps.find((step) => step.name === "Check out repository");
    assert.equal(checkout.with["persist-credentials"], false);
    for (const step of job.steps) {
      if (step.uses !== undefined) assert.match(step.uses, /@[0-9a-f]{40}( #|$)/, step.uses);
    }
    const source = job.steps.find((step) => step.name === "Resolve the attested GHCR image");
    assert.equal(source.env.IMAGE_NAME, "ghcr.io/${{ github.repository_owner }}/agentsafe");
    assert.match(source.run, /--signer-workflow "\$RELEASE_WORKFLOW"/);
    assert.equal(
      source.env.RELEASE_WORKFLOW,
      "${{ github.repository }}/.github/workflows/deploy.yml",
    );
    const copy = job.steps.find((step) => step.name === "Copy the manifest to Docker Hub");
    assert.equal(copy.env.HUB_IMAGE_NAME, "docker.io/${{ github.repository_owner }}/agentsafe");
    assert.match(copy.run, /-z "\$DOCKERHUB_USERNAME" \|\| -z "\$DOCKERHUB_TOKEN"/);
    assert.match(
      copy.run,
      /\$hub:\$minor\$suffix" -t "\$hub:\$major\$suffix" -t "\$hub:latest\$suffix"/,
    );
    assert.match(
      copy.run,
      /docker buildx imagetools create "\$\{tags\[@\]\}" "\$SOURCE_IMAGE@\$source_digest"/,
    );
    assert.match(copy.run, /if \[\[ "\$digest" != "\$source_digest" \]\]; then/);
    assert.match(copy.run, /init_digest="\$\(copy "-init" "\$SOURCE_INIT_DIGEST"\)"/);
    assert.match(source.run, /\$image:\$RELEASE_VERSION-init/);
    assert.doesNotMatch(copy.run, /docker buildx build/);
    const attestInit = job.steps.find((step) => step.name === "Attest the Docker Hub init image");
    assert.equal(attestInit.if, "steps.hub.outputs.init_digest != ''");
    assert.equal(attestInit.with["subject-digest"], "${{ steps.hub.outputs.init_digest }}");
    assert.equal(attestInit.with["push-to-registry"], true);
    const attest = job.steps.find((step) => step.name === "Attest the Docker Hub image");
    assert.equal(attest.with["subject-name"], "${{ steps.hub.outputs.name }}");
    assert.equal(attest.with["subject-digest"], "${{ steps.hub.outputs.digest }}");
    assert.equal(attest.with["push-to-registry"], true);
    const verify = job.steps.find((step) => step.name === "Verify the published image attestation");
    assert.equal(
      verify.env.SIGNER_WORKFLOW,
      "${{ github.repository }}/.github/workflows/dockerhub.yml",
    );
    assert.match(verify.run, /gh attestation verify "oci:\/\/\$IMAGE_REFERENCE"/);
  });

  it("publishes the Docker Hub overview from the repository, a page whose links all leave Docker Hub", async () => {
    const publish = parse(await read(".github/workflows/dockerhub.yml"));
    const overview = publish.jobs.publish.steps.find(
      (step) => step.name === "Publish the repository overview",
    );
    assert.equal(overview.env.OVERVIEW_FILE, "packaging/dockerhub/README.md");
    assert.ok(
      overview.env.SHORT_DESCRIPTION.length <= 100,
      "the short description fits Docker Hub",
    );
    assert.match(overview.run, /--request POST https:\/\/hub\.docker\.com\/v2\/users\/login/);
    assert.match(
      overview.run,
      /--request PATCH "https:\/\/hub\.docker\.com\/v2\/repositories\/\$repository\/"/,
    );
    assert.match(overview.run, /umask 077/);
    assert.match(overview.run, /--header @"\$header"/);
    assert.match(overview.run, /rm -f "\$header"/);
    assert.doesNotMatch(
      overview.run,
      /\$DOCKERHUB_TOKEN/,
      "the token reaches curl through stdin only",
    );

    const page = await read(overview.env.OVERVIEW_FILE);
    assert.ok(page.length <= 25000, "the overview fits Docker Hub");
    assert.match(page, /^# AgentSafe/);
    const links = [...page.matchAll(/\]\(([^)]+)\)/g)].map((match) => match[1]);
    assert.ok(links.length >= 8);
    for (const link of links) {
      assert.match(
        link,
        /^https:\/\/(github\.com\/decionis\/agent-safe-pipeline|decionis\.com)/,
        link,
      );
    }
    for (const expectation of [
      "decionis/agentsafe:<version>     immutable",
      "ghcr.io/decionis/agentsafe",
      "gh attestation verify oci://docker.io/decionis/agentsafe:<version> --repo decionis/agent-safe-pipeline",
      "oci://ghcr.io/decionis/charts/agentsafe",
      "GATEWAY_STOPPED",
      "TRADEMARKS.md",
    ]) {
      assert.ok(page.includes(expectation), expectation);
    }
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
