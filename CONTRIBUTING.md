# Contributing

Use Node.js 22.14 or later and pnpm 9. Create focused changes with production code under `src/` and tests under `test/`.

```bash
pnpm install --frozen-lockfile
pnpm verify
pnpm mutation
```

Installation activates the repository's `simple-git-hooks` pre-commit hook. It checks staged files with Prettier, checks staged Markdown with markdownlint, and runs the lint, security-audit, and performance guardrails. Run `pnpm format:fix` before committing if it reports formatting drift; use `pnpm hooks:install` to reinstall the hook manually.

`pnpm verify` includes the deterministic performance suite and audits the complete development
toolchain at moderate severity. `pnpm mutation` remains a separate, required assurance check for
trust-boundary changes.

Security-boundary changes must include negative tests and document their fail-open/fail-closed behavior. Cross-repository contract changes must update the Decionis OpenAPI, SDK types, contract tests, and discovery inventory in the same release train.

Do not add secrets, production policy data, customer fixtures, generated dependency directories, or claims that an endpoint/package is live without verifying it. Use synthetic identifiers and values in examples.

Contributions are licensed under Apache-2.0. By submitting a contribution, you represent that you have the right to license it on those terms.

## Releases

After verification succeeds on a merge to `master`, CI reads the matching workspace and package versions, builds the npm tarball, generates an artifact-derived CycloneDX SBOM and dependency-license inventories, asserts the SBOM component floor, creates signed GitHub artifact and SBOM attestations, verifies the provenance in-run, installs the tarball in a clean consumer directory, and creates the corresponding `v<version>` GitHub release. The tarball, inventories, SBOM, SHA-256 manifest, Sigstore bundles, raw in-toto statements, and trusted root are release assets. Existing releases are skipped safely, prerelease versions are marked as prereleases, and a tag without a matching GitHub release fails closed for manual review. Increment both versions in the release PR when a new release is intended.

Before merging a release change, exercise the same build and attestation path without publishing:

```sh
gh workflow run deploy.yml --ref <branch> -f release_dry_run=true
```

The release can publish the exact tarball to npm without a long-lived token after the package
exists. Until issue #19 is complete, keep `NPM_PUBLISH_ENABLED=false`. The one-time
`npm-bootstrap.yml` workflow is pinned to the signed v0.1.2 release tarball and runs only from
`master`, as `@ocularminds`, with the exact confirmation `publish-v0.1.2`, through the protected
`npm-bootstrap` environment.

An npm owner completes the bootstrap as follows:

1. Create the `npm-bootstrap` GitHub environment with `@ocularminds` as required reviewer,
   protected branches only, and administrator bypass disabled.
2. Create a one-day granular npm token with read/write package-and-scope access to `@decionis` and
   2FA bypass. Organization-management permission does not grant package publication permission.
3. Store it only as the `NPM_BOOTSTRAP_TOKEN` environment secret, dispatch `npm-bootstrap.yml` from
   `master`, enter `publish-v0.1.2`, and approve the environment deployment.
4. Confirm the workflow verifies the GitHub checksum and attestation, publishes with provenance,
   then downloads and verifies the registry tarball against SHA-256
   `4cb14a3906f42fbea23fc4c9cc6450f731f09b18bc15eccbab2e723c30d1a92a`.
5. Delete the environment secret, revoke the granular token, and remove `npm-bootstrap.yml` in the
   next pull request.
6. Configure npm trusted publishing for organization/user `decionis`, repository
   `agent-safe-pipeline`, workflow filename `deploy.yml`, with `npm publish` permission. Then select
   "Require two-factor authentication and disallow tokens" for traditional package publishing.
7. Increment both manifests to `0.1.3-rc.1` in a release pull request. Temporarily set
   `NPM_PUBLISH_ENABLED=true` immediately before merging it; `deploy.yml` creates the tag and
   prerelease, so do not create the tag manually. Verify npm provenance and the registry/GitHub
   tarball digest before leaving the variable enabled for stable releases.

Without the completed bootstrap and trusted-publisher setup, `deploy.yml` creates a GitHub-only
release and records that npm was skipped.

To verify a release as an outsider, download all assets into an empty directory, run `shasum -a 256 -c SHA256SUMS`, then verify the tarball offline with the matching provenance bundle and `trusted_root.jsonl`:

```sh
gh attestation verify decionis-agent-safe-pipeline-<version>.tgz \
  --repo decionis/agent-safe-pipeline \
  --bundle agent-safe-pipeline-<version>.provenance.sigstore.json \
  --custom-trusted-root trusted_root.jsonl
```
