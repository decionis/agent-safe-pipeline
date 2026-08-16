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

The package was bootstrapped from the signed v0.1.2 GitHub release tarball; its temporary npm token
and GitHub environment secret were revoked and deleted. The one-time bootstrap workflow is no
longer part of the repository. npm trusted publishing is bound to repository
`decionis/agent-safe-pipeline` and workflow filename `deploy.yml` with publish permission.

`NPM_PUBLISH_ENABLED` is the repository-level release gate. When it is `true`, `deploy.yml`
publishes the exact release tarball without a long-lived token, assigns prereleases to the `next`
tag, and waits for bounded public-registry propagation before creating the GitHub release. Confirm
the trusted-publisher binding and the gate before merging a release version. After publication,
verify npm provenance and compare the registry tarball digest with the GitHub release asset.

To verify a release as an outsider, download all assets into an empty directory, run `shasum -a 256 -c SHA256SUMS`, then verify the tarball offline with the matching provenance bundle and `trusted_root.jsonl`:

```sh
gh attestation verify decionis-agent-safe-pipeline-<version>.tgz \
  --repo decionis/agent-safe-pipeline \
  --bundle agent-safe-pipeline-<version>.provenance.sigstore.json \
  --custom-trusted-root trusted_root.jsonl
```
