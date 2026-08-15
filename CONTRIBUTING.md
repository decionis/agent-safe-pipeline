# Contributing

Use Node.js 20 or 22 and pnpm 9. Create focused changes with production code under `src/` and tests under `test/`.

```bash
pnpm install --frozen-lockfile
pnpm verify
```

Installation activates the repository's `simple-git-hooks` pre-commit hook. It checks staged files with Prettier, checks staged Markdown with markdownlint, and runs the lint, security-audit, and performance guardrails. Run `pnpm format:fix` before committing if it reports formatting drift; use `pnpm hooks:install` to reinstall the hook manually.

Security-boundary changes must include negative tests and document their fail-open/fail-closed behavior. Cross-repository contract changes must update the Decionis OpenAPI, SDK types, contract tests, and discovery inventory in the same release train.

Do not add secrets, production policy data, customer fixtures, generated dependency directories, or claims that an endpoint/package is live without verifying it. Use synthetic identifiers and values in examples.

Contributions are licensed under Apache-2.0. By submitting a contribution, you represent that you have the right to license it on those terms.

## Releases

After verification succeeds on a merge to `master`, CI reads the matching workspace and package versions and creates the corresponding `v<version>` GitHub release. Existing releases are skipped safely, prerelease versions are marked as prereleases, and a tag without a matching GitHub release fails closed for manual review. Increment both versions in the release PR when a new release is intended.

If the exact `@decionis/agent-safe-pipeline` version is already public on npm when the job runs, its registry link is prepended to the GitHub release notes. The workflow does not publish to npm; publishing remains a separate, explicitly authorized operation.
