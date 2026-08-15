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
