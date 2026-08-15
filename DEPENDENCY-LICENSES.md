# Dependency licenses

The dependency-license inventory is generated from an installation locked by `pnpm-lock.yaml`; it is not hand-maintained.

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm license:check
pnpm license:inventory
```

`license-policy.json` contains the permissive allowlist and package-scoped exceptions. Every exception requires an exact package, license, and written justification.

| Package        | Reported license | Scope and decision                                                                                                            |
| -------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `caniuse-lite` | CC-BY-4.0        | Development-only mutation-testing data; attribution remains in dependency metadata and it is absent from the runtime artifact |

No current production dependency requires an exception.

GitHub's dependency-review license evaluation is lockfile-wide even when vulnerability failures are restricted with `fail-on-scopes`. Both workflow passes therefore use this same exact package exception, while `pnpm license:check` and the packed-artifact inventory independently confirm that no production dependency needs one.

CI generates two JSON artifacts: the complete workspace tree, including development tools that execute on the runner, and the production tree of `@decionis/agent-safe-pipeline`. Release assets include both inventories plus an SBOM generated after extracting the packed npm artifact.

## Platform-conditional dependencies

The workspace toolchain includes optional native binaries selected by operating system and architecture, including Rollup, esbuild, and resolver bindings. Consequently a developer's installed inventory can contain a Darwin or Windows binary while the CI artifact records Linux x64. Every inventory records its OS, architecture, and lockfile SHA-256 so this difference is explicit. The published package's current production graph is platform-independent; the artifact-derived SBOM remains authoritative for each release.
