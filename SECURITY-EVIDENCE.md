# Security evidence map

This map is an evidence index, not a claim of independent certification. The OpenSSF Best Practices record is a public self-assessment, and commands are run from a clean checkout unless stated otherwise. Known gaps are published in the final section.

| Control question                                            | Repository evidence                                                         | Verification                                                                                                                                                                  |
| ----------------------------------------------------------- | --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Full history contains no detected secret                    | `.github/workflows/secrets.yml`, `.gitleaks.toml`                           | `gitleaks git --log-opts="--all" --redact`                                                                                                                                    |
| Apache-2.0 text and package metadata are canonical          | `LICENSE`, `NOTICE`, package manifests, `scripts/CheckLicenses.mjs`         | `pnpm license:check`                                                                                                                                                          |
| Runtime and CI dependency risks are gated separately        | `.github/workflows/supply-chain.yml`, root scripts                          | `pnpm security:production && pnpm security:toolchain`                                                                                                                         |
| Dependency monitoring covers the workspace and Actions      | `DEPENDENCY-POLICY.md`, `.github/dependabot.yml`                            | `pnpm dependabot:check` proves weekly root npm/pnpm-workspace and GitHub Actions coverage                                                                                     |
| Dependency licenses are reviewable                          | `license-policy.json`, `DEPENDENCY-LICENSES.md`                             | `pnpm license:inventory`                                                                                                                                                      |
| CI dependencies are immutable                               | `.github/workflows/*.yml`                                                   | Every `uses:` reference is a 40-character commit SHA; `actionlint` validates syntax                                                                                           |
| Agent output cannot authorize execution                     | `THREAT-MODEL.md`, `docs/trust-boundary.md`, `SafeExecutor` tests           | `pnpm test` and `pnpm mutation`                                                                                                                                               |
| Canonical intent handling is property-fuzzed                | `.github/workflows/fuzz.yml`, `test/fuzz`                                   | `pnpm fuzz`; scheduled runs retain minimized synthetic counterexamples on failure                                                                                             |
| Fixtures are synthetic by construction                      | `FIXTURE-PROVENANCE.md`, `scripts/CheckFixtureProvenance.mjs`               | `pnpm fixture:check`                                                                                                                                                          |
| Browser framing controls                                    | Not applicable to the current Node.js library and CLI examples              | The repository has no HTTP listener, browser UI, redirects, or hosted demo; any future web surface must test CSP (including `frame-ancestors`) on success and error responses |
| Releases are independently verifiable                       | `.github/workflows/deploy.yml`, `CONTRIBUTING.md`                           | Release tarball, SBOM, inventories, checksums, Sigstore bundles, raw in-toto statements, and trusted root are attached to the GitHub release                                  |
| Release tags are identity-bound and verified                | `.github/workflows/deploy.yml`, `docs/release-tag-signing.md`               | The deploy workflow signs the exact release commit with keyless gitsign, verifies its Fulcio identity and issuer before building assets, and requires GitHub to reuse the tag |
| npm bootstrap provenance and digest were verified           | v0.1.2 GitHub release, package manifest, `CONTRIBUTING.md`                  | The public npm tarball SHA-256 matched the signed GitHub release asset; the temporary token and secret were removed and the one-time workflow was retired                     |
| Vulnerabilities have private reporting and response targets | `SECURITY.md`                                                               | GitHub private vulnerability reporting and `security@decionis.com`                                                                                                            |
| Repository changes are protected                            | `.github/CODEOWNERS`, GitHub branch protection and ruleset APIs             | Up-to-date required checks plus one code-owner review; the named maintainer has PR-only bypass to avoid deadlock                                                              |
| Contribution and governance authority are explicit          | `GOVERNANCE.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`                    | The `DCO` workflow enforces author-matching sign-offs; role, escalation, access-continuity, and bus-factor limits are public                                                  |
| OpenSSF Best Practices Passing evidence is public           | README badge, [project 14098](https://www.bestpractices.dev/projects/14098) | The active record identifies this canonical repository, has achieved Passing, and publishes unanswered Silver criteria for follow-up                                          |

## Negative-control record

The following gates were observed failing on 2026-08-15 before their controls were restored and the full suite passed:

| Gate                | Deliberate break                                                                     | Expected failure observed                                                                                                    |
| ------------------- | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| Secret scanning     | Redacted GitHub-token canary sent through stdin without writing it to the repository | Gitleaks exited 1; complete history and working tree then passed                                                             |
| Canonical licensing | Apache appendix/canonical digest mismatch                                            | `pnpm license:check` rejected the file                                                                                       |
| License policy      | Unreviewed CC-BY and multi-license development dependencies                          | Package-scoped justification was required before the gate passed                                                             |
| Dependency audits   | Isolated temporary lockfile containing known-vulnerable `lodash@4.17.20`             | Production/low and complete-toolchain/moderate audit commands both exited 1; the repository lockfile then passed both        |
| Fixture provenance  | Non-reserved actor, request, and dossier identities                                  | `pnpm fixture:check` rejected the values                                                                                     |
| Coverage            | A single-test run left global coverage below threshold                               | Vitest exited nonzero; the complete suite passed all four thresholds                                                         |
| Mutation assurance  | Pre-consume schema validation was removed by a mutant                                | The test initially allowed the mutation; a grant-consumption assertion was added and the final score is 29/29 mutants killed |
| SBOM integrity      | Valid CycloneDX envelope with zero components, then a missing serial number          | The assertion exited nonzero; the packed artifact reports five runtime components and a deterministic artifact-bound UUID    |
| Workflow syntax     | Malformed release-note shell quoting                                                 | `actionlint` rejected the workflow before the quoting was corrected                                                          |
| Property fuzzing    | Canonical equality was deliberately inverted                                         | Fast-check reported a shrunk counterexample; the correct property and complete fuzz target then passed                       |

## Known gaps and external dependencies

- npm trusted publishing produced `v0.1.3-rc.2` with SLSA provenance. The npm and GitHub release
  tarballs were byte-identical with SHA-256
  `5b04318b3a73d8bb1e3b2551cc3633ea36891eb1fa6d4976d1ab5f15bc714c82`; the temporary bootstrap
  credential was revoked and the one-time workflow was removed.
- Fixture provenance, trademark ownership, and disclosure targets require the written human decisions tracked in `PUBLICATION-SIGNOFFS.md`; automation cannot manufacture those approvals.
- Repository-age, contributor-count, and historical review signals improve only with real project activity.
- The project has a lead and a maintainer, but code-owner, private-report, npm-recovery, and
  emergency-release authority are not independently available to two people. `GOVERNANCE.md`
  therefore records OpenSSF access continuity and bus factor as unmet rather than overstating them.
- The OpenSSF Best Practices record has achieved Passing. Remaining Silver evidence and controls are
  tracked in [#46](https://github.com/decionis/agent-safe-pipeline/issues/46),
  [#47](https://github.com/decionis/agent-safe-pipeline/issues/47),
  [#48](https://github.com/decionis/agent-safe-pipeline/issues/48),
  [#51](https://github.com/decionis/agent-safe-pipeline/issues/51), and
  [#52](https://github.com/decionis/agent-safe-pipeline/issues/52).
- The release job alone receives job-scoped `contents: write` so it can create tags and GitHub Releases after verification. OpenSSF Scorecard does not recognize the custom `gh release create` path as a release exception, so its Token-Permissions check may continue to report that necessary permission even though every workflow declares a read-only default.
