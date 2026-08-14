# Agent Safe Pipeline Discovery Rules

These rules keep `agent-safe-pipeline` discoverable by developers, search systems, and AI agents
without overstating what the package ships. They apply alongside `coding.rules.md` and
`security.rules.md`.

## 1. Verify before claiming

- Describe the package as an execution architecture in which agents may propose actions but cannot
  authorize their own execution. Do not claim that the package alone secures an entire agent,
  deployment, or downstream system.
- Capability claims must match shipped code and tests. Distinguish reference adapters and examples
  from production services operated by Decionis.
- Never publish registry, marketplace, documentation, or repository links before verifying that the
  destination resolves publicly.
- Do not publish latency, throughput, accuracy, or security-effectiveness numbers without a checked-
  in benchmark or governed measurement that pins the claim.
- Use absolute public links in npm-facing documentation and machine-readable discovery files.

## 2. Canonical discovery surfaces

- `README.md` is the human entry point and must explain the trust boundary, install path, minimal
  usage, ALLOW/HOLD/BLOCK behavior, support, and license.
- `packages/pipeline/README.md` is the package-facing source that ships to npm. It must not link to
  repository-relative files that are absent from the published tarball.
- `llms.txt` is the concise package and documentation map. `llms-full.txt` is its detailed superset;
  both must use the same frozen product vocabulary.
- `package.json` metadata, exports, files, engine requirements, and repository links must match the
  actual published artifact.
- Do not add OpenAPI, MCP, security.txt, sitemap, or registry manifests unless the corresponding
  callable surface actually exists in this repository.

## 3. Drift prevention

- `scripts/CheckDiscovery.mjs` must validate the discovery files and their public links. Extend this
  check whenever a new hand-maintained inventory or discovery surface is added.
- Every exported API named in discovery copy must exist in `packages/pipeline/src/Index.ts` and be
  covered by build/type checks.
- Examples may demonstrate only public exports and documented environment variables. An example is
  not evidence that a hosted integration exists.
- Remove stale claims and links in the same pull request that removes or renames the underlying
  capability.

## 4. Package release rules

- The npm README must contain a one-line description, install command, minimal end-to-end example,
  fail-closed/outcome semantics, support information, and license.
- Verify the npm package page and any other distribution URL on the release date before adding it to
  `sameAs`, package inventories, or discovery copy.
- Regenerate and inspect the package tarball before release. Only `dist`, `README.md`, and `LICENSE`
  should ship unless the manifest intentionally says otherwise.
- Documentation improvements do not reach npm until a new package version is published; include
  them in the release plan.

## 5. Pull-request checklist

- [ ] Claims match shipped public exports and tested behavior
- [ ] `README.md`, package README, `llms.txt`, and `llms-full.txt` remain consistent
- [ ] All external URLs resolve and all off-repo links are absolute
- [ ] No unsupported performance, security, or availability figures were introduced
- [ ] `pnpm discovery` and `pnpm verify` pass
- [ ] Public API or package changes include an inspected package build/tarball

## 6. Current validation entry points

| Concern                  | Agent Safe Pipeline source       |
| ------------------------ | -------------------------------- |
| Public exports           | `packages/pipeline/src/Index.ts` |
| Human documentation      | `README.md`                      |
| npm documentation        | `packages/pipeline/README.md`    |
| Machine-readable summary | `llms.txt`                       |
| Detailed agent context   | `llms-full.txt`                  |
| Discovery drift gate     | `scripts/CheckDiscovery.mjs`     |
| Package metadata         | `packages/pipeline/package.json` |
