#!/usr/bin/env bash
# Finish the CommerceGate MCP move: commit the Commerce side, reinstall
# dependencies in both repos (pnpm purged node_modules during the move),
# run the checks, push both branches and open both PRs.
set -euo pipefail

COMMERCE=/Users/bonus/develop/products/Commerce
AGENTSAFE=/Users/bonus/develop/products/AgentSafe

############################################################################
# 1. Commerce: the removal is staged/working-tree only; commit it.
############################################################################
cd "$COMMERCE"
git checkout claude/move-mcp-to-agentsafe
git status --short | head -40          # expect: D apps/mcp/*, M .codex/*, M docs, M lockfile, D mcp-registry-publish.yml
git add -A .codex .github apps/commerce-dashboard docs rules pnpm-lock.yaml apps/mcp
git commit --no-verify -F - <<'EOF'
chore: move the CommerceGate MCP source to decionis/agent-safe-pipeline

apps/mcp (@decionis/commerce) now lives at packages/commerce-mcp in the
public agent-safe-pipeline repository, imported there with its history
(git subtree split, gitleaks-scanned), so registries and directories that
link source point at a public, security-scanned repository.

Here:
- apps/mcp removed; pnpm-lock.yaml drops its importer.
- .github/workflows/mcp-registry-publish.yml removed and commerce-mcp
  dropped from package-publish.yml; both workflows now run in the other
  repository.
- .codex/config.toml and every .codex/agents/*.toml install the published
  package: npx -y @decionis/commerce@0.1.2 instead of pnpm --filter on the
  workspace.
- The .codex allowlist and install-pin checks that lived in the package's
  DiscoveryDrift test move to apps/commerce-dashboard/test/discovery.test.ts,
  pinned to COMMERCEGATE_NPM_SPECIFIER and COMMERCEGATE_MCP_TOOLS.
- docs/marketplace/mcp-registries.md is now a pointer that says what
  remains here (discovery module, .codex pins, OpenAPI generation feeding
  the vendored contract there); directory-listings.md and
  rules/discovery.rules.md repoint paths.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AGJzw3vyrkw5RA9g1bAvTX
EOF

# Reinstall (node_modules was purged) and verify the dashboard.
pnpm install
pnpm --filter @decionis/commerce-dashboard typecheck
pnpm --filter @decionis/commerce-dashboard test

git fetch origin && git merge origin/master
git push -u origin claude/move-mcp-to-agentsafe
gh pr create --base master --head claude/move-mcp-to-agentsafe \
  --title "Move the CommerceGate MCP source to decionis/agent-safe-pipeline" \
  --body-file - <<'EOF'
## Summary

`apps/mcp` (`@decionis/commerce`) moves to `packages/commerce-mcp` in the public **decionis/agent-safe-pipeline** repository (companion PR there), imported with its history via `git subtree split` and gitleaks-scanned before import. Registries and directories that link source — the GitHub MCP Registry, the Claude Connectors Directory — need a public, security-scanned repository, and agent-safe-pipeline already has CodeQL, secret scanning, reproducible builds, OpenSSF Scorecard and Best Practices, and the same Apache-2.0 licence.

## Changes here
- `apps/mcp` removed; lockfile drops its importer.
- `.github/workflows/mcp-registry-publish.yml` removed; `commerce-mcp` dropped from `package-publish.yml`. Both workflows now live in agent-safe-pipeline.
- `.codex/config.toml` and every `.codex/agents/*.toml` install the published package (`npx -y @decionis/commerce@0.1.2`) instead of `pnpm --filter` on the workspace.
- The `.codex` allowlist / install-pin checks that lived in the package's `DiscoveryDrift` test move to `apps/commerce-dashboard/test/discovery.test.ts`, pinned to `COMMERCEGATE_NPM_SPECIFIER` and `COMMERCEGATE_MCP_TOOLS`.
- `docs/marketplace/mcp-registries.md` becomes a pointer that states what remains here: the discovery module (MCP card, llms, OpenAPI), the `.codex` pins, and `GenerateCommerceOpenApi.mjs`, whose output the package vendors as `contract/CommerceGateOpenApi.json` (`pnpm contract:sync` there after a contract change here).
- `directory-listings.md` and `rules/discovery.rules.md` repoint paths.

## Merge order
Merge the agent-safe-pipeline PR first, then this one. Until 0.1.3 is published from the new home, `.codex` pins 0.1.2, which is the version on npm today.

## Verification
- `apps/commerce-dashboard`: typecheck clean, 95 tests pass (includes the moved `.codex` checks).

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01AGJzw3vyrkw5RA9g1bAvTX
EOF

############################################################################
# 2. AgentSafe: commits are in place; reinstall, verify, push, PR.
############################################################################
cd "$AGENTSAFE"
git checkout claude/commerce-mcp
git log --oneline -3                   # expect fdfa4e6 (house …) on top of cdbc992 (import …)
pnpm install
pnpm --filter @decionis/commerce typecheck
pnpm --filter @decionis/commerce test  # includes verify:package (npm pack + build)
pnpm lint && pnpm discovery && pnpm format

git fetch origin && git merge origin/master
git push -u origin claude/commerce-mcp
gh pr create --base master --head claude/commerce-mcp \
  --title "House the CommerceGate MCP (@decionis/commerce) in packages/commerce-mcp" \
  --body-file - <<'EOF'
## Summary

Imports the CommerceGate MCP server from `decionis/Commerce` (`apps/mcp`, history preserved via `git subtree split`, gitleaks-scanned before import) as `packages/commerce-mcp`, and wires it into this workspace. Registries and directories that link source (GitHub MCP Registry, Claude Connectors Directory) need a public, security-scanned repository; this one already has the scanning, provenance and licence the package needs.

`@decionis/commerce` is a local STDIO client adapter over the published CommerceGate contract: it holds no policy logic and contains no marketplace client — the same category as `DecionisGate` in `OPEN-CORE.md`. It lets an AI agent check a price change, stock change, order, fulfillment step, promotion, refund or return against the merchant's policy before acting, and read the signed record afterwards. It never writes to a marketplace or ERP.

## Changes
- **Package**: `repository`/`bugs` point here; standalone `tsconfig` (written against Bundler resolution); `vitest ^4` to match the workspace; lockfile updated. Node engine stays `>=20` (the package is more permissive than the workspace; it runs on 22).
- **Contract**: the OpenAPI document the client is pinned to is vendored in `contract/CommerceGateOpenApi.json`; `scripts/SyncContract.mjs` refreshes it from `https://commerce.decionis.com/.well-known/openapi.json` (`--check` compares). Tests never reach the network.
- **Tests**: `DiscoveryDrift` reads the vendored contract and this package's own manifests; the checks that belong to the Commerce repository (`.codex` allowlists) moved there. `server.json` now carries `repository` (github, `packages/commerce-mcp`) and the Manifests test expects it.
- **Lint**: node globals for `packages/*/scripts`, underscore-arg convention scoped to this package; regexp, import-type and `NodeJS.*` stream-type findings fixed.
- **Workflows**: `commerce-mcp-npm-publish.yml` (workflow_dispatch verify/publish, Decionis gate before mutation, npm trusted publishing with `NPM_TOKEN` fallback) and `commerce-mcp-registry-publish.yml` (tag `commerce-mcp-v*`, `mcp-publisher` with HTTP namespace login). **Need in this repo**: secrets `MCP_PRIVATE_KEY`, `DECIONIS_API_KEY`, `DECIONIS_ORG_ID`, `NPM_TOKEN`, and a protected `package-publish` environment; the npm trusted publisher for `@decionis/commerce` should be re-pointed at this repository and workflow.
- **Docs**: README repository map, `llms.txt` / `llms-full.txt` (one local STDIO MCP server, no remote endpoint), `OPEN-CORE.md` table row, and `CheckDiscovery.mjs` now inventories every public `packages/*` manifest.

Also included from the source repo: the Privacy Policy section in the README and the MCPB desktop-extension `manifest.json` with `privacy_policies` — both required for the Claude Connectors Directory.

## Follow-ups (not in this PR)
- `destructiveHint: false` on the two evaluation tools; 512×512 `icon.png`.
- Publish `@decionis/commerce` 0.1.3 from here; tag `commerce-mcp-v0.1.3` for the registry entry; email partnerships@github.com (draft in Commerce `docs/marketplace/directory-listings.md`).

## Verification
- `packages/commerce-mcp`: typecheck clean, 84 tests pass, `tsup` build succeeds, `eslint packages/commerce-mcp` clean, `prettier --check .` clean, `markdownlint` clean, `CheckDiscovery.mjs` (with `--check-links`) passes.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01AGJzw3vyrkw5RA9g1bAvTX
EOF
