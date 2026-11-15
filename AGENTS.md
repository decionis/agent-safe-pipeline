# AgentSafe repository

AgentSafe is the execution gateway: an agent sends its action through AgentSafe, Decionis decides **ALLOW**, **ESCALATE** or **BLOCK**, and only an allowed action runs, once, on a single-use grant. AgentSafe decides nothing itself.

## Layout

- `packages/pipeline` (`@decionis/agent-safe-pipeline`): `SafeExecutor`, `ActionRegistry`, intent capture, the Decionis gate and grant verifier.
- `packages/agentsafe` (`@decionis/agentsafe`): the `Gateway`, adapters and the CLI.
- `spec/`: versioned contracts such as `agent-safe.executors.native/1` and `agent-safe.intent/1`.
- `govern/`: `govern init`, which writes a shadow-mode CI workflow and `DECIONIS_POLICY.md`.

## Rules

- Never rename the wire verdicts ALLOW, ESCALATE and BLOCK.
- Commit with a DCO sign-off: `git commit -s`.
- Let the pre-commit hook run the whole gate (`pnpm precommit`); never bypass it.
- Use Node 22.14 or later (`.nvmrc`) and pnpm 9.15.3.
- Push branches only. The Decionis bot opens the pull request.
- Never commit keys, tokens or customer payloads.

## Guides for AI assistants

The Decionis guides for policy authoring, AgentSafe implementation and workflow setup are installed with `npx @decionis/mcp context install --client <claude|codex|copilot|kiro|cursor>` from the same source as the Decionis repository. Reinstall to update them; never hand-edit them.
