# AgentSafe Coding Rules

These rules apply to the AgentSafe repository, including the publishable
`@decionis/agent-safe-pipeline` package, runnable examples, repository automation, and documentation.
They are release requirements alongside `security.rules.md` and `discovery.rules.md`.

## 1. Structure and naming

- Publishable TypeScript belongs under `packages/pipeline/src/`; its tests belong under the sibling
  `packages/pipeline/test/` tree and should mirror the source feature when useful. Runnable consumer
  examples belong under `examples/`, repository automation belongs under `scripts/`, and automation
  tests belong under `test/automation/`.
- Group code by responsibility: `intent`, `decision`, `approval`, `execution`, `shadow`, and
  narrowly scoped supporting modules such as `http`.
- Use PascalCase for TypeScript file names, classes, interfaces, and exported types. Use camelCase
  for variables, properties, and methods.
- Keep the public surface explicit through `packages/pipeline/src/Index.ts`. Internal helpers must
  not become exports accidentally.
- Keep each class or module focused on one trust-boundary responsibility. Extract shared behavior
  instead of duplicating security-sensitive validation.

## 2. Architecture

- Preserve the separation between intent capture, independent decision authority, optional human
  approval, authorization verification, and action execution.
- An agent may propose an action but must never authorize its own execution.
- Keep captured intents and decisions immutable. Any transformation that affects authorization
  must be represented in the canonical intent hash.
- Depend on interfaces at boundaries (`DecisionAuthority`, `AuthorizationVerifier`, action
  handlers, replay storage) so production integrations remain replaceable and testable.
- Do not add hidden network calls, ambient credentials, or implicit execution to constructors or
  data-model helpers.

## 3. TypeScript and readability

- Maintain strict TypeScript settings and ESM/NodeNext imports, including `.js` extensions for
  relative runtime imports.
- Prefer precise domain types over `any`, unchecked casts, or stringly typed state.
- Use stable, non-sensitive error/reason codes at trust boundaries. Do not expose raw downstream
  errors, credentials, tokens, or response bodies.
- Bound all input-dependent work. Avoid ambiguous or backtracking regular expressions on caller-
  controlled data; use linear scans or platform parsers where possible.
- Comments should explain invariants and security reasoning, not restate syntax.

## 4. Change discipline

- Preserve fail-closed behavior. Network, parsing, verification, replay-store, and binding
  uncertainty must not produce an executable authorization.
- Add a regression test for every bug fix. Security and performance fixes require an adversarial
  case that would have triggered the original failure mode.
- Keep refactors behavior-preserving and separate from feature changes where practical.
- Update examples and the package README when a public API, required environment variable, or
  outcome contract changes.

## 5. Required validation

- `pnpm format`
- `pnpm lint`
- `pnpm security`
- `pnpm performance`
- `pnpm typecheck`
- `pnpm test`
- `pnpm build`

Run `pnpm verify` before opening or updating a pull request. Do not weaken checks, coverage, or
strict compiler options to make a change pass.
