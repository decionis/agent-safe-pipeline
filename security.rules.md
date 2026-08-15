# AgentSafe Security and Performance Rules

These rules apply to the AgentSafe repository, including the publishable
`@decionis/agent-safe-pipeline` package, runnable examples, and repository automation. They are
release requirements and do not authorize testing production, customer, marketplace, or third-party
systems. Security and load tests must use local injection, loopback, mocks, or an explicitly
authorized isolated environment.

## 1. Trust-boundary invariants

- An agent may capture and submit intent but must never mint, approve, verify, or consume its own
  execution authorization.
- Intent capture, independent decision, optional presence approval, grant verification, replay
  prevention, and execution remain separate stages with explicit interfaces.
- Every executable decision must bind the canonical intent hash, decision ID, dossier ID, grant ID,
  and expiry. Missing or mismatched binding fails closed.
- Captured intents, decisions, and authorization evidence are immutable after creation.
- `ALLOW` without a valid, unexpired, atomically consumable grant is not executable.

## 2. Network and input safety

- Authority and verification endpoints require HTTPS. Plain HTTP is permitted only for explicit
  loopback use in local development or tests.
- URLs containing credentials are forbidden. API keys and bearer tokens must be supplied through
  headers and must never appear in URLs, logs, errors, or persisted evidence.
- Downstream timeouts must be finite and clamped to the documented maximum. Abort timers must always
  be cleared.
- Authority responses are capped at 100 KiB before JSON parsing. Malformed, oversized, or schema-
  invalid responses fail closed without exposing their contents.
- Caller-controlled work must be bounded and linear where practical. Ambiguous backtracking regular
  expressions on URLs, identifiers, tokens, or response text are prohibited.
- Use strict schemas for external data and reject unknown execution semantics rather than guessing.

## 3. Authorization, replay, and execution

- Canonical hashing must cover action, target, parameters, tenant, actor, downstream operation,
  idempotency key, and security-relevant context in stable order.
- Grant verification must compare the consumed grant to the captured intent and independent decision
  before returning `VerifiedAuthorization`.
- Replay storage must use single-winner semantics. A store error or duplicate grant must block
  execution.
- The action registry is an allowlist. Never resolve arbitrary modules, shell commands, URLs, or
  functions directly from agent-controlled action names.
- The executor must re-check intent conformance immediately before invoking the registered handler.
- Logs and telemetry may contain stable IDs and hashes; they must not contain raw API keys, bearer
  tokens, authorization headers, sensitive parameters, or downstream response bodies.

## 4. Dependency and source security

- Use the declared pnpm version and commit `pnpm-lock.yaml`. CI and release installs use
  `--frozen-lockfile`.
- `pnpm audit --audit-level moderate` must pass before commit and in CI. Critical/high findings block
  merge; lower findings require triage and a documented disposition.
- GitHub Actions must be pinned to immutable commit SHAs and use least-privilege permissions.
- CodeQL high/critical findings block merge. Fix the data flow and add a regression test; do not
  dismiss a true positive or suppress a rule to obtain a green check.
- Regular expressions are linted for exponential or polynomial backtracking. Security rules must not
  be disabled inline without maintainer review and a bounded-input proof.

## 5. Performance requirements

- Security-sensitive parsing, normalization, hashing, replay checks, and registry lookup must have
  bounded complexity under adversarial input.
- Performance regressions require a deterministic local test with a generous budget and an input
  shaped like the original worst case.
- Do not use production endpoints for load or performance checks. Network behavior must be mocked or
  limited to loopback.
- A performance test may use a wall-clock ceiling only when the gap between safe and vulnerable
  behavior is large enough to avoid flaky results.

## 6. Required tests

- Binding tests cover intent, decision, dossier, grant, and expiry mismatch.
- Replay tests cover duplicate and concurrent consumption with at most one successful execution.
- URL tests cover HTTPS, explicit loopback HTTP, embedded credentials, trailing separators, and
  adversarial separator runs.
- Response tests cover transport failure, non-success status, malformed JSON, oversized bodies, and
  schema mismatch.
- Executor tests cover unknown actions, conformance failure, missing authorization, handler failure,
  and successful single execution.

## 7. Release checklist

- [ ] `pnpm install --frozen-lockfile` succeeds
- [ ] `pnpm audit --audit-level moderate` reports no blocking findings
- [ ] `pnpm verify` passes, including security and performance checks
- [ ] CodeQL has no unresolved high/critical findings introduced by the change
- [ ] No secret, token, credential, private URL, or sensitive fixture is present in the diff
- [ ] Public exports, examples, package README, and discovery files match shipped behavior

## 8. Current validation entry points

| Concern                   | AgentSafe source                                           |
| ------------------------- | ---------------------------------------------------------- |
| Canonical intent binding  | `packages/pipeline/src/intent/CanonicalIntentHasher.ts`    |
| Independent authority     | `packages/pipeline/src/decision/DecionisGate.ts`           |
| Grant consumption         | `packages/pipeline/src/execution/AuthorizationVerifier.ts` |
| Replay prevention         | `packages/pipeline/src/execution/ReplayStore.ts`           |
| Execution boundary        | `packages/pipeline/src/execution/SafeExecutor.ts`          |
| URL hardening             | `packages/pipeline/src/http/AuthorityBaseUrl.ts`           |
| Security regression tests | `packages/pipeline/test/`                                  |
| Performance regressions   | `packages/pipeline/test/performance/`                      |
