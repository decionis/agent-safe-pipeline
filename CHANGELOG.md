# Changelog

Releases of `@decionis/agent-safe-pipeline` (the library) and `@decionis/agentsafe` (the runtime).
Each entry names what an adopter can rely on and what they must do, if anything.

## Library 0.4.0, runtime 0.6.0 (unreleased)

One execution contract: every write to a system of record, on any platform, runs through one runner
and carries one single-use permit.

**Release order.** The library now calls the authority's REST resources
(`POST /v1/authority/grants`, `POST /v1/authority/grants/{grantId}/claims`, `…/receipts`,
`…/reconciliations`). Decionis Core must serve them (with the verb routes kept as aliases on the
same handlers) before this release is published. Clients on 0.3.8 keep working against that Core
through the aliases.

### Library (`@decionis/agent-safe-pipeline` 0.4.0)

- **`NativeExecutor`** (`agent-safe.executors.native/1`): the one interface every native executor
  implements, in two styles. `dispatch`: the executor writes, once, inside the dispatch the runner
  opens. `permit`: the platform writes and presents a permit, and its receipt settles it.
  `ExecutionCapability` matches Commerce's executor seam field for field.
- **`GovernedExecutionRunner`**: the only implementation of admission (an authoritative `ALLOW` or
  `PROCEED`, never after a fail-closed gate, only with a dossier, only through a capability the
  connection has), the authority calls, the dispatch deadline, the journal's durable claim and
  single-use idempotency key, reconciliation after an outcome nobody knows, failure posture
  (`STRICT`, `BOUNDED_CONTINUITY`, `CUSTOM`; the runner never writes without a grant), the
  `agent-safe.executor-evidence/1` line, and the six outcomes. `HELD` joins the outcome table.
- **`SafeExecutor`** is now a facade over the runner, with its signatures and outcomes unchanged.
  One addition to its refusals: an `ALLOW` without a dossier is `BLOCKED` as `DOSSIER_MISSING`
  before the grant is presented, where it was refused as `AUTHORIZATION_INVALID` by the verifier.
- **`ExecutionJournal`** moved here from the runtime (`agent-safe.attempts/1`, unchanged), with an
  optional `dispatchedUnder` read, and **`PostgresExecutionJournal`**, the journal replicas share,
  whose unique index makes an idempotency key single-use across them.
- **`EffectAdapter`** moved here as the deprecated name of the dispatch style; its preparation is
  exported as `EffectPreparedAction`. `MonotonicDeadline` and `dispatchBudgetMs` moved here too.
- **`AuthorityPaths`**: every execution-authority path in one place, as REST resources.
  `DecionisGate` evaluates through `POST /v1/authority/grants`; `DecionisGrantVerifier` claims and
  records receipts on the grant's resources (by the token's `jti`; a token with none uses the
  deprecated aliases) and reports reconciliations through `AuthorizationVerifier.reconcile`.
- `LocalAuthority` serves the REST resources beside the aliases.
- `spec/executors/native/v1`: the specification, its generated JSON Schema, and eighteen
  conformance vectors the runner is held to.

### Runtime (`@decionis/agentsafe` 0.6.0)

- The banking family runs as `BankingExecutor` (dispatch) and the cards family's issuer results are
  read by `CardAuthorizationExecutor` (permit), with no change in behaviour; `EffectAdapterExecutor`
  runs any effect adapter as a dispatch-style executor, and `executorActionHandler` bridges one into
  the registry.
- `EffectAdapter`, `PreparedAction`, `ExecutionJournal` and `MonotonicDeadline` are re-exported
  from the library, so existing imports keep working.
- `agentsafe doctor` probes `POST /v1/authority/grants`.
