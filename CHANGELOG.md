# Changelog

Releases of `@decionis/agent-safe-pipeline` (the library) and `@decionis/agentsafe` (the runtime).
Each entry names what an adopter can rely on and what they must do, if anything.

## Library 0.4.1 (unreleased)

The policy projection, first class: an intent states the policy path Decionis decides it under, and
the binding carries it inside the hash.

**Nothing to do** for an intent that states no projection: it hashes and travels byte-identically
to 0.4.0 (`conformance/vectors/policy-projection-absent.json`). Decionis Core already accepts and
binds `policy_projection` on `POST /v1/authority/grants` and on the claim's `intent`. The runtime
(`@decionis/agentsafe` 0.6.0, which depends on `^0.4.0`) takes this release on its next install.

- **`TrustedIntentContext.policyProjection`** and **`PreparedAction.policyProjection`** (optional):
  `decisionType`, and `transactionType`, `workflowKey` and `channel`, each a string or `null`.
  `IntentCapture` validates and trims it, the agent proposal still cannot carry it, and
  `CanonicalIntentHasher.bindingOf` emits it as the top-level `policy_projection` Core routes the
  grant by. `DecionisGate`'s grant request, a managed escalation and `DecionisGrantVerifier`'s
  claim carry it because they carry the binding; `GovernedExecutionRunner`'s own re-hash
  reproduces it, so a runner no longer needs another hasher for a projected intent.
- **Admission:** `GovernedExecutionRunner` refuses, as `INTENT_BINDING_MISMATCH`, an executor whose
  `prepare` names another policy path than the decided intent's (or names one where the intent
  has none, or none where it has one).
- `AuthorityIntentBinding`, `AuthorityIntentBindingSchema` and `spec/intent/v1/schema.json` gain the
  optional property; `PolicyProjection` and `PolicyProjectionSchema` are exported. `LocalAuthority`
  accepts and re-hashes it, and its policy hook sees it.
- `conformance/vectors/policy-projection.json` (a projected binding and five mutations, six
  distinct hashes) and `policy-projection-absent.json`. `@decionis/verify` 0.4.0's
  `intent` command does not know the property yet and reports a projected binding as
  `BINDING_INVALID`; `agentsafe verify intent` and the schema accept it.

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
