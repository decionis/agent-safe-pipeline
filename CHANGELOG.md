# Changelog

Releases of `@decionis/agent-safe-pipeline` (the library) and `@decionis/agentsafe` (the runtime).
Each entry names what an adopter can rely on and what they must do, if anything.

## Runtime (unreleased): subject-bound sessions

An agent limited to the customer it is serving, with no code of yours: a `subject` section names
your identity provider, and an API profile says where the customer sits.

**Nothing to do** to keep things as they are: without `subject`, reads pass through as before and
no session is read.

- The app that starts the agent exchanges the provider's short-lived token for a gateway session
  (RFC 8693, `POST /_agentsafe/v1/sessions`), or the agent presents the token itself on each call
  (`AgentSafe-Subject-Token`). The gateway pins the customer; the agent cannot change it. Neither
  header is forwarded.
- A read an API profile operation names is checked against the session's customer, in the call
  and in every item of its answer; an answer with another customer's record is refused whole
  (`403 RESPONSE_SUBJECT_MISMATCH`, `agentsafe-execution: WITHHELD`) and recorded, never filtered.
  `interception.refuseUnknownReads: true` refuses a read the profile cannot check.
- A write states the customer to the authority as the fact `session.subject`.
- `agent-safe.profile.api/1` gains `subject` pointers and `GET` operations, additively, with
  vectors; `session` is a reserved fact name. `businesscentral/api/v2` scopes its customer, sales
  document and customer ledger entry reads, and states the subject of a new sales order.
- New wire values, additive: the state `REFUSED`, the execution `WITHHELD`, the header
  `agentsafe-subject: CHECKED`. [Subject-bound sessions](docs/gateway/subject-sessions.md).

## Runtime (unreleased): facts-only privacy for the gateway

One setting keeps the request out of the authority: `interception.privacy: facts` (or
`AGENTSAFE_PRIVACY=facts`).

**Nothing to do** to keep things as they are: privacy is `full` by default and sends what it always
sent. To turn it on, name an API profile (`interception.profile`) and set `privacy: facts`.

- The authority receives the profile operation's id and path template and the facts it names, a
  keyed digest that binds the held request, and nothing else of the request: no raw path, query,
  header or body byte, and not the plain digests. The upstream still receives the request as sent.
- A write the profile does not name is refused with `403 PROFILE_OPERATION_UNMATCHED`, never
  governed under its raw path.
- At start, facts-only privacy refuses by name a missing profile, explicit routes, a principal
  header and `unmatched: passthrough`.
- `agentsafe config` now prints `interception.profile` and `interception.privacy`.
- `request_hmac_sha256` joins the reserved fact names of `agent-safe.profile.api/1`.
  [Facts-only privacy](docs/gateway/http-interception.md#facts-only-privacy).

## Runtime (unreleased): card authorization outcome evidence

The card purchases' outcome evidence for the Decionis meter (`decionis.outcomes.evidence/1`), kept
and stated after the fact.

**Nothing to do** to keep things as they are: `EXECUTOR_CARD_OUTCOMES` is `off` by default, and no
authorization is answered differently with it on. To send evidence, Decionis registers the
deployment as a producer (`outcomes: "agentsafe"` in `DECIONIS_DELIVERY_PRODUCERS_JSON`) and runs
the meter (`DECIONIS_OUTCOMES_ENABLED=1`); the bank sets `EXECUTOR_CARD_OUTCOMES=publish`,
`EXECUTOR_CARD_OUTCOMES_DIR`, `EXECUTOR_CARD_OUTCOMES_ORG_ID` and `DECIONIS_PRODUCER_TOKEN_FILE`,
and its agreement's scope names the platform `card-authorization` and the action `CARD_PURCHASE`.

- `record` keeps each purchase's decision, a person's answer to its escalation, the claim and the
  issuer's result as facts (`agent-safe.card-outcome/1`, JSONL per day and replica) once each
  answer has been given; a full queue or a refused write is dropped and counted
  (`CARD_OUTCOMES_DROPPED`), never retried into the request.
- `publish` also states each purchase as one digest-only subject and sends what Decionis has not
  accepted to `POST /v1/outcomes/evidence` with the producer token, on a timer (hourly by default):
  revisions rise only when a purchase's evidence changes, a revision conflict restates the subject
  under its next revision, a refusal keeps the evidence owed (`CARD_OUTCOMES_REFUSED`), an outage
  is retried with backoff.
- What is stated, and never: no card reference, merchant, authorization id or tap; no issuer
  settlement or reversal (`financial` is null); and no `CONFIRMED_PROBLEM`, since AgentSafe
  records no person's confirmation, so no card purchase is counted as prevented. The guide has the
  full table: [card authorization](docs/banking/card-authorization.md#outcome-evidence-for-the-decionis-meter).
- Core's contract is vendored byte for byte at `packages/agentsafe/contracts/OutcomeEvidence.v1.json`
  (owner revision e264bfbf5) with its digest pinned in the source and held by a test.

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
