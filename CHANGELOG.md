# Changelog

Releases of `@decionis/agent-safe-pipeline` (the library) and `@decionis/agentsafe` (the runtime).
Each entry names what an adopter can rely on and what they must do, if anything.

## Runtime (unreleased): the action space as a document

`agentsafe actions manifest` writes the actions this build can run as one `agent-safe.actions/1`
document, for a policy release to be held to: Decionis refuses a release that leaves a manifest
action matched by no rule but its default.

**Nothing to do**: the command reads only what it is told to, and nothing else changes.

- Sources: `--family forward|banking|cards` (a family's own registration, so the schemas are the
  ones admission uses), `--api <profile id>` (a shipped API profile's writes) and `--mcp <file>` (an
  MCP tool profile), each repeatable. Each entry states its action, source, parameters JSON Schema,
  target scope templates and effect type; `--digest` prints the digest a signed release manifest
  records as `actionManifestDigest`.
- The library exports `ActionManifest` (`fromRegistry`, `fromApiProfile`, `fromMcpProfile`,
  `document`, `digest`), so an adopter with handlers of their own describes their registry the
  same way, and `ActionRegistry.describe()`, which lists a sealed registry's actions with the
  schemas they are admitted against.
- [CLI reference](docs/reference/cli.md#agentsafe-actions-manifest).

## Library (unreleased): held allowances in the local authority

Decionis is adding allowances it holds itself: named counters for an organisation that a policy
rule draws on, reserved with the grant, converted at the claim and settled by the outcome. A draw
that does not fit is refused as `BLOCK` with `ALLOWANCE_EXHAUSTED`, `ALLOWANCE_UNDEFINED` or
`ALLOWANCE_AMOUNT_INVALID`, and no grant is issued. The loopback authority models it, so the race
for the last unit of a limit nobody publishes, or publishes late, can be tested offline.

**Nothing to do**: a `LocalAuthority` built as before draws on no allowance. No production code path
changed, and a client reads the refusal as any other `BLOCK`.

- **`LocalAuthority`** (`@decionis/agent-safe-pipeline/testing`): the `allowanceDraws` option names
  what an approval draws on, `setAllowance(key, limit)` defines an allowance or tops it up, and
  `allowanceUsage(key)` reports what it has reserved, held, consumed and left.
  [docs/local-testing.md](docs/local-testing.md#held-allowances) says what it models and what it
  does not.
- **`HardLimits`** stays the host's backstop. Its documentation and
  [the card guide](docs/banking/card-authorization.md#card-limits-and-the-hosted-allowance) say where
  a limit that must hold across replicas belongs, and why card holds do not move onto an allowance
  yet.
- **`examples/changed-conditions-demo`**: the case the Changed Conditions Test reported open, an
  allowance published after the commit instead of with it, is refused now. The authority holds the
  canary allowance too, so a second rollout is refused with `ALLOWANCE_EXHAUSTED` while the first's
  grant holds the last unit and again inside the window before the late publication, and it
  completes after a top-up. The run has no `OPEN:` line:
  `PROVEN: 21 changed-condition attempts, 0 stale commits; 15 legitimate counterparts completed,
each exactly once.`

## Library (unreleased): governed plans

One change carried out as several governed steps: `agent-safe.plan/1`, and the step stamp an
executor binds into each step's intent ([ADR 0008](docs/architecture/decisions/0008-governed-plans.md)).

**Nothing to do** to keep things as they are: an intent that states no plan carries no `agent_safe`
key and hashes as before. A trusted context that already wrote `agent_safe` by hand is now refused
with `INTENT_CONTEXT_KEY_RESERVED`; nothing in this repository wrote it.

- `GovernedPlanSchema` and `planDigest` (steps, `ordered` / `all_or_escalate` / `independent`
  edges, a partial-commit rule and compensation steps); `matchPlanStep` refuses a proposal outside
  its step before anything is captured.
- **`TrustedIntentContext.plan`** (optional): `{plan_id, plan_digest, step_id}`, stamped by
  `IntentCapture` as `context.agent_safe.plan`. `agent_safe` joins the reserved context keys.
- `derivePlanStepFacts`, `planStepStatuses` and `planState`: the reference derivation of a step's
  plan facts from finalization records, which Decionis mirrors, and the per-step signal its claim
  revalidates. A plan step's grant is the authority's to issue: registering a plan authorizes
  nothing.
- `LocalPlans` (testing): a plan registry beside `LocalAuthority`, deriving facts from its claims
  and finalizations for a policy hook. It does not re-derive them at the claim.
- `examples/staged-change-demo`, in `pnpm examples:prove`. The SCITT mapping gains
  `partially_completed` for a `PARTIAL` plan.

## Library and runtime (unreleased): the Changed Conditions Test

The loopback authority re-derives authority at the claim as hosted Decionis does, and a new
self-checking corpus shows changed conditions refused while legitimate work completes.

**Nothing to do**: a `LocalAuthority` built as before decides, claims and finalizes as before. No
production code path changed.

- **`LocalAuthority`** (`@decionis/agent-safe-pipeline/testing`): `releasePolicy()` activates the
  next policy release, and a grant decided under an earlier one fails at claim with
  `POLICY_VERSION_STALE`; `publishSignal()` ingests a material signal, the `materialSignals` option
  names the ones a request rests on, their values reach the policy hook as `material_signals`, and a
  grant whose signal was published again fails `SIGNAL_VERSION_STALE`. Each signal is a concurrency
  scope: a claim fails `AUTHORIZATION_SCOPE_BUSY` while another holds it and
  `CURRENT_STATE_UNRESOLVED` behind an `INDETERMINATE` one until it is reconciled. None of these
  consumes the grant. `tenantKeys` binds keys to one organisation (403 `AUTHORITY_TENANT_MISMATCH`,
  `TENANT_MISMATCH`); `/v1/policies` answers 401 `ACCOUNT_SESSION_REQUIRED` to any key;
  `addressableGrants` mints hosted-shaped tokens so a client reaches the reconciliations resource.
- **`RecordingTarget`** is exported from `@decionis/agentsafe`: the loopback target behind
  `agentsafe test`, for a corpus that counts what reached the target.
- **`examples/changed-conditions-demo`**, in `pnpm examples:prove`: nineteen attempts on changed
  conditions, none of which reaches the target, thirteen legitimate counterparts that each reach it
  exactly once, and one case reported open: an allowance published after the commit instead of with
  it. The race for its last unit is refused when it is published with each commit.
  [docs/changed-conditions-test.md](docs/changed-conditions-test.md) is the page.

## Runtime (unreleased): MCP tools as data

An MCP server's consequential tools can be declared in a file instead of TypeScript:
`agent-safe.profile.mcp/1`, which `McpGuard` reads.

**Nothing to do** to keep things as they are: a binding written in code works as before, and a call
to a tool with no `subject` binds byte-identically.

- A tool profile names each tool's action, target template, subject argument, consequential
  arguments and accepted arguments; `McpToolProfile.parse` validates it and `McpGuard` takes it as
  `profile`, with the tools it implements as `{ tool, invoke }`.
- `guard(invocation, { subject })` holds a tool that names a subject argument to the session's
  customer, refusing `SUBJECT_SESSION_REQUIRED`, `SUBJECT_ABSENT` or `SUBJECT_MISMATCH` before the
  authority is asked, and states the subject as `session.subject`. A code binding may name a
  `subject` too.
- `SubjectSessions`, `IssuerSubjectVerifier` and `profiledBinding` are exported, so an MCP host
  verifies a session the way the gateway does.
- The specification, schema and vectors are at
  [spec/profiles/mcp/v1](spec/profiles/mcp/v1/README.md).

## Runtime (unreleased): subject-bound sessions

An agent limited to the customer it is serving, with no code of yours: a `subject` section names
your identity provider, and an API profile says where the customer sits.

**Nothing to do** to keep things as they are: without `subject`, reads pass through as before and
no session is read.

- The app that starts the agent exchanges the provider's short-lived token for a gateway session
  (RFC 8693, `POST /_agentsafe/v1/sessions`), or the agent presents the token itself on each call
  (`AgentSafe-Subject-Token`). The gateway pins the customer; the agent cannot change it. Neither
  header is forwarded.
- A read an API profile operation names is checked against the session's customer before it is
  sent and in every item of its answer. A list must carry exactly the profile's subject filter
  (`$filter=number eq 'C-10000'`, no second predicate) and only the query options the profile
  allows, so `$count`, `$search` and `$apply` are refused (`403 QUERY_PARAMETER_REFUSED`); a `+` in
  a checked read's query is refused, as platforms read it differently. An answer with another
  customer's record, or a key beside the list the profile does not name (`@odata.count`), is
  refused whole (`403 RESPONSE_SUBJECT_MISMATCH`, `RESPONSE_KEY_REFUSED`,
  `agentsafe-execution: WITHHELD`) and recorded, never filtered.
- `interception.refuseUnknownReads` is on by default with `subject` and a profile, and refuses
  what the profile cannot check: a read it does not name, a path beneath one (`/$count`), and a
  write no operation or route names, `$batch` included, whatever `unmatched` says. A gateway that
  holds the upstream credential and pins subjects refuses `false` at start.
- A write whose operation names a subject needs a session (`401 SUBJECT_SESSION_REQUIRED`), states
  the customer to the authority as the fact `session.subject`, and has its successful answer
  checked like a read's: `PATCH …/customers(<another's id>)` no longer relays that customer's record.
- Exchanging the same token again replaces its session, and a token whose key id the key set does
  not hold refreshes the set once, at most every 30 seconds (the executor's workload tokens too).
- Neither session header can be `interception.principalHeader`, whose value the authority
  receives; the configuration refuses it by name, as it refuses the tenant key.
- `agent-safe.profile.api/1` gains `subject` (`request`, `response`, `query`, `parameters`,
  `envelope`) and `GET` operations, additively, with vectors; `session` is a reserved fact name.
  `businesscentral/api/v2` scopes its customer, sales document and customer ledger entry reads,
  and the answers of `customers.update` and `salesOrders.create`.
- New wire values, additive: the state `REFUSED`, the execution `WITHHELD` (with `upstream_status`
  in the body), the header `agentsafe-subject: CHECKED`.
  [Subject-bound sessions](docs/gateway/subject-sessions.md).

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
