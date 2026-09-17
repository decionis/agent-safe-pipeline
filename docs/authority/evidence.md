# Evidence

Every consequential request the gateway handles leaves two kinds of record: the Decision Dossier
Decionis keeps, and the chained lines the gateway writes.

## The Decision Dossier

Every evaluation is a dossier at the authority; the gateway carries its identifier on the
response (`agentsafe-dossier-id`), in the report (`Dossier`), and on every evidence line. A dossier
records why Decionis allowed, escalated or blocked: policy snapshot, inputs, evidence, grant
metadata, and, once finalized, the outcome. It is the record of the decision and never a
credential ([Decision Dossiers](../decision-dossiers.md)); with a Decionis key,
`pnpm decionis:verify <id>` in this repository, or `npx @decionis/verify` against the published
JWKS, checks its signatures offline.

## The gateway's chains

The gateway writes the library's audit events (`agent-safe.audit/1`, [audit events](../audit-events.md))
through the executor's chained sink: each line carries the event, the verdict, the reason codes,
the intent, decision, dossier and grant identifiers, the duration, and is linked by SHA-256 to the
line before it on the `agent-safe.executor-evidence/1` stream. Its own stream,
`agent-safe.gateway-events/1`, carries what the audit contract has no event for: the start, an
escalation held, an escalation refused on resume, and every ungoverned forward under fail open.
`agentsafe verify chain <file>` checks either stream offline and names the first break.

Where the lines go is the configuration's: `evidence.journalDir` keeps `evidence.jsonl` and the
chain heads a restart resumes from; JSON output puts them on standard output for a log pipeline;
on a terminal `--verbose` shows them.

## What is never in evidence

A request body, a response body, a request header, a credential, a grant token, a Presence
biometric, or a secret's digest. Evidence carries identifiers, digests of the intent and of the
body, verdicts, codes and durations; metric labels carry verdicts, codes and configured action
names; the key is read through a handle and redacted from every line by digest. The
[telemetry reference](../reference/telemetry.md) lists every metric and every milestone.
