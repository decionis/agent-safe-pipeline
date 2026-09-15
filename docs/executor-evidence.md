# Executor evidence streams

`@decionis/agentsafe` writes two streams of evidence, each a hash chain of JSON lines: the
evidence stream on standard output and the security stream on standard error. The chain lets
anyone holding the lines, and nothing else, detect a line that was altered, removed, or reordered.
It does not prove who wrote the lines; that is what a signature over an export is for, and it is
not part of this contract.

## The envelope

Every chained line has the same envelope around its fields:

| Field       | Meaning                                                                                     |
| ----------- | ------------------------------------------------------------------------------------------- |
| `stream`    | `agent-safe.executor-evidence/1` or `agent-safe.security/1`                                 |
| `seq`       | The line's position in its stream, from 1                                                   |
| `prev_hash` | The `hash` of the line before it; `sha256:` followed by sixty-four zeros for the first line |
| `hash`      | `sha256:` and the hex SHA-256 of the canonical JSON of every field but `hash`               |

Canonical JSON is the same form the intent hash uses: object keys sorted, recursively, with
ECMAScript number and string serialisation and no whitespace. The envelope wins over a field of
the same name, so nothing a line says can move it in its chain. Lines the process writes about
itself at start, `POSTURE_VERIFIED` and `LISTENING`, carry no `stream` and belong to no chain.

## The evidence stream

`agent-safe.executor-evidence/1` is the executor's envelope around the pipeline's audit contract,
[`agent-safe.audit/1`](./audit-events.md), which is unchanged. Each line carries the recorder's
identifiers, digests, verdict, reason codes and duration, and one field of the executor's own:
`caller_principal`, the principal the request was made as (`legacy-caller` without a principals
file), or `null` for a line written outside any request. Parameters, targets, bodies, headers and credentials have no place in it.

```json
{
  "stream": "agent-safe.executor-evidence/1",
  "seq": 7,
  "prev_hash": "sha256:4b1e…",
  "at": "2026-09-15T10:04:12.311Z",
  "event": "EXECUTION_COMPLETED",
  "authority": "AUTHORITATIVE",
  "verdict": "ALLOW",
  "reason_codes": [],
  "intent_id": "…",
  "intent_hash": "sha256:…",
  "correlation_id": "synthetic-run-3",
  "decision_id": "…",
  "dossier_id": "…",
  "grant_id": "…",
  "duration_ms": 41,
  "caller_principal": "legacy-caller",
  "hash": "sha256:9c07…"
}
```

## The security stream

`agent-safe.security/1` carries what happened to the process rather than to an intent: posture
verified, waived, drifted and restored; a secret rotated or a reload refused; the credential
clients rebuilt; a redaction (`LEAK_SUSPECTED`); a refusal at the door (`AUTH_FAILED` with the
method, `bearer`, `jwt`, `mtls` or `none`, and the code); a principal locked after repeated proven
failures (`PRINCIPAL_LOCKED`); the principals loaded at start, or the legacy caller mode
(`PRINCIPALS_LOADED`, `LEGACY_PRINCIPAL_MODE`, `BEARER_PRINCIPAL_CONFIGURED`); the JWKS refreshed
or not (`JWKS_REFRESHED`, `JWKS_REFRESH_FAILED`); an operator's action (`OPERATOR_ACTION` with the
principal and the action); an outbound request the egress policy refused (`EGRESS_REFUSED` with
the origin and the code); the listener's TLS context replaced; and the chain's own bookkeeping
(`CHAIN_RESUMED`, `CHAIN_CHECKPOINT`). Every field is an identifier, a code, an origin, or a
count, checked against a schema before the line is written; an event that does not fit is dropped
and counted rather than written incomplete.

## Verifying a chain

```bash
agentsafe verify-chain executor.log
```

reads a file (or standard input) and walks every stream in it, reporting one finding per break:

| Code                  | What it means                                                            |
| --------------------- | ------------------------------------------------------------------------ |
| `CHAIN_LINE_INVALID`  | Not JSON, or a line with a `stream` whose envelope is malformed          |
| `CHAIN_HASH_MISMATCH` | The line's fields no longer produce its `hash`: the line was altered     |
| `CHAIN_SEQ_GAP`       | The sequence skipped or rewound: a line is missing, or the order changed |
| `CHAIN_PREV_MISMATCH` | The sequence fits but `prev_hash` is not the previous line's hash        |

The report also says how many lines belong to no chain, and for each stream how many lines it
saw, the head it ended on, and how many times the stream started from genesis. The command exits
0 only when there is no finding. The same walk is available as `verifyAuditChain(lines)` from the
package.

## Restarts and checkpoints

A chain is per process. With `EXECUTOR_JOURNAL_DIR` set, the executor persists each stream's head
under `<dir>/chain/` every `EXECUTOR_AUDIT_CHECKPOINT_LINES` lines (one hundred by default) and
once more on a clean shutdown, and the next process continues the sequence from that head,
recording `CHAIN_RESUMED` with it. Without a journal directory, or when the head is not usable,
the stream starts again from genesis and the verifier counts a start.

A process that dies between two checkpoints resumes from the older head, and the verifier reports
the overlap as `CHAIN_SEQ_GAP` at the point of the crash. That is deliberate: a crash leaves a
visible mark rather than a seamless chain. The log pipeline that keeps the lines is the durable
store; the checkpoint keeps the sequence honest across restarts, no more.

## What this is not

The chain is unkeyed. Anyone who can rewrite the whole log can rewrite the whole chain, and a
verifier cannot tell a log truncated and re-chained from genesis from a process that restarted.
Compare the start count with the process's restarts, keep the lines somewhere the process cannot
write, and treat the chain as an integrity and continuity check over what was kept, not as proof
of origin.
