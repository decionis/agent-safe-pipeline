# Failure policy

What the gateway does with a consequential request when the authority cannot be asked is a
setting, and it is explicit.

```yaml
authority:
  failurePolicy: failClosed # the default
```

## Fail closed

The request is not forwarded. The caller receives `503 Service Unavailable` with
`state: AUTHORITY_UNAVAILABLE`, the reason code the client saw (`AUTHORITY_UNAVAILABLE`,
`AUTHORITY_REQUEST_FAILED`, `AUTHORITY_RESPONSE_TOO_LARGE`, `AUTHORITY_BINDING_MISMATCH`, and so
on), `execution: NOT_FORWARDED`, and `Retry-After: 5`. The terminal shows the state under its own
heading; it is not a `BLOCK`, and neither the response, the report, the evidence nor the metrics
(`agentsafe_authority_errors_total{code=...}`) present it as one. The evidence chain carries an
`EXECUTION_BLOCKED` line with `AUTHORITY_FAILED_CLOSED` before it, the same shape the executor
records.

This is the recommended mode for every consequential action, and the only mode in which the
gateway's presence in front of a service is a guarantee about what reached it.

## Fail open

```yaml
authority:
  failurePolicy: failOpen
```

Only where an operator writes that down, an unreachable authority lets the request through. The
request is forwarded exactly as a passthrough would be, and every surface says what happened:

- the response carries `agentsafe-state: AUTHORITY_UNAVAILABLE` and `agentsafe-execution:
FORWARDED_UNGOVERNED`;
- the report shows `AUTHORITY UNAVAILABLE` with `Execution FORWARDED (fail-open, ungoverned)`;
- the gateway's evidence stream gains an `EXECUTION_UNGOVERNED` line with the intent id and hash
  and the reason codes, chained like every other line;
- `agentsafe_ungoverned_forwards_total` counts it.

Fail open is a decision about availability that a deployment makes for a specific service; it is
never a default, never inferred, and never chosen by the gateway on its own. A gateway that has
forwarded ungoverned traffic has evidence of every such request, which is the least an incident
review will want.

## What is not a failure

A `BLOCK` is the authority's answer, and so is an `ESCALATE`; neither is a failure. A grant the
verifier could not claim (`AUTHORIZATION_INVALID`), a handler that stopped before sending, an
upstream that answered `5xx` or not at all: each has its own state (`ERROR`, `EXECUTION_FAILED`,
`EXECUTION_INDETERMINATE`) and its own finalization with the authority, and none of them is
collapsed into a policy verdict. The states are listed in
[HTTP interception](./http-interception.md#responses-the-gateway-makes-itself).
