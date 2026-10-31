# Target state

A grant authorizes one exact intent. Revalidation at the claim then catches a policy, a signal or an
approval that changed between the grant and the commit. Neither catches a target that changed
underneath an unchanged policy: someone else's write to the same firewall rule, the same customer
record, the same deployment, landing after the decision and before the write. The decision was
right about a state that no longer exists.

The target's state version closes that, in four places.

## 1. The runtime reads the target

An executor that can read the target before it writes says so: `NativeExecutor.readState`, an
optional operation of [`agent-safe.executors.native/1`](../../spec/executors/native/v1/README.md).
`GovernedExecutionRunner.submit` calls it once, after `prepare` and before the authority is asked.
It is the only I/O before a decision, it is read-only, and a read that fails refuses the submission
(`TARGET_STATE_UNREADABLE`): nothing is decided without the version the executor said it would
bind.

An [API profile](../../spec/profiles/api/v1/README.md) names the read as data. A write operation's
`precondition` names a read in the same profile and where its answer states the version (an
`ETag` header, an `@odata.etag`, a resource version) and, optionally, the target's state:

```json
"precondition": { "read": "customers.get", "version": "/body/@odata.etag", "state": "/body/blocked" }
```

`ApiProfile.stateRead` turns the write's call into the read's (the same placeholders, written as the
call wrote them), and `ApiProfile.precondition` turns the read's answer into the precondition. The
Business Central profile's `customers.update` declares one: its version is the `@odata.etag`
Business Central requires back as `If-Match`, and its state is `blocked`.

The gateway makes the same read, in enforcement, for every write whose profile operation names
one: a `GET` it makes as itself, with its own upstream credential and gateway token and none of the
caller's headers, before the authority is asked. An answer that is not `2xx`, or states no usable
version, refuses the write (`TARGET_STATE_UNREADABLE`), as a read that fails refuses an executor's
submission. It sends the bound version on the forwarded write as
`x-agent-safe-expected-state-version`, the header a verifying hop sets, and reads the same target
again after the write and after a refusal
([the target a write names](../gateway/http-interception.md#the-target-a-write-names)).

## 2. The intent binds what was read

The runner hands the read to the capture as the trusted context's `precondition`, and the capture
stamps it into the hashed context under the reserved key `agent_safe`:

```json
"context": {
  "agent_safe": {
    "precondition": {
      "version": "W/\"JzE5Oyc=\"",
      "state": " ",
      "source": "businesscentral/api/v2#customers.get",
      "read_at": "2026-10-23T12:00:00.000Z"
    }
  }
}
```

The agent never supplies it: a proposal cannot reach `context`, and a trusted context that sets
`agent_safe` by hand is refused (`INTENT_CONTEXT_KEY_RESERVED`). An intent without a precondition
carries no `agent_safe` key at all and hashes exactly as before, so every published vector holds
(`conformance/vectors/target-precondition.json` pins one that carries it).

## 3. Policy decides on it

Decionis reads the precondition into the facts policy sees, as `agent_safe.precondition`. A bundle's
`allowed_transitions` states which states a decision type's target may move between, from the
state the runtime read to the one the action asks for, and refuses any other move
(`transition_not_allowed`, REJECT) before any rule is matched. It generalises the commerce lifecycle
check to any action. A state the request does not name, or the same state, is no transition; a
precondition that should be there and is not fails safe to ESCALATE.

## 4. The provider holds the write to it

The grant binds the version as `binding.expected_state_version`, and the claim's attestation
carries it to the provider. A [verifying provider](./verifying-provider.md) effects only while the
target is still at exactly that version, atomically with the effect, and otherwise refuses with
`TARGET_STATE_CHANGED` (step 9). The executor reads that `4xx` as `DEFINITELY_NOT_EXECUTED`, and
finalizes `FAILED`. A dispatch-style executor whose platform takes a conditional write, but verifies
nothing, sends the version as the write's own precondition (`If-Match`) itself, from
`preconditionOf(run.intent.intent.context)`.

## What it does not do

- It does not lock the target. Between the read and the commit the target may change; what the
  version guarantees is that such a change refuses the write rather than lets it land.
- It does not make a provider that ignores the version check it. A system of record that neither
  verifies at VP-2 nor honours a conditional write takes the write whatever its state.
- It does not read in shadow: a shadow gateway asks the authority without the target's version.
- `LocalAuthority` carries the version into its attestations as Decionis does, and refuses a
  malformed precondition (`INTENT_PRECONDITION_INVALID`), but it does not evaluate
  `allowed_transitions`: its policy is the hook a test gives it.

`packages/agentsafe/test/verify/TargetStateVersion.test.ts` runs the whole path over a real authority
stack: a read binds `"17"`, the provider effects; someone else's write moves the target to `"18"`
after the decision, and the provider refuses with `TARGET_STATE_CHANGED`, effecting nothing; a move
the policy does not allow from the state read is refused before anything is claimed.
