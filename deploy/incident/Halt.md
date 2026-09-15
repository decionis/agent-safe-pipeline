# The stop, as commands

The copy on-call keeps open. Everything here is also in
[`docs/incident-response.md`](../../docs/incident-response.md), which says _why_; this file is the
_what_, so nobody is reading prose at three in the morning.

Replace `agent-safe-executor` with your namespace if you changed it.

## Stop it now

The way that works whether or not the listener answers:

```bash
kubectl -n agent-safe-executor create configmap agent-safe-executor-halt \
  --from-literal=halted="describe the incident here"
```

Every replica halts within seconds. Work in flight finishes and is journaled; nothing new starts.

Through the front door instead, as an operator holding the `halt` scope:

```bash
curl -sS --cert ops.crt --key ops.key -X POST \
  https://agent-safe-executor.agent-safe-executor.svc.cluster.example:8443/v1/control/halt \
  -H 'content-type: application/json' -d '{"reason":"describe the incident here"}'
```

## See where it stands

```bash
kubectl -n agent-safe-executor logs statefulset/agent-safe-executor --tail=200
```

```bash
curl -sS --cert ops.crt --key ops.key \
  https://agent-safe-executor.agent-safe-executor.svc.cluster.example:8443/v1/control/status
```

```bash
curl -sS --cert ops.crt --key ops.key \
  https://agent-safe-executor.agent-safe-executor.svc.cluster.example:8443/v1/control/open-attempts
```

Anything in `open-attempts` is a provider you have not yet asked. Resolve those first.

## Take the evidence

```bash
curl -sS --cert ops.crt --key ops.key -X POST \
  https://agent-safe-executor.agent-safe-executor.svc.cluster.example:8443/v1/control/evidence-export \
  -H 'content-type: application/json' -d '{"reason":"on-call took a bundle"}'
```

Copy the directory it names off the volume, then verify it where you will read it:

```bash
agentsafe verify-bundle ./2026-03-02T10-00-00-000Z
```

`ORIGIN_AND_CONSISTENCY` needs your own public key in `AGENTSAFE_EVIDENCE_PUBLIC_KEY`. Without one
the answer is `INTERNAL_CONSISTENCY`: the bundle is the bundle that was made, and nothing says who
made it.

## Rotate a credential

Replace the file in the Secret, then make it immediate rather than waiting for the watch:

```bash
curl -sS --cert ops.crt --key ops.key -X POST \
  https://agent-safe-executor.agent-safe-executor.svc.cluster.example:8443/v1/control/secrets/reload
```

Confirm the old value no longer authenticates from the caller's side, not from the logs.

## Start again

Refused while the cause still stands, which is the check working:

```bash
kubectl -n agent-safe-executor delete configmap agent-safe-executor-halt
```

```bash
curl -sS --cert ops.crt --key ops.key -X POST \
  https://agent-safe-executor.agent-safe-executor.svc.cluster.example:8443/v1/control/resume \
  -H 'content-type: application/json' -d '{"reason":"cause removed: ..."}'
```

Before you do: zero unknown attempts, posture not degraded, the cause actually gone, a reason
worth reading later, and a bundle already taken. The full list is the resume checklist in
[`docs/incident-response.md`](../../docs/incident-response.md#the-resume-checklist).

## Never

- Never re-send a dispatch whose outcome is unknown. Ask the provider; a retry is how one payment
  becomes two.
- Never set `EXECUTOR_POSTURE=DEVELOPMENT` to get a pod running. It waives the checks that are
  telling you what is wrong.
- Never point the authority URL at the fixture authority to keep working.
- Never edit or backfill audit lines to make a chain verify.
