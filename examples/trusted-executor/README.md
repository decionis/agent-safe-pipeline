# Trusted executor: the proof and the template

The execution boundary as one process you deploy is `@decionis/agentsafe`
([`packages/agentsafe`](../../packages/agentsafe)). This directory is two things on top of it: the
offline proof that the process holds, and the template an adopter starts from.

```bash
pnpm --filter @decionis/agent-safe-example-trusted-executor demo
```

The demo is a self-checking proof against the loopback Decionis double from
`@decionis/agent-safe-pipeline/testing` and a loopback provider: it exits 0 only when every refusal
held, every legitimate path executed exactly once, a lost provider response was reconciled without a
second send, and no credential, token or key reached a response or an audit line.

## The template

Two files are the whole of an adopter's process:

- [`src/Handlers.ts`](./src/Handlers.ts) is the seam. It exports the handler registration the
  executor seals at startup; the reference registration from the package forwards the verified
  parameters to one configured downstream endpoint, and you replace it with the handlers for your
  own provider, keeping the shape the [package README](../../packages/agentsafe/README.md)
  describes: a strict parameter schema, the side effect inside `dispatch.run`, and a read-only
  `reconcile`.
- [`src/Serve.ts`](./src/Serve.ts) is the process: `serve(handlers)`, with the configuration read
  from the environment and mounted files, and a refusal to start that names any missing variable.

The wire contract, the configuration table, and the image are documented with the package; the
Kubernetes manifest and the runbook from shadow to enforcement are under [`deploy/`](../../deploy).

## What the proof runs

[`src/Index.ts`](./src/Index.ts) starts the loopback authority, Presence, and provider doubles, then
drives the executor over real HTTP through: refusals to start, shadow (nothing executes),
enforcement (one `ALLOW` is one dispatch), refusals at the door (trusted fields, unregistered
actions, anonymous and wrong tokens, oversized and malformed bodies, unknown routes), a lost
provider response reconciled without a second send, named principals (a proposer that executes and
is named on every evidence line, a token nobody holds, an action outside a principal's list, an
operator route refused to a proposer and answered for the operator, and one proposer's intent that
another may not reconcile), direct escalation, managed escalation, a verification of the executor's
own evidence chain (with one altered line reported at its sequence number), and a final assertion
that no caller token, principal token, downstream credential, authority key, or grant token
appears in any response, exposition, or audit line.

## What a green run is not

The proof runs against a loopback authority and a loopback provider with synthetic policy. It shows
the boundary holding in this process on this commit; it is not evidence that a hosted integration
exists, that any provider behaves this way, or that a deployment has the isolation the threat model
asks the host for.

## Hosted epilogue

`DECIONIS_HOSTED=1` (or `DECIONIS_API_KEY` with `DECIONIS_TENANT_ID`) runs the same executor
process once more after the proof, in shadow against Decionis: one proposal, observed and recorded,
nothing executed, no grant claimed, ending with the signed Decision Dossier it left and how to
verify it. With no key, the run mints a free provisional workspace and stores its key for the next
run; a provisional key evaluates in shadow only.
