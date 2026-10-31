# Acceptance demo: `agentsafe accept` against a gateway on loopback

The build's other proofs prove the runtime. An [acceptance run](../../docs/deployment/acceptance.md)
proves where it was put, and this demo proves the tool that makes one. It runs offline in a few
seconds with no credentials, and exits 0 only when every expectation holds.

```bash
pnpm --filter @decionis/agent-safe-example-acceptance demo
```

## What runs

- A real gateway, built from a real configuration with an acceptance key and an operator token, in
  front of a loopback system of record shaped like Business Central, and decided by the loopback
  Decionis double.
- The real `agentsafe` binary, as a child process the way an operator runs it: `accept`, then
  `identity --json` for the key, then `verify acceptance --current`.
- The target is the observer: every count is what reached it.

## What it checks

The run is played twice against the same gateway.

1. With no origin in the plan, the gateway signs `ACCEPTED`:
   - the permitted write reaches the target once and is read back as asked (`CONFIRMED`);
   - the prohibited write is refused in shadow, then in enforcement, and its canary is read
     `UNCHANGED`;
   - with the authority unreachable, a second gateway built from the same configuration refuses
     every write and sends nothing on;
   - the key `identity` prints verifies the report, current against the running gateway.
2. With the target's own address as an origin, the gateway signs `NOT_ACCEPTED` and names it: on
   loopback the agent's zone reaches the API directly, which is a hole a run must report.

A customer's run proves that customer's deployment and nothing else. This one proves the tool. All
identities and records are synthetic.
