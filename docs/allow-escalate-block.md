# ALLOW, ESCALATE, BLOCK

`ALLOW` is executable only when `should_execute` is true and a non-expired, intent-bound grant is present. A response that says ALLOW without those conditions fails closed.

`ESCALATE` stops execution and begins a Presence flow. After verified human evidence, Decionis evaluates the exact same intent again. Policy may still BLOCK it.

`BLOCK`, authority or Presence errors, transport failures, malformed responses, binding mismatches,
replay, and missing authorization all stop execution with stable reason codes.

Shadow mode is observational. Its observation never becomes an execution grant, never delays or
fails production, and is rejected by `SafeExecutor` with `DECISION_NOT_AUTHORITATIVE`. See
[shadow mode](./shadow-mode.md).
