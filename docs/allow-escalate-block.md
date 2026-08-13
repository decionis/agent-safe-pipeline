# ALLOW, ESCALATE, BLOCK

`ALLOW` is executable only when `should_execute` is true and a non-expired, intent-bound grant is present. A response that says ALLOW without those conditions fails closed.

`ESCALATE` stops execution and begins a Presence flow. After verified human evidence, Decionis evaluates the exact same intent again. Policy may still BLOCK it.

`BLOCK`, authority errors, transport failures, malformed responses, binding mismatches, replay, and missing authorization all stop execution.

Shadow mode is observational. Its hypothetical decision never becomes an execution grant.
