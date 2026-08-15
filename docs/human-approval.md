# Human approval

Presence receives an immutable presentation of action, target, and intent hash. The reference coordinator accepts only a terminal receipt dossier with a request ID. Decionis independently fetches and verifies that receipt, including signature/chain status and the exact displayed intent binding.

Presence is an evidence provider, not the execution authority. Client-side booleans, screenshots, copied proof strings, or model claims such as “the user approved” are never sufficient.

Transport failures, unknown verdicts, malformed or unbounded receipt identifiers, and independent
reauthorization failures produce stable fail-closed outcomes. Raw Presence or authority errors are
not returned through the coordinator.

If the intent changes or expires during approval, capture a new intent and start again.
