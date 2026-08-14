# Decision Dossiers

A Decision Dossier records why Decionis allowed, escalated, or blocked an intent and links policy, evidence, and execution-grant metadata. Use its identifier for audit and support correlation.

Do not treat a dossier URL or identifier as an execution credential. Only the signed, short-lived, single-use grant can authorize `SafeExecutor`, and the trusted verifier must consume it atomically.

Avoid putting secrets or raw provider payloads in intent context. Prefer opaque references or precomputed hashes where policy does not need the plaintext.
