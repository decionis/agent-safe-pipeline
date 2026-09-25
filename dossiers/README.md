# Synthetic Decision Dossier conformance corpus

This directory is the public, offline conformance corpus for Decionis Decision Dossier proof
bundles. It follows the same pattern as [`conformance/vectors/`](../conformance/vectors/): every
vector publishes the input document, exact canonical JSON bytes, SHA-256 digest, detached Ed25519
signature, and expected verifier result.

The corpus contains synthetic `ALLOW`, `BLOCK`, and `ESCALATE` dossiers in the shape the Decionis
authority issues under Protocol 1.1. Every vector signs its portable JSON, inputs snapshot, and
JSON-LD artifacts, and the signed portable artifact carries the verdict, the immutable policy
reference, the evaluator semantics, and a commitment to the inputs snapshot, so a verifier can check
both the signatures and that the record is complete enough to reproduce. Every `ALLOW` is
execution-eligible and also signs a version `2.1` execution binding with RFC 8785/JCS; `BLOCK` and
`ESCALATE` are not eligible and carry none. The automated test discovers every file in
[`vectors/`](./vectors/) and verifies it with the separately published `@decionis/verify` package.

The proof bundles declare the rotation policy production dossiers carry (`JWKS_OVERLAP`, with the
well-known JWKS path). The synthetic key is not served from that path, so pass
[`corpus-jwks.json`](./corpus-jwks.json) to a verifier explicitly, as the commands below do.

## Deliberately public signing key

[`synthetic-corpus-private.jwk.json`](./synthetic-corpus-private.jwk.json) is a private Ed25519 JWK
published deliberately. It is not a credential or a Decionis production key. Anyone can sign new
documents with it, which is precisely why a corpus signature makes no production-authenticity
claim. Its reserved key ID is `agent-safe-synthetic-dossier-corpus-v1`, and the matching public key
is [`corpus-jwks.json`](./corpus-jwks.json).

Never load this key into an application, authority service, or production verifier. It is outside
the published Decionis production JWKS and exists only so reviewers can regenerate every byte and
signature instead of trusting precomputed fixtures.

All artifacts here are synthetic: they are not exports, samples, or transformations of customer,
production, support, or incident data. Do not add a real dossier to this directory, even after
redaction.

## Verify the committed corpus

Install the locked workspace and verify any vector offline:

```bash
pnpm install --frozen-lockfile
pnpm exec decionis-verify \
  --file dossiers/vectors/allow.json \
  --jwks dossiers/corpus-jwks.json
```

The command must print `CRYPTOGRAPHICALLY VERIFIED` and `REPRODUCTION_READY`, and exit `0`.
`pnpm dossiers:check` independently regenerates the
public JWKS, canonical bytes, digests, and signatures in memory and requires them to match the
committed files byte for byte.

`allow`, `block`, and `escalate` deliberately omit issuer context and must report `Issuer not
stated`. [`owned-execution-bound.json`](./vectors/owned-execution-bound.json) and
[`runtime-signals.json`](./vectors/runtime-signals.json) place `issuer_context.tier: "owned"` inside
the signed portable artifact; the verifier must report a `Claimed owned workspace` whose claim is
signature-covered. It stays a claim because a key the caller selects cannot establish who issued a
dossier. Mutating that tier invalidates the proof and removes signature coverage.

To intentionally rebuild the corpus after reviewing a format change:

```bash
pnpm dossiers:regenerate
pnpm dossiers:check
pnpm test
```

`pnpm fixture:check` discovers every tracked JSON file under `dossiers/` and requires an exact entry
in [`fixtures/manifest.json`](../fixtures/manifest.json). Unlisted files and non-synthetic fixture
identities fail the repository build.

## Verify a production dossier

The synthetic corpus proves verifier behavior; it does not prove that a production dossier verifies.
That claim requires a real dossier and the live Decionis JWKS. Run the following locally against a
dossier obtained through an authorized Decionis route, and do not commit the dossier or its contents:

```bash
npx -y @decionis/verify@0.4.0 \
  --file /absolute/path/to/live-decision-dossier.json \
  --jwks https://api.decionis.com/v1/.well-known/decision-dossier-jwks.json
```

Exit `0` and `VERIFIED` establish that the signed artifacts match a key in the live JWKS. A missing
key, changed artifact, digest mismatch, malformed proof bundle, or invalid signature must exit
nonzero. This live check is deliberately documented rather than put in CI: committing a production
dossier would violate the fixture policy, and a network-dependent check would not be a reproducible
repository gate.

## Changes

- **2026-09-25:** regenerated in the Protocol 1.1 shape with the production rotation policy. The
  earlier corpus declared a `STATIC_PUBLIC_CORPUS_KEY` rotation policy and Protocol 1.0 metadata,
  which `@decionis/verify` has rejected since 0.3.0 (Protocol 1.1); the repository pinned 0.2.0, so
  its own test never saw it. Every `ALLOW` now carries an execution binding, and the repository pins
  `@decionis/verify` 0.4.0. Releases archived before this change keep the earlier files.
