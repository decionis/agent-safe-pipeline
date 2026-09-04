# Synthetic Decision Dossier conformance corpus

This directory is the public, offline conformance corpus for Decionis Decision Dossier proof
bundles. It follows the same pattern as [`conformance/vectors/`](../conformance/vectors/): every
vector publishes the input document, exact canonical JSON bytes, SHA-256 digest, detached Ed25519
signature, and expected verifier result.

The corpus contains synthetic `ALLOW`, `BLOCK`, and `ESCALATE` dossiers. Each dossier carries a
portable JSON artifact and a JSON-LD artifact under a version `2.0` proof bundle. The automated test
discovers every file in [`vectors/`](./vectors/) and verifies it with the separately published
`@decionis/verify` package.

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

The command must print `VERIFIED` and exit `0`. `pnpm dossiers:check` independently regenerates the
public JWKS, canonical bytes, digests, and signatures in memory and requires them to match the
committed files byte for byte.

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
npx -y @decionis/verify@0.1.0 \
  --file /absolute/path/to/live-decision-dossier.json \
  --jwks https://api.decionis.com/v1/.well-known/decision-dossier-jwks.json
```

Exit `0` and `VERIFIED` establish that the signed artifacts match a key in the live JWKS. A missing
key, changed artifact, digest mismatch, malformed proof bundle, or invalid signature must exit
nonzero. This live check is deliberately documented rather than put in CI: committing a production
dossier would violate the fixture policy, and a network-dependent check would not be a reproducible
repository gate.
