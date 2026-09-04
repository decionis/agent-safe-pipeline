# Release tag signing

AgentSafe release tags are annotated Git tags signed keylessly by
[gitsign](https://github.com/sigstore/gitsign). The deploy workflow exchanges its
short-lived GitHub Actions OIDC token for a Fulcio signing certificate and records
the signature in Rekor. No long-lived private signing key is stored in GitHub.

This policy applies to tags created after this control is merged. Earlier tags,
including the existing release candidates, remain legacy unsigned or lightweight
tags and are not retroactively changed.

## Trust policy

The accepted signer is deliberately narrow:

- certificate identity:
  `https://github.com/decionis/agent-safe-pipeline/.github/workflows/deploy.yml@refs/heads/master`
- certificate issuer: `https://token.actions.githubusercontent.com`
- target: the exact commit selected by the release workflow from `master`

The release job has only the permissions needed for publication: `contents: write`
to push the tag and create the release, `id-token: write` for the ephemeral signing
certificate, and `attestations: write` for release artifact attestations. Checkout
credentials are not persisted. The workflow installs a fixed gitsign release and
verifies its published SHA-256 checksum before use.

The workflow signs and locally verifies the tag before it builds release assets.
It pushes that exact tag immediately before creating the GitHub release, and
`gh release create --verify-tag` refuses to create a replacement tag.

## Verify a release tag

Install gitsign using the instructions for your platform, then run:

```bash
tag=vX.Y.Z
git fetch origin "refs/tags/$tag:refs/tags/$tag"
gitsign verify-tag \
  --certificate-identity "https://github.com/decionis/agent-safe-pipeline/.github/workflows/deploy.yml@refs/heads/master" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$tag"
git show --no-patch --format=fuller "$tag"
git rev-parse "$tag^{commit}"
```

The final command prints the commit the signed tag protects. Confirm it matches
the target commit shown by the corresponding GitHub release before using the
attached tarball or SBOM. A valid cryptographic signature with a different
identity, issuer, or target does not satisfy this policy.

## Maintainer signing and rotation

Release tags are created only by `.github/workflows/deploy.yml` on a push to
`master`; maintainers do not manually create release tags. A dry run exercises
the release build without requesting a signing identity or creating a tag.

There is no private key to rotate. The workflow path, repository, branch, GitHub
Actions issuer, pinned gitsign version, and checksum form the maintained trust
configuration. If any identity component changes, update the workflow verification
arguments and this document in the same reviewed pull request. Existing signatures
continue to verify against the identity that signed them. A gitsign upgrade must
pin a specific release and checksum and pass the workflow policy tests before it
is merged.
