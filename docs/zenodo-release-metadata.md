# Zenodo release metadata

The repository treats [`CITATION.cff`](../CITATION.cff) as the authoritative
release-description source used by GitHub and the GitHub–Zenodo integration.
[`metadata/zenodo-release.json`](../metadata/zenodo-release.json) is a small,
versioned automation contract for stable identity and archive expectations. It
does not duplicate the title, abstract, release date, version, or keywords in
the citation file.

The contract deliberately stores creator names as separate family and given
components. Automation derives Zenodo's `Family, Given` display form and checks
the ORCID checksum and exact affiliation. This prevents a syntactically valid
but inverted creator name from splitting the publication identity.

Do not add `.zenodo.json` while `CITATION.cff` is authoritative. Zenodo gives
`.zenodo.json` precedence when both files exist, which would create two mutable
metadata sources.

## Before a release

Update all of the following in the same reviewed change:

1. the workspace and published-package versions;
2. `CITATION.cff` `version` and `date-released`; and
3. any intentional title, abstract, keyword, or creator change.

Run `pnpm metadata:check`. The normal `precommit` and `verify` commands run the
same check. It rejects version drift, creator-name inversion, missing or invalid
ORCIDs, affiliation drift, repository mismatch, malformed release dates, and a
competing `.zenodo.json` file.

Publication remains a human-approved action. The preflight validates intended
metadata; it does not enable a Zenodo hook, publish a GitHub release, create a
DOI, or edit a published record.

## After a release

Publishing a stable GitHub release starts the read-only `Verify Zenodo release`
workflow. Zenodo deposits are asynchronous, so the workflow uses a bounded
five-minute retry window. It verifies that:

- the public record is the requested version under concept DOI
  `10.5281/zenodo.22312955`;
- title, description, creators, ORCIDs, affiliation, keywords, repository,
  version, release date, access, and resource type match the committed sources;
- the record links to the exact GitHub release tag; and
- both the version DOI and concept DOI resolve to Zenodo over HTTPS.

On success, the workflow retains a machine-readable evidence file containing
the record ID, both DOIs, creator identity, Zenodo publication date, release
URL, verification time, and a digest of the checked metadata. It never changes
Zenodo metadata. A mismatch requires maintainer review and, when appropriate, a
human-approved metadata edit in Zenodo.

The workflow can be rerun manually for the version represented by the selected
workflow ref. For an older release, select that release tag so its committed
`CITATION.cff` and automation contract are used rather than current metadata.

## DOI and date semantics

The concept DOI identifies the release family and resolves to its latest
version. Each archived release receives a distinct version DOI. Fixed citations
should use the version DOI and the `publication_date` reported by that Zenodo
record. They should not infer the publication date from a package tag or local
clock.

When adapting this contract to another repository, change the repository,
package, creator list, and concept DOI. A new archive has no concept DOI until
its first human-approved deposit; add the minted concept DOI to the contract
before enabling post-release verification.
