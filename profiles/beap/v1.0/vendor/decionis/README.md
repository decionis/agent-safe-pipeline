# Vendored Decionis protocol schemas

`policy-bundle.schema.json` is a verbatim copy of the Decionis Protocol v1 policy-bundle JSON Schema (draft 2020-12). BEAP domain policy packs conform to it; the BEAP reference policy evaluator implements the subset described in the specification (section 12). The file is not edited here.

`policy-bundle.schema.json.sha256` records the SHA-256 of the vendored bytes. `node scripts/CheckVendoredSchemas.mjs` fails when the file and its recorded digest disagree, so a drift between the copy and the digest is caught in CI. Refresh both files together from the Decionis repository when the protocol publishes a new revision, and note the change in `spec/CHANGELOG.md`.

The schema's `$id` names a host that does not currently resolve; consumers should treat the vendored file, not the `$id`, as the source of truth.
