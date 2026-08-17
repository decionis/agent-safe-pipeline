# Reproducible Package Builds

The npm package must be byte-for-byte reproducible from the same Git commit when the Node.js
version, pnpm version, and `pnpm-lock.yaml` are held constant.

The `Reproducible package build` workflow checks out the triggering commit twice into independent
directories, installs each tree with lifecycle scripts disabled, builds both packages with Node.js
24.18.0 and pnpm 9.15.3, and runs `pnpm pack` separately. The comparison fails unless all of the
following match:

- npm tarball byte size and SHA-256 digest;
- SHA-256 digest of the uncompressed tar payload; and
- ordered tar member names, types, sizes, and their manifest digest.

The workflow retains both tarballs and `reproducibility-report.json` for 14 days, including on a
comparison failure. That report distinguishes gzip-container drift from archive-content drift.

## Controlled inputs

Package contents come only from the manifest `files` allowlist and the TypeScript build. Dependency
resolution is frozen by the committed lockfile. The workflow pins its runner actions by commit and
uses the same Node.js and pnpm releases in both trees. `npm pack` normalizes the generated archive;
the repository does not inject wall-clock timestamps, host paths, user IDs, or generated randomness
into the package.

No nondeterministic field is currently accepted. If a future toolchain introduces unavoidable
metadata, the comparison must continue to report both compressed and uncompressed digests, the
field must be documented here, and a narrowly reviewed normalization must happen before hashing.
Disabling the byte-for-byte gate is not an acceptable workaround.

For a local comparison, build two clean checkouts and run:

```sh
pnpm reproducible:compare \
  /path/to/first/decionis-agent-safe-pipeline-<version>.tgz \
  /path/to/second/decionis-agent-safe-pipeline-<version>.tgz \
  /tmp/reproducibility-report.json
```
