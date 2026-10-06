# Dependency audit disposition: 6 October 2026

The deployment-documentation verification run found newly published advisories after the previous
day's clean audit. No production or third-party endpoint was tested.

## Fixed: proxy address trust bypass

[GHSA-jqcg-44mw-7w3h](https://github.com/advisories/GHSA-jqcg-44mw-7w3h) rates the
`proxy-addr` IPv4-mapped IPv6 trust-subnet bypass critical. The affected version, 2.0.7, was
reached through the MCP example's SDK and Express dependency. An IPv6 trust range such as
`::ffff:10.0.0.0/8` could incorrectly trust an arbitrary IPv4 peer and accept its forged
`X-Forwarded-For` address.

The workspace now overrides `proxy-addr` to patched version 2.0.8. The lockfile changes only that
resolution and its override. The regression in
[ProxyAddressSecurity.test.mjs](../../test/automation/ProxyAddressSecurity.test.mjs) failed against
2.0.7 and passes against 2.0.8. Positive cases retain correctly configured IPv4, mapped IPv4 and
native IPv6 proxy behavior. This is a dependency-level reproduction; it does not establish that
the example configures the vulnerable trust range in production.

## Retained: development-only KaTeX advisory

[GHSA-238p-pmpm-9mq7](https://github.com/advisories/GHSA-238p-pmpm-9mq7) rates KaTeX's
read-side prototype-pollution gadget low. Version 0.16.47 is present through the root development
dependency `markdownlint` 0.41.1 and `micromark-extension-math` 3.1.0. It is absent from the
production audit.

The advisory requires pre-existing prototype pollution or attacker control of the renderer
options prototype. Its XSS/resource-loading scenario additionally requires inserting generated
HTML into a web page. The repository invokes markdownlint as a CLI linter; markdownlint uses
the math syntax extension to produce tokens, not the `mathHtml` renderer. No affected HTML
rendering path was identified in that use.

Disposition: retain this development dependency pending a compatible markdownlint/math-extension
upgrade. The upstream dependency declares KaTeX `^0.16.0`; the fix is 0.18.2, outside that range,
so this change does not force an unvalidated cross-minor override. Reassess before using this
dependency chain to render untrusted math in a browser or when its upstream range is updated.
The advisory is not suppressed or dismissed.

## Validation

- `pnpm install --frozen-lockfile` passed with the minimal updated lockfile.
- All three proxy-address regression tests passed; the attack case failed before the upgrade.
- `pnpm security:production` reported no known vulnerabilities.
- `pnpm security:toolchain` passed its moderate-severity gate, reporting the one low advisory above.
- `pnpm verify` passed, including 170 automation tests and the existing runtime, contract and
  performance suites. Sixteen opt-in integration tests remained skipped.
