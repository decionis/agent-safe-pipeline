# Maintenance and version support

This policy describes the support offered for Agent-Safe Pipeline releases. It is a maintenance
commitment for this public reference implementation, not a service-level agreement for the
Decionis hosted service.

## Supported release lines

| Release line                   | Status          | Support                                                                  |
| ------------------------------ | --------------- | ------------------------------------------------------------------------ |
| Latest published `0.x` release | Supported       | Security fixes and corrections for trust-boundary defects                |
| Older `0.x` releases           | End of life     | No routine fixes; upgrade to the latest release                          |
| Prereleases such as `-rc.N`    | Evaluation only | May be replaced without a backport; not supported for production use     |
| Unreleased `master`            | Development     | Receives changes through reviewed pull requests; not a supported release |

Until `1.0.0`, only the latest published `0.x` release is supported. A security fix normally ships
as a new patch release on that line. If a vulnerability cannot be fixed without changing the
documented trust boundary or public API, maintainers publish migration guidance and choose the
smallest responsible semantic-version increment. Older versions become end of life when the
replacement release is published unless a security advisory states a short, explicit overlap
period.

End-of-life versions remain available as historical artifacts, but their presence does not imply
support. Security reports concerning an end-of-life version are assessed against the latest
supported release; reporters may be asked to reproduce the issue there.

## Change and documentation policy

Every release change must update both workspace and package versions and pass the release checks in
[CONTRIBUTING.md](./CONTRIBUTING.md). The same pull request must update documentation when it
changes any of the following:

- the proposal, authorization, approval, grant-consumption, or execution trust boundary;
- public exports, wire contracts, runtime requirements, or supported configurations;
- failure behavior, security assumptions, accepted risks, or operator responsibilities; or
- release, verification, maintenance, or end-of-life procedures.

Reviewers compare affected code with `README.md`, `ARCHITECTURE.md`, `THREAT-MODEL.md`,
`SECURITY.md`, package documentation, and the public evidence map. A release must not claim a
planned feature as available. Released capabilities are linked to immutable tags or release
artifacts; future work remains labeled committed or exploratory in [ROADMAP.md](./ROADMAP.md).

This policy is reviewed before each stable release and whenever the trust boundary, runtime floor,
or release process changes. Material policy changes are announced in release notes and take effect
when merged unless a later effective date is stated.
