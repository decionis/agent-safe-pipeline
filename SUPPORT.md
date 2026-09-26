# Support

Where to take each kind of question about AgentSafe. Support for the hosted Decionis service is
outside this repository.

| You have                                  | Where it goes                                                                                                                                                                                                                                      |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A suspected vulnerability                 | Privately, never in a public issue: the [reporting form](https://github.com/decionis/agent-safe-pipeline/security/advisories/new) or [security@decionis.com](mailto:security@decionis.com). [SECURITY.md](./SECURITY.md) has the response targets. |
| A bug, a question, or a documentation gap | A [GitHub issue](https://github.com/decionis/agent-safe-pipeline/issues/new).                                                                                                                                                                      |
| A change you want to make                 | A pull request, as [CONTRIBUTING.md](./CONTRIBUTING.md) describes.                                                                                                                                                                                 |
| The hosted Decionis service               | [decionis.com/contact](https://decionis.com/contact).                                                                                                                                                                                              |

## Before you open an issue

- Check that you run a supported release. Only the latest published `0.x` release is supported
  ([MAINTENANCE.md](./MAINTENANCE.md)); a report about an older one may be answered with a request
  to reproduce it on the latest.
- Say which distribution and version you run (the output of `agentsafe version`, and whether it is
  the Homebrew formula, a `.deb` or `.rpm`, a container image tag, the Helm chart or an npm
  package) and on which platform. [COMPATIBILITY.md](./COMPATIBILITY.md) lists what each release
  runs on.
- Leave secrets out. No API keys, grants, customer payloads or unredacted dossier contents belong
  in an issue, a log excerpt or a support bundle
  ([SECURITY.md](./SECURITY.md#integration-requirements)).

## What to expect

There is no response-time commitment for issues or pull requests. The targets in
[SECURITY.md](./SECURITY.md) apply to vulnerability reports. The maintenance policy is a
commitment for this public reference implementation, not a service-level agreement
([MAINTENANCE.md](./MAINTENANCE.md)).

Participation follows the [code of conduct](./CODE_OF_CONDUCT.md).
