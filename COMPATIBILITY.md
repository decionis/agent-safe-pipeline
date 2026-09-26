# Compatibility

What release `v0.3.5` runs on, and which versions of its specification and tools go together. The
runtime is the same in every distribution; only the packaging differs
([cross-runtime conformance](./conformance/runtime/README.md)). A release that changes a runtime
requirement or a supported configuration updates this page in the same pull request
([MAINTENANCE.md](./MAINTENANCE.md#change-and-documentation-policy)).

## The runtime, `agentsafe` 0.2.5

| Distribution                                    | Runs on                                                     | Needs                                  | Details                                                                                         |
| ----------------------------------------------- | ----------------------------------------------------------- | -------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Executable: Homebrew, the archive, `install.sh` | macOS on Apple silicon and Intel; Linux on x86_64 and arm64 | Nothing else: it carries a pinned Node | [macOS](./docs/install/macos.md), [Linux](./docs/install/linux.md)                              |
| `.deb` and `.rpm`                               | Linux on x86_64 and arm64                                   | Nothing else                           | [Linux](./docs/install/linux.md)                                                                |
| Container image                                 | `linux/amd64` and `linux/arm64`                             | A container runtime                    | [Docker](./docs/install/docker.md)                                                              |
| Helm chart 0.2.5                                | Kubernetes 1.27 or later (`kubeVersion: ">=1.27.0-0"`)      | The container image above              | [Kubernetes](./docs/install/kubernetes.md), [`charts/agentsafe`](./charts/agentsafe/Chart.yaml) |
| npm: `@decionis/agentsafe` 0.2.5                | Node.js                                                     | Node.js 22.14.0 or later               | [`packages/agentsafe`](./packages/agentsafe/package.json)                                       |

There is no Windows build of the runtime. The hosted path, `agentsafe.decionis.com`, is not live
yet ([hosted](./docs/install/hosted.md)).

## Other packages in this repository

| Package                               | Needs                    | Details                                                         |
| ------------------------------------- | ------------------------ | --------------------------------------------------------------- |
| `@decionis/agent-safe-pipeline` 0.3.5 | Node.js 22.14.0 or later | [`packages/pipeline`](./packages/pipeline/package.json)         |
| `@decionis/commerce` 0.1.5            | Node.js 20 or later      | [`packages/commerce-mcp`](./packages/commerce-mcp/package.json) |

## Govern 2.1.0

| Platform                       | Distribution                                                                           |
| ------------------------------ | -------------------------------------------------------------------------------------- |
| macOS, Apple silicon and Intel | Homebrew, the archive, `govern/install.sh`, `go install …/govern/v2/cmd/govern@v2.1.0` |
| Linux, x86_64 and arm64        | Homebrew, the archive, `govern/install.sh`, `go install`                               |
| Windows x64                    | `govern-2.1.0-windows-x64.zip`, checked against `SHA256SUMS`; no installer             |

The GitHub Action, `uses: decionis/govern@v2`, fetches or builds the binary itself, on Windows
runners too ([govern/README.md](./govern/README.md)).

## Specification and verification

- **Agent-Safe Intent v1** ([spec/intent/v1](./spec/intent/v1/README.md)) is published and in
  force. Within `/1` a change can only add an optional property that leaves the bytes and the hash
  of every existing binding unchanged; anything else is `agent-safe.intent/2` (its §9). The change
  process is its §10.
- **`@decionis/verify` 0.4.0 or later** is needed for `npx @decionis/verify intent` against the
  [conformance vectors](./conformance).
- **Framework coverage** is one matrix, capability by framework, for the OpenAI Responses API and
  Agents SDK, the Vercel AI SDK, LangChain and MCP: for each part of the binding, whether the
  framework's own tool-call record carries it (native) or the adapter adds it
  ([frameworks.md](./spec/intent/v1/frameworks.md)). None of the frameworks needs to change for a
  producer built on it to conform.
