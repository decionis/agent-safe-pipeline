# AgentSafe — an authority boundary in front of any agent or API

`decionis/agentsafe` is the AgentSafe runtime as a container. An agent, an application or a tool
sends its HTTP request to AgentSafe instead of the target; AgentSafe captures the action as an
intent, asks the [Decionis](https://decionis.com) control plane (the Independent Execution
Authority, bound to the exact action) for a decision, and forwards exactly the authorized request
once on a claimed single-use grant, holds it for a person, or refuses it, leaving a chained record
of each. It decides nothing itself.

This is the same runtime as the `agentsafe` executable, the Homebrew formula, the Linux packages
and the npm package `@decionis/agentsafe`, built once by the release workflow of
[decionis/agent-safe-pipeline](https://github.com/decionis/agent-safe-pipeline) for `linux/amd64`
and `linux/arm64`: distroless, non-root (`65532`), under Node's permission model, with no
configuration and no credential inside it.

## Tags

```text
decionis/agentsafe:<version>     immutable: use this in production
decionis/agentsafe:<major>.<minor>
decionis/agentsafe:<major>
decionis/agentsafe:latest        moves; never in production
```

The tag is the runtime version; the
[releases page](https://github.com/decionis/agent-safe-pipeline/releases) lists them with their
digests. Docker Hub carries the same manifest list as `ghcr.io/decionis/agentsafe`: after each
release the manifest is copied here by digest, a copy whose digest differs is refused, and the
Docker Hub name is attested by the same keyless workflow identity. One digest therefore names a
release on both registries, and either name pulls the same bytes.

## Run the gateway

The image's default command is the gateway. It runs as `NODE_ENV=production`, which refuses the
demo authority and a key in the environment: a container asks Decionis, and reads its key from a
mounted file.

```bash
mkdir -p secrets && (umask 077; printf '%s' "$DECIONIS_API_KEY" > secrets/decionis-api-key)

docker run --rm -p 8080:8080 \
  -e AGENTSAFE_LISTEN=:8080 \
  -e AGENTSAFE_UPSTREAM=http://host.docker.internal:3000 \
  -e AGENTSAFE_UPSTREAM_INSECURE=true \
  -e DECIONIS_API_KEY_FILE=/var/run/agent-safe/secrets/decionis-api-key \
  -e DECIONIS_TENANT_ID=<your organization id> \
  -v "$PWD/secrets:/var/run/agent-safe/secrets:ro" \
  decionis/agentsafe:<version>
```

`AGENTSAFE_UPSTREAM_INSECURE=true` is the statement that the hop from the container to a
plain-http upstream is protected by the network, as it is on a host or inside a cluster; an
`https://` upstream needs no such statement. The mounted key file must be readable by the
container's user (`65532`): `chmod 0440` and `chown :65532`, or a Docker secret. The output is one
JSON line per event, the chained evidence included, on standard output; `AGENTSAFE_EVIDENCE_DIR`
with a volume under `/var/lib/agent-safe` keeps them in files instead.

A configuration file works too, mounted at `/etc/agentsafe`:

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/agentsafe.yaml:/etc/agentsafe/agentsafe.yaml:ro" \
  -v "$PWD/secrets:/var/run/agent-safe/secrets:ro" \
  -e AGENTSAFE_CONFIG=/etc/agentsafe/agentsafe.yaml \
  -e DECIONIS_API_KEY_FILE=/var/run/agent-safe/secrets/decionis-api-key \
  decionis/agentsafe:<version>
```

The other commands are the same binary: `docker run --rm decionis/agentsafe:<version> version`,
`... doctor`, `... config --json`, and `... serve` for the trusted executor the
[deployment kit](https://github.com/decionis/agent-safe-pipeline/blob/master/deploy/README.md)
runs.

## Intercept transparently

The gateway is addressed: a workload is pointed at it. `decionis/agentsafe:<version> intercept`
holds the same boundary without configuring the workload: its outbound connections to ports 80 and
443 are redirected into AgentSafe beside it, at the network layer, and every destination it reaches
is reported by name and count. Name the destinations to govern in `AGENTSAFE_INTERCEPT_GOVERN`,
with an authority the workload trusts in `AGENTSAFE_INTERCEPT_CA_CERT_FILE` and `_CA_KEY_FILE`, and
the same hop terminates their TLS and runs the gateway's lifecycle on each request: intent,
decision, one forwarded request, or held, or refused. The redirect is the
`decionis/agentsafe:<version>-init` tag, run once with `NET_ADMIN` and `NET_RAW` in the shared
network namespace; the
[compose recipe](https://github.com/decionis/agent-safe-pipeline/blob/master/deploy/intercept/docker/compose.yaml)
puts the three containers together, and
[transparent interception](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/gateway/transparent-interception.md)
says what is observed, what is governed, and what the operator authority costs.

## Send your first governed action

With the gateway running in the container and a service on the host at port 3000:

```bash
curl -i -X POST http://127.0.0.1:8080/payments -H 'content-type: application/json' -d '{"amount": 500}'
```

In shadow, the default with a Decionis key, the request goes through and the container's log says
what Decionis would have decided (`"state":"SHADOW"`). `AGENTSAFE_MODE=enforcement` makes the
decisions binding: `ALLOW` is forwarded once, `ESCALATE` is held (`202`), `BLOCK` is refused
(`403`).

## Health, readiness, shutdown

`GET /_agentsafe/healthz` answers while the process lives; `GET /_agentsafe/readyz` once the
listener is bound. `SIGTERM` (`docker stop`) closes the listener, gives requests in flight ten
seconds, and exits `0`; the last line is `GATEWAY_STOPPED`.

## Verify before you run

```bash
gh attestation verify oci://docker.io/decionis/agentsafe:<version> --repo decionis/agent-safe-pipeline
docker buildx imagetools inspect docker.io/decionis/agentsafe:<version>
```

The manifest carries BuildKit's SBOM and provenance attestations for both architectures. The
digest `inspect` prints is the one `ghcr.io/decionis/agentsafe:<version>` prints and the one the
release notes carry; a difference is a reason to stop and to
[report it](https://github.com/decionis/agent-safe-pipeline/blob/master/SECURITY.md). Production
pins that digest, never `latest`, and mirrors the image into its own registry before a cluster
pulls it.

## Kubernetes

The Helm chart deploys this image as one Deployment in front of one Service:

```bash
helm install agentsafe oci://ghcr.io/decionis/charts/agentsafe --version <chart version> \
  --namespace payments \
  --set decionis.tenantId=<your organization id> \
  --set upstream.service=payments --set upstream.port=8080
```

`--set image.repository=docker.io/decionis/agentsafe` pulls from here instead of GHCR; the
[Kubernetes page](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/install/kubernetes.md)
has the values file and the routes.

## Documentation

- [Run in Docker](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/install/docker.md),
  the page this overview follows
- [5-minute quickstart](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/quickstart/README.md)
- [Production checklist](https://github.com/decionis/agent-safe-pipeline/blob/master/docs/deployment/production.md)
- [Security policy](https://github.com/decionis/agent-safe-pipeline/blob/master/SECURITY.md) and
  [threat model](https://github.com/decionis/agent-safe-pipeline/blob/master/THREAT-MODEL.md)
- [Source, issues and releases](https://github.com/decionis/agent-safe-pipeline)

AgentSafe is Apache-2.0. Decionis, AgentSafe and Agent-Safe Pipeline are trademarks of Decionis,
Inc.; `docker.io/decionis/agentsafe` is an official distribution under the
[trademark policy](https://github.com/decionis/agent-safe-pipeline/blob/master/TRADEMARKS.md).
