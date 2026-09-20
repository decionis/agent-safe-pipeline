# Run in Docker

The image is the same runtime as the executable and the npm package, built by the release
workflow for `linux/amd64` and `linux/arm64`, distroless, non-root, under Node's permission model,
with no configuration and no credential inside it.

```text
ghcr.io/decionis/agentsafe:<version>     immutable: use this in production
ghcr.io/decionis/agentsafe:<major>.<minor>
ghcr.io/decionis/agentsafe:<major>
ghcr.io/decionis/agentsafe:latest        moves; never in production
```

The same manifest list is on Docker Hub as `docker.io/decionis/agentsafe`, under the same four
tags. It is not a second build: after each release the [`Docker Hub image`
workflow](../../.github/workflows/dockerhub.yml) copies the release's manifest from GHCR by digest,
refuses a copy whose digest differs, and attests the Docker Hub name with the same keyless workflow
identity. One digest therefore names the release on both registries, and either name pulls the same
bytes. The overview shown on Docker Hub is
[`packaging/dockerhub/README.md`](../../packaging/dockerhub/README.md), published by the same run,
so the page and the image change together. Docker Hub applies pull-rate limits to anonymous
clients; a cluster that pulls often should authenticate to it, pull from GHCR, or mirror.

> Availability: the image is pushed to GHCR by the release workflow from `v0.2.0` on; the tag is
> the runtime version. Docker Hub carries a version once the Docker Hub job of its release, or a
> maintainer's dispatch of the workflow for that version, has copied it. Before `v0.2.0`, build it
> from a clone: `docker build -f packages/agentsafe/Dockerfile -t agentsafe .`

The image's default command is the gateway. The image runs as `NODE_ENV=production`, which
refuses the demo authority and a key in the environment: a container asks Decionis, and reads its
key from a mounted file.

## Run the gateway

```bash
mkdir -p secrets && (umask 077; printf '%s' "$DECIONIS_API_KEY" > secrets/decionis-api-key)

docker run --rm -p 8080:8080 \
  -e AGENTSAFE_LISTEN=:8080 \
  -e AGENTSAFE_UPSTREAM=http://host.docker.internal:3000 \
  -e AGENTSAFE_UPSTREAM_INSECURE=true \
  -e DECIONIS_API_KEY_FILE=/var/run/agent-safe/secrets/decionis-api-key \
  -e DECIONIS_TENANT_ID=<your organization id> \
  -v "$PWD/secrets:/var/run/agent-safe/secrets:ro" \
  ghcr.io/decionis/agentsafe:<version>
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
  ghcr.io/decionis/agentsafe:<version>
```

The other commands are the same binary: `docker run --rm ghcr.io/decionis/agentsafe:<version>
version`, `... doctor`, `... config --json`, and `... serve` for the trusted executor the
[deployment kit](../../deploy/README.md) runs. The image is marked `NODE_ENV=production`, where
the synthetic authority the boundary test runs on refuses to start; to run
[`agentsafe test`](../reference/cli.md#agentsafe-test-namehostport) in the container, unset it
for that run: `docker run --rm -e NODE_ENV= ghcr.io/decionis/agentsafe:<version> test`.

## Health, readiness, shutdown

`GET /_agentsafe/healthz` answers while the process lives; `GET /_agentsafe/readyz` once the
listener is bound. `SIGTERM` (`docker stop`) closes the listener, gives requests in flight ten
seconds, and exits `0`; the last line is `GATEWAY_STOPPED`.

## Verify the image

```bash
gh attestation verify oci://ghcr.io/decionis/agentsafe:<version> --repo decionis/agent-safe-pipeline
docker buildx imagetools inspect ghcr.io/decionis/agentsafe:<version>
```

The manifest carries BuildKit's SBOM and provenance attestations for both architectures, and the
release workflow attests the manifest digest with the same keyless identity that signs the release
tag. The Docker Hub copy verifies the same way, against the attestation the Docker Hub workflow
made for that name:

```bash
gh attestation verify oci://docker.io/decionis/agentsafe:<version> --repo decionis/agent-safe-pipeline
docker buildx imagetools inspect docker.io/decionis/agentsafe:<version>
```

The two `inspect` digests are equal for every version; a difference is a reason to stop and to
report it. Mirror the image into your own registry before a cluster pulls it; the
[kit](../../deploy/README.md#getting-the-image) says why.

## Send your first governed action

With the gateway running in the container and a service on the host at port 3000:

```bash
curl -i -X POST http://127.0.0.1:8080/payments -H 'content-type: application/json' -d '{"amount": 500}'
```

In shadow, the default with a Decionis key, the request goes through and the container's log
says what Decionis would have decided (`"state":"SHADOW"`). `AGENTSAFE_MODE=enforcement` makes the
decisions binding: `ALLOW` is forwarded once, `ESCALATE` is held (`202`), `BLOCK` is refused
(`403`). The [gateway pages](../gateway/http-interception.md) say what was bound and forwarded.
