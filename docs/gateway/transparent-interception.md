# Transparent interception

`agentsafe proxy` is addressed: a workload is configured to send its requests to the gateway. The
interceptor is the other way to hold the same boundary, and the workload is not configured at
all. Its outbound connections to ports 80 and 443 are redirected, at the network layer, into an
AgentSafe process beside it, in the same pod or the same Docker network namespace. The workload's
request leaves for the address it named and arrives at the interceptor, which reads the
destination from the request's own first bytes, places the connection there, and counts it. The
agent's code, configuration and credentials are untouched. This is what "runtime interception"
means here: in the runtime, on the wire, before anything leaves.

> This page describes the **observe** phase, which is what ships. The interceptor decrypts nothing
> and decides nothing; it shows an operator what a workload actually reaches, by name and count,
> the way [shadow mode](../shadow-mode.md) shows what the authority would have decided. Governing
> those destinations in the same hop is the next phase, and its price is stated
> [below](#what-comes-next). The decision and its reasoning are
> [ADR 0004](../architecture/decisions/0004-transparent-interception.md).

## How it sits in the path

Three placements hold one boundary, and each is honest about what it holds:

| Placement     | Where the boundary is                      | What holds it                                                                             |
| ------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------- |
| Addressed     | a URL the workload is configured to use    | the workload's configuration ([`proxy`](./http-interception.md))                          |
| Transparent   | the runtime's own egress, ports 80 and 443 | the network: a redirect the workload cannot see or unset                                  |
| Provider-side | the system of record's door                | the [Verifying Provider Profile](../authority/verifying-provider.md): no grant, no effect |

The transparent placement is the one that answers "what does this agent reach" without asking the
agent. It is not sniffing: a connection the interceptor cannot place is refused, which is the
difference between being in the path and watching it.

## What is intercepted, and what is not

- TCP to port 80 and port 443, from every user in the namespace except the interceptor's own
  (`65532`). A workload container that runs as that user is not intercepted; run it as anything
  else.
- Loopback is left alone: a workload talking to a sidecar or to itself is not talking to a
  system of record.
- Other ports are not redirected. A system of record on another port is outside this boundary
  until `AGENTSAFE_INTERCEPT_HTTP_FROM` or `AGENTSAFE_INTERCEPT_HTTPS_FROM` names it.
- IPv6 to the intercepted ports is refused with a reset (`AGENTSAFE_INTERCEPT_IPV6=auto`), since
  the interceptor listens on IPv4 loopback and a connection it cannot see must not pass beside
  it; `off` leaves IPv6 alone, knowingly, for a workload that must reach a destination over it.
- UDP, and so DNS, is untouched: the workload resolves names as before. The interceptor resolves
  the destination again, for itself, when it dials.

## What the interceptor does with a connection

1. Reads the first bytes, up to 64 KiB and for at most five seconds.
2. Reads the destination: the `server_name` of a TLS ClientHello, or the authority of an HTTP/1
   request (`Host`, or the absolute-form target, which must agree with `Host`). The port is the
   one the connection was addressed to, unless the HTTP authority names another.
3. Refuses, by name, what it cannot place: a TLS hello without a server name, a request without
   a host, a repeated `Host`, a head that does not follow its grammar, bytes that are neither TLS
   nor HTTP, a destination that is one of its own listeners, a destination it cannot reach.
4. Dials the destination and splices the two sockets: both directions, back-pressure, half-close,
   a five-minute idle bound. Nothing in the bytes is changed. HTTP/2 over TLS passes through
   like any other TLS.
5. Counts it: host and port, protocol, the method where the protocol shows it, bytes each way.

Each placed or refused connection is one line as it happens, and the report is printed when the
process is stopped:

```text
{"event":"INTERCEPT_OBSERVED","at":"…","protocol":"TLS","host":"api.shopify.com","port":443,"alpn":["h2","http/1.1"]}
{"event":"INTERCEPT_OBSERVED","at":"…","protocol":"HTTP","host":"payments.internal","port":80,"method":"POST","target":"/refunds"}
{"event":"INTERCEPT_REFUSED","at":"…","reason":"DESTINATION_UNKNOWN","protocol":"TLS"}
{"event":"INTERCEPT_REPORT","at":"…","intercept":{"connections":41,"placed":40,"refused":{"DESTINATION_UNKNOWN":1},"destinations":{"api.shopify.com:443":{"protocol":"TLS","connections":38,"bytes_to_destination":91204,"bytes_from_destination":1120933,"methods":{}},"payments.internal:80":{"protocol":"HTTP","connections":2,"bytes_to_destination":1912,"bytes_from_destination":640,"methods":{"POST":2}}}},"next":"…"}
```

The report is names and counts. No path, header, body or caller address is kept in it; the
`target` on a plaintext observation line is the request line's path, shown so an operator can
write a route for it, and never a header or a body.

## In Kubernetes

The interceptor is a sidecar, added to a Deployment of yours by a kustomize Component: an init
container that writes the redirect once, and the interceptor beside your containers.

```yaml
# kustomization.yaml, in the directory that owns the workload
resources:
  - deployment.yaml
components:
  - ../../agent-safe-pipeline/deploy/intercept/kubernetes
```

Label the Deployment `agent-safe-intercept: "true"`, `kubectl apply -k .`, and read
`kubectl logs deploy/<name> -c agentsafe-intercept`. The patch is
[`deploy/intercept/kubernetes/Sidecar.yaml`](../../deploy/intercept/kubernetes/Sidecar.yaml):
the init container runs as root with `NET_ADMIN` and `NET_RAW`, every other capability dropped, a
read-only root, and exits; the interceptor runs as `65532` under the same hardening as the
gateway, listens on loopback only, and needs no key, no Secret and no configuration.

Three things the patch cannot check for you: the workload's containers must not run as `65532`;
the namespace's Pod Security profile must be `baseline` or looser, since `restricted` does not
admit the init container's capabilities (the executor kit's own namespaces stay `restricted`, and
are not where this goes); and the pod's NetworkPolicy must let the pod, which now includes the
interceptor, reach the destinations and cluster DNS, because the interceptor dials from the pod's
own address. The image tags in the patch are the runtime's version and move with each release;
production pins them by digest.

## In Docker

[`deploy/intercept/docker/compose.yaml`](../../deploy/intercept/docker/compose.yaml) is the same
three containers in one network namespace, which the interceptor owns:

```bash
AGENT_IMAGE=your/agent:tag AGENTSAFE_VERSION=<runtime version> \
  docker compose -f deploy/intercept/docker/compose.yaml up
docker compose -f deploy/intercept/docker/compose.yaml logs -f agentsafe-intercept
```

The redirect container joins the namespace with `NET_ADMIN` and `NET_RAW`, writes the rules and
exits; the workload joins once it has. Ports the workload publishes are published on the
`agentsafe-intercept` service, because the namespace is its. The version is pinned on purpose.

## The process

```bash
agentsafe intercept [--http-port 15001] [--https-port 15002] [--bind 127.0.0.1] [--json]
```

| Setting                          | Meaning                                                | Default     |
| -------------------------------- | ------------------------------------------------------ | ----------- |
| `AGENTSAFE_INTERCEPT_HTTP_PORT`  | the listener redirected port-80 connections arrive at  | `15001`     |
| `AGENTSAFE_INTERCEPT_HTTPS_PORT` | the listener redirected port-443 connections arrive at | `15002`     |
| `AGENTSAFE_INTERCEPT_BIND`       | the address the listeners bind                         | `127.0.0.1` |

The redirect ([`packaging/intercept/Redirect.sh`](../../packaging/intercept/Redirect.sh), the init
image's only content) takes the same two ports, the interceptor's user id
(`AGENTSAFE_INTERCEPT_UID`, `65532`), the intercepted ports (`AGENTSAFE_INTERCEPT_HTTP_FROM`,
`AGENTSAFE_INTERCEPT_HTTPS_FROM`), destinations to leave alone
(`AGENTSAFE_INTERCEPT_EXCLUDE_CIDRS`, comma-separated) and the IPv6 stance
(`AGENTSAFE_INTERCEPT_IPV6`), refuses a value that is not what it says it is before touching a
rule, and prints the rules it wrote. It is idempotent.

`SIGTERM` prints the report and exits `0`. The process holds no key and asks no authority; the
only network it opens is to the destinations the workload named.

## Reading the report

Every destination in the report is somewhere the workload acts. The methods under a plaintext
destination say which of those actions are consequential; a TLS destination says only that the
workload talks to it, since nothing inside is read. From here an operator has the addressed
boundary today: `agentsafe proxy --upstream https://<host>` in front of one destination, or the
[Verifying Provider Profile](../authority/verifying-provider.md) at the system of record's own
door, which refuses whatever did not pass through AgentSafe whichever way it came.

## What comes next

The govern phase runs the gateway's lifecycle inside this same hop for the destinations an
operator lists: TLS is terminated with a certificate minted for the server name from a CA the
operator holds, TLS to the real host is originated and verified, the request is captured as an
intent with the real destination, and shadow then enforcement apply as they do to the gateway;
unlisted destinations pass through counted, or are refused. The price is structural rather than
technical, and it is stated here so that it is not a surprise later: governing HTTPS transparently
means every workload runtime trusts a CA you hold, and a client that pins its provider's
certificate stops working until it is told about the boundary. Observing costs none of that, which
is why it comes first.
