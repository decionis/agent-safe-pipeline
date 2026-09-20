# Transparent interception

`agentsafe proxy` is addressed: a workload is configured to send its requests to the gateway. The
interceptor is the other way to hold the same boundary, and the workload is not configured at
all. Its outbound connections to ports 80 and 443 are redirected, at the network layer, into an
AgentSafe process beside it, in the same pod or the same Docker network namespace. The workload's
request leaves for the address it named and arrives at the interceptor, which reads the
destination from the request's own first bytes, places the connection there, and counts it. The
agent's code, configuration and credentials are untouched. This is what "runtime interception"
means here: in the runtime, on the wire, before anything leaves.

> The interceptor has two phases, both here. **Observe** decrypts nothing and decides nothing; it
> shows an operator what a workload actually reaches, by name and count, the way
> [shadow mode](../shadow-mode.md) shows what the authority would have decided. **Govern** takes the
> destinations an operator lists and runs the gateway's lifecycle inside this same hop: the
> request is captured, the authority decides, exactly the authorized request is forwarded once.
> Its price is stated [below](#govern). The decisions and their reasoning are
> [ADR 0004](../architecture/decisions/0004-transparent-interception.md) and
> [ADR 0005](../architecture/decisions/0005-governing-in-the-interceptor.md).

## How it sits in the path

Three placements hold one boundary, and each is honest about what it holds:

| Placement     | Where the boundary is                      | What holds it                                                                             |
| ------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------- |
| Addressed     | a URL the workload is configured to use    | the workload's configuration ([`proxy`](./http-interception.md))                          |
| Transparent   | the runtime's own egress, ports 80 and 443 | the network: a redirect the workload cannot see or unset                                  |
| Provider-side | the system of record's door                | the [Verifying Provider Profile](../authority/verifying-provider.md): no grant, no effect |

The transparent placement is the one that answers "what does this agent reach" without asking the
agent, and then, for the destinations an operator names, "and is this action permitted" without
asking it either. It is not sniffing: a connection the interceptor cannot place is refused, which
is the difference between being in the path and watching it.

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
4. For a governed destination, becomes the connection's other end ([below](#govern)); for any
   other, dials it and splices the two sockets: both directions, back-pressure, half-close, a
   five-minute idle bound. Nothing in the bytes is changed. HTTP/2 over TLS passes through like
   any other TLS.
5. Counts it: host and port, protocol, whether governed, the method where the protocol shows it,
   bytes each way.

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
agentsafe intercept --govern api.shopify.com,payments.internal --unlisted passthrough \
  --ca-cert /var/run/agent-safe/intercept/ca.crt --ca-key /var/run/agent-safe/intercept/ca.key \
  [--mode shadow|enforcement] [--failure-policy failClosed|failOpen] [--authority decionis] [--config <file>]
```

| Setting                            | Meaning                                                                                   | Default       |
| ---------------------------------- | ----------------------------------------------------------------------------------------- | ------------- |
| `AGENTSAFE_INTERCEPT_HTTP_PORT`    | the listener redirected port-80 connections arrive at                                     | `15001`       |
| `AGENTSAFE_INTERCEPT_HTTPS_PORT`   | the listener redirected port-443 connections arrive at                                    | `15002`       |
| `AGENTSAFE_INTERCEPT_BIND`         | the address the listeners bind                                                            | `127.0.0.1`   |
| `AGENTSAFE_INTERCEPT_GOVERN`       | the destinations to govern, host names, comma-separated; empty observes everything        | empty         |
| `AGENTSAFE_INTERCEPT_UNLISTED`     | a destination not governed: `passthrough` (spliced and counted) or `refuse`               | `passthrough` |
| `AGENTSAFE_INTERCEPT_CA_CERT_FILE` | the operator authority's certificate, PEM, governed TLS is terminated under               | unset         |
| `AGENTSAFE_INTERCEPT_CA_KEY_FILE`  | the operator authority's private key, PEM, EC or RSA; with the certificate, never without | unset         |

With destinations to govern, the gateway's own settings apply as they do to `agentsafe proxy`,
from the same places: `AGENTSAFE_MODE`, `AGENTSAFE_FAILURE_POLICY`, `DECIONIS_API_KEY_FILE`,
`DECIONIS_TENANT_ID` and the rest of the [environment](../reference/environment.md), or a
configuration file; the upstream is each governed host itself, and needs no setting.

The redirect ([`packaging/intercept/Redirect.sh`](../../packaging/intercept/Redirect.sh), the init
image's only content) takes the same two ports, the interceptor's user id
(`AGENTSAFE_INTERCEPT_UID`, `65532`), the intercepted ports (`AGENTSAFE_INTERCEPT_HTTP_FROM`,
`AGENTSAFE_INTERCEPT_HTTPS_FROM`), destinations to leave alone
(`AGENTSAFE_INTERCEPT_EXCLUDE_CIDRS`, comma-separated) and the IPv6 stance
(`AGENTSAFE_INTERCEPT_IPV6`), refuses a value that is not what it says it is before touching a
rule, and prints the rules it wrote. It is idempotent.

`SIGTERM` prints the report, the governed gateways' own reports (the shadow report among them),
and exits `0`. Observing, the process holds no key and asks no authority; the only network it
opens is to the destinations the workload named.

## Reading the report

Every destination in the report is somewhere the workload acts. The methods under a plaintext
destination say which of those actions are consequential; a TLS destination says only that the
workload talks to it, since nothing inside is read. A destination marked `governed` is one the
gateway took, and it is reported by the gateway's own account rather than by bytes the hop never
counted: `gateway ENFORCEMENT: governed x3, interceptions x3, allows x1, escalations x1, blocks x1`
(in JSON, `"gateway": {"mode", "requests"}`, the same counts `agentsafe status` shows for an
addressed gateway; `null` when no request reached it). From here an operator names the
destinations to govern, or uses the addressed
boundary in front of one (`agentsafe proxy --upstream https://<host>`), or the
[Verifying Provider Profile](../authority/verifying-provider.md) at the system of record's own
door, which refuses whatever did not pass through AgentSafe whichever way it came.

## Govern

For the hosts in `AGENTSAFE_INTERCEPT_GOVERN`, a redirected connection is not spliced through.
Over TLS, the interceptor terminates it with a leaf certificate minted for the server name from
the operator's authority, one leaf per host, valid for a day, minted in memory and never written;
over plain HTTP, it reads the request as sent. Either way the request then runs the gateway's
lifecycle for that host, as if `agentsafe proxy --upstream https://<host>` stood there: the
consequential request becomes an intent whose `downstream_target.system` is the host, the
authority decides, and exactly the authorized request is forwarded once to the real host (TLS to
the real host is originated by the gateway and verified against the system's trust store), held
for a person, or refused. Shadow first, then enforcement, with the same switches as the gateway.
A plaintext request to a governed host is forwarded as plaintext: the workload chose that hop,
and the boundary does not make it safer by refusing to speak it.

**The price, stated plainly.** Governing HTTPS transparently means every workload runtime trusts
a certificate authority you hold. The interceptor presents a certificate it minted, so a client
that pins its provider's certificate stops working until it is told about the boundary, and the
authority's private key, mounted into the sidecar, is a credential whose compromise lets its
holder impersonate every governed host to that workload; keep it as you keep the Decionis key,
and give it no other job. Observing costs none of this, which is why it comes first.

Making the authority:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out intercept-ca.key
openssl req -x509 -new -key intercept-ca.key -sha256 -days 3650 \
  -subj "/CN=AgentSafe Intercept CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
  -out intercept-ca.crt
```

The certificate goes to the workload's trust store and the sidecar; the key goes to the sidecar
only. What a runtime reads: Node `NODE_EXTRA_CA_CERTS=/path/ca.crt`; OpenSSL-based clients, Go
and curl `SSL_CERT_FILE=/path/ca.crt`; Python `requests` `REQUESTS_CA_BUNDLE=/path/ca.crt`; Java
a truststore with the certificate imported (`keytool -importcert`) and
`-Djavax.net.ssl.trustStore`. In Kubernetes the certificate is a ConfigMap mounted into the
workload, the certificate and key a Secret mounted into the sidecar at
`/var/run/agent-safe/intercept/`, with `AGENTSAFE_INTERCEPT_GOVERN`, the Decionis key and tenant
on the sidecar: [`deploy/intercept/kubernetes/GovernExample.yaml`](../../deploy/intercept/kubernetes/GovernExample.yaml)
is that patch, to add to a workload's kustomization beside the component. In Docker, the same
files as volumes and the same variables on the `agentsafe-intercept` service.

What govern does not do: HTTP/2 to a governed host (the interceptor offers `http/1.1` alone, and
every client negotiates down); a governed host on a port other than 443 or 80; a destination named
by address rather than name; a client that sends no server name, which is refused as it always was.
