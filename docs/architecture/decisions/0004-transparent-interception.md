# ADR 0004: transparent interception beside the workload, observing first

Status: accepted, 2026-09-20.

## Problem

AgentSafe is asked how Decionis sits in the path. The answer so far is a reverse proxy
([ADR 0001](./0001-http-interception-ingress.md)): the workload is configured to send its HTTP
requests to the gateway, which forwards the authorized request once or nothing. That boundary is
cooperative. It holds as long as the workload's configuration does, and it says nothing about the
requests a workload makes to hosts nobody put a gateway in front of. The question being asked is
whether the boundary can be a property of where the workload runs rather than of how it is
configured: interception at the network layer, in the runtime, with no change to the agent.

## Options considered

1. **Passive observation.** Capture packets (pcap, eBPF) and report what the workload reaches.
   It changes nothing about the agent and needs no trust from it. It also enforces nothing: by
   the time a packet is observed it has left, and under TLS what is observed is a server name and
   a byte count. An answer of "we sniff" would be an answer about telemetry, not authority.
2. **A forward proxy the workload is told about.** `HTTPS_PROXY` pointing at the gateway, with
   `CONNECT` and TLS termination. Many HTTP clients honour the variables; Node's fetch does not
   without an agent, and a workload can unset them. It is the reverse proxy's cooperation in
   another form.
3. **Redirect at the network layer, in the workload's own namespace.** An iptables `REDIRECT` of
   the workload's outbound TCP on 80 and 443 into a listener beside it, in the same pod or the
   same Docker network namespace, exempting the listener's own user id. The workload's request
   leaves for the address it named and arrives at the listener, which learns the destination
   from the client's own first bytes: the TLS server name, or the HTTP host. This is the pattern
   service meshes settled on, and it is in the path: a connection the listener does not place
   goes nowhere.

## Decision

Option 3, in two phases, the first of which this record covers.

**Observe.** `agentsafe intercept` binds two loopback listeners (15001 for redirected port 80,
15002 for redirected port 443). For each connection it reads the first bytes under a bound and a
timeout, takes the destination from a TLS ClientHello's `server_name` or an HTTP/1 request's
authority (`src/intercept/ClientHello.ts`, `src/intercept/RequestHead.ts`,
`src/intercept/Destination.ts`), dials it (`src/egress/TransparentDial.ts`), and splices the two
sockets with back-pressure, half-close and an idle bound (`src/http/InterceptServer.ts`). Nothing
is decrypted, nothing is decided, no request is altered. A ledger (`src/intercept/InterceptLedger.ts`)
keeps destinations, protocols, methods where readable, bytes and refusals; the process prints one
line per placed or refused connection and the report on `SIGTERM`. A connection whose destination
no byte names, a TLS hello without a server name, an HTTP request without a host, a head that two
parsers could read differently, a loop back into a listener, an unreachable destination: each is
refused by name, never guessed.

The redirect is `packaging/intercept/Redirect.sh`, POSIX sh run once by an init container built
from the `init` stage of `packages/agentsafe/Dockerfile` and published as `<version>-init` beside
the runtime image. It validates every setting before touching a rule, keeps its rules in chains of
its own, is idempotent, exempts the interceptor's user id and loopback, and refuses IPv6 on the
intercepted ports with a reset rather than let it pass beside the boundary while the interceptor
listens on IPv4 only. `deploy/intercept/kubernetes` is a kustomize Component that patches the init
container and the sidecar into any Deployment labelled `agent-safe-intercept: "true"`;
`deploy/intercept/docker/compose.yaml` is the same three containers in one Docker network
namespace the interceptor owns.

**Govern** (the next phase, its own record). For destinations an operator lists, the same hop
terminates TLS with a leaf certificate minted per server name from an operator's CA, originates
TLS to the real host with verification, and runs the gateway's lifecycle over the request: routes
gain a host, intents carry the real destination, shadow then enforce, unlisted destinations pass
through counted or are refused. Its price is stated now so nobody is surprised by it later:
governing HTTPS transparently means every workload runtime trusts a CA the operator holds.

## Reason

The boundary is the last point where an intention is still a request and not yet an effect.
Redirecting the workload's egress into AgentSafe makes that point a property of the pod or the
container, not of the agent's code or configuration, and makes "runtime interception" a literal
description rather than a figure of speech. Observing first is the same discipline as shadow
mode: an operator learns what a workload reaches, in a report of names and counts, before a
single connection is held. And the observe phase is honest about the one thing passive capture
cannot be honest about: a connection the interceptor cannot place is refused, which is what being
in the path means.

## Protocol impact

None. No intent is captured and no authority is asked in the observe phase. The govern phase
uses `agent-safe.intent/1` and the execution contract as the gateway does, with the destination
host in `downstream_target.system`.

## Compatibility impact

A new command, `agentsafe intercept`, with its `AGENTSAFE_INTERCEPT_*` variables; a new image tag
family, `<version>-init`, under the existing image name, copied to Docker Hub with the rest; two
files under `deploy/intercept`. Nothing existing changes. The executor kit's namespaces stay under
the `restricted` Pod Security profile, which does not admit the init container's capabilities; the
component is for an operator's own namespace under `baseline`, and says so.

## Security impact

- The interceptor decides where bytes go from the client's own bytes and from nothing else; the
  two parsers are bounded, linear, and refuse ambiguity (a repeated `Host`, a target that
  disagrees with it, an oversized or fragmented-then-broken hello) rather than choose.
- The interceptor's egress is deliberately not sealed by `EgressPolicy`: it forwards to what the
  client asked for, or to nothing. `src/egress/TransparentDial.ts` is the one such place and says
  so. What the workload reaches is what the workload reached before; the difference is that it is
  now seen, counted, and can be refused.
- The listeners bind loopback. `REDIRECT` maps a locally generated packet's destination to
  `127.0.0.1`, so nothing outside the namespace can use the interceptor as a relay; a destination
  that is one of its own listeners is refused as a loop.
- The redirect exempts one user id, the interceptor's. A workload container that runs as `65532`
  is not intercepted; the component and the recipe say the workload must not, and the report
  shows by absence when it does.
- Ports other than 80 and 443 are not redirected. A system of record on another port is outside
  this boundary until the redirect is told about it.
- The init container runs as root with `NET_ADMIN` and `NET_RAW` for the moment it takes to write
  the rules, then exits; it holds no AgentSafe code, no key and no configuration beyond ports and
  a user id, and refuses any setting that is not what it says it is.
- The report is names and counts: host names, ports, protocols, methods, bytes, refusals. No
  path, header, body, or caller address is kept.

## Migration impact

None. The reverse proxy, the envelope ingress and the kit are unchanged. An operator who wants to
learn what a workload reaches adds the component or the recipe and reads the report; nothing else
moves until they choose to govern.
