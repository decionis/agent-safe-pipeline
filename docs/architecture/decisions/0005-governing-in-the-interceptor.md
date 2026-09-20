# ADR 0005: governing in the interceptor, under an authority the operator holds

Status: accepted, 2026-09-20.

## Problem

[ADR 0004](./0004-transparent-interception.md) put AgentSafe in a workload's network egress
without configuring the workload, and stopped at observing: every destination reported by name
and count, nothing decrypted, nothing decided. The report answers what a workload reaches. It
does not answer the question the boundary exists for, whether a given request to one of those
destinations is authorized, because a TLS connection spliced through is opaque to the hop that
carries it. Governing a destination transparently means the hop must become the other end of the
connection, and for HTTPS that means presenting a certificate for a name the operator does not
own.

## Options considered

1. **Govern plaintext only.** Terminate nothing; run the gateway's lifecycle over the port-80
   connections and keep splicing 443. Honest and cheap, and nearly useless: the systems of record
   that matter speak TLS.
2. **Terminate TLS under a certificate authority the operator holds.** For each governed host,
   mint a leaf certificate for its server name from an operator CA the workload's runtimes trust,
   terminate the connection with it, run the gateway over the plaintext, and originate a verified
   TLS connection to the real host. This is what a corporate TLS-inspecting proxy does, and it
   carries that proxy's price: a CA in every trust store, a signing key in the sidecar, pinned
   clients that stop working until they are told.
3. **Terminate TLS by reading the workload's own session keys.** Have the runtime export its TLS
   keys (`SSLKEYLOGFILE` and its equivalents) to the sidecar. Passive again: the hop could read
   the request but not stop it, and only for runtimes that export keys.

## Decision

Option 2, for the hosts an operator lists and for those alone, with the price stated in the same
paragraph as the feature wherever the feature is described.

**What is governed.** `AGENTSAFE_INTERCEPT_GOVERN` (`--govern`) names hosts. A redirected
connection whose destination is a listed host is taken (`src/http/InterceptGovernor.ts`): over
TLS it is terminated with a leaf for the server name; over plain HTTP it is read as sent. The
plaintext then enters a gateway created for that host on first use, `Gateway.create` with the
gateway's own configuration and an upstream of `https://<host>` (or `http://<host>`, plaintext
in and plaintext out, since the workload chose that hop), through `GatewayHttpServer.accept`,
which feeds the stream to the same HTTP server the addressed gateway listens with. From there
nothing is new: the consequential request is an intent whose `downstream_target.system` is the
host, the authority decides, the authorized request is forwarded exactly once on a claimed grant,
held, or refused; shadow mode, the failure policy, the demo authority's refusal in production,
all as for `agentsafe proxy`. A destination not listed follows `AGENTSAFE_INTERCEPT_UNLISTED`:
`passthrough` splices and counts it as the observe phase does; `refuse` refuses it by name.

**The authority.** `AGENTSAFE_INTERCEPT_CA_CERT_FILE` and `AGENTSAFE_INTERCEPT_CA_KEY_FILE`, PEM,
come together or not at all. `src/intercept/LeafIssuer.ts` checks at start that the certificate
is an authority and that the key is its key, and refuses otherwise by code
(`CA_NOT_AN_AUTHORITY`, `CA_KEY_MISMATCH`, `CA_KEY_INVALID`, `CA_CERTIFICATE_INVALID`) before a
listener is bound. Leaves are minted in memory, one per host, on one P-256 key generated per
process: subject and `dNSName` are the host, the issuer is the authority's subject byte for byte,
validity is a day backdated an hour against clock skew, reissue two hours before expiry, signed
`ecdsa-with-SHA256` or `sha256WithRSAEncryption` by the authority's key type (an authority of any
other key type is refused rather than signed with), at most a thousand kept. The DER is written by
`src/intercept/Der.ts` in strict, shortest-form encoding, because the verifier that reads the leaf
may be Go's or Java's or a Rust web-PKI library, each of which refuses a length OpenSSL would
tolerate; the issuer is the authority's subject byte for byte for the same reason. No leaf and no
key is written anywhere. Without the authority, governed TLS is refused as `GOVERN_UNAVAILABLE`
(`GOVERN_TLS_UNAVAILABLE`) and governed plaintext still runs.

**The seam.** Node's TLS reads a raw socket through its handle, beneath the JavaScript stream the
destination was read from, so a `TLSSocket` over the peeked socket would lose the ClientHello.
`replayed()` is a `Duplex` that delivers the bytes already read and then the socket's, and writes
through; it is the one place the interceptor's own code touches ciphertext, and it copies. The
handshake is bounded by `handshakeTimeoutMs` (10 s); a handshake that fails (OpenSSL's code, such
as a client offering HTTP/2 alone, since the interceptor offers `http/1.1` and nothing else),
times out (`TIMEOUT`), or loses its client (`CLOSED`, the moment the stream underneath ends or
closes, not when the timer says) refuses the connection as `GOVERN_UNAVAILABLE` with that detail,
and a gateway that cannot be created for a host refuses the same way. Refusal, in every case, is a
closed connection: the workload learns nothing was placed. Once the handshake is done, the
connection is the gateway's: a client that half-closes after its request is still answered.

## Reason

The boundary's claim is that an intention becomes an effect only through a hop that can refuse
it. In the observe phase that hop could refuse connections but not requests, because it could
not read them. Governing makes the hop the other end of the connection, which is the only
position from which a request under TLS can be read before it is forwarded and withheld if it
should not be. The price is real and it is the same price every TLS-inspecting proxy charges; the
decision here is to charge it only for the hosts the operator names, to check the authority
before anything listens, to mint and hold nothing on disk, and to say the price beside the feature
every time. Observing costs none of it, which is why it stays the first phase and the default.

## Protocol impact

None to the protocol. The governed gateway emits `agent-safe.intent/1` with the destination host
in `downstream_target.system`, claims grants and forwards under the execution contract exactly as
the addressed gateway does. The intent now carries the host the workload named rather than the
host an operator configured, which is the difference the boundary was built to make.

## Compatibility impact

New settings on `agentsafe intercept`: `--govern`, `--unlisted`, `--ca-cert`, `--ca-key`, and
the gateway's own `--mode`, `--failure-policy`, `--authority`, `--config`, `--verbose`, each with
its variable. The `OBSERVED` line carries `governed`; a new `INTERCEPT_GOVERNING` line states the
hosts, the unlisted policy and whether TLS can be terminated. Two refusals join the ledger,
`UNLISTED_DESTINATION` and `GOVERN_UNAVAILABLE`. `GatewayHttpServer` gains `accept(stream)`.
Nothing about the addressed gateway, the envelope ingress or the kit changes; an interceptor with
no `--govern` behaves as ADR 0004 says it does. `deploy/intercept/kubernetes/GovernExample.yaml`
is the patch that adds the authority and the settings to a workload beside the component.

## Security impact

- The authority's private key in the sidecar is a credential whose holder can impersonate every
  governed host to that workload. It is mounted as a Secret, read once at start, held in memory,
  and given no other job; the documentation says to keep it as the Decionis key is kept.
- The start-up check tells an authority from a leaf and a key from a stranger's; it cannot tell a
  CA made for this from one trusted for anything else. The guide says to make one for this and
  for nothing else, so that the trust the workload extends reaches exactly one hop.
- Clients that pin their provider's certificate refuse the leaf and fail closed. That is a change
  the operator must make deliberately, per client, and the guide says so.
- The gateway originates TLS to the real host and verifies it against the system trust store, so
  terminating the workload's TLS does not weaken the hop's own. A plaintext governed connection is
  forwarded as plaintext because that is what the workload sent; the report shows it as `HTTP`.
- Governed traffic passes through the gateway's request handling, which already bounds header and
  body sizes, refuses ambiguity and never forwards more than the authorized request once; the
  interceptor adds the handshake bound and nothing else to that surface.
- The leaf issuer, its DER writer and the governor are under the repository's mutation gate at
  100%: a leaf that names the wrong host, chains to the wrong issuer or is not strict DER, and a
  governor that hands bytes past the boundary or holds a connection its client has left, are
  mutants a test kills.
- Hosts are matched exactly, lowercase, on the name the client sent; a destination named by
  address is never governed, and a hello without a server name is refused as before.

## Migration impact

None for existing deployments; the observe-phase component, recipe and report are unchanged. An
operator who governs adds the authority to the workload's trust store, the certificate and key to
the sidecar, and the hosts to `AGENTSAFE_INTERCEPT_GOVERN`, in shadow mode first, and reads the
gateway's shadow report for those hosts before enforcing.
