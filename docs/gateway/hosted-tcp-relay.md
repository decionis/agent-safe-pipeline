# Hosted TCP relay

AgentSafe 0.3.0 can connect a local application to an enabled Decionis TCP resource through an
outbound connector. The connector opens only its locally configured numeric IP and port.
The relay controls connections and forwards opaque bytes; it does not make SQL or API
ALLOW/HOLD/BLOCK decisions.

## Enable the resource and save its credentials

Enable TCP for the resource in your workspace. The resource must contain a numeric IP and an
explicit port, such as `10.20.30.40:5432`. A public-address resource uses the same form, for
example `203.0.113.10:5432` (a documentation address to replace with your resource). IPv6 uses
brackets, such as `[fd00::10]:5432`.

Reveal the route credentials once. Save the **connector credential** as `connector.key` on a
machine that can reach the resource, and the different **client credential** as `client.key`
on the application machine. Keep the values in those files, outside commands and logs. They
are route credentials, separate from a workspace API key.

The following commands require Node.js 22.14 or newer. Replace the example gateway, route UUID,
and target with the exact values for your resource. Relative credential paths are resolved
from the directory where you run the command.

## Run the connector beside the service

On the machine that can reach `10.20.30.40:5432`:

```sh
chmod 600 ./connector.key
npx @decionis/agentsafe@0.7.0 connector \
  --gateway https://acme.decionisedge.com \
  --route 00000000-0000-4000-8000-000000000123 \
  --credential-file ./connector.key \
  --target 10.20.30.40:5432
```

The connector keeps two spare outbound connections ready for applications. It validates each
ticket against the configured route, gateway, and target before connecting to the service.
The relay cannot supply a different target.

## Run the tunnel beside the application

On the application machine:

```sh
chmod 600 ./client.key
npx @decionis/agentsafe@0.7.0 tunnel \
  --gateway https://acme.decionisedge.com \
  --route 00000000-0000-4000-8000-000000000123 \
  --credential-file ./client.key \
  --target 10.20.30.40:5432 \
  --port 15432
```

Connect the application to `127.0.0.1:15432`. The tunnel always binds loopback; `--port` does
not expose it on other interfaces. Both commands require the same `--target` to verify the
resource binding, even when the application machine cannot directly reach that address.

Both commands use `https://api.decionis.com` by default. `--control-api <https-origin>`
(alias `--api`) selects another control-plane deployment. See the
[CLI reference](../reference/cli.md#agentsafe-connector-agentsafe-tunnel).

## Networking and application TLS

The tunnel and connector each make an outbound HTTPS CONNECT connection to the tenant gateway
on port 443, with TLS 1.2 or newer and certificate verification. They also reach the control API
over HTTPS on port 443. Allow DNS resolution and those outbound connections; no inbound customer
firewall opening is needed. The connector additionally needs access to the configured service
IP and port on its own network.

These are two TLS connections to the relay. Application TLS can pass through them unchanged.
Configure the application to dial `127.0.0.1:15432` while verifying the **actual service
hostname** and its certificate chain. For example, PostgreSQL libpq supports
`host=db.internal.example hostaddr=127.0.0.1 port=15432 sslmode=verify-full`; configure its trusted
CA for that service. The localhost dial address does not replace the server identity.

## Status, stopping, and limits

“Connector online” means an authenticated connector leg is present. It does not establish that
a database login or an application request succeeds.

`Ctrl+C`, `SIGINT`, or `SIGTERM` stops a command and closes its channels. Disabling TCP for the
resource revokes credentials and new tickets; the broker closes existing channels when leases
are rechecked. Leases refresh every 10 seconds and expire within 30 seconds.

One broker performs rendezvous. A broker restart closes existing sessions; connectors reconnect
with backoff, and applications must reopen lost connections. There is no seamless failover.
Authenticated connector spares wait under their leases until they close or reach the idle or
session limit. Healthy idle reconnections reset backoff, even when no client has attached.

Version 1 limits are:

| Limit                                    | Value                                       |
| ---------------------------------------- | ------------------------------------------- |
| Broker legs, including waiting legs      | 128 total, 16 per organization, 8 per route |
| Local command legs                       | 8 maximum; connector keeps up to 2 spares   |
| Client waiting for a matching connector  | 20 seconds                                  |
| Connecting to the fixed service target   | 10 seconds                                  |
| Idle session / maximum session duration  | 300 seconds / 1 hour                        |
| Bytes per pair, both directions combined | 1 GiB                                       |

A leg is one endpoint connection to the relay. An active session uses two legs, one for the
client and one for the connector; spare connector legs also count toward the limits.
