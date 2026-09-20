# Five-minute quickstart

Put AgentSafe in front of something that takes HTTP writes, send it one request, and watch the
request be intercepted, decided and either forwarded, held or refused. Nothing here needs an
account: without a Decionis key the gateway starts a local demo authority in the same process, on
loopback, with a synthetic policy, and says so on every line.

## From a clone

Requirements: Node.js 22.14 or later and pnpm 9.

```bash
git clone https://github.com/decionis/agent-safe-pipeline.git
cd agent-safe-pipeline
pnpm install --frozen-lockfile
pnpm --filter @decionis/agent-safe-pipeline build && pnpm --filter @decionis/agentsafe build
alias agentsafe="node $PWD/packages/agentsafe/dist/Cli.js"
```

The installed forms are the same runtime and the same commands: [macOS](../install/macos.md)
(Homebrew), [Linux](../install/linux.md) (packages and an installer), [Docker](../install/docker.md).

## Test your boundary

Before anything of yours is involved, see what the gateway changes:

```bash
agentsafe test
```

It sends eight consequential requests three ways at a synthetic loopback target that records what
reaches it: directly, through the gateway in shadow, and through the gateway in enforcement. Every
adversarial one reaches the target directly and in shadow; under enforcement each is refused or
held and none is forwarded, the routine ones go through exactly once with a dossier, a forged
approval header changes nothing, an unreachable authority fails closed, and the evidence the run
left verifies. The last line is `Verdict BOUNDARY HOLDS` and the exit status `0`. Nothing real is
called and nothing in your configuration, environment or stored login is read; the gateways under
test are the same `Gateway` behind the same listener that `agentsafe proxy` runs. Name a real
system of record, `agentsafe test ledger=ledger.internal:443`, and the test also dials it from
where you stand and says whether it answers without the gateway.

To see Decionis decide the same requests, `agentsafe login --provision` (a free workspace, no
account, shadow only) then `agentsafe test --hosted`: the first governed action against Decionis
for that workspace, and a signed Decision Dossier per consequential request, fetched and shown by
its proof. Nothing real is called there either.

## Start the gateway

Anything that answers HTTP will do as the upstream. If you have nothing to hand:

```bash
node -e 'require("http").createServer((q,s)=>{s.writeHead(201,{"content-type":"application/json"});s.end("{\"ok\":true}")}).listen(3000)' &
```

Then:

```bash
agentsafe proxy --upstream http://localhost:3000 --port 8080
```

```text
AgentSafe 0.2.2

Gateway      http://127.0.0.1:8080
Upstream     http://localhost:3000
Mode         ENFORCEMENT
Authority    local/demo (synthetic policy on loopback; not Decionis)
Failure      fail-closed
Routes       none named; every unsafe method is governed
Evidence     not written; use --verbose or evidence.journalDir
Status       READY

Waiting for consequential actions...
```

## Send your first governed action

In another terminal:

```bash
curl -i -X POST http://127.0.0.1:8080/payments \
  -H 'content-type: application/json' \
  -d '{"amount": 500}'
```

The gateway prints:

```text
ESCALATE

POST /payments

Action       http.post
Decision     ESCALATE
Reason       HUMAN_APPROVAL_REQUIRED
Execution    HELD
Dossier      synthetic-dossier-1
Latency      4ms
```

and the caller receives `202 Accepted` with the same facts as JSON, a `resume` path, and nothing
from the upstream: the request was held, not forwarded. The demo policy escalates anything over
100.00 and blocks anything over 1,000.00 (in `amount`, or `amountMinor` in minor units), escalates
every `DELETE` and every body it cannot read, and allows the rest. Try the other two:

```bash
curl -i -X POST http://127.0.0.1:8080/payments -H 'content-type: application/json' -d '{"amount": 50}'
curl -i -X POST http://127.0.0.1:8080/payments -H 'content-type: application/json' -d '{"amount": 5000}'
```

The first is `ALLOW`: the exact bytes go to the upstream once, under a claimed single-use grant,
and the upstream's own answer comes back with `agentsafe-decision`, `agentsafe-dossier-id` and
`agentsafe-execution: FORWARDED` beside it. The second is `BLOCK`: `403`, not forwarded, with the
dossier that records why. A `GET` is not consequential and passes through untouched.

## See the evidence

Every step is a chained line: the captured intent, the authority's decision, the grant consumed,
the execution and its finalization. Run with `--verbose` to see them on the terminal, or give them
a directory:

```bash
agentsafe proxy --upstream http://localhost:3000 --port 8080 --verbose
```

With `evidence.journalDir` in [`agentsafe.yaml`](../reference/config.md) the lines go to
`evidence.jsonl` there, and `agentsafe verify chain <that file>` checks the chain offline.

## Connect Decionis

The demo authority is for the first five minutes. With a Decionis key the same gateway asks the
Decionis authority instead, in shadow first:

```bash
agentsafe login              # stores the key for this user, readable by this user alone
export DECIONIS_TENANT_ID=... # the key's organization id, if login did not record it
agentsafe doctor             # binary, configuration, upstream, Decionis, credentials, evidence
agentsafe proxy --upstream http://localhost:3000 --port 8080
```

`Mode` is now `SHADOW`: every consequential request goes through unchanged while Decionis records
what it would have decided, and each line says `Would decide` and `Actual execution PASSTHROUGH`.
`agentsafe status` prints the [shadow report](../shadow-mode.md#from-shadow-to-enforcement) so
far, what enforcement would have held or refused by action, and the gateway prints it when it
stops. When the decisions look right, `--mode enforcement` makes them binding. A key without an account
comes from `POST https://api.decionis.com/v1/public/agents/provision` (no signup, 50 decisions a
month, every dossier marked `provisional_anonymous`); an owned organization's key comes from the
Decionis console.

## Where next

- [Configuration](../reference/config.md): the file, `agentsafe init`, and the precedence.
- [HTTP interception](../gateway/http-interception.md): what is intercepted, what is bound, what
  is forwarded.
- [Failure policy](../gateway/failure-policy.md): what happens when Decionis cannot be reached.
- [CLI reference](../reference/cli.md).
