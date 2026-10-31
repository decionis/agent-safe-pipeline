# What an integration requires

What each way of putting AgentSafe in front of an action asks of you: what you supply, what code you
write, what runs beside it, what you measure, and who supports which part. This page claims nothing
of its own. Each row points to the guide that states it, and the guide is the authority if the two
ever differ.

## By form

| Form                                                           | Where the boundary sits                                           | You supply                                                                                                                                                                                                         | Code you write                                                                                                                             | Is the effect read back?                                                                                                                                                     | Guide                                                                                                                         |
| -------------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Gateway, addressed (`agentsafe proxy`, `agentsafe gateway`)    | A URL the agent or tool is configured to call instead of the API  | An authority and its key; the upstream credential the gateway forwards with, or the gateway's own token; a network or identity control that keeps the agent from calling the API directly; an evidence destination | None for an API a shipped profile covers. Otherwise an [API intent profile](../../spec/profiles/api/v1/README.md), which is data, not code | No. The gateway relays the upstream's answer ([execution outcomes](../execution-outcomes.md#acknowledged-effected-consequential)), unless the upstream signs effect receipts | [Agent integration](../gateway/deployment.md), [routes](../gateway/routes.md)                                                 |
| Gateway, transparent (`agentsafe intercept`)                   | The workload's own egress on ports 80 and 443                     | The redirect that sends that traffic to the interceptor; for the destinations it governs, a certificate authority you hold and the workload trusts                                                                 | As for the addressed gateway                                                                                                               | As for the addressed gateway                                                                                                                                                 | [Transparent interception](../gateway/transparent-interception.md)                                                            |
| Managed gateway (run by Decionis; enforcement in private beta) | An assigned cloud gateway in front of a public HTTPS API          | A Decionis workspace. In enforcement, the upstream credential, which the gateway holds in a key vault of your tenant's own                                                                                         | As for the addressed gateway                                                                                                               | As for the addressed gateway                                                                                                                                                 | [Managed gateway](../gateway/deployment.md#set-up-the-decionis-managed-cloud-gateway), [hosted install](../install/hosted.md) |
| Trusted executor (`agentsafe serve`) with an adapter family    | A separate process that alone holds the downstream credentials    | Principals and their credentials; the downstream credentials; the host posture the executor checks at start; an egress policy; a volume for the attempt journal                                                    | Nothing for the `forward`, `banking` and `cards` families. Otherwise a handler, and an `EffectAdapter` if its effect is to be read back    | Yes, for families with an effect plane (banking, cards) and for an `EffectAdapter` of your own                                                                               | [Trusted executor kit](../../deploy/README.md), [production](./production.md)                                                 |
| MCP guard                                                      | After the tool and its arguments are chosen, before the tool runs | An authority; a [tool profile](../../spec/profiles/mcp/v1/README.md) for each governed tool                                                                                                                        | A binding in code, or a declarative tool profile                                                                                           | No: the guard reports whether the tool ran, and a lost outcome as unknown, never as "no"                                                                                     | [MCP interception](../authority/mcp-interception.md)                                                                          |
| The library in process (`@decionis/agent-safe-pipeline`)       | Inside your service, between the decision and the handler         | A `DecisionAuthority` and an `AuthorizationVerifier`: the Decionis service, or your own implementation                                                                                                             | The handlers registered for each action                                                                                                    | Only when your runtime observes the effect and supplies effect evidence at finalization ([effect evidence](../execution-outcomes.md#effect-evidence))                        | [The library](../../README.md#the-library)                                                                                    |
| Verifying provider                                             | At the system of record, or the last hop its owner controls       | A system of record, or a last hop, that holds the only credential the system accepts, running a verifier                                                                                                           | The verification procedure, or one of the reference verifiers under `verifiers/`                                                           | At VP-3, by the provider's signed effect receipt                                                                                                                             | [Verifying Provider Profile](../authority/verifying-provider.md)                                                              |

## What runs beside every form

- **The authority.** Decionis decides, in one of three tiers: hosted, dedicated single-tenant, or
  self-managed under a commercial licence ([hosting tiers](../gateway/deployment.md#hosting-tiers-and-where-the-keys-live)).
  The same page lists which key signs what, and where each key lives.
- **Presence**, only if a policy answers `ESCALATE` to a person ([human approval](../human-approval.md)).
- **Your evidence store.** The chained streams are written where you point them, and verified
  offline ([executor evidence](../executor-evidence.md)).

## What you measure

This repository publishes no latency or throughput figure for the gateway or the executor.
[High availability](./high-availability.md) says what to measure: the whole lifecycle, under the
workload you intend to run. The exception is card authorization, which states measured in-process
figures and the budgets its suite asserts ([card authorization](../banking/card-authorization.md)).

## Who supports what

- This repository is a public reference implementation. It carries no response-time commitment for
  issues or pull requests ([SUPPORT.md](../../SUPPORT.md)), and its maintenance policy is not a
  service-level agreement ([MAINTENANCE.md](../../MAINTENANCE.md)). Vulnerability reports have the
  targets in [SECURITY.md](../../SECURITY.md).
- The Decionis service is operated under its own terms. [OPEN-CORE.md](../../OPEN-CORE.md) states
  the seam between what this repository ships and what Decionis operates.
- Your cluster, network, secret store and on-call stay yours. The [owner table](../../EVALUATION-PATH.md#who-owns-which-control)
  says which controls those are.

## Before enforcement

Run the checks in [Verify the boundary before promotion](./gateway-strategies.md#verify-the-boundary-before-promotion)
from the agent's own network and identity. Record the image, the configuration and the network
policy they ran against. [Four questions](../../EVALUATION-PATH.md#four-questions-and-where-each-answer-stops)
says what that evidence establishes for a deployment, and what it leaves unsaid.
