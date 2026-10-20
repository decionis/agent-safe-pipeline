# AgentCore Gateway: the gateway as a target's egress

An agent on Amazon Bedrock AgentCore reaches a platform's API through an AgentCore Gateway
target: the target turns the API's OpenAPI document into tools, and AgentCore calls the API when
the agent uses one. Put the AgentSafe gateway between the target and the platform, and every one of
those calls is decided by Decionis before it reaches Business Central or Walmart, under the same
policy, with the same facts, as the platform's own connector writes. A held or refused call is
answered by the gateway and never forwarded.

```text
agent ─▶ AgentCore Gateway target ─▶ AgentSafe gateway (your account) ─▶ Business Central / Walmart
                                              │
                                              └─▶ Decionis: decide, grant, evidence
```

## 1. Run the gateway in your account

The gateway is the published image (`ghcr.io/decionis/agentsafe`, mirrored to Docker Hub), run as
in [Deployment](./deployment.md) on ECS, EKS or a host: pin a verified digest, keep the Decionis
key in a secret file, and put HTTPS in front of it. Configure it with the platform's profile:

```yaml
version: 1
gateway:
  listen: "0.0.0.0:8080"
  upstream: "https://marketplace.walmartapis.com" # or https://api.businesscentral.dynamics.com
  environment: production
authority:
  endpoint: "https://api.decionis.com"
  tenantId: "00000000-0000-4000-8000-000000000000" # your Decionis organization
  mode: enforcement
  failurePolicy: failClosed
interception:
  profile: walmart/api/v3 # or businesscentral/api/v2
  unmatched: govern
evidence:
  enabled: true
  journalDir: /var/lib/agent-safe/evidence
```

`AGENTSAFE_PROFILE` sets the profile from the environment, which suits a task definition. The
profile names each consequential call's action and the facts it is decided with; see
[Routes](./routes.md#by-an-api-profile) and the profile itself in
[`profiles/`](../../profiles). Reads pass through unchanged.

Enforcement runs in the gateway you run. The hosted gateway fleet observes in shadow only, so it
can show what would have been held but never holds anything.

## 2. Write the target's OpenAPI document

```bash
agentsafe profile openapi walmart/api/v3 --server https://agentsafe.internal.example > walmart.json
```

The document's only server is your gateway, so the target cannot call the platform around it. Each
operation keeps the profile's summary as its tool description and says which action it is governed
as. For Business Central, `--prefix` picks the path form your target uses: the default is
`/v2.0/{tenantId}/{environment}/api/v2.0`, and `--prefix ""` gives bare paths when the gateway's
upstream already carries the API base.

## 3. Create the target

Create an OpenAPI target on your AgentCore Gateway from that document, with the outbound
credential the platform expects (Business Central's OAuth token; Walmart's access token and
headers). The gateway forwards the platform's credentials untouched and removes only hop-by-hop
headers and its own `AgentSafe-Tenant-Key`; set a tenant key digest on the gateway and give the
target the key when the gateway is reachable beyond the target.

## What the agent sees

| The decision               | The gateway answers                                                                                                    |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `ALLOW`                    | the platform's own answer, forwarded once (`agentsafe-execution: FORWARDED`, or `FAILED` / `INDETERMINATE`)            |
| `ESCALATE`                 | `202`, `HELD`, with how it resumes; nothing is sent until a person approves                                            |
| `BLOCK`                    | `403`, `NOT_FORWARDED`; nothing is sent                                                                                |
| Decionis cannot be reached | `503 AUTHORITY_UNAVAILABLE`, `NOT_FORWARDED`, failing closed; forwarded and recorded only under an explicit `failOpen` |

See [HTTP interception](./http-interception.md#responses-the-gateway-makes-itself) for the full response contract.
A tool call that came back held is not a success: an agent should report it, not retry it.
