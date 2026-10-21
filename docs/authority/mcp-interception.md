# MCP execution interception

The Model Context Protocol has become the connective layer between agents and the tools they
reach. It is very good at a question this project does not answer:

> **MCP decides _how_ an agent invokes a tool.**
>
> **AgentSafe and Decionis decide whether _this exact invocation_ is authorized to execute.**

Those are different questions, and the gap between them is where a consequential tool call goes
wrong. A tool can be correctly published, correctly authenticated and correctly called, and still
be deleting the wrong customer or moving more money than the institution permits.

## Where the boundary sits

```text
Agent
  ↓
MCP
  ↓
tool selected
  ↓
arguments constructed
  ↓
AgentSafe          ← here
  ↓
Agent-Safe Intent
  ↓
enforce-and-bind
  ↓
Decionis  →  ALLOW | BLOCK | ESCALATE
  ↓
atomic claim
  ↓
the tool runs, exactly once
```

Everything above the marked line is MCP's. Everything below it is the same lifecycle every other
AgentSafe surface runs, unchanged.

## What this is not

- **Not an MCP server.** `McpGuard` depends on no MCP SDK. A server hands it a plain
  `{ tool, arguments }` and gets back a verdict; stdio, streamable HTTP and a test all hand over
  the same thing.
- **Not an MCP registry.** It holds the tools an operator bound, and nothing about discovery,
  publication or distribution.
- **Not a replacement for MCP authentication.** Whoever the caller is remains MCP's and the host's
  question. This one is about the action.

## Declaring a tool

A tool is declared as data, in an [MCP tool profile](../../spec/profiles/mcp/v1/README.md)
(`agent-safe.profile.mcp/1`): the action it becomes, its target template, the argument that names
its subject, its consequential arguments and every argument it accepts. The guard reads the file;
the code beside it only says what each tool does.

```json
{
  "profile": "agent-safe.profile.mcp/1",
  "id": "erp/mcp/v1",
  "title": "Your ERP's MCP server",
  "system": "erp",
  "tools": [
    {
      "tool": "update_credit_limit",
      "action": "customer.credit_limit.update",
      "operation": "customers.updateCreditLimit",
      "summary": "Set a customer's credit limit.",
      "target": "erp:customer:{customerNumber}",
      "subject": "customerNumber",
      "consequential": ["customerNumber", "creditLimit"],
      "arguments": {
        "customerNumber": { "type": "string", "required": true, "maxLength": 50 },
        "creditLimit": { "type": "number", "required": true },
        "note": { "type": "string", "maxLength": 200 }
      }
    }
  ]
}
```

```ts
const guard = new McpGuard({
  profile: McpToolProfile.parse(JSON.parse(readFileSync("erp-mcp.json", "utf8"))),
  tools: [{ tool: "update_credit_limit", invoke: async (args) => await erp.setCreditLimit(args) }],
  authority: gate.authority,
  verifier: gate.verifier,
  tenantId: gate.tenantId,
  actor: { id: "synthetic-mcp-agent", type: "AI_AGENT", runtime: "mcp" },
});
```

A tool listed in `tools` that the profile does not declare is refused when the guard is built
(`MCP_TOOL_NOT_PROFILED`), and a tool the profile declares but `tools` does not implement is not
governed, so a call to it is refused (`MCP_TOOL_NOT_BOUND`).

### A binding in code

A binding written in TypeScript still works, beside or instead of a profile, and may name a
`subject` too. It is what an operator declares about one consequential tool, in trusted startup
code beside the code that will run it:

```ts
const guard = new McpGuard({
  tools: [
    {
      binding: {
        tool: "delete_customer",
        action: "delete_customer",
        system: "crm",
        operation: "delete_customer",
        target: "crm:customer:{customerId}",
        consequential: ["customerId"],
        argumentsSchema: z.object({ customerId: z.string().min(1).max(120) }).strict(),
      },
      invoke: async (args) => await crm.delete(args["customerId"]),
    },
  ],
  authority: gate.authority,
  verifier: gate.verifier,
  tenantId: gate.tenantId,
  actor: { id: "synthetic-mcp-agent", type: "AI_AGENT", runtime: "mcp" },
});
```

`target` is a template, not a callback, so a binding stays something an operator can read, and can
hold in a profile, rather than arbitrary code reached by tool name.

`invoke` runs only behind a claimed single-use grant.

## The customer in context

An agent serving one customer should act for that customer only. The host knows whose
conversation it is: it verifies the token your identity provider issued for the session, the way
the gateway's [subject-bound sessions](../gateway/subject-sessions.md) do (`SubjectSessions` and
`IssuerSubjectVerifier` are exported for it), and passes the subject to the guard. The model never
sends it.

```ts
const outcome = await guard.guard(invocation, { subject: verifiedCustomerNumber });
```

A tool whose profile or binding names a `subject` argument is refused, before the authority is
asked, without a session subject (`SUBJECT_SESSION_REQUIRED`), when the argument names no one
(`SUBJECT_ABSENT`), or when it names another customer (`SUBJECT_MISMATCH`). Every intent captured
with a session subject states it as `session: { subject }`, so a policy reads the fact
`session.subject`.

## What it refuses, and when

These refusals happen **before the authority is asked**, so none of them costs a decision or a
dossier:

| Refusal                    | Why it is a refusal and not a default                                                                 |
| -------------------------- | ----------------------------------------------------------------------------------------------------- |
| `MCP_TOOL_NOT_BOUND`       | adding a consequential tool to a server must not quietly add an ungoverned path to a system of record |
| `MCP_ARGUMENTS_INVALID`    | a dropped argument is one the authority never saw and the tool might still act on                     |
| `SUBJECT_SESSION_REQUIRED` | a tool scoped to a customer has no customer to be scoped to                                           |
| `SUBJECT_ABSENT`           | the subject argument names no one                                                                     |
| `SUBJECT_MISMATCH`         | the call is for another customer than the session's                                                   |
| `MCP_TARGET_UNRESOLVED`    | a target that cannot be resolved from the arguments is refused rather than guessed                    |

After that the ordinary lifecycle applies: `DECISION_NOT_ALLOW` for a BLOCK or an ESCALATE,
`INTENT_BINDING_MISMATCH` for a decision about a different invocation, and the atomic claim for
single use.

## Arguments cannot change after the authority

This is the property the whole adapter exists for, and it holds twice over.

**In the hash.** Every argument is inside the canonical intent hash. An argument that changes is a
different intent, and the grant issued for the first authorizes none of the second:

```text
authorized   delete_customer { customerId: "42" }     →  ALLOW, grant for sha256:a…
presented    delete_customer { customerId: "9000" }   →  INTENT_BINDING_MISMATCH
```

**At the dispatch.** The tool is handed the parameters off the hash-bound intent, never a copy
something else could have edited, and the handler recomputes their canonical digest immediately
before the point of no return and compares it to the one binding recorded. A tool receives the
arguments a policy saw, or receives nothing.

## What the intent carries

Beyond the action, target and arguments, the context records what MCP knew:

| Key                    | Meaning                                                          |
| ---------------------- | ---------------------------------------------------------------- |
| `ingress`              | `mcp`                                                            |
| `mcp_tool`             | the tool as the server published it                              |
| `mcp_arguments_digest` | the canonical digest of the arguments, under RFC 8785            |
| `mcp_consequential`    | the arguments an operator named as deciding what the action does |
| `mcp_server`           | which server holds the tool, when a caller runs more than one    |
| `mcp_transport`        | how the call arrived; carried as context, never as authority     |
| `claimed_principal`    | the host's authenticated principal, else what the caller claimed |
| `session`              | `{ subject }`, the session's subject, when the host gave one     |

`mcp_consequential` narrows nothing: every argument is in the proposal and therefore in the hash.
It is there so evidence and an approval screen can show the few that matter.

The [enforcement boundary](./enforcement-boundary.md) and
[workload provenance](./workload-provenance.md) are bound too, when the process has them.

## Outcomes

`guard()` returns the executor's own vocabulary rather than simplifying it:

| `executed` | Means                                          |
| ---------- | ---------------------------------------------- |
| `true`     | the grant was claimed and the tool ran, once   |
| `false`    | nothing ran, and `reason` says what refused it |
| `null`     | the tool was reached and its outcome was lost  |

`null` is not "no". Re-invoking on it would be a second attempt at an effect that may already
exist; reconcile instead ([execution outcomes](../execution-outcomes.md)).

## Conformance

[`conformance/frameworks/mcp.json`](../../conformance/frameworks/mcp.json) pins a `tools/call`
request, the tool binding an operator declared, the proposal, the canonical bytes and the hash.
Unlike the other three frameworks, whose record-to-proposal mapping each integration writes,
MCP's ships: the pipeline reproduces the vector from the outside and the package holds
`bindMcpInvocation` to it from the inside, so the file is a contract between the two rather than a
transcript.

[`examples/mcp-tool-gate`](../../examples/mcp-tool-gate) is a real stdio MCP server running on it.

## See also

- [Agent-Safe Intent v1](../../spec/intent/v1/README.md) — what is inside the hash, and why
- [MCP Tool Profile v1](../../spec/profiles/mcp/v1/README.md) — tools as data, and the subject rule
- [The enforcement boundary](./enforcement-boundary.md) and [workload provenance](./workload-provenance.md)
- [Execution outcomes](../execution-outcomes.md) — committed, failed, indeterminate
