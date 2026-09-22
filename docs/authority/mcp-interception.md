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

A binding is what an operator declares about one consequential tool, in trusted startup code
beside the code that will run it:

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

`target` is a template, not a callback, so a binding stays something an operator can read — and
later hold in configuration — rather than arbitrary code reached by tool name.

`invoke` runs only behind a claimed single-use grant.

## What it refuses, and when

Three refusals happen **before the authority is asked**, so none of them costs a decision or a
dossier:

| Refusal                 | Why it is a refusal and not a default                                                                 |
| ----------------------- | ----------------------------------------------------------------------------------------------------- |
| `MCP_TOOL_NOT_BOUND`    | adding a consequential tool to a server must not quietly add an ungoverned path to a system of record |
| `MCP_ARGUMENTS_INVALID` | a dropped argument is one the authority never saw and the tool might still act on                     |
| `MCP_TARGET_UNRESOLVED` | a target that cannot be resolved from the arguments is refused rather than guessed                    |

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
- [The enforcement boundary](./enforcement-boundary.md) and [workload provenance](./workload-provenance.md)
- [Execution outcomes](../execution-outcomes.md) — committed, failed, indeterminate
