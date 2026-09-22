# Framework coverage

What four agent frameworks' and protocols' tool-call records carry of an Agent-Safe Intent binding, and what
the adapter adds. This is a description, not a grade: no framework was designed to carry
execution authority, and none of these needs to change for a producer built on it to conform.
Each row is a vector under [`conformance/frameworks/`](../../../conformance/frameworks) that
carries the framework's own record, the proposal it becomes, the trusted context, and the
binding, bytes and hash that result; the reference test reproduces every one, and
`agentsafe verify intent conformance/frameworks` does the same offline.

The record shapes were read from the frameworks' own public documentation and source on
**2026-09-19** and are quoted from there; a change on their side is a correction here, reported
as §10 of the [specification](./README.md) says.

MCP is the one column whose adapter is not an integration's to write: `@decionis/agentsafe` ships
it as `bindMcpInvocation`, so the vector is reproduced from the outside by the reference
implementation and from the inside by the shipped adapter
([MCP interception](../../../docs/authority/mcp-interception.md)).

## The matrix

| Capability           | OpenAI Responses API / Agents SDK      | Vercel AI SDK                         | LangChain                               | MCP (`tools/call`)                      |
| -------------------- | -------------------------------------- | ------------------------------------- | --------------------------------------- | --------------------------------------- |
| `action_identity`    | native: `name`                         | native: `toolName`                    | native: `name`                          | native: `params.name`                   |
| `parameters`         | adapter: `arguments` is a JSON string  | native: `input` is an object          | native: `args` is an object             | native: `params.arguments` is an object |
| `target_identity`    | adapter                                | adapter                               | adapter                                 | adapter: the shipped binder's template  |
| `principal`          | adapter                                | adapter                               | adapter                                 | adapter                                 |
| `expiry`             | adapter                                | adapter                               | adapter                                 | adapter                                 |
| `idempotency`        | adapter (`call_id` is the model's)     | adapter (`toolCallId` is the model's) | adapter (`id` is the model's, optional) | adapter (the caller's, when it has one) |
| `intent_digest`      | adapter                                | adapter                               | adapter                                 | adapter                                 |
| `effect_correlation` | native: `function_call_output.call_id` | native: `tool-result.toolCallId`      | native: `ToolMessage.tool_call_id`      | native: the JSON-RPC `id`               |

Read down a column: every framework names the action and correlates the result with the call;
two of the three hand over the arguments as the object that is hashed and one hands over text.
Nothing else that authority must be bound to is in the record, and that is not a defect of the
frameworks: the principal, the target, the expiry, the retry identity and the digest are the
trusted runtime's to state, because an agent that could state them could state the ones it
wants. The adapter is the same shape for all three, and it is small.

## The records

**OpenAI**, a `function_call` item as the Responses API returns it and as the Agents SDK's
function tools produce it; the result goes back as `function_call_output` with the same
`call_id` ([function calling guide](https://developers.openai.com/api/docs/guides/function-calling)):

```json
{
  "id": "fc_synthetic_1",
  "call_id": "call_synthetic_1",
  "type": "function_call",
  "name": "refund_order",
  "arguments": "{\"orderId\":\"synthetic-1\",\"amountMinor\":35000,\"currency\":\"USD\"}"
}
```

**Vercel AI SDK**, a `tool-call` part as `generateText` and `streamText` return it; the
`tool-result` part carries the same `toolCallId`
([`generateText` reference](https://ai-sdk.dev/docs/reference/ai-sdk-core/generate-text)):

```json
{
  "type": "tool-call",
  "toolCallId": "call_synthetic_2",
  "toolName": "refund_order",
  "input": { "orderId": "synthetic-1", "amountMinor": 35000, "currency": "USD" }
}
```

**LangChain**, a `ToolCall` as an `AIMessage` carries it in `tool_calls` and a LangGraph
`ToolNode` receives it; the `ToolMessage` answers with the same id as `tool_call_id`
([`ToolCall` in `@langchain/core`](https://github.com/langchain-ai/langchainjs/blob/main/libs/langchain-core/src/messages/tool.ts)):

```json
{
  "type": "tool_call",
  "id": "call_synthetic_3",
  "name": "refund_order",
  "args": { "orderId": "synthetic-1", "amountMinor": 35000, "currency": "USD" }
}
```

## The adapter

The adapter is the few lines between the record and `IntentCapture`. In the reference test it is
exactly this, once per framework:

```ts
// OpenAI: the arguments are a JSON string.
const parameters = JSON.parse(item.arguments) as JsonObject;
const proposal = { action: item.name, target: `shopify:order:${parameters.orderId}`, parameters };

// Vercel AI SDK: the input is already an object.
const proposal = {
  action: part.toolName,
  target: `shopify:order:${part.input.orderId}`,
  parameters: part.input,
};

// LangChain: the args are already an object.
const proposal = {
  action: call.name,
  target: `shopify:order:${call.args.orderId}`,
  parameters: call.args,
};

// The same for all three: the trusted runtime states what the record cannot.
const captured = new IntentCapture().capture(proposal, {
  tenantId, // the organization
  actor: { id: "synthetic-support-agent", type: "AI_AGENT", runtime: "openai" }, // the principal, from the runtime's own identity
  downstreamTarget: { system: "shopify", operation: "refund", endpoint: "POST /refunds" },
  context: { source: "conformance", tool_call_id: item.call_id }, // the framework's id, kept for correlation
  idempotencyKey: "refund-synthetic-1-openai-v1", // the runtime's retry identity, never the model's id
});
// captured.intentHash is what the authority is asked about and what the grant is bound to.
```

The target is the adapter's to name because the framework does not distinguish it from the
other arguments; which argument identifies the resource is a property of the tool, not of the
framework. The framework's call id is kept in the trusted context so the binding correlates with
the framework's own record, and it is not used as the idempotency key: it identifies the model's
call, and a retry of the same call by the runtime must present the same intent, while a new call
with the same id from a different turn must not.

## What this does not say

- It does not say a framework is or is not secure, compliant or suitable; it says what its
  record carries.
- It does not say the adapter above is the only one; a producer may bind more into `context` and
  name the target differently. What it must not do is let the agent supply any of it.
- It does not cover CrewAI, AutoGen, Mastra or others; a vector for one is a pull request under
  `conformance/frameworks/`, in this shape, with its coverage row.
