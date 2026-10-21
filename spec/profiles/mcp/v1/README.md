# MCP Tool Profile v1

**Identifier:** `agent-safe.profile.mcp/1` · **Status:** draft · **Publisher:** Decionis ·
**Reference implementation:** `McpToolProfile` in
[`@decionis/agent-safe-pipeline`](../../../../packages/pipeline), read by `McpGuard` in
[`@decionis/agentsafe`](../../../../packages/agentsafe) · **Schema:** [`schema.json`](./schema.json) ·
**Vectors:** [`vectors/`](./vectors) · **Changes:** [`CHANGELOG.md`](./CHANGELOG.md)

An MCP tool profile describes an MCP server's consequential tools as data: the action each tool
becomes, the target it acts on, the argument that names its subject (the customer it acts for), the
arguments that decide what it does, and the arguments it accepts. A guard reads the profile in place
of a binding written in code, so governing a tool is a file an operator reviews, not code reached by
tool name. It is the MCP counterpart of the
[API intent profile](../../api/v1/README.md) and holds tool calls to the same subject rule. It is
published by Decionis and implemented by its reference runtime; it is not a standard approved by any
standards body.

The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119 and RFC 8174.

## 1. The definition

A closed JSON document, validated by [`schema.json`](./schema.json) and by the rules in §1.3 that
a schema cannot state.

### 1.1 Fields

| Field         | Meaning                                                                |
| ------------- | ---------------------------------------------------------------------- |
| `profile`     | Always `agent-safe.profile.mcp/1`.                                     |
| `id`          | `<system>/<server>/<version>`, for example `erp/mcp/v1`.               |
| `title`       | Plain words.                                                           |
| `system`      | The system the tools' effects land in: the intent's downstream system. |
| `environment` | Optional; the intent's downstream environment.                         |
| `tools`       | One to two hundred tools.                                              |

A tool:

| Field           | Meaning                                                                                                   |
| --------------- | --------------------------------------------------------------------------------------------------------- |
| `tool`          | The tool's name as the server publishes it; unique in the profile.                                        |
| `action`        | The intent's action type.                                                                                 |
| `operation`     | The operation in the downstream system: the intent's downstream operation.                                |
| `summary`       | Plain words.                                                                                              |
| `target`        | A template, such as `erp:customer:{customerNumber}`: literal text and `{argument}` placeholders.          |
| `subject`       | Optional. The argument naming the party the call is for (§3).                                             |
| `consequential` | The arguments that decide what the tool does, for evidence and an approval screen. They narrow nothing.   |
| `arguments`     | Argument name → `{ "type", "required"?, "maxLength"? }`: every argument the tool accepts, and only those. |

An argument's `type` is `string`, `number` (finite), `integer`, `boolean`, `array` or `object`
(holding JSON). `required` is `false` when absent. `maxLength` bounds a string. An argument's name
starts with a letter and holds letters, digits and `_`, at most 64 characters.

### 1.2 Arguments

A call's arguments MUST be refused (`MCP_ARGUMENTS_INVALID`) when one is not declared, a required
one is missing, or one is not of its declared type or is over its bound. An undeclared argument is
refused, never dropped: a dropped argument is one the authority never saw and the tool might still
act on. Every argument a call carries is in the intent's parameters, and so inside its hash.

### 1.3 Rules a schema cannot state

A definition MUST be refused (`MCP_PROFILE_INVALID`) when:

- two tools share a name, or an action (a grant authorizes an action, and the guard runs the one
  tool registered under it);
- a tool declares more than 64 arguments, or bounds the length of an argument that is not a string;
- a target's braces are unbalanced, a placeholder is empty, it holds more than 16 placeholders, or
  a placeholder is not a required argument of type `string`, `number`, `integer` or `boolean`;
- a `subject` is not a required argument of type `string`, `number` or `integer`;
- a consequential argument is named twice or is not declared.

## 2. Binding a call

A call is a tool name and its arguments, as MCP's `tools/call` carries them. A guard:

1. refuses a tool the profile does not declare (`MCP_TOOL_NOT_BOUND`), so adding a tool to a server
   cannot quietly add an ungoverned path to a system of record;
2. checks the arguments (§1.2);
3. checks the subject (§3);
4. fills the target, refusing one that does not resolve (`MCP_TARGET_UNRESOLVED`);
5. captures an [Agent-Safe Intent](../../../intent/v1/README.md): the tool's `action`, the filled
   `target`, the arguments as `parameters`, the profile's `system`, the tool's `operation` and the
   profile's `environment` as the downstream target, and in the trusted context `ingress: "mcp"`,
   `mcp_tool`, `mcp_arguments_digest`, the consequential arguments the call carried
   (`mcp_consequential`), and `session` (§3).

Every refusal in steps 1 to 4 is made before the authority is asked: it costs no decision and no
dossier. A tool bound this way and a tool bound in code produce the same intent.

## 3. Subjects

The host that runs the guard knows the session a call belongs to: the subject its identity
provider named for the conversation, which the host verifies and the model never sends. When a
tool names a `subject` argument, the guard MUST refuse the call:

- with no session subject: `SUBJECT_SESSION_REQUIRED`;
- when the argument names no subject (it is not a string or a finite number of 1 to 200
  characters once written as a string): `SUBJECT_ABSENT`;
- when it names another subject than the session's: `SUBJECT_MISMATCH`.

Subjects compare as exact strings; a number is written as its decimal string. This is the rule
[`agent-safe.profile.api/1`](../../api/v1/README.md#7-subjects) holds a read to. When the host gives
a session subject, the guard states it in the intent's trusted context as
`session: { "subject": <string> }` for every tool, scoped or not, so a policy reads the fact
`session.subject`. A tool with no `subject` is not scoped.

## 4. Conformance

[`vectors/`](./vectors) holds the vectors: a `definition`, an `invocation`
(`{ "tool", "arguments" }`), an optional `session` (the session's subject), and either the
`expected` binding (`action`, `target`, `operation`, `system`, `environment` when the profile states
one, the `consequential` arguments the call carried, and `session` when there is one) or the
`refusal` code; or a `definition` and the `error` it is refused with. An implementation conforms
when, for every vector, it binds the call exactly as expected, refuses it with the expected code, or
refuses the definition with the expected code.
