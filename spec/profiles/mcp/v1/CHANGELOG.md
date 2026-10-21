# MCP Tool Profile v1: changes

Every entry names what changed and the vectors that pin it.

## 2026-10-21: the profile

- The profile is written down: a closed definition of an MCP server's consequential tools, each
  with its action, target template, subject argument, consequential arguments and the arguments it
  accepts ([README.md](./README.md)).
- [`schema.json`](./schema.json), JSON Schema 2020-12 of the definition, generated from the
  reference implementation's validator; a test holds the file to the generator.
- [`vectors/`](./vectors): binding from the profile, each subject refusal, argument refusals, an
  undeclared tool, and ten definition refusals.
- `McpGuard` reads the profile (`profile` and profiled `tools`); a binding written in code still
  works and is held to the same subject rule when it names a `subject`.
