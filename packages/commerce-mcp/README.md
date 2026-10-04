# Commerce Gate MCP — released-source index

Commerce owns ongoing MCP development and release preparation. This directory is a public index;
it is no longer a buildable AgentSafe workspace package.

The Commerce Gate MCP package is `@decionis/commerce`; its executable is `commercegate-mcp` and its MCP identity is `com.decionis/commerce-gate`.

The published `v0.1.6` source is pinned to commit
`087b591a19464ecfe0f8b33cac113cc6757944e6`:

- [Released source](https://github.com/decionis/agent-safe-pipeline/tree/087b591a19464ecfe0f8b33cac113cc6757944e6/packages/commerce-mcp)
- [Released README](https://github.com/decionis/agent-safe-pipeline/blob/087b591a19464ecfe0f8b33cac113cc6757944e6/packages/commerce-mcp/README.md)
- [Released license](https://github.com/decionis/agent-safe-pipeline/blob/087b591a19464ecfe0f8b33cac113cc6757944e6/packages/commerce-mcp/LICENSE)
- [GitHub MCP listing](https://github.com/mcp/com.decionis/commerce-gate)
- [Commerce Gate documentation](https://commerce.decionis.com/mcp)

The released runtime remains Apache-2.0 licensed. Its source, license, and Git history are preserved at the pinned commit.
Published tags, packages, and release artifacts are unchanged by the source move.

To run the released MCP runtime:

```sh
npx -y @decionis/commerce@0.1.6
```

The unpublished candidate moved to Commerce includes the optional versioned eleven-check preflight
contract. It is distinct from the released source above; moving it does not publish a new package
or enable a connector. The MCP records policy evidence and never executes a marketplace or ERP action.

For the ownership cutover, deliver and validate the candidate in Commerce before merging the
AgentSafe source-removal change. Future releases must publish the selected npm version before its
matching MCP registry entry. Future publishing configuration and provenance must be verified for
the owning repository; this index makes no provenance claim for a future private-repository publish.
