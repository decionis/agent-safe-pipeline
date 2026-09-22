import { readFile } from "node:fs/promises";
import { z } from "zod";
import { describe, expect, it } from "vitest";
import {
  CanonicalIntentHasher,
  IntentCapture,
  type AgentProposal,
  type JsonObject,
  type TrustedIntentContext,
} from "@decionis/agent-safe-pipeline";
import { bindMcpInvocation } from "../../../src/adapters/mcp/McpIntentBinder.js";
import type { McpToolBinding } from "../../../src/adapters/mcp/McpInvocation.js";
import { repositoryPath } from "../../support/RepositoryRoot.js";

/**
 * The MCP framework vector, from the side that ships the adapter.
 *
 * The pipeline's own coverage test reproduces this file from the outside:
 * given the tool binding an operator declared, these are the proposal, the
 * canonical bytes and the hash. This holds `bindMcpInvocation` to the same
 * file, so the vector is a contract between the two rather than a transcript
 * of whatever the binder happens to do.
 */
interface McpVector {
  readonly framework: "mcp";
  readonly record: {
    readonly id: string;
    readonly params: { readonly name: string; readonly arguments: JsonObject };
  };
  readonly tool_binding: Omit<McpToolBinding, "argumentsSchema">;
  readonly proposal: AgentProposal;
  readonly trusted_context: TrustedIntentContext;
  readonly capture: { intent_id: string; captured_at: string; ttl_seconds: number };
  readonly binding: JsonObject;
  readonly canonical_json: string;
  readonly intent_hash: string;
}

async function vector(): Promise<McpVector> {
  const path = repositoryPath("conformance", "frameworks", "mcp.json");
  return JSON.parse(await readFile(path, "utf8")) as McpVector;
}

describe("the MCP framework vector", () => {
  it("is what the shipped binder produces, byte for byte and hash for hash", async () => {
    const file = await vector();
    const binding: McpToolBinding = {
      ...file.tool_binding,
      argumentsSchema: z
        .object({ customerId: z.string().min(1).max(120) })
        .strict() as unknown as z.ZodType<JsonObject>,
    };
    const bound = bindMcpInvocation(
      {
        tool: file.record.params.name,
        arguments: file.record.params.arguments,
        server: "synthetic-crm-tools",
        transport: "stdio",
        correlationId: file.record.id,
        idempotencyKey: file.trusted_context.idempotencyKey,
      },
      binding,
      { idempotencyKey: "unused" },
    );

    expect(bound.proposal).toEqual(file.proposal);
    // The context the binder computes is the vector's, less the correlation
    // the trusted runtime adds under the convention the other frameworks use.
    expect({ ...bound.context, tool_call_id: file.record.id }).toEqual(
      file.trusted_context.context,
    );

    const captured = new IntentCapture({
      clock: () => new Date(file.capture.captured_at),
      createId: () => file.capture.intent_id,
      ttlSeconds: file.capture.ttl_seconds,
    }).capture(bound.proposal, file.trusted_context);

    expect(CanonicalIntentHasher.bindingOf(captured.intent)).toEqual(file.binding);
    expect(captured.canonicalIntent).toBe(file.canonical_json);
    expect(captured.intentHash).toBe(file.intent_hash);
  });

  it("changes the hash when a single argument changes", async () => {
    const file = await vector();
    const binding: McpToolBinding = {
      ...file.tool_binding,
      argumentsSchema: z
        .object({ customerId: z.string().min(1).max(120) })
        .strict() as unknown as z.ZodType<JsonObject>,
    };
    const capture = new IntentCapture({
      clock: () => new Date(file.capture.captured_at),
      createId: () => file.capture.intent_id,
      ttlSeconds: file.capture.ttl_seconds,
    });
    const mutated = bindMcpInvocation(
      {
        tool: file.record.params.name,
        arguments: { customerId: "synthetic-2" },
        server: "synthetic-crm-tools",
        transport: "stdio",
        correlationId: file.record.id,
        idempotencyKey: file.trusted_context.idempotencyKey,
      },
      binding,
      { idempotencyKey: "unused" },
    );
    const captured = capture.capture(mutated.proposal, {
      ...file.trusted_context,
      context: { ...mutated.context, tool_call_id: file.record.id },
    });

    // A grant for the vector's hash authorises none of this one.
    expect(captured.intentHash).not.toBe(file.intent_hash);
    expect(mutated.proposal.target).not.toBe(file.proposal.target);
  });
});
