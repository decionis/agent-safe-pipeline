import type { AgentProposal, JsonObject } from "@decionis/agent-safe-pipeline";
import { jcsDigest, type Sha256 } from "../JcsDigest.js";
import {
  McpInvocationSchema,
  fillTarget,
  type McpInvocation,
  type McpToolBinding,
} from "./McpInvocation.js";

export class McpBindingError extends Error {
  public constructor(public readonly code: McpBindingCode) {
    super(code);
    this.name = "McpBindingError";
  }
}

export type McpBindingCode =
  | "MCP_INVOCATION_INVALID"
  | "MCP_TOOL_NOT_BOUND"
  | "MCP_TOOL_MISMATCH"
  | "MCP_ARGUMENTS_INVALID"
  | "MCP_TARGET_UNRESOLVED";

/** What the runtime knows, as against what the model sent. */
export interface McpTrustedContext {
  /** The principal the host authenticated, if it authenticated one. */
  readonly principal?: string;
  /** A fallback idempotency key when the invocation carries none. */
  readonly idempotencyKey: string;
}

export interface BoundMcpInvocation {
  readonly proposal: AgentProposal;
  /** The trusted context the runtime computes; never anything the model sent as context. */
  readonly context: JsonObject;
  readonly idempotencyKey: string;
  readonly correlationId: string | undefined;
  /**
   * The canonical digest of the arguments as bound. The guard recomputes it
   * immediately before dispatch: arguments that changed after the authority
   * was issued are a refusal, not an execution.
   */
  readonly argumentsDigest: Sha256;
}

/**
 * The gate between the MCP transport and the action.
 *
 * A tool name and a bag of arguments arrive from a model. What leaves is an
 * Agent-Safe proposal: an action the operator named, a target derived from
 * the arguments rather than accepted from the caller, and the arguments
 * themselves, validated whole.
 *
 * Every refusal here happens before the authority is asked, so none of them
 * costs a decision or a dossier:
 *
 * - a tool with no binding is refused rather than passed through, so adding
 *   a consequential tool to a server cannot quietly add an ungoverned path;
 * - an argument the tool's schema does not name is refused rather than
 *   dropped, because a dropped argument is one the authority never saw and
 *   the tool might still act on;
 * - a target that cannot be resolved from the arguments is refused rather
 *   than guessed.
 *
 * What it does not do is authorize anything. It produces a proposal; the
 * authority decides, and the claim is what makes a dispatch legal.
 */
export function bindMcpInvocation(
  input: McpInvocation,
  binding: McpToolBinding,
  trusted: McpTrustedContext,
): BoundMcpInvocation {
  const parsed = McpInvocationSchema.safeParse(input);
  if (!parsed.success) throw new McpBindingError("MCP_INVOCATION_INVALID");
  const invocation = parsed.data;
  if (invocation.tool !== binding.tool) throw new McpBindingError("MCP_TOOL_MISMATCH");
  const args = binding.argumentsSchema.safeParse(invocation.arguments);
  if (!args.success) throw new McpBindingError("MCP_ARGUMENTS_INVALID");
  const target = fillTarget(binding.target, args.data);
  if (target === null) throw new McpBindingError("MCP_TARGET_UNRESOLVED");
  // The consequential names are an operator's list of what matters, for a
  // reviewer and for evidence. They narrow nothing: every argument is in the
  // proposal and therefore in the hash.
  const consequential = binding.consequential.filter((name) => Object.hasOwn(args.data, name));
  return {
    proposal: { action: binding.action, target, parameters: args.data },
    context: {
      ingress: "mcp",
      mcp_tool: binding.tool,
      mcp_arguments_digest: jcsDigest(args.data),
      mcp_consequential: consequential,
      ...(invocation.server === undefined ? {} : { mcp_server: invocation.server }),
      ...(invocation.transport === undefined ? {} : { mcp_transport: invocation.transport }),
      // The host's own principal when it has one, else what the caller
      // claimed, marked as claimed either way it is read.
      ...(trusted.principal === undefined
        ? invocation.principal === undefined
          ? {}
          : { claimed_principal: invocation.principal }
        : { claimed_principal: trusted.principal }),
    },
    idempotencyKey: invocation.idempotencyKey ?? trusted.idempotencyKey,
    correlationId: invocation.correlationId,
    argumentsDigest: jcsDigest(args.data),
  };
}

/** The binding for a tool, or a refusal naming the tool as ungoverned. */
export function bindingFor(
  bindings: ReadonlyMap<string, McpToolBinding>,
  tool: string,
): McpToolBinding {
  const binding = bindings.get(tool);
  if (binding === undefined) throw new McpBindingError("MCP_TOOL_NOT_BOUND");
  return binding;
}
