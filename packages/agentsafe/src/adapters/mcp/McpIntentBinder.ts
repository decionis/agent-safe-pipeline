import type {
  AgentProposal,
  JsonObject,
  JsonValue,
  McpToolProfile,
} from "@decionis/agent-safe-pipeline";
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
  | "MCP_TARGET_UNRESOLVED"
  | "SUBJECT_SESSION_REQUIRED"
  | "SUBJECT_ABSENT"
  | "SUBJECT_MISMATCH";

/** What the runtime knows, as against what the model sent. */
export interface McpTrustedContext {
  /** The principal the host authenticated, if it authenticated one. */
  readonly principal?: string;
  /** A fallback idempotency key when the invocation carries none. */
  readonly idempotencyKey: string;
  /**
   * The subject the host's session is pinned to: the customer the identity
   * provider named for this conversation, verified by the host, never sent
   * by the model.
   */
  readonly subject?: string;
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
 *   than guessed;
 * - a tool that names a subject argument is refused without a session
 *   subject, or when the argument names another subject or none, the rule
 *   `agent-safe.profile.api/1` holds a read to.
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
  // The subject before the target: a call for no one, or for another, is
  // that, whatever else is wrong with it.
  if (binding.subject !== undefined) {
    if (trusted.subject === undefined) throw new McpBindingError("SUBJECT_SESSION_REQUIRED");
    const named = subjectOf(args.data[binding.subject]);
    if (named === null) throw new McpBindingError("SUBJECT_ABSENT");
    if (named !== trusted.subject) throw new McpBindingError("SUBJECT_MISMATCH");
  }
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
      // The session's subject, as the authority reads it: the fact session.subject.
      ...(trusted.subject === undefined ? {} : { session: { subject: trusted.subject } }),
    },
    idempotencyKey: invocation.idempotencyKey ?? trusted.idempotencyKey,
    correlationId: invocation.correlationId,
    argumentsDigest: jcsDigest(args.data),
  };
}

/**
 * A subject as stated: a string or a finite number, as a string, of 1 to 200
 * characters; else null. `Number.isFinite` is true of a finite number only,
 * never of a value it would have to convert.
 */
function subjectOf(value: JsonValue | undefined): string | null {
  const named = typeof value === "string" ? value : Number.isFinite(value) ? String(value) : null;
  return named === null || named.length === 0 || named.length > 200 ? null : named;
}

/**
 * A tool's binding as an `agent-safe.profile.mcp/1` profile declares it: the
 * same shape a binding written in code has, read from data. Null when the
 * profile does not declare the tool.
 */
export function profiledBinding(profile: McpToolProfile, tool: string): McpToolBinding | null {
  const declared = profile.tool(tool);
  if (declared === null) return null;
  const environment = profile.definition.environment;
  return {
    tool: declared.tool,
    action: declared.action,
    system: profile.definition.system,
    operation: declared.operation,
    ...(environment === undefined ? {} : { environment }),
    target: declared.target,
    consequential: declared.consequential,
    argumentsSchema: profile.argumentsSchema(declared.tool),
    ...(declared.subject === undefined ? {} : { subject: declared.subject }),
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
