import { z } from "zod";
import type { JsonObject } from "@decionis/agent-safe-pipeline";

/**
 * An MCP tool invocation, at the one moment worth intercepting: the model has
 * chosen a tool and constructed its arguments, and nothing has happened yet.
 *
 * The distinction this file exists to keep is small and load-bearing:
 *
 *     MCP decides *how* an agent invokes a tool.
 *     AgentSafe and Decionis decide *whether this exact invocation* may run.
 *
 * So nothing here is an MCP server, a registry, or a replacement for MCP's
 * own authentication. The type below is a plain description of a call, with
 * no dependency on any MCP SDK, so a stdio server, a streamable-HTTP server
 * and a test can all hand over the same thing.
 */

const toolName = z
  .string()
  .trim()
  .min(1)
  .max(200)
  .regex(/^[a-z0-9][\w.:/-]*$/i);

const bounded = (max: number): z.ZodString => z.string().trim().min(1).max(max);

export const McpInvocationSchema = z
  .object({
    /** The tool the model selected, by the name the server published. */
    tool: toolName,
    /** The arguments the model constructed. Untrusted, and hashed whole. */
    arguments: z.record(z.string(), z.unknown()).default({}),
    /** Which server holds the tool, when the caller runs more than one. */
    server: bounded(200).optional(),
    /** How the call arrived. Carried as context, never as authority. */
    transport: bounded(80).optional(),
    /** Who the caller says it is. Claimed, never verified here. */
    principal: bounded(200).optional(),
    correlationId: bounded(200).optional(),
    idempotencyKey: bounded(180).optional(),
  })
  .strict();

export type McpInvocation = z.infer<typeof McpInvocationSchema>;

/**
 * What an operator declares about one tool, in trusted startup code beside
 * the registry that will run it.
 *
 * A tool with no binding is not governed by this adapter and not silently
 * allowed by it either: the guard refuses it, so adding a consequential tool
 * to a server cannot quietly add an ungoverned path to a system of record.
 *
 * `target` is a template rather than a callback so that a binding stays a
 * description an operator can read, and later hold in configuration, rather
 * than arbitrary code reached by tool name.
 */
export interface McpToolBinding {
  readonly tool: string;
  /** The Agent-Safe action name this tool becomes. */
  readonly action: string;
  /** The system the effect lands in, and the operation there. */
  readonly system: string;
  readonly operation: string;
  readonly environment?: string;
  /** `crm:customer:{customerId}` — every placeholder must be an argument. */
  readonly target: string;
  /**
   * The arguments that decide what the action does. They are named so that
   * evidence and an approval screen can show the few that matter; every
   * argument is inside the intent hash regardless, named or not.
   */
  readonly consequential: readonly string[];
  /** The arguments this tool accepts. Anything else is refused, not dropped. */
  readonly argumentsSchema: z.ZodType<JsonObject>;
}

export const MAX_TEMPLATE_PLACEHOLDERS = 16;

/**
 * Fills a target template from the arguments, by a single linear scan.
 *
 * Deliberately not a regular expression: the template is an operator's, but
 * the values substituted into it are the model's, and a scan has no
 * backtracking to exploit. A placeholder with no argument, an argument that
 * is not a scalar, and an unterminated brace are each a refusal rather than a
 * target with a hole in it.
 */
export function fillTarget(template: string, args: JsonObject): string | null {
  let out = "";
  let placeholders = 0;
  for (let at = 0; at < template.length; at += 1) {
    const character = template[at];
    if (character !== "{") {
      if (character === "}") return null;
      out += character;
      continue;
    }
    const close = template.indexOf("}", at + 1);
    if (close === -1) return null;
    placeholders += 1;
    if (placeholders > MAX_TEMPLATE_PLACEHOLDERS) return null;
    const name = template.slice(at + 1, close);
    if (name.length === 0 || !Object.hasOwn(args, name)) return null;
    const value = args[name];
    if (typeof value === "string") {
      if (value.length === 0) return null;
      out += value;
    } else if (typeof value === "number" && Number.isFinite(value)) {
      out += String(value);
    } else if (typeof value === "boolean") {
      out += String(value);
    } else {
      return null;
    }
    at = close;
  }
  return out.length === 0 || out.length > 500 ? null : out;
}
