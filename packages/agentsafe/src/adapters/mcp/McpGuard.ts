import {
  ActionRegistry,
  IntentCapture,
  SafeExecutor,
  type AuditRecorder,
  type AuthorizationVerifier,
  type DecisionAuthority,
  type ExecutionSignals,
  type GateDecision,
  type IntentActor,
  type JsonObject,
  type SafeExecutionResult,
} from "@decionis/agent-safe-pipeline";
import { jcsDigest } from "../JcsDigest.js";
import { McpBindingError, bindMcpInvocation, bindingFor } from "./McpIntentBinder.js";
import type { McpInvocation, McpToolBinding } from "./McpInvocation.js";

/**
 * One consequential MCP tool: what an operator declared about it, and what it
 * actually does. `invoke` runs only behind a claimed single-use grant, with
 * the arguments the authority evaluated.
 */
export interface McpTool<TResult = unknown> {
  readonly binding: McpToolBinding;
  invoke(args: JsonObject): Promise<TResult>;
}

export interface McpGuardOptions {
  readonly tools: readonly McpTool[];
  readonly authority: DecisionAuthority;
  readonly verifier: AuthorizationVerifier;
  readonly tenantId: string;
  readonly actor: IntentActor;
  readonly audit?: AuditRecorder;
  readonly capture?: IntentCapture;
  /** The boundary and workload this process is, bound into every intent. */
  readonly signals?: ExecutionSignals;
  readonly boundaryId?: string;
  readonly workloadDigest?: string;
  readonly createIdempotencyKey?: (invocation: McpInvocation) => string;
}

export type McpRefusal = McpBindingError["code"] | "MCP_ARGUMENTS_MISMATCH" | string;

/**
 * What became of one invocation. `executed` follows the executor's own
 * vocabulary rather than simplifying it: `null` is a tool that was authorized
 * and dispatched and whose outcome was lost, which is not the same answer as
 * "no" and must never be reported as one. Re-invoking on `null` would be a
 * second attempt at an effect that may already exist; reconcile instead.
 */
export type McpOutcome<TResult = unknown> =
  | {
      readonly executed: true;
      readonly intentHash: string;
      readonly verdict: "ALLOW";
      readonly dossierId: string | null;
      readonly result: TResult;
    }
  | {
      readonly executed: false;
      /** Null when the invocation was refused before an intent existed. */
      readonly intentHash: string | null;
      readonly verdict: "ALLOW" | "BLOCK" | "ESCALATE" | null;
      readonly dossierId: string | null;
      readonly reason: McpRefusal;
    }
  | {
      readonly executed: null;
      readonly intentHash: string;
      readonly verdict: "ALLOW";
      readonly dossierId: string | null;
      readonly reason: "PROVIDER_OUTCOME_UNKNOWN";
    };

/** What an intent's dispatch is held to: the tool, and the arguments as bound. */
interface Held {
  readonly tool: McpTool;
  readonly digest: string;
}

/**
 * The authority boundary for MCP tool execution.
 *
 * MCP has already decided how the agent calls the tool. This decides whether
 * this exact invocation may run, and it is the only thing between a selected
 * tool and its effect:
 *
 *     tool selected → arguments constructed → **guard** → intent →
 *     enforce-and-bind → authority → atomic claim → the tool runs, once
 *
 * It is not an MCP server, an MCP registry, or a replacement for MCP's own
 * authentication. It holds no opinion about transports and depends on no MCP
 * SDK; a server hands it an invocation and gets back a verdict and, when the
 * verdict is ALLOW and the grant was claimed, a result.
 *
 * The property worth stating plainly: **arguments that change after the
 * authority is issued invalidate it.** They are inside the canonical intent
 * hash, so a changed argument is a different intent whose grant does not
 * match; and independently, the handler recomputes their canonical digest
 * immediately before the point of no return and refuses if it is not the one
 * the intent bound. A tool therefore receives the arguments a policy saw, or
 * receives nothing.
 */
export class McpGuard {
  private readonly bindings: ReadonlyMap<string, McpToolBinding>;
  private readonly tools: ReadonlyMap<string, McpTool>;
  private readonly held = new Map<string, Held>();
  private readonly capture: IntentCapture;
  private readonly executor: SafeExecutor;
  private readonly options: McpGuardOptions;

  public constructor(options: McpGuardOptions) {
    this.options = options;
    this.bindings = new Map(options.tools.map((tool) => [tool.binding.tool, tool.binding]));
    this.tools = new Map(options.tools.map((tool) => [tool.binding.tool, tool]));
    this.capture =
      options.capture ?? new IntentCapture({ ...(options.audit && { audit: options.audit }) });
    let registry = new ActionRegistry();
    for (const tool of options.tools) {
      registry = registry.register(tool.binding.action, {
        parametersSchema: tool.binding.argumentsSchema,
        execute: async ({ intent, parameters, dispatch }) => {
          const held = this.held.get(intent.intent.intentId);
          if (held === undefined) throw new Error("MCP_INVOCATION_NOT_HELD");
          // The point of no return is one line below. The tool is handed the
          // parameters off the hash-bound intent, never a copy something else
          // could have edited, and their canonical digest is compared here to
          // the one binding recorded. Arguments that drifted between
          // authorization and dispatch fail before the grant is spent.
          if (jcsDigest(parameters) !== held.digest) throw new Error("MCP_ARGUMENTS_MISMATCH");
          return await dispatch.run(async () => await held.tool.invoke(parameters));
        },
      });
    }
    this.executor = new SafeExecutor(registry.seal(), options.verifier, options.audit, {
      ...(options.boundaryId === undefined ? {} : { boundaryId: options.boundaryId }),
      ...(options.workloadDigest === undefined ? {} : { workloadDigest: options.workloadDigest }),
    });
  }

  /** Every tool this guard governs, for a server publishing its tool list. */
  public governs(tool: string): boolean {
    return this.bindings.has(tool);
  }

  public async guard<TResult = unknown>(invocation: McpInvocation): Promise<McpOutcome<TResult>> {
    let bound;
    let binding: McpToolBinding;
    try {
      binding = bindingFor(this.bindings, invocation.tool);
      bound = bindMcpInvocation(invocation, binding, {
        idempotencyKey:
          this.options.createIdempotencyKey?.(invocation) ??
          `mcp-${invocation.tool}-${jcsDigest(invocation.arguments as JsonObject).slice(7, 23)}`,
      });
    } catch (error) {
      // Refused before the authority was asked: no decision, no dossier.
      const code = error instanceof McpBindingError ? error.code : "MCP_INVOCATION_INVALID";
      return { executed: false, intentHash: null, verdict: null, dossierId: null, reason: code };
    }
    const captured = this.capture.capture(bound.proposal, {
      tenantId: this.options.tenantId,
      actor: this.options.actor,
      downstreamTarget: {
        system: binding.system,
        operation: binding.operation,
        ...(binding.environment === undefined ? {} : { environment: binding.environment }),
      },
      context: bound.context,
      idempotencyKey: bound.idempotencyKey,
      ...(bound.correlationId === undefined ? {} : { correlationId: bound.correlationId }),
      ...(this.options.signals === undefined ? {} : { signals: this.options.signals }),
    });
    const tool = this.tools.get(invocation.tool);
    if (tool === undefined) throw new Error("MCP_TOOL_NOT_REGISTERED");
    // Held from capture, before the authority is asked, so there is no window
    // in which an intent exists without the arguments its dispatch is held to.
    this.held.set(captured.intent.intentId, { tool, digest: bound.argumentsDigest });
    let execution: SafeExecutionResult<TResult>;
    try {
      const decision = await this.options.authority.evaluate(captured);
      execution = await this.executor.run<TResult>(captured, decision);
      return this.outcomeOf(captured.intentHash, decision, execution);
    } finally {
      this.held.delete(captured.intent.intentId);
    }
  }

  private outcomeOf<TResult>(
    intentHash: string,
    decision: GateDecision,
    execution: SafeExecutionResult<TResult>,
  ): McpOutcome<TResult> {
    if (execution.outcome === "COMPLETED") {
      return {
        executed: true,
        intentHash,
        verdict: "ALLOW",
        dossierId: decision.dossierId,
        result: execution.result,
      };
    }
    if (execution.outcome === "UNKNOWN_AFTER_DISPATCH") {
      // The tool was reached and may have acted. Saying "not executed" here
      // would invite a second attempt at an effect that may already exist.
      return {
        executed: null,
        intentHash,
        verdict: "ALLOW",
        dossierId: decision.dossierId,
        reason: execution.reason,
      };
    }
    return {
      executed: false,
      intentHash,
      verdict: decision.verdict,
      dossierId: decision.dossierId,
      reason: execution.reason,
    };
  }
}
